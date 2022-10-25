import ida_segment
import ida_ua
import idaapi
import ida_idaapi
import ida_funcs
import ida_bytes
import ida_segregs
import ida_idp
import ida_name
import idautils
import ida_dbg
import ida_xref
import ida_kernwin
import idc
import os
import string
from unicorn import * 
from unicorn.arm_const import * 
from unicorn.mips_const import * 
from unicorn.arm64_const import * 
import struct
import hexdump

from EWS.utils.utils import *
from EWS.emu.emubase import Emulator
from EWS.utils.exec_trace import *

from EWS.ui.debug_view import *

MAX_INSN_SIZE=8
MAX_EXEC= 0x10000 # max number of executed insn 
FOLLOW_PC= False  #TODO move it to the configuration option

class Emucorn(Emulator):

    def __init__(self,conf):
        super().__init__(conf)
        self.nb_insn=0
        self.running_stubs = dict()
        self.exec_trace = Exec_Trace(self.conf.arch,addr=None)
        self.exec_trace.addr = {}
        self.debug_view = None # todo create the reference in EWS_Plugin object
        self.filetype = ida_loader.get_file_type_name()
        self.assembler = None




#---------------------------------------------------------------------------------------------
#
#   EMULATOR Mapping functions
#
#---------------------------------------------------------------------------------------------
    @staticmethod
    def do_required_mappng(uc,s_ea,e_ea,p_size,perms):
        """ Use this function to avoid page mappings
                that already exist. 
                Usefull when mapping user provided ranges,
                or for small sections that will share pages.    
        """ 
        b_page = s_ea & ~(p_size -1)
        while b_page < e_ea:    
            alrdy_map = False
            for rsta,rsto,rpriv in uc.mem_regions():
                if b_page == rsta:
                    alrdy_map = True
                    break
            if not alrdy_map: 
                logger.console(LogType.INFO,'[%s] map page %8X'%('Emucorn',b_page))
                uc.mem_map(b_page,p_size,perms)
            b_page += p_size


    def flush(self):
        """
            bug3 test
        """

        for i in range(len(self.exec_trace.addr.keys())-1):
            try:
                self.exec_trace.addr.pop()
            except:
                pass

    def add_mapping(self,addr,mem,perms=UC_PROT_ALL):
        """ Add mapping
            params: 
                addr: base address
                mem: bytes content
                perms (optnal) : permissions
        """
        for rsta,rsto,rpriv in self.uc.mem_regions():
            if addr in range(rsta,rsto):
                logger.console(LogType.WARN,'0x%x is already map, please use another addr or change mapping using emu.helper.mem_write()'%addr)
                return -1

        Emucorn.do_required_mappng(self.uc,addr,addr+len(mem),self.conf.p_size,perms)
        self.uc.mem_write(addr,mem) 
        logger.console(LogType.INFO,'[%s] Additionnal mapping for data at 0x%x'%('Emucorn',addr)) 
        return 0

    @staticmethod
    def do_mapping(uc,conf):
        """
            Do required mapping according the 
            configuration object.
        """

        inf = ida_idaapi.get_inf_structure()
        last_vb = None

        # Maps program segment
        if conf.map_with_segs:
            for seg in conf.segms:
                vbase = Emucorn.do_required_mappng(uc,seg.start_ea, seg.end_ea, conf.p_size, UC_PROT_ALL if not conf.use_seg_perms else seg.perm) 
                uc.mem_write(seg.start_ea,ida_bytes.get_bytes(seg.start_ea,seg.end_ea-seg.start_ea))
#                logger.console(LogType.INFO,'[%s] Mapping seg %s\n'%('EmuCorn',ida_segment.get_segm_name(seg)))
                logger.logfile(LogType.INFO,'Mapping seg %s\n'%(ida_segment.get_segm_name(seg)))
        else:
            for seg in get_seg_list():

                # only show waitbox for big segment (speed-up)
                if seg.end_ea - seg.start_ea > 20 * conf.p_size:
                    idaapi.show_wait_box("Mapping %s"%ida_segment.get_segm_name(seg))
                vbase=seg.start_ea&~(conf.p_size-1)
                if last_vb == None:
                    nb_pages = ((seg.end_ea- vbase) // conf.p_size) +1
                    try:
                        uc.mem_map(vbase,nb_pages*conf.p_size)
                    except Exception as e:
                        logger.console(LogType.ERRR,"mapping at %x  for %d returns : %s"%(vbase,nb_pages,str(e)))
                    last_vb = vbase + nb_pages*conf.p_size
                else:
                    if seg.end_ea > (last_vb):
                        if vbase < last_vb:
                            vbase = last_vb
                        nb_pages = ((seg.end_ea - vbase) // conf.p_size) +1
                        try:
                            uc.mem_map(vbase,nb_pages*conf.p_size)
                        except Exception as e:
                            logger.console(LogType.ERRR,"mapping at %x  for %d returns : %s"%(vbase,nb_pages,str(e)))
                        last_vb = vbase + (nb_pages)*conf.p_size

                logger.console(LogType.INFO,'Mapped segment %s [%x:%x]'%(ida_segment.get_segm_name(seg),
                                                                         seg.start_ea,
                                                                         seg.end_ea))
                try:
                    uc.mem_write(seg.start_ea,ida_bytes.get_bytes(seg.start_ea,seg.size()))
                except Exception as e:
                    logger.console(LogType.ERRR,"writing segment %x to %x content returns : %s"%(seg.start_ea,seg.end_ea,str(e)))

                # close waitbox if it was openend
                if seg.end_ea - seg.start_ea > 20 * conf.p_size:
                    idaapi.hide_wait_box()

        #Map user provided areas 
        for m_ea,content in conf.amap_conf.mappings.items():
            idaapi.show_wait_box("Mapping user content")
            Emucorn.do_required_mappng(uc,m_ea,m_ea+len(content),conf.p_size,UC_PROT_ALL)
            uc.mem_write(m_ea,content) 
            logger.console(LogType.INFO,'[%s] Additionnal mapping for data at %8X'%('Emucorn',m_ea)) 
            idaapi.hide_wait_box()

        idaapi.show_wait_box("Mapping stack") 
        stk_p,r = divmod(conf.stk_size,conf.p_size)
        if r: stk_p+=1 
        uc.mem_map(conf.stk_ba,stk_p*conf.p_size)
        logger.logfile(LogType.INFO,' [%s] mapped stack at 0x%.8X '%('Emucorn',conf.stk_ba))
        
        idaapi.hide_wait_box()
        logger.console(LogType.INFO, "All IDB segment has been successfully mapped in emulator")


#---------------------------------------------------------------------------------------------
#
#Emulator reg/mem accesses 
#
#---------------------------------------------------------------------------------------------


    def mem_read(self,addr,size):
        return self.uc.mem_read(addr,size)

    def mem_write(self,addr,data):
        self.uc.mem_write(addr,data)

    def reg_read(self,r_id):
        """ 
            id mapping functions might be call before 
        """
        return self.uc.reg_read(r_id)

    def reg_write(self,r_id,value):
        """ id 
            mapping functions should be call before 
        """
        self.uc.reg_write(r_id,value)


#---------------------------------------------------------------------------------------------
#
#   Hooking events functions 
#
#---------------------------------------------------------------------------------------------
    @staticmethod
    def unmp_read(uc,access,addr,value,size,user_data):

        _self = user_data
        logger.console(LogType.WARN,'[!] Read Access Exception',
                       'Cannot read 0x%.8X'%addr,
                       'for size %d (reason: unmapped page)'%size)
        logger.console(LogType.WARN,'[!] Fault instruction at %x'%_self.helper.get_pc())
        conf = _self.conf
        if conf.autoMap:
            base_addr = addr & ~(conf.p_size-1)
            uc.mem_map(base_addr,conf.p_size)
            uc.mem_write(base_addr,b'\xff'*conf.p_size)
            logger.console(LogType.INFO,'[*] Automap: added page 0x%.8X'%base_addr)
            return True
        logger.console(LogType.ERRR,'Automap is not enabled. Aborting()')
        return False


    @staticmethod
    def unmp_write(uc,access,addr,size,value,user_data):
   
        _self = user_data
        logger.console(LogType.WARN,
                       '[!] Write Access Excpetion:'
                       'cannot write value 0x%.8X at address 0x%.8X'%(value,addr),
                       '(reason: unmapped page)')
        logger.console(LogType.WARN,'[!] Fault instruction at %x'%_self.helper.get_pc())
        conf = _self.conf
        if conf.autoMap:
            base_addr = addr & ~(conf.p_size-1)
            try:
                uc.mem_map(base_addr,conf.p_size)
            except UcError:
                logger.console(LogType.WARN,'[*] Automap not supported for this arch')
                return False
            logger.console(LogType.INFO,'[*] Automap: added page 0x%.8X'%base_addr)
            return True
        logger.console(LogType.ERRR,'Automap is not enabled. Aborting()')
        return False


    @staticmethod
    def hk_read(uc,access,addr,size,value,user_data):
        """ 
        Unicorn callback. Default hook for read accesses. 
        Parameters:
                - user_data is a pointer to emulator object. 
        """

        _self= user_data

        out= ': [read]  '
        out +='with size: %d '%size
        out +=hexdump.hexdump(uc.mem_read(addr,size),result='return').replace('00000000','')

        _self.exec_trace.add_instruction(addr=addr,
                                        assembly=out,
                                        regs=_self.get_regs(),
                                        color=get_insn_color(addr),
                                        tainted=False,
                                        count=_self.nb_insn)

        logger.logfile(LogType.INFO,out) 



    @staticmethod
    def hk_write(uc,access,addr,size,value,user_data):
        """
        Unicorn callback. Default hook for write accesses.
        Parameters:
                - user_data is a pointer to emulator object. 
        """
        _self = user_data


        out = ': [write] '
        out +='with size %d '%size
        out += hexdump.hexdump(int_to_bytes(value,size),
                               result='return').replace('00000000','')

        _self.exec_trace.add_instruction(addr=addr,
                                        assembly=out,
                                        regs=_self.get_regs(),
                                        color=get_insn_color(addr),
                                        tainted=False,
                                        count=_self.nb_insn)

        logger.logfile(LogType.INFO,out) 


    def hook_code(self,uc,addr,size,user_data): 

        asm = ''
        if addr in self.running_stubs.keys():
            try:
                self.running_stubs[addr].do_it()
                s_name = self.running_stubs[addr].name
                asm = log = '0x%x:\t%s'%(addr,s_name)


            except Exception as e:
                logger.console(LogType.WARN,'Error in stub, aborting')
                uc.emu_stop()
                logger.console(LogType.ERRR,'backtrace:\n',e.__str__())
                return False
        
        elif addr in self.user_breakpoints or ida_dbg.exist_bpt(addr):
                print("entering breakpoint shit")
                if self.last_pc != self.helper.get_pc():
                        uc.emu_stop()
                        logger.console(LogType.INFO,'Breakpoint at %x reached.\nType emu.continuee() to pursue execution'%addr)
                        self.last_pc = self.helper.get_pc()
                        return True
        
        self.color_map[addr] = get_insn_color(addr)

        if addr in self.conf.patches.keys():
            asm = log = ':\t'+self.conf.patches[addr]
        else:
            if asm == '':
                asm = get_captsone_repr(self,addr)
                log = build_insn_repr(self,addr)
    
        self.exec_trace.add_instruction(addr=addr,
                                            assembly=asm,
                                            regs=self.get_regs(),
                                            color=get_insn_color(addr),
                                            tainted=False,
                                            count=self.nb_insn)
        logger.logfile(LogType.INFO,log)


        self.last_pc = self.helper.get_pc()
        if FOLLOW_PC:
            ida_kernwin.jumpto(self.last_pc)
        
#        if  self.nb_insn >= MAX_EXEC:
        if self.nb_insn >= self.conf.max_insn:
            logger.console(LogType.WARN,
                           "Execution reach the max number of insn (%d)"%self.conf.max_insn)
            uc.emu_stop()
            return False
        self.nb_insn+=1
        return True


#---------------------------------------------------------------------------------------------
#  STUB MECHANISM
#  TODO insert features descriptions
#---------------------------------------------------------------------------------------------

    def stub_ELF_sym(self,
                     ea: int,
                     stub_func,
                     name:str=''):

        """
            patch the first instruction of the PLT
            resolution handler associated to the symbol.
        """

        self.stub_func_addr(ea,
                            stub_func,
                            stub_type=StubType.BUILTIN,
                            name=name)
        
        logger.logfile(LogType.INFO,"%s is now stubbed at %x"%\
                       (name,ea))


    def stub_PE_sym(self,
                    ea,
                    stub_func,
                    name: str = ''):
        """
            nop each call based on the IAT entry
            associated to the symbol.
        """

        stub =    self.get_new_stub(stub_func,
                                    stub_type=StubType.BUILTIN,
                                    name=name)
        self.running_stubs[ea] = stub
        self.nop_insn(ea)
        self.stubbed_bytes[ea] = get_insn_bytecode(ea)

        logger.logfile(LogType.INFO,"%s is now stubbed at %x"%\
                       (name,ea))



    def stub_sym(self,
                 ea: int,
                 stub_func,
                 name: str = ''):

        """
            stub the right way according the architecture.
        """

        if hasattr(self,'loader_type'):
            if self.loader_type == LoaderType.PE:
                self.stub_PE_sym(ea,stub_func,name)
                return

        # default behavior is based on ELF format. 
        self.stub_ELF_sym(ea,
                          stub_func,
                          name)




    def stub_func_addr(self,
                       ea:int,
                       stub_func,
                       stub_type:StubType,
                       name:str=''):

        """
            stub a function by it address.
            a return instruction will replace
            the first instruction of the targeted 
            function.
            It creates a new stub object recorded 
            in running_stubs list.
        """

        if not ida_funcs.get_func(ea):
            logger.logfile(LogType.WARN,"%s %x not a function"%\
                           (sys._getframe().f_code.co_name,
                            ea))
            return

        stub =    self.get_new_stub(stub_func,
                                    stub_type=stub_type,
                                    name=name)
        self.running_stubs[ea] = stub
        self.uc.mem_write(ea,self.get_retn_insn(ea))

        self.stubbed_bytes[ea] = get_insn_bytecode(ea)




    def unstub_func_addr(self,
                         ea: int):

        """
            unstubbing consists in :
                conf cleaning
                removing stub object from stub list
                repatching memory with original bytecode
        """

        if ea in self.running_stubs.keys():

            if self.running_stubs[ea].stub_type == StubType.TAG:
                self.conf.remove_tag(ea)
            elif self.running_stubs[ea].stub_type == StubType.NULL:
                self.conf.remove_null_stub(ea)

            del self.running_stubs[ea]

            self.helper.mem_write(ea,self.stubbed_bytes[ea])

            del self.stubbed_bytes[ea]


    def unstub_all(self,
                   clean_configuration: bool = False):

        """
            remove all stubs for symbols and user defined stubs
        """

        for ea, v in self.running_stubs.items():
            if clean_configuration:
                if v.stub_type == StubType.TAG:
                    self.conf.remove_tag(ea)
                elif v.stub_type == StubType.NULL:
                    self.conf.remove_null_stub(ea)


            del self.running_stubs[ea]
            del self.stubbed_bytes[ea]


    def stub_PLT(self):

        """
            stubs PLT
        """

        for k,v in self.reloc_map.items():

            # TODO change by ida_xref.get_first_dref_to(v) ? 
            xref_g = idautils.XrefsTo(v)

            try:

             while True:

                xref = next(xref_g)

                if k in self.stubs.keys():

                    self.stubs[k].set_helper(self.helper)
                    self.stub_ELF_sym(xref.frm,self.stubs[k].do_it,k)

                elif k == '__libc_start_main':

                        logger.logfile(LogType.INFO,'libc_start_main stubbed!')
                        self.uc.mem_write(v,
                                        int.to_bytes(self.libc_start_main_trampoline,
                                        8 if idc.__EA64__ else 4,
                                     'little'))

                else:

                     if self.conf.s_conf.auto_null_stub:

                            self.add_null_stub(xref.frm)

            except StopIteration:

                pass

        for s_ea in self.conf.s_conf.nstubs.keys():
                self.add_null_stub(s_ea)

        for k,v in self.conf.s_conf.tags.items():
            self.tag_func(k,v)



    def stub_PE(self):

        """
            stubs PE
        """

        for k,v in self.reloc_map.items():

            # TODO change by ida_xref.get_first_dref_to(v) ? 
            xref_g = idautils.XrefsTo(v)

            try:

             while True:

                xref = next(xref_g)

                if k in self.stubs.keys():

                    self.stubs[k].set_helper(self.helper)
                    self.stub_PE_sym(xref.frm,self.stubs[k].do_it,k)


                else:

                     if self.conf.s_conf.auto_null_stub:
                         self.nop_insn(xref.frm)

            except StopIteration:

                pass

        for s_ea in self.conf.s_conf.nstubs.keys():
                self.add_null_stub(s_ea)

        for k,v in self.conf.s_conf.tags.items():
            self.tag_func(k,v)





    def add_null_stub(self,ea,update_conf=False):

        """
            Null stubs allow to directly bypass
            a function call.
        """

        if ea in self.running_stubs.keys():
            self.unstub_func_addr(ea)

        self.stub_func_addr(ea,
                            self.nstub_obj.do_it,
                            stub_type=StubType.NULL)

        if update_conf:
            self.conf.add_null_stub(ea)

    def remove_null_stub(self,ea,update_conf=False):

        self.unstub_func_addr(ea)
        

    def add_custom_stub(self,
                        ea: int,
                        func,
                        name:str='user stub'):

        """
            Custom stub allows the user to define a function
            that will be called instead a stubbed address / symbols.
        """

        stub = self.get_new_stub(func,StubType.USER,name=name)
        if ea in self.running_stubs.keys():
            logger.console(LogType.WARN,"Function at %x is already stubbed."
                           "Overwritting stub with new tag"%ea)
            self.unstub_func_addr(ea)

        self.stub_func_addr(ea,stub.do_it,stub_type=StubType.USER)
        logger.console(LogType.INFO,'[+] %s is now stubbed'%get_func_name(ea))


    def remove_custom_stub(self,
                           ea:int):

        self.unstub_func_addr(ea)


    def tag_func(self,
                 ea: int,
                 stub_name: str):

        """
            Function tagging consists in associating
            a function to a stub. If you find a memcpy like
            function, you can tag it with the internal memcpy
            stub. You will then be able to track its argument.
        """

        if not stub_name in self.stubs.keys():
            logger.console(LogType.WARN,'[!] %s is not among available stubs. ',
                           'Please refers to list_stubs command to get the list of available stubs'%stub_name)
            return

        if ea in self.running_stubs.keys():
                logger.console(LogType.WARN,"Function at %x is already stubbed. ",
                               ' Overwritting stub with new tag'%(stub_name, ea))
                self.unstub_func_addr(ea)

        else:
                self.stubs[stub_name].set_helper(self.helper)

        self.stub_func_addr(ea,self.stubs[stub_name].do_it,stub_type=StubType.TAG)

        logger.console(LogType.INFO,'[+] %x is now stubbed with %s function'%(ea,stub_name))
        self.conf.add_tag(ea,stub_name)


    def remove_tag(self,ea):
        self.unstub_func_addr(ea)






#---------------------------------------------------------------------------------------------
#
# DEBUGGING FUNCTION
#
#---------------------------------------------------------------------------------------------






    def start(self,cnt=0,saddr=None): 
        """
            This function launch unicorn **start** function. 
            It will run a limited instructions from the start address.
        """

        stop_addr=self.conf.exec_eaddr
        self.nb_insn = 0
        if not saddr:
            saddr = self.conf.exec_saddr
        # in case saddr has changed between emulator creation and emulator is launched
        if self.conf.registers.get_program_counter() != saddr and not self.is_running:
            logger.console(LogType.WARN,'exec_saddr != registers.PC, using registers.PC')
            saddr = self.conf.registers.get_program_counter()
        try:
            idaapi.show_wait_box("Running...")
            self.uc.emu_start(saddr,stop_addr,timeout=0,count=cnt)
            self.is_running = True

        except UcError as e:
            logger.console(LogType.ERRR,'Error in unicorn engine')
            raise e
        except Exception as e:
            logger.console(LogType.WARN,
                           '[!] Exception in program : %s' % e.__str__())
        finally:
            idaapi.hide_wait_box()

        # Deprecated with new execution trace feature; 
#        if self.conf.color_graph:
#            colorate_graph(self.color_map)


    def step_n(self,n):
        pc =    self.helper.get_pc()
        self.start(cnt=n,saddr=pc)
        logger.console(LogType.INFO,'[+] exectution stopped at 0x%x'%self.helper.get_pc())

    def step_in(self):

        if self.helper.get_pc() == self.conf.exec_eaddr:

            insn = get_insn_at(self.helper.get_pc())
            self.conf.exec_eaddr+=insn.size

        self.step_n(1)

    def continuee(self):
        self.step_n(0)



    def step_over(self):
        """
            Try to detect the target using IDA API.
            Use IDA breakpoint to notify the user that breakpoint are added (there is no wizard)
            It will then have to remove it if he/she restarts the program.
            It handles call, direct jump, and jump tables
        """

        insn = get_insn_at(self.helper.get_pc())
        bp_addr = []

        if ida_idp.is_call_insn(insn) or ida_idp.has_insn_feature(insn.itype,ida_idp.CF_STOP):
            self.uc.emu_start(insn.ea,insn.ea+insn.size,0,0)
        elif ida_idp.is_indirect_jump_insn(insn):
            logger.console(LogType.WARN,
                           "Indirect jump incompatible with step_over feature.",
                           "Please do it manually")
        else:
            self.step_in()

    def add_watchpoint(self,base_addr, rang, mode=0x3):

        def hk_read_wp(uc,access,addr,size,value,user_data):
            if addr >= base_addr and addr < base_addr + rang:
                logger.console(LogType.INFO,"[Watchpoint] read access for addr " 
                               "%x reached at pc %x"% (addr,self.helper.get_pc()))

        def hk_write_wp(uc,access,addr,size,value,user_data):

            if addr >= base_addr and addr < base_addr + rang:
                logger.console(LogType.INFO,"[Watchpoint] write access for addr " 
                               "%x reached at pc %x"% (addr,self.helper.get_pc()))

        if mode & 0x1:

            self.uc.hook_add(UC_HOOK_MEM_READ,
                       hk_read_wp,
                       self)
            logger.console(LogType.INFO,"Add read watchpoint "
                           "for [%x: %x]"%(base_addr,(base_addr+rang)))
        if (mode >> 1) & 0x1:
            self.uc.hook_add(UC_HOOK_MEM_WRITE,
                       hk_write_wp,
                       self)

            logger.console(LogType.INFO,"Add write watchpoint "
                           "for [%x: %x]"%(base_addr,(base_addr+rang)))

        self.conf.add_watchpoint(base_addr,size)

    def reset_color_graph(self):
        pass



    def patch_insn(self,addr,asm,update_conf=False):
        bytecode = self.assembler.assemble(asm,addr)
        # TODO: check perms, add Write Perm on Page (if required)
        self.uc.mem_write(addr,bytecode)
        logger.console(LogType.INFO,"insn at %x as been patched"%addr)
        # TODO: remove addtionnal perm
        if update_conf:
            self.conf.add_patch(addr,asm)

