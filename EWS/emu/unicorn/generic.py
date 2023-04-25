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
import math

from EWS.utils.utils import *
from EWS.utils.configuration import Configuration, StubConfiguration
from EWS.emu.emubase import Emulator
from EWS.utils.exec_trace import *
from EWS.utils.configuration import AdditionnalMapping

from EWS.ui.debug_view import *

MAX_INSN_SIZE=8
MAX_EXEC= 0x10000 # max number of executed insn 
FOLLOW_PC= False  #TODO move it to the configuration option

class Emucorn(Emulator):

    def __init__(self,conf):


        super().__init__(conf)

        self.nb_insn=0
        self.running_stubs = dict()

        self.exec_trace = Exec_Trace(self.conf.arch,content=None)
        self.exec_trace.content = {}
        self.debug_view = None # todo create the reference in EWS_Plugin object

        self.filetype = ida_loader.get_file_type_name()

        self.assembler = None

        # Debugger Variables
        self.stop = False
        self.ignore_end_addr = False

        self.amap = dict()
        self.patches = dict()

        self.watchpoints = dict()

        self.tags = dict()




#---------------------------------------------------------------------------------------------
#
#   EMULATOR Mapping functions
#
#---------------------------------------------------------------------------------------------
    @staticmethod
    def do_required_mappng(uc: Uc,
                           s_ea: int,
                           e_ea:int,
                           p_size:int,
                           perms:int):

        """ !Use this function to avoid page mappings
                that already exist. 
                Usefull when mapping user provided ranges,
                or for small sections that will share pages.    

            @param uc Unicorn Engine 
            @param s_ea Effective Start Address 
            @param e_ea Effective Stop Address
            @param p_size Page Size
            @param perms Permissions on the Page 

        """ 

        b_page = s_ea & ~(p_size -1)

        while b_page < e_ea:    

            alrdy_map = False

            for rsta,rsto,rpriv in uc.mem_regions():

                if b_page == rsta:

                    alrdy_map = True
                    break

            if not alrdy_map: 

                logger.console(LogType.INFO,f'Map page {b_page:x}')
                uc.mem_map(b_page,p_size,perms)

            b_page += p_size


    def flush(self):

        """ 
        !flush the trace list instructions. Somehow there is a cache issue/leak. 
        this function is executed from the UI when plugin is reset. 

        """

        for i in range(len(self.exec_trace.content.keys())-1):
            try:
                self.exec_trace.addr.pop()
            except:
                pass

    def add_mapping(self,
                    addr:int,
                    mem:bytes,
                    perms:int=UC_PROT_ALL) -> int :
        """ 
            !Create and Write into memory mapping.
             

            @params addr: base address
            @param  mem: content of the mapping
            @params perms : permissions

            @return 0 for Success -1 for Fail
        """

        for rsta,rsto,rpriv in self.uc.mem_regions():

            if addr in range(rsta,rsto):

                logger.console(LogType.WARN,f'Address 0x{addr:x} is already mapped.')
                return -1

        Emucorn.do_required_mappng(self.uc,addr,addr+len(mem),self.conf.p_size,perms)

        self.uc.mem_write(addr,mem) 

        logger.console(LogType.INFO,f'Created new mapping starting at 0x{addr:x}') 

        self.amap[addr] = mem
        
        return 0

    @staticmethod
    def do_mapping(uc: Uc,
                   conf:Configuration):

        """
            !Do required mapping according the 
            configuration object.
                
            @param uc Unicorn Engine reference
            @param conf Configuration Object Reference
            
            
        """

        inf = ida_idaapi.get_inf_structure()
        last_vb = None

        # Maps program segment
        if conf.map_with_segs:

            for seg in conf.segms:

                vbase = Emucorn.do_required_mappng(uc,seg.start_ea, seg.end_ea, conf.p_size, UC_PROT_ALL if not conf.use_seg_perms else seg.perm) 
                uc.mem_write(seg.start_ea,ida_bytes.get_bytes(seg.start_ea,seg.end_ea-seg.start_ea))
                logger.logfile(LogType.INFO,f'Map seg {ida_segment.get_segm_name(seg)}')

        else:

            for seg in get_seg_list():

                if seg.end_ea - seg.start_ea > 20 * conf.p_size:
                    idaapi.show_wait_box(f"Map segment {ida_segment.get_segm_name(seg)}")

                vbase=seg.start_ea&~(conf.p_size-1)

                if last_vb == None:

                    nb_pages = ((seg.end_ea- vbase) // conf.p_size) +1

                    try:

                        uc.mem_map(vbase,nb_pages*conf.p_size)
                    except Exception as e:

                        logger.console(LogType.ERRR,f"Map at {vbase:x}  for {nb_pages} returns : {str(e)}")


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

                    size = seg.size()


                    # get_bytes API does not allow to get more than 0xffffffff bytes. 
                    # nonetheless such mapping should be discarded ?

                    if seg.size() > (math.pow(2,32) -1):     
                        logger.console(LogType.WARN,f"Segment size is too big: {size:x}, restraining to 4GB")
                        size =  int(math.pow(2,32) - 1) & 0xffffffff
                        print(f'size:{size:x}')

                    uc.mem_write(seg.start_ea,ida_bytes.get_bytes(seg.start_ea,size))
                    
                except Exception as e:

                    logger.console(LogType.ERRR,"writing segment %x to %x content returns : %s"%(seg.start_ea,seg.end_ea,str(e)))

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


    def mem_read(self,
                 addr:int,
                 size:int) -> bytes:

        """
        !mem_read

        @param addr Address to read from
        @param size Size to read

        @return bytes with memory content
    
        """

        return self.uc.mem_read(addr,size)

    def mem_write(self,
                  addr:int,
                  data:bytes) -> None:

        """
        !mem_write

        @param addr Address to write to
        @param size Size of the data to write 

        @return bytes with memory content
        """

        self.uc.mem_write(addr,data)

    def reg_read(self,
                 r_id) -> int: 

        """
        !reg_read

        @param r_id (string/int) register identifier 
        
        @return register value

        """

        return self.uc.reg_read(r_id)

    def reg_write(self,
                  r_id,
                  value:int) -> None:

        """ 

        !reg_write

        @param r_id (string/int) register identifier
        @param value register value 


        """

        self.uc.reg_write(r_id,value)


#---------------------------------------------------------------------------------------------
#
#   Hooking events functions 
#
#---------------------------------------------------------------------------------------------
    @staticmethod
    def unmp_read(uc:Uc,
                  access: int,
                  addr: int,
                  value:int,
                  size:int,
                  user_data) -> None:
        """
        ! unmp_read Unicorn Hook Declaration for unmapped address. 

        @param Unicorn Egine
        @param access Access Fashion
        @param addr address which raised the Fault
        @param value ignore_end_addr
        @param size size of the read operation 
        @param user_data Reference to the object


        """

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
    def unmp_write(uc:Uc,
                   access:int,
                   addr:int,
                   size:int,
                   value:int,
                   user_data):

        """
        ! unmp_write Unicorn Hook Declaration for unmapped address. 

        @param Unicorn Egine
        @param access Access Fashion
        @param addr address which raised the Fault
        @param value ignore_end_addr
        @param size size of the write operation 
        @param user_data Reference to the object


        """
   
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
    def hk_read(uc:Uc,
                access:int,
                addr:int,
                size:int,
                value:int,
                user_data):
        """
        ! hk_read Unicorn Hook Declaration for memory access. 

        @param Unicorn Egine
        @param access Access Fashion
        @param addr address which is accessed
        @param value ignore_end_addor
        @param size size of the read operation 
        @param user_data Reference to the object


        """


        _self= user_data

        out= ': [read]  '
        out +='with size: %d '%size
        out +=hexdump.hexdump(uc.mem_read(addr,size),result='return').replace('00000000','')

        _self.exec_trace.add_instruction(addr=addr,
                                        assembly=out,
                                        regs=_self.get_regs(),
                                        color=get_insn_color(addr),
                                        tainted=False)

        logger.logfile(LogType.INFO,out) 



    @staticmethod
    def hk_write(uc:Uc,
                 access:int,
                 addr:int,
                 size:int,
                 value:int,
                 user_data):
        """
        ! hk_read Unicorn Hook Declaration for memory access. 

        @param Unicorn Egine
        @param access Access Fashion
        @param addr address which is accessed
        @param value ignore_end_addor
        @param size size of the read operation 
        @param user_data Reference to the object

        """

        _self = user_data


        out = ': [write] '
        out += f'with size {size} '
        out += hexdump.hexdump(int_to_bytes(value,size),
                               result='return').replace('00000000','')

        _self.exec_trace.add_instruction(addr=addr,
                                        assembly=out,
                                        regs=_self.get_regs(),
                                        color=get_insn_color(addr),
                                        tainted=False)

        logger.logfile(LogType.INFO,out) 


    def hook_code(self,uc:Uc,
                  addr:int,
                  size:int,
                  user_data): 

        """
        ! hook_code Unicorn Hook Declaration for memory access. 

        @param uc Unicorn Egine
        @param addr address which is accessed
        @param size size of the read operation 
        @param user_data Reference to the object

        """
        asm = ''

        if self.stop: 

            uc.emu_stop()

            logger.console(LogType.INFO,f'Breakpoint at 0x{addr:x} reached.',
            f'{self.nb_insn} instruction(s) executed.')

            self.nb_insn = 0

            return False

            

        elif addr in self.running_stubs.keys():
            
            try:

                self.running_stubs[addr].do_it()

                s_name = self.running_stubs[addr].name
                
                asm = log = f'0x{addr}:\t{s_name}'



            except Exception as e:
                
                logger.console(LogType.WARN,'Error in stub, aborting')

                uc.emu_stop()

                logger.console(LogType.ERRR,'backtrace:\n',e.__str__())

                return False
        
        elif addr in self.user_breakpoints or ida_dbg.exist_bpt(addr):

            self.stop = True

                        
        self.color_map[addr] = get_insn_color(addr)


        if asm == '':
                        

                asm = get_captsone_repr(self,addr)
                log = build_insn_repr(self,addr)
    
        self.exec_trace.add_instruction(addr=addr,
                                            assembly=asm,
                                            regs=self.get_regs(),
                                            color=get_insn_color(addr),
                                            tainted=False)
        logger.logfile(LogType.INFO,log)


        self.last_pc = self.helper.get_pc()

        if FOLLOW_PC:
            
            ida_kernwin.jumpto(self.last_pc)
        
        if self.nb_insn >= self.conf.max_insn:

            logger.console(LogType.WARN,
                          f"Execution reach the max number of insn {self.conf.max_insn}")

            self.stop = True

            self.nb_insn = 0

            return True

        self.nb_insn+=1
        return True


#---------------------------------------------------------------------------------------------
#  STUB MECHANISM
#---------------------------------------------------------------------------------------------

    def stub_ELF_sym(self,
                     ea: int,
                     stub_func,
                     name:str=''):

        """
            !stub_elf_sym stub the function given a effective address.  

            @param ea Effective Address in the .plt
            @param stub Stub Object 
            @param name Symbol of the function
        """

        self.stub_func_addr(ea,
                            stub_func,
                            stub_type=StubType.BUILTIN,
                            name=name)
        
        logger.logfile(LogType.INFO,f"{name} is now stubbed at {ea:x}")


    def stub_PE_sym(self,
                    ea:int,
                    stub_func,
                    name: str = ''):

        """
            !stub_elf_sym stub the function given a effective address.  

            @param ea Effective Address in the .plt
            @param stub Stub Object 
            @param name Symbol of the function
        """



        stub =    self.get_new_stub(stub_func,
                                    stub_type=StubType.BUILTIN,
                                    name=name)
        self.running_stubs[ea] = stub
        self.nop_insn(ea)
        self.stubbed_bytes[ea] = get_insn_bytecode(ea)

        logger.logfile(LogType.INFO,f"{name} is now stubbed at {ea:x}")



    def stub_sym(self,
                 ea: int,
                 stub_func,
                 name: str = ''):

        """
            !stub the right way according the architecture.

            @param ea Effective Address in the .plt
            @param stub Stub Object 
            @param name Symbol of the function
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

            @param ea Effective Address in the .plt
            @param stub Stub Object 
            @param stub_type Stub Type
            @param name Symbol of the function
        """

        if not ida_funcs.get_func(ea):
            logger.logfile(LogType.WARN,"%s %x not a function"%\
                           (sys._getframe().f_code.co_name,
                            ea))
            return

        if stub_type == StubType.NULL: 
            ea = ida_funcs.get_func(ea).start_ea

        stub =    self.get_new_stub(stub_func,
                                    stub_type=stub_type,
                                    name=name)
        self.running_stubs[ea] = stub
        self.uc.mem_write(ea,self.get_retn_insn(ea))

        self.stubbed_bytes[ea] = get_insn_bytecode(ea)




    def unstub_func_addr(self,
                         ea: int):

        """
            !unstub_func_addr sunstubbing consists in :
                conf cleaning
                removing stub object from stub list
                repatching memory with original bytecode

            @param ea



        """

        if ea in self.running_stubs.keys():

            """
            if self.running_stubs[ea].stub_type == StubType.TAG:
                self.conf.remove_tag(ea)
            elif self.running_stubs[ea].stub_type == StubType.NULL:
                self.conf.remove_null_stub(ea)
            """

            del self.running_stubs[ea]

            self.helper.mem_write(ea,self.stubbed_bytes[ea])

            del self.stubbed_bytes[ea]


    def unstub_all(self):

        """
            !unstub_all remove all stubs for symbols and user defined stubs

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





    def add_null_stub(self,
                      ea:int):

        """
            Null stubs allow to directly bypass
            a function call.

            @param Function Address to Stub with a direct return sequence
        """

        if ea in self.running_stubs.keys():
            self.unstub_func_addr(ea)

        self.stub_func_addr(ea,
                            self.nstub_obj.do_it,
                            stub_type=StubType.NULL)

    def remove_null_stub(self,
                         ea:int):

        """ 
        !remove_null_stub remove a null stub given its address.

        @param ea Address where the stub was registred.
        """

        self.unstub_func_addr(ea)
        

    def add_custom_stub(self,
                        ea: int,
                        func,
                        name:str='user stub'):

        """
            !add_custom_stub Custom stub allows the user to define a function
            that will be called instead a stubbed address / symbols.
        
            @param Address of the function 
            @param function function declaration (in python) 
            @param name associated Name

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

        """ 
        !remove_custom_stub remove a user provided stub given its address

        @param ea Effectiva Address where the stub was registred.
        """

        self.unstub_func_addr(ea)


    def tag_func(self,
                 ea: int,
                 stub_name: str):

        """
            !tag_func Function tagging consists in associating
            a function to a stub. If you find a memcpy like
            function, you can tag it with the internal memcpy
            stub. You will then be able to track its argument.

            @param ea Effective Address of the target function 
            @param stub_name User provided name  


        """

        if not stub_name in self.stubs.keys():
            logger.console(LogType.WARN,'[!] %s is not among available stubs. '%stub_name,
                           'Please refers to list_stubs command to get the list of available stubs')
            return

        if ea in self.running_stubs.keys():
            logger.console(LogType.WARN,f"Function at {ea:x} is already stubbed. ",
                               f'Overwritting stub with new tag {stub_name}')
            self.unstub_func_addr(ea)

        else:
                self.stubs[stub_name].set_helper(self.helper)

        self.stub_func_addr(ea,self.stubs[stub_name].do_it,stub_type=StubType.TAG,name=stub_name)

        logger.console(LogType.INFO,'[+] %x is now stubbed with %s function'%(ea,stub_name))




    def remove_tag(self,
                   ea:int):
        

        """ 
        !remove_tag remove a tag association given its Effective Address

        @param ea Address 

        """

        self.unstub_func_addr(ea)






#---------------------------------------------------------------------------------------------
#
# DEBUGGING FUNCTION
#
#---------------------------------------------------------------------------------------------


    def start(self,
              cnt: int = 0,
              saddr: int = -1):
        """
            !This function launch unicorn **start** function. 
            It will run a limited instructions from the start address.

            @param cnt Maximum instruction to be executed. 
            @param saddr Address of the first instruction to be executed.
        """

        self.nb_insn = 0

        if saddr == -1:
            saddr = self.conf.exec_saddr


        if self.isThumb():

            saddr |= 1
        
        if self.ignore_end_addr:

            end_addr = 0xffffffffffffffff

        else: 

            end_addr = self.conf.exec_eaddr

        try:

            idaapi.show_wait_box("Running...")

            self.uc.emu_start(saddr,end_addr,timeout=0,count=cnt)
            self.is_running = True

        except UcError as e:

            logger.console(LogType.ERRR,'Error in unicorn engine')
            raise e

        except Exception as e:

            logger.console(LogType.WARN,
                          '[!] Exception in program : %s' % e.__str__())
        finally:

            idaapi.hide_wait_box()




    def step_n(self,
               n:int) -> None:

        """ 
        !step_n 

        @param n Number of instructions to be executed. 

        """

        if self.stop: 

            insn = get_insn_at(self.helper.get_pc())
            pc = self.helper.get_pc() + insn.size
            self.stop = False

        else: 

            pc = self.helper.get_pc()

        pc = self.helper.get_pc()

        if pc >= self.conf.exec_eaddr and not self.ignore_end_addr: 

            uret = ida_kernwin.ask_yn(True,
            f"Execution reached the limit address specified in configuration {self.conf.exec_eaddr:x}"\
                    ", do you want to continue?")   
            if uret == ida_kernwin.ASKBTN_YES: 
                self.ignore_end_addr = True

        self.start(cnt=n,saddr=pc)


    def step_in(self):

        """
        !step_in executes a single instruction 

        """

        self.step_n(1)

    def continuee(self):

        """ 
        !continue 

        """

        self.step_n(0)



    def step_over(self):

        """
        !step_over Try to detect the target using IDA API.
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

        """ 
        !add_watchpoint Enable a watchpoint to track data during execution.
        
        @param base_addr address of the first byte of the data to be tracked.
        @param rang size of the data to be tracked.
        @param mode READ, WRITE or BOTH

        """

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

        self.watchpoints[base_addr]= mode << 24 | rang 

    def reset_color_graph(self):
        pass



    def patch_insn(self,
                   addr:int,
                   asm:bytes) -> None:


        """ 
        !patch_insn Patch instruction(s) with the bytecode

        @param addr Effective Address to apply the patch from 
        @param asm  compiled assebmly. 
         
        """


        bytecode = self.assembler.assemble(asm,addr)
        self.uc.mem_write(addr,bytecode)
        logger.console(LogType.INFO,f"Instruction(s) at {addr:x} patched")
        self.patches[addr] = bytecode

        # This handles use case where new bytecode is bigger than 
        # the original one. Stop address might not be detected
        # causing execution drift.
        if addr >= self.conf.exec_saddr: 
            if addr + len(bytecode) > self.conf.exec_eaddr: 
                self.conf.exec_eaddr = addr + len(bytecode) 


    def isThumb(self) -> bool:

        """ 
        ! necessary for arm32 architecture.
        """

        return False


    def extract_current_configuration(self) -> Configuration:


        cur_nstubs = dict()
        cur_tagstub = dict() 

        for ea,s in self.running_stubs.items(): 
            if s.stub_type == StubType.TAG: 
                cur_tagstub[ea] = s.name 
            elif s.stub_type == StubType.NULL:
                cur_nstubs[ea] = s 

            


        return Configuration(
                 path=self.conf.path,
                 arch=self.conf.arch,
                 emulator=self.conf.emulator,
                 p_size=self.conf.p_size,
                 stk_ba=self.conf.stk_ba,
                 stk_size=self.conf.stk_size,
                 autoMap=self.conf.autoMap,
                 showRegisters=self.conf.showRegisters,
                 exec_saddr=self.conf.exec_saddr,
                 exec_eaddr=self.conf.exec_eaddr,
                 mapping_saddr=self.conf.mapping_saddr,
                 mapping_eaddr=self.conf.mapping_eaddr,
                 segms=self.conf.segms,
                 map_with_segs=self.conf.map_with_segs,
                 use_seg_perms=self.conf.use_seg_perms,
                 useCapstone=self.conf.useCapstone,
                 registers=self.get_regs(),
                 showMemAccess=self.conf.showMemAccess,
                 s_conf=StubConfiguration(nstubs={**self.conf.s_conf.nstubs, **cur_nstubs},
                                            tag_func_tab = self.conf.s_conf.tag_func_tab,
                                            activate_stub_mechanism=self.conf.s_conf.activate_stub_mechanism,
                                            orig_filepath=self.conf.s_conf.orig_filepath,
                                            custom_stubs_file=self.conf.s_conf.custom_stubs_file,
                                            auto_null_stub=self.conf.s_conf.auto_null_stub,
                                            tags={**self.conf.s_conf.tags,**cur_tagstub}),
                 amap_conf=AdditionnalMapping({**self.conf.amap_conf.mappings ,**self.amap}),
                 memory_init=self.conf.memory_init,
                 color_graph=self.conf.color_graph,
                 breakpoints=self.user_breakpoints,
                 watchpoints=self.watchpoints, #TODO
                 patches= {**self.patches, ** self.conf.patches}, #TODO
                 max_insn=0x10000)




