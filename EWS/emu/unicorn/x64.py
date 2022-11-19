import ida_segregs
from EWS.emu.unicorn.generic import *
import string
from EWS.utils.utils import *
import ida_loader
import idc
import ida_ua
import ida_funcs
import idautils
from EWS.stubs.emu.unicorn.sea import UnicornX64SEA, UnicornX64MSVCSEA
import struct
from unicorn.x86_const import * 
from keystone import * 
from capstone import *
from EWS.utils import consts_x64 
from keystone import * 
from EWS.emu.unicorn.x86 import x86Corn
from EWS.stubs.ELF.allocator import *
from EWS.stubs.ELF import ELF
from EWS.stubs.PE import PE
from EWS.utils.configuration import *
from EWS.utils.registers import *
from EWS.asm.assembler import *





class x64Corn(Emucorn): 

    def __init__(self,conf):

        super().__init__(conf) 

        self.uc = Uc(UC_ARCH_X86,UC_MODE_64)

        if self.conf.p_size != self.uc.query(UC_QUERY_PAGE_SIZE):

            logger.logfile(LogType.WARN,' invalid page size, using default')
            self.conf.p_size = self.uc.query(UC_QUERY_PAGE_SIZE)

        Emucorn.do_mapping(self.uc,self.conf)


        # init capstone engine
        if conf.useCapstone:
            self.cs=Cs(CS_ARCH_X86, CS_MODE_64)

        # init keystone engine
        self.ks = Ks(KS_ARCH_X86,KS_MODE_64)
        self.pointer_size = 8

        # setup regs 
        self.setup_regs(self.conf.registers)
        self.pcid = UC_X86_REG_RIP

        # init stubs engine 
        if self.conf.s_conf.activate_stub_mechanism:
                self.setub_stub_mechanism()

        # install hooks
        self.install_hooks()


        self.assembler = assemblers['x64'][0]


        for k,v in self.conf.patches.items():
            self.patch_insn(k,v)


        
        # TODO move it to the do_mapping
        for k,v in self.conf.memory_init.mappings.items():
                self.uc.mem_write(k,v)

    def setub_stub_mechanism(self):

        """
            install stubs mechanism.
        """

        # map allocator
        self.uc.mem_map(consts_x64.ALLOC_BA,
                        self.conf.p_size*consts_x64.ALLOC_PAGES,
                        UC_PROT_READ | UC_PROT_WRITE)

    
        if '(PE)' in self.filetype:
             self.helper = UnicornX64MSVCSEA(emu=self,
                                             allocator=DumpAllocator(consts_x64.ALLOC_BA,
                                                                     consts_x64.ALLOC_PAGES*\
                                                                     self.conf.p_size),
                                             wsize=8)
        else:
            self.helper = UnicornX64SEA(emu=self,
                                        allocator=DumpAllocator(consts_x64.ALLOC_BA,
                                                                consts_x64.ALLOC_PAGES*\
                                                                self.conf.p_size),
                                        wsize=8)
        if self.conf.s_conf.activate_stub_mechanism:

            if '(PE)' in self.filetype:

                self.stubs = PE.windows_stubs
                self.nstub_obj = PE.NullStub()
                self.loader_type = LoaderType.PE
                self.nstub_obj.set_helper(self.helper)
                if verify_valid_PE(self.conf.s_conf.orig_filepath):
                        self.reloc_map = get_imports(self.conf.s_conf.orig_filepath)
                        self.stub_PE()


            elif 'ELF' in self.filetype:

                self.stubs = ELF.libc_stubs
                self.nstub_obj = ELF.NullStub()
                self.loader_type = LoaderType.ELF
                self.nstub_obj.set_helper(self.helper)

                if verify_valid_elf(self.conf.s_conf.orig_filepath):
                    self.reloc_map = get_relocs(self.conf.s_conf.orig_filepath,
                                                lief.ELF.RELOCATION_X86_64.JUMP_SLOT)

                    self.libc_start_main_trampoline = consts_x64.LIBCSTARTSTUBADDR
                    self.stub_PLT()


            for k,v in self.conf.s_conf.tags.items(): 
                self.tag_func(k, v)



    def install_hooks(self):

        """
            intall unicorn hooks
        """

        self.uc.hook_add(UC_HOOK_CODE,
                         self.hook_code,
                         user_data=self)

        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED,
                         Emucorn.unmp_read,
                         user_data=self)

        self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED,
                         Emucorn.unmp_write,
                         user_data=self)

        if self.conf.showMemAccess:

            self.uc.hook_add(UC_HOOK_MEM_WRITE,
                             Emucorn.hk_write,
                             self)
            self.uc.hook_add(UC_HOOK_MEM_READ,
                             Emucorn.hk_read,
                             self)



    def get_retn_insn(self,
                      ea: int) -> bytes:

        f = ida_funcs.get_func(ea)
        retn = bytes()

        if f == None:

                logger.logfile(LogType.ERRR,
                                             "%s: %x not in a function"%(sys._getframe().f_code.co_name,
                                                                                                     ea))

                raise Exception('Error in %s for ea %x'%(sys._getframe().f_code.co_name,ea))

#                insn    = get_insn_at(ea)
#                retn = self.ks.asm('nop',as_bytes=True)[0]*insn.size

        else:
                n = x86Corn.tail_retn(f.start_ea)
                if n > 0:
                    try:
                        retn = self.ks.asm('ret %d'%n,as_bytes=True)[0]

                    except:
                        logger.console(LogType.WARN,'could not compile retn insn')

                elif n == 0:
                    retn = self.ks.asm('ret',as_bytes=True)[0]

        return retn

    def get_new_stub(self,
                     stub_func,
                     stub_type: StubType,
                     name:str=''):

        """
            Stub factory
        """


        if 'ELF' in self.filetype:
            stub = ELF.Stub(self.helper,
                            stub_type=stub_type,
                            name=name)
            stub.do_it = stub_func

        elif 'PE' in self.filetype:
            stub = PE.Stub(self.helper,
                           stub_type=stub_type,
                           name=name)
            stub.do_it = stub_func

        return stub


    def nop_insn(self,
                 ea: int):

        """
            nop instructation at address *ea*
        """
        insn    = get_insn_at(ea)
        nops = self.ks.asm('nop',as_bytes=True)[0]*insn.size
        self.uc.mem_write(ea,nops)




        # DEPRECATED use reset() function from the plugin

#    def repatch(self):
#        if not self.conf.s_conf.activate_stub_mechanism:
#            return 
#        # need to remap according to the arch settings 
#        self.uc.mem_map(consts_x64.ALLOC_BA,
#                                            self.conf.p_size*consts_x64.ALLOC_PAGES,
#                                            UC_PROT_READ | UC_PROT_WRITE)
#        self.stubbit()
#



    def setup_regs(self,
                   regs: x64Registers):

        """
            initiate emulator' registers given
            *regs* arguemnt.
        """


        self.uc.reg_write(UC_X86_REG_RAX,regs.RAX)

        self.uc.reg_write(UC_X86_REG_RBX,regs.RBX)

        self.uc.reg_write(UC_X86_REG_RCX,regs.RCX)

        self.uc.reg_write(UC_X86_REG_RDX,regs.RDX)

        self.uc.reg_write(UC_X86_REG_RDI,regs.RDI)

        self.uc.reg_write(UC_X86_REG_RSI,regs.RSI)

        self.uc.reg_write(UC_X86_REG_RSP,regs.RSP)

        self.uc.reg_write(UC_X86_REG_RBP,regs.RBP)

        self.uc.reg_write(UC_X86_REG_R8,regs.R8)

        self.uc.reg_write(UC_X86_REG_R9,regs.R9)

        self.uc.reg_write(UC_X86_REG_R10,regs.R10)

        self.uc.reg_write(UC_X86_REG_R11,regs.R11)

        self.uc.reg_write(UC_X86_REG_R12,regs.R12)

        self.uc.reg_write(UC_X86_REG_R13,regs.R13)

        self.uc.reg_write(UC_X86_REG_R14,regs.R14)

        self.uc.reg_write(UC_X86_REG_R15,regs.R15)

        self.uc.reg_write(UC_X86_REG_RIP,regs.RIP)

    def get_regs(self) -> x64Registers:

        """
            return a register snapshot
        """

        return x64Registers(RAX=self.uc.reg_read(UC_X86_REG_RAX),
                            RBX=self.uc.reg_read(UC_X86_REG_RBX),
                            RCX=self.uc.reg_read(UC_X86_REG_RCX),
                            RDX=self.uc.reg_read(UC_X86_REG_RDX),
                            RDI=self.uc.reg_read(UC_X86_REG_RDI),
                            RSI=self.uc.reg_read(UC_X86_REG_RSI),
                            RSP=self.uc.reg_read(UC_X86_REG_RSP),
                            RBP=self.uc.reg_read(UC_X86_REG_RBP),
                            R8=self.uc.reg_read(UC_X86_REG_R8),
                            R9=self.uc.reg_read(UC_X86_REG_R9),
                            R10=self.uc.reg_read(UC_X86_REG_R10),
                            R11=self.uc.reg_read(UC_X86_REG_R11),
                            R12=self.uc.reg_read(UC_X86_REG_R12),
                            R13=self.uc.reg_read(UC_X86_REG_R13),
                            R14=self.uc.reg_read(UC_X86_REG_R14),
                            R15=self.uc.reg_read(UC_X86_REG_R15),
                            RIP=self.uc.reg_read(UC_X86_REG_RIP))


    def reset_regs(self):

        """
            reset the emulator registers
        """

        self.uc.reg_write(UC_X86_REG_RAX,0)

        self.uc.reg_write(UC_X86_REG_RBX,0)

        self.uc.reg_write(UC_X86_REG_RCX,0)

        self.uc.reg_write(UC_X86_REG_RDX,0)

        self.uc.reg_write(UC_X86_REG_RDI,0)

        self.uc.reg_write(UC_X86_REG_RSI,0)

        self.uc.reg_write(UC_X86_REG_RSP,0)

        self.uc.reg_write(UC_X86_REG_RBP,0)

        self.uc.reg_write(UC_X86_REG_RIP,0)

        self.uc.reg_write(UC_X86_REG_R8,0)

        self.uc.reg_write(UC_X86_REG_R9,0)

        self.uc.reg_write(UC_X86_REG_R10,0)

        self.uc.reg_write(UC_X86_REG_R11,0)

        self.uc.reg_write(UC_X86_REG_R12,0)

        self.uc.reg_write(UC_X86_REG_R13,0)

        self.uc.reg_write(UC_X86_REG_R14,0)

        self.uc.reg_write(UC_X86_REG_R15,0)

        self.uc.reg_write(UC_X86_REG_RIP,0)




    @staticmethod
    def reg_convert(r_id: str) -> int:

        """
            convert register accronym to its corresponding
            value in unicorn world.
        """

        if r_id.lower() == 'rax':
            return UC_X86_REG_RAX

        elif r_id.lower() == 'rbx':
            return UC_X86_REG_RBX

        elif r_id.lower() == 'rcx':
            return UC_X86_REG_RCX

        elif r_id.lower() == 'rdx':
            return UC_X86_REG_RDX

        elif r_id.lower() == 'rdi':
            return UC_X86_REG_RDI

        elif r_id.lower() == 'rsi':
            return UC_X86_REG_RSI

        elif r_id.lower() == 'rsp':
            return UC_X86_REG_RSP

        elif r_id.lower() == 'rbp':
            return UC_X86_REG_RBP

        elif r_id.lower() == 'rip':
            return UC_X86_REG_RIP

        elif r_id.lower() == 'r8':
            return UC_X86_REG_R8

        elif r_id.lower() == 'r9':
            return UC_X86_REG_R9

        elif r_id.lower() == 'r10':
            return UC_X86_REG_R10

        elif r_id.lower() == 'r11':
            return UC_X86_REG_R11

        elif r_id.lower() == 'r12':
            return UC_X86_REG_R12

        elif r_id.lower() == 'r13':
            return UC_X86_REG_R13

        elif r_id.lower() == 'r14':
            return UC_X86_REG_R14

        elif r_id.lower() == 'r15':
            return UC_X86_REG_R15



    def reg_convert_ns(self,
                       r_id: str) -> int:

        """
            convert register accronym to its corresponding
            value in unicorn world.
            class method
        """

        if r_id.lower() == 'rax':
            return UC_X86_REG_RAX

        elif r_id.lower() == 'rbx':
            return UC_X86_REG_RBX

        elif r_id.lower() == 'rcx':
            return UC_X86_REG_RCX

        elif r_id.lower() == 'rdx':
            return UC_X86_REG_RDX

        elif r_id.lower() == 'rdi':
            return UC_X86_REG_RDI

        elif r_id.lower() == 'rsi':
            return UC_X86_REG_RSI

        elif r_id.lower() == 'rsp':
            return UC_X86_REG_RSP

        elif r_id.lower() == 'rbp':
            return UC_X86_REG_RBP

        elif r_id.lower() == 'rip':
            return UC_X86_REG_RIP

        elif r_id.lower() == 'r8':
            return UC_X86_REG_R8

        elif r_id.lower() == 'r9':
            return UC_X86_REG_R9

        elif r_id.lower() == 'r10':
            return UC_X86_REG_R10

        elif r_id.lower() == 'r11':
            return UC_X86_REG_R11

        elif r_id.lower() == 'r12':
            return UC_X86_REG_R12

        elif r_id.lower() == 'r13':
            return UC_X86_REG_R13

        elif r_id.lower() == 'r14':
            return UC_X86_REG_R14

        elif r_id.lower() == 'r15':
            return UC_X86_REG_R15


    def print_registers(self) -> str:

        """
            log register' values to console.
        """

        strout =    '[RAX=%.8X] [RBX=%.8X] [RCX=%.8X] [RDX=%.8X]\n'%\
            (self.uc.reg_read(UC_X86_REG_RAX),
             self.uc.reg_read(UC_X86_REG_RBX),
             self.uc.reg_read(UC_X86_REG_RCX),
             self.uc.reg_read(UC_X86_REG_RDX))
        strout += '[RDI=%.8X] [RSI=%.8X] [RBP=%.8X] [RSP=%.8X]\n'%\
            (self.uc.reg_read(UC_X86_REG_RDI),
             self.uc.reg_read(UC_X86_REG_RSI),
             self.uc.reg_read(UC_X86_REG_RBP),
             self.uc.reg_read(UC_X86_REG_RSP))
        strout += '[R8=%.8X] [R9=%.8X] [R10=%.8X] [R11=%.8X]\n'%\
            (self.uc.reg_read(UC_X86_REG_R8),
            self.uc.reg_read(UC_X86_REG_R9),
            self.uc.reg_read(UC_X86_REG_R10),
            self.uc.reg_read(UC_X86_REG_R11))
        strout += '[R12=%.8X] [R13=%.8X] [R14=%.8X] [R15=%.8X]\n'%\
            (self.uc.reg_read(UC_X86_REG_R12),
             self.uc.reg_read(UC_X86_REG_R13),
             self.uc.reg_read(UC_X86_REG_R14),
             self.uc.reg_read(UC_X86_REG_R15))

        return strout


    def get_alu_info(self):

        """
            return the RFlags
        """

        return x64RFLAGS.create(self.uc.reg_read(UC_X86_REG_EFLAGS))


    @staticmethod
    def generate_default_config(
                                 path: str = None,
                                 arch: str = None,
                                 emulator: str = None,
                                 p_size: int = None,
                                 stk_ba: int = None,
                                 stk_size: int = None,
                                 autoMap: bool = None,
                                 showRegisters: bool = None,
                                 exec_saddr: int =None,
                                 exec_eaddr: int =None,
                                 mapping_saddr: int =None,
                                 mapping_eaddr: int =None,
                                 segms: list =None,
                                 map_with_segs: bool = None,
                                 use_seg_perms: bool =None,
                                 useCapstone: bool = None,
                                 registers: Registers = None,
                                 showMemAccess: bool =None,
                                 s_conf: StubConfiguration = None,
                                 amap_conf: AdditionnalMapping = None,
                                 memory_init: AdditionnalMapping =None,
                                 color_graph: bool =None,
                                 breakpoints: list =None,
                                 watchpoints: dict =None) -> Configuration:
      """this method get called by:
            - ui **emulate_function**
            - ui **emulate_selection**
      """

      if not registers: 
        if stk_ba and stk_size: 
            RBP = RSP =  stk_ba + stk_size - consts_x64.initial_stack_offset 
        elif stk_ba and not stk_size: 
            RBP = RSP =  stk_ba +  consts_x64.STACK_SIZE - consts_x64.initial_stack_offset 
        elif stk_size and not stk_ba: 
            RBP = RSP = consts_x64.STACK_BASEADDR + stk_size - consts_x64.initial_stack_offset 
        else:
            RBP = RSP = consts_x64.STACK_BASEADDR+consts_x64.STACK_SIZE-\
                                 consts_x64.initial_stack_offset
        registers = x64Registers.get_default_object(RBP=RBP,RSP=RSP,RIP=exec_saddr)



      return Configuration.generate_default_config(stk_ba=stk_ba if stk_ba\
                                                    else consts_x64.STACK_BASEADDR,
                                                    stk_size=stk_size if stk_size\
                                                    else consts_x64.STACK_SIZE,
                                                    registers=registers,
                                                    exec_saddr=exec_saddr,
                                                    exec_eaddr=exec_eaddr,
                                                   arch='x64')




#    @staticmethod
#    def generate_default_config(path=None,
#                                arch=None,
#                                emulator=None,
#                                p_size=None,
#                                stk_ba=None,
#                                stk_size=None,
#                                autoMap=None,
#                                showRegisters=None,
#                                exec_saddr=None,
#                                exec_eaddr=None,
#                                mapping_saddr=None,
#                                mapping_eaddr=None,
#                                segms=None,
#                                map_with_segs=None,
#                                use_seg_perms=None,
#                                useCapstone=None,
#                                registers=None,
#                                showMemAccess=None,
#                                s_conf=None,
#                                amap_conf=None,
#                                memory_init=None,
#                                color_graph=None,
#                                breakpoints=None) -> Configuration:
#
#        """
#            generate a default configuration object.
#            TODO: these function should use a XML file.
#        """
#
#
#        if registers == None:
#                registers = x64Registers(RAX=0,
#                                         RBX=1,
#                                         RCX=2,
#                                         RDX=3,
#                                         RDI=4,
#                                         RSI=5,
#                                         R8=6,
#                                         R9=7,
#                                         R10=8,
#                                         R11=9,
#                                         R12=10,
#                                         R13=11,
#                                         R14=12,
#                                         R15=13,
#                                         RBP=consts_x64.STACK_BASEADDR+consts_x64.STACK_SIZE-\
#                                         consts_x64.initial_stack_offset,
#                                         RSP=consts_x64.STACK_BASEADDR+consts_x64.STACK_SIZE-\
#                                         consts_x64.initial_stack_offset,
#                                         RIP=exec_saddr)
#        else:
#                registers = regs
#
#        if s_conf == None:
#
#                exec_path = search_executable()
#                stub_conf = StubConfiguration(nstubs=dict(),
#                                              activate_stub_mechanism=True if exec_path != "" else False,
#                                              orig_filepath=exec_path,
#                                              custom_stubs_file=None,
#                                              auto_null_stub=True if exec_path != "" else False,
#                                              tags=dict())
#        else:
#                stub_conf = s_conf
#
#        if amap_conf == None:
#                addmap_conf = AdditionnalMapping.create()
#
#        else:
#                addmap_conf = amap_conf
#
#
#        if memory_init == None:
#                meminit = AdditionnalMapping.create()
#
#        else:
#                meminit = memory_init
#
#
#        return Configuration(path=path if path else '',
#                             arch='x86_64',
#                             emulator='unicorn',
#                             p_size=p_size if p_size else consts_x64.PSIZE,
#                             stk_ba=stk_ba if stk_ba else consts_x64.STACK_BASEADDR,
#                             stk_size=stk_size if stk_size else consts_x64.STACK_SIZE,autoMap=autoMap if autoMap else False,
#                             showRegisters=showRegisters if showRegisters else True,
#                             exec_saddr=exec_saddr if exec_saddr else 0,
#                             exec_eaddr=exec_eaddr if exec_eaddr else 0xFFFFFFFF,
#                             mapping_saddr=get_min_ea_idb() if not mapping_saddr else mapping_saddr,
#                             mapping_eaddr=get_max_ea_idb() if not mapping_eaddr else mapping_eaddr,
#                             segms=segms if segms else [],
#                             map_with_segs=map_with_segs if map_with_segs else False,
#                             use_seg_perms=use_seg_perms if use_seg_perms else False,
#                             useCapstone=useCapstone if useCapstone else True,
#                             registers=registers,
#                             showMemAccess=showMemAccess if showMemAccess else True,
#                             s_conf=stub_conf,
#                             amap_conf=addmap_conf,
#                             memory_init=meminit,
#                             color_graph=False,
#                             breakpoints=breakpoints if breakpoints else [])
#
#
#

