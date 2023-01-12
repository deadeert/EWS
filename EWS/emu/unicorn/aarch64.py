import ida_segregs
from EWS.emu.unicorn.generic import * 
import string
from EWS.utils.utils import * 
from EWS.utils import consts_aarch64
from EWS.stubs.allocators.allocator import *
from EWS.stubs.ELF import ELF
from EWS.stubs.emu.unicorn.sea import UnicornAarch64SEA
import struct
import lief
from EWS.utils.configuration import *
from EWS.utils.registers import *
from EWS.asm.assembler import *

class Aarch64Corn(Emucorn):

    def __init__(self,conf):

        super().__init__(conf)

        # Init engine 
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        self.pointer_size = 8

        
        # Map pages 
        d,r = divmod(self.conf.p_size,0x1000)
        if r:
          logger.console(LogType.WARN,'[+] invalid page size, using default')
          self.conf.p_size = uc.query(UC_QUERY_PAGE_SIZE)
        Emucorn.do_mapping(self.uc,self.conf)

        # Init capstone engine
        if conf.useCapstone:
            from capstone import Cs, CS_ARCH_ARM64,  CS_MODE_ARM
            self.cs=Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            self.cs.detail=True

        # Setup regs 
        self.setup_regs(self.conf.registers)
        self.pcid = UC_ARM64_REG_PC 


        # Init stubs engine
        if self.conf.s_conf.activate_stub_mechanism:
            self.setup_stub_mechanism()

        self.install_hooks()
     
        for k,v in self.conf.memory_init.mappings.items():
            self.uc.mem_write(k,v)

        self.assembler = assemblers['aarch64'][0]


        for k,v in self.conf.patches.items():
            self.patch_mem(k,v)

        for k,v in self.conf.watchpoints.items():
            self.add_watchpoint(k, v&0xff,mode=v>>24)


    def install_hooks(self):

        self.uc.hook_add(UC_HOOK_CODE,
                         self.hook_code,
                         user_data=self.conf)
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

    def setup_stub_mechanism(self):

        self.uc.mem_map(consts_aarch64.ALLOC_BA,
                          self.conf.p_size*consts_aarch64.ALLOC_PAGES,
                          UC_PROT_READ | UC_PROT_WRITE)

        self.helper = UnicornAarch64SEA(emu=self,
                                          allocator=DumpAllocator(consts_aarch64.ALLOC_BA,
                                                                  consts_aarch64.ALLOC_PAGES*self.conf.p_size),
                                          wsize=4)
        self.nstub_obj = ELF.NullStub()
        self.nstub_obj.set_helper(self.helper) 

        if verify_valid_elf(self.conf.s_conf.orig_filepath):
          self.reloc_map = get_relocs(self.conf.s_conf.orig_filepath,
                                      lief.ELF.RELOCATION_AARCH64.JUMP_SLOT)
          self.stubs = ELF.libc_stubs 
          self.libc_start_main_trampoline = consts_aarch64.LIBCSTARTSTUBADDR
          self.stub_PLT()


        for k,v in self.conf.s_conf.tags.items():
            self.tag_func(k,v)


    

    def nop_insn(self,insn):

        # use self.assembler() now we added an assembler :) TODO
        self.uc.mem_write(insn.ea,
                          struct.pack('<I',consts_aarch64.nop))
    

    def get_retn_insn(self,ea):

        # same
        return struct.pack('>I',
                           consts_aarch64.ret)

    def get_new_stub(self,
                     stub_func,
                     stub_type:StubType,
                     name:str=''):

        stub = ELF.Stub(self.helper,
                        stub_type=stub_type,
                        name=name)
        stub.do_it = stub_func
        return stub



    """  Register specific functions 
    """


    def setup_regs(self,regs):

        """ 
        Setup Emulator's registers using Register object. 

        @param regs: Register object.

        """





        for k,v in consts_aarch64.reg_map_unicorn.items():

            self.uc.reg_write(v,getattr(regs,k)) 

    def get_regs(self):


            """ 
            Returns a Register object instancied with 
            the current emulator register values. 

            @return Register Object.
            """

            regs = Aarch64Registers.create() 
            for k,v in consts_aarch64.reg_map_unicorn.items():
                setattr(regs,k,self.uc.reg_read(v))
            return regs




    def reset_regs(self):

        """ 
        Reset the Emulator' registers.
        """


        for k,v in consts_aarch64.reg_map_unicorn.items():
            self.uc.reg_write(v,0)
        

    @staticmethod
    def reg_convert(reg_id):

        if type(reg_id) == type(str()):

          return Aarch64Corn.str2reg(reg_id)

        elif type(reg_id) == type(int()):

          return Aarch64Corn.int2reg(reg_id)

        else:

          raise Exception('[reg_convert] unhandled conversion for type %s'%type(reg_id))

    def reg_convert_ns(self,reg_id):

        if type(reg_id) == type(str()):

          return Aarch64Corn.str2reg(reg_id)

        else:
          raise Exception('[reg_convert] unhandled conversion for type %s'%type(reg_id))



    @staticmethod
    def int2reg(reg_id):
        if reg_id == 31:
          return UC_ARM64_REG_SP
        elif reg_id == 29:
          return UC_ARM64_REG_FP
        elif reg_id == 30: 
          return UC_ARM64_REG_LR
        elif reg_id == 260:
          return UC_ARM64_REG_PC
        else: 
            return UC_ARM64_REG_X0 + reg_id

    @staticmethod           
    def str2reg(r_str):

        return consts_aarch64.reg_map_unicorn[r_str] 
        
    def get_alu_info(self): 
        return aarch64CPSR.create(self.uc.reg_read(UC_ARM_REG_CPSR))



    def print_registers(self):

        strout = 'Registers:\n'
        for k,v in consts_aarch64.reg_map_unicorn.items():
            strout += f"{k}={self.uc.reg_read(v):x}" 
         
        return strout


        
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
            x31 =  stk_ba + stk_size - consts_aarch64.initial_stack_offset 
        elif stk_ba and not stk_size: 
            x31 =  stk_ba +  consts_aarch64.STACK_SIZE - consts_aarch64.initial_stack_offset 
        elif stk_size and not stk_ba: 
            x31 = consts_aarch64.STACK_BASEADDR + stk_size - consts_aarch64.initial_stack_offset 
        else:
            x31 = consts_aarch64.STACK_BASEADDR+consts_aarch64.STACK_SIZE-\
                                 consts_aarch64.initial_stack_offset
        registers = Aarch64Registers.get_default_object(X30=exec_eaddr, # LR
                                         X31=x31,
                                         PC=exec_saddr)
      return Configuration.generate_default_config(stk_ba=stk_ba if stk_ba\
                                                    else consts_aarch64.STACK_BASEADDR,
                                                    stk_size=stk_size if stk_size\
                                                    else consts_aarch64.STACK_SIZE,
                                                    registers=registers,
                                                    exec_saddr=exec_saddr,
                                                    exec_eaddr=exec_eaddr, 
                                                   arch='aarch64')

