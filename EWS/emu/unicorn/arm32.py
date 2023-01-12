import ida_segregs
from EWS.emu.unicorn.generic import * 
import string
from EWS.utils.utils import * 
from EWS.utils import consts_arm
from EWS.stubs.allocators.allocator import *

from EWS.stubs.ELF import ELF
from EWS.stubs.emu.unicorn.sea import UnicornArmSEA
from EWS.utils.configuration import *
from EWS.utils.registers import *
from EWS.asm.assembler import *
import struct




class ArmCorn(Emucorn): 

    def __init__(self,conf):

        super().__init__(conf) 

        # Init engine 
        pinf = proc_inf('arm',conf.exec_saddr)
        self.pinf = pinf
        if pinf['endianness'] == 'little':    
            if pinf['proc_mode'] == 16:
                self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB) 
                self.conf.exec_saddr = self.conf.exec_saddr | 1
            elif pinf['proc_mode'] == 32:
                self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM) 
        elif pinf['endianness'] == 'big':
            if pinf['proc_mode'] == 16:
                self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB + UC_MODE_BIG_ENDIAN) 
                self.conf.exec_saddr = self.conf.exec_saddr | 1
            elif pinf['proc_mode'] == 32:
                self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_BIG_ENDIAN) 

        self.endns = pinf['endianness']
        self.pointer_size = 4 

        # Map pages 
        d,r = divmod(self.conf.p_size,0x400) 
        if r: 
            logger.console(LogType.WARN,'[+] invalid page size, using default')
            self.conf.p_size = uc.query(UC_QUERY_PAGE_SIZE)
        Emucorn.do_mapping(self.uc,self.conf)

        
        # Init capstone engine
        if conf.useCapstone:
            from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN
            if pinf['proc_mode'] == 16:
                self.cs=Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN if pinf['endianness'] else CS_MODE_THUMB + CS_MODE_BIG_ENDIAN)

            elif pinf['proc_mode'] == 32:
                self.cs=Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN if pinf['endianness'] else CS_MODE_ARM + CS_MODE_BIG_ENDIAN)
            self.cs.detail=True

        # Setup regs 
        self.setup_regs(self.conf.registers)
        self.pcid = UC_ARM_REG_PC 

        # Init stubs engine 
        if self.conf.s_conf.activate_stub_mechanism:
                self.setup_stub_mechanism()

        self.install_hooks()


        for k,v in self.conf.memory_init.mappings.items():
                self.uc.mem_write(k,v)


        # TODO handle CPU working on two mode
        # TODO handle endianess as well? 
        if pinf['proc_mode'] == 16:
                self.assembler = assemblers['armt'][0]
        elif pinf['proc_mode'] == 32:
                self.assembler = assemblers['arm'][0]

        for k,v in self.conf.patches.items():
            self.patch_mem(k,v) 


        for k,v in self.conf.watchpoints.items():
            self.add_watchpoint(k, v&0xFF,mode=v>>24)



    def install_hooks(self):

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
    def setup_stub_mechanism(self):

            self.uc.mem_map(consts_arm.ALLOC_BA,
                            self.conf.p_size*consts_arm.ALLOC_PAGES,
                            UC_PROT_READ | UC_PROT_WRITE)

            self.helper = UnicornArmSEA(emu=self,
                                        allocator=DumpAllocator(consts_arm.ALLOC_BA,
                                        consts_arm.ALLOC_PAGES*self.conf.p_size),
                                        wsize=4)
            self.nstub_obj = ELF.NullStub()
            self.nstub_obj.set_helper(self.helper)
 
            self.stubs = ELF.libc_stubs
            if verify_valid_elf(self.conf.s_conf.orig_filepath):
                        self.reloc_map = get_relocs(self.conf.s_conf.orig_filepath,
                                                    lief.ELF.RELOCATION_ARM.JUMP_SLOT)
                        self.libc_start_main_trampoline = consts_arm.LIBCSTARTSTUBADDR
                        self.stub_PLT()


            for k,v in self.conf.s_conf.tags.items(): 
                        self.tag_func(k, v)


    def nop_insn(self,insn):

        i = get_insn_at(insn.ea) 
        if i.size == 2:
                #TODO add new assembler method instead of const
            if self.endns == 'little':
                self.uc.mem_write(insn.ea,struct.pack('<H',consts_arm.nop_thumb))
            else:
                self.uc.mem_write(insn.ea,struct.pack('>H',consts_arm.nop_thumb))
        elif i.size == 4: 
            if self.endns == 'little':
                self.uc.mem_write(insn.ea,struct.pack('<I',consts_arm.nop))
            else:
                self.uc.mem_write(insn.ea,struct.pack('>I',consts_arm.nop))
        else:
            logger.console(LogType.ERRR,'Invalid insn size')


    def get_retn_insn(self,ea):
        f = ida_funcs.get_func(ea)
        if f == None:
            logger.console(LogType.WARN,'cannot decode function at specified address %x'%ea)
            return 
        i = get_insn_at(f.start_ea) 
        if ida_segregs.get_sreg(f.start_ea,ida_idp.str2reg('T')):
            if self.endns == 'little':
                #TODO: use new assembler feature
                retn = struct.pack('<H',consts_arm.mov_pc_lr_thumb)
            else:
                retn = struct.pack('>H',consts_arm.mov_pc_lr_thumb)
        else:
            if self.endns == 'little':
                retn = struct.pack('<I',consts_arm.mov_pc_lr)
            else:
                retn = struct.pack('>I',consts_arm.mov_pc_lr)
        return retn

    def get_new_stub(self,
                                     stub_func,
                                     stub_type: StubType,
                                     name:str=''):
        stub = ELF.Stub(self.helper,
                                        stub_type=stub_type,
                                        name=name)
        stub.do_it = stub_func
        return stub

    def setup_regs(self,regs):
        """ 
        Setup Emulator's registers using Register object. 

        @param regs: Register object.

        """

        for k,v in consts_arm.reg_map_unicorn.items():

            self.uc.reg_write(v,getattr(regs,k)) 

    def get_regs(self):

            """ 
            Returns a Register object instancied with 
            the current emulator register values. 

            @return Register Object.
            """

            regs = ArmRegisters.create() 
            for k,v in consts_arm.reg_map_unicorn.items():
                setattr(regs,k,self.uc.reg_read(v))
            return regs

    def reset_regs(self):

        """ 
        Reset the Emulator' registers.
        """


        for k,v in consts_arm.reg_map_unicorn.items():
            self.uc.reg_write(v,0)
        

    def isThumb(self) -> bool:

            """ 
            !Indicate if the emulator is currently either in thumb mode or not.

            @return True/False

            """

            # somehow unicorn does not query properly
            # BUG FIXME ?
            return self.pinf['proc_mode'] == 16 or self.uc.query(UC_QUERY_MODE) == 16



    @staticmethod
    def reg_convert(reg_id) -> int:
        """ 
        !Convert register identifier according its type 

        @return the corresponding id 

        """

        if type(reg_id) is str:
            return ArmCorn.str2reg(reg_id)

        elif type(reg_id) is int:
            return ArmCorn.int2reg(reg_id)

        else:
            raise Exception('[reg_convert] unhandled conversion for type %s'%type(reg_id))

    def reg_convert_ns(self,
                       reg_id:int) -> int:

        """ 
        !Class method that converts register identifier according its type 

        @return the corresponding id 

        """


        if type(reg_id) is str:
            return self.str2reg(reg_id)

        elif type(reg_id) is int:
            return self.int2reg(reg_id)

        else:
            raise Exception('[reg_convert] unhandled conversion for type %s'%type(reg_id))

    @staticmethod
    def int2reg(reg_id:int) -> int:

        """ 
        ! Convert the integer register Arm notation to the Unicorn Arm register notation

        @param reg_id The integer notation 

        @return The Unicorn Arm Notation

        """

        if reg_id == 13:
            return UC_ARM_REG_SP

        elif reg_id == 14:
            return UC_ARM_REG_LR

        elif reg_id == 15:
            return UC_ARM_REG_PC

        return UC_ARM_REG_R0 + reg_id



    @staticmethod
    def str2reg(r_str:str) -> int:

        """
        !Convert string notation to Unicorn notation.

        @param str string identifier

        @param unicorn notation

        @param str string identifier

        @param unicorn notation


        """

        return consts_arm.reg_map_unicorn[r_str] 
        

    def get_alu_info(self) -> arm32CPSR : 
        """ 
        !return the CPSR flags 

        @return Arm32CPSR object

        """
        return arm32CPSR.create(self.uc.reg_read(UC_ARM_REG_CPSR))




    def print_registers(self) -> str:

        """ 
        ! build a string with the current register values 
        
        @return a string with the current register values 

        """

        strout = 'Registers:\n'
        for k,v in consts_arm.reg_map_unicorn.items():
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
                        r13 = stk_ba + stk_size - consts_arm.initial_stack_offset 
                elif stk_ba and not stk_size: 
                        r13 = stk_ba +    consts_arm.STACK_SIZE - consts_arm.initial_stack_offset 
                elif stk_size and not stk_ba: 
                        r13 = consts_arm.STACK_BASEADDR + stk_size - consts_arm.initial_stack_offset 
                else:
                        r13 = consts_arm.STACK_BASEADDR+consts_arm.STACK_SIZE-\
                                                                 consts_arm.initial_stack_offset
                registers = ArmRegisters.get_default_object(r13=r13,
                                                                                                            r14=exec_eaddr,
                                                                                                            r15=exec_saddr)

            return Configuration.generate_default_config(arch='arm',stk_ba=stk_ba if stk_ba\
                                                        else consts_arm.STACK_BASEADDR,
                                                        stk_size=stk_size if stk_size\
                                                        else consts_arm.STACK_SIZE,
                                                        registers=registers,
                                                        exec_saddr=exec_saddr,
                                                        exec_eaddr=exec_eaddr)






