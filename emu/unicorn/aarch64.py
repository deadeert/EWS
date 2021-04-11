import ida_segregs
from emu.unicorn.generic import * 
import string
from utils.utils import * 
from utils import consts_aarch64
from stubs.ELF.allocator import *
from stubs.ELF import ELF
from stubs.emu.unicorn.sea import UnicornAarch64SEA
import struct
import lief



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
        if self.conf.s_conf.stub_dynamic_func_tab :

          
          self.uc.mem_map(consts_aarch64.ALLOC_BA,
                          conf.p_size*consts_aarch64.ALLOC_PAGES,
                          UC_PROT_READ | UC_PROT_WRITE)

          self.helper = UnicornAarch64SEA(emu=self,
                                          allocator=DumpAllocator(consts_aarch64.ALLOC_BA,
                                                                  consts_aarch64.ALLOC_PAGES*conf.p_size),
                                          wsize=4)
          self.nstub_obj = ELF.NullStub()
          self.nstub_obj.set_helper(self.helper) 

          if verify_valid_elf(self.conf.s_conf.orig_filepath):
              self.get_relocs(self.conf.s_conf.orig_filepath,lief.ELF.RELOCATION_AARCH64.JUMP_SLOT)
              self.stubs = ELF.libc_stubs 
              self.stubbit()

        self.uc.hook_add(UC_HOOK_CODE,
                         self.hook_code,
                         user_data=self.conf)
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED,
                         Emucorn.unmp_read,
                         user_data=self.conf)

        self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED,
                         Emucorn.unmp_write,
                         user_data=self.conf)
        if self.conf.showMemAccess:
          self.uc.hook_add(UC_HOOK_MEM_WRITE,
                    Emucorn.hk_write,
                    self.conf)
          self.uc.hook_add(UC_HOOK_MEM_READ,
                           Emucorn.hk_read,
                           self.conf)

    def repatch(self):
        """ when using restart() function from debugger 
            memory is erased, thus stub instruction has be 
            to be patch again 
        """ 

        if not self.conf.s_conf.stub_dynamic_func_tab: 
          return 
        self.uc.mem_map(consts_aarch64.ALLOC_BA,
                        self.conf.p_size*consts_aarch64.ALLOC_PAGES,
                        UC_PROT_READ | UC_PROT_WRITE)

        if verify_valid_elf(self.conf.s_conf.orig_filepath):
            self.stubbit()





    def start(self,cnt=0,saddr=None): 
        """ Need to overload because of thumb mode
        """ 
        if not saddr:
          saddr = self.conf.exec_saddr 

        try:
          self.uc.emu_start(saddr,self.conf.exec_eaddr,timeout=0,count=cnt)
        except UcError as e:  
          logger.console(LogType.ERRR,'Error in unicorn engine')
          raise e 
        except Exception as e:
          logger.console(LogType.WARN,'[!] Exception in program : %s' % e.__str__())
          raise e
        if self.conf.color_graph:
          colorate_graph(self.color_map)


    def nop_insn(self,insn):
        self.uc.mem_write(insn.ea,struct.pack('<I',consts_aarch64.nop))

    def get_retn_insn(self,ea):
        return struct.pack('<I',consts_aarch64.ret)

    def get_new_stub(self,stub_func):
        stub = ELF.Stub(self.helper)
        stub.do_it = stub_func
        return stub



    """  Register specific functions 
    """

#-------------------------------------------------------------------------------------------

    def setup_regs(self,regs):

        self.uc.reg_write(UC_ARM64_REG_X0,regs.X0)
        self.uc.reg_write(UC_ARM64_REG_X1,regs.X1)
        self.uc.reg_write(UC_ARM64_REG_X2,regs.X2)
        self.uc.reg_write(UC_ARM64_REG_X3,regs.X3)
        self.uc.reg_write(UC_ARM64_REG_X4,regs.X4)
        self.uc.reg_write(UC_ARM64_REG_X5,regs.X5)
        self.uc.reg_write(UC_ARM64_REG_X6,regs.X6)
        self.uc.reg_write(UC_ARM64_REG_X7,regs.X7)
        self.uc.reg_write(UC_ARM64_REG_X8,regs.X8)

        self.uc.reg_write(UC_ARM64_REG_X9,regs.X9)
        self.uc.reg_write(UC_ARM64_REG_X10,regs.X10)
        self.uc.reg_write(UC_ARM64_REG_X11,regs.X11)
        self.uc.reg_write(UC_ARM64_REG_X12,regs.X12)
        self.uc.reg_write(UC_ARM64_REG_X13,regs.X13)
        self.uc.reg_write(UC_ARM64_REG_X14,regs.X14)
        self.uc.reg_write(UC_ARM64_REG_X15,regs.X15)
        self.uc.reg_write(UC_ARM64_REG_X16,regs.X16)
        self.uc.reg_write(UC_ARM64_REG_X17,regs.X17)
        self.uc.reg_write(UC_ARM64_REG_X18,regs.X18)

        self.uc.reg_write(UC_ARM64_REG_X19,regs.X19)
        self.uc.reg_write(UC_ARM64_REG_X20,regs.X20)
        self.uc.reg_write(UC_ARM64_REG_X21,regs.X21)
        self.uc.reg_write(UC_ARM64_REG_X22,regs.X22)
        self.uc.reg_write(UC_ARM64_REG_X23,regs.X23)
        self.uc.reg_write(UC_ARM64_REG_X24,regs.X24)
        self.uc.reg_write(UC_ARM64_REG_X25,regs.X25)
        self.uc.reg_write(UC_ARM64_REG_X26,regs.X26)
        self.uc.reg_write(UC_ARM64_REG_X27,regs.X27)
        self.uc.reg_write(UC_ARM64_REG_X28,regs.X28)
        self.uc.reg_write(UC_ARM64_REG_FP,regs.FP)
        self.uc.reg_write(UC_ARM64_REG_LR,regs.LR)
        self.uc.reg_write(UC_ARM64_REG_SP,regs.SP)
        self.uc.reg_write(UC_ARM64_REG_PC,regs.PC)

    def get_regs(self):
        return Aarch64Registers(
                X0=self.uc.reg_read(UC_ARM64_REG_X0),
                X1=self.uc.reg_read(UC_ARM64_REG_X1),
                X2=self.uc.reg_read(UC_ARM64_REG_X2),
                X3=self.uc.reg_read(UC_ARM64_REG_X3),
                X4=self.uc.reg_read(UC_ARM64_REG_X4),
                X5=self.uc.reg_read(UC_ARM64_REG_X5),
                X6=self.uc.reg_read(UC_ARM64_REG_X6),
                X7=self.uc.reg_read(UC_ARM64_REG_X7),
                X8=self.uc.reg_read(UC_ARM64_REG_X8),

                X9=self.uc.reg_read(UC_ARM64_REG_X9),
                X10=self.uc.reg_read(UC_ARM64_REG_X10),
                X11=self.uc.reg_read(UC_ARM64_REG_X11),
                X12=self.uc.reg_read(UC_ARM64_REG_X12),
                X13=self.uc.reg_read(UC_ARM64_REG_X13),
                X14=self.uc.reg_read(UC_ARM64_REG_X14),
                X15=self.uc.reg_read(UC_ARM64_REG_X15),
                X16=self.uc.reg_read(UC_ARM64_REG_X16),
                X17=self.uc.reg_read(UC_ARM64_REG_X17),
                X18=self.uc.reg_read(UC_ARM64_REG_X18),

                X19=self.uc.reg_read(UC_ARM64_REG_X19),
                X20=self.uc.reg_read(UC_ARM64_REG_X20),
                X21=self.uc.reg_read(UC_ARM64_REG_X21),
                X22=self.uc.reg_read(UC_ARM64_REG_X22),
                X23=self.uc.reg_read(UC_ARM64_REG_X23),
                X24=self.uc.reg_read(UC_ARM64_REG_X24),
                X25=self.uc.reg_read(UC_ARM64_REG_X25),
                X26=self.uc.reg_read(UC_ARM64_REG_X26),
                X27=self.uc.reg_read(UC_ARM64_REG_X27),
                X28=self.uc.reg_read(UC_ARM64_REG_X28),
                FP=self.uc.reg_read(UC_ARM64_REG_FP),
                LR=self.uc.reg_read(UC_ARM64_REG_LR),
                SP=self.uc.reg_read(UC_ARM64_REG_SP),
                PC=self.uc.reg_read(UC_ARM64_REG_PC)
        ) 

    def reset_regs(self):

        # Function Arguments
        self.uc.reg_write(UC_ARM64_REG_X0,0)
        self.uc.reg_write(UC_ARM64_REG_X1,0)
        self.uc.reg_write(UC_ARM64_REG_X2,0)
        self.uc.reg_write(UC_ARM64_REG_X3,0)
        self.uc.reg_write(UC_ARM64_REG_X4,0)
        self.uc.reg_write(UC_ARM64_REG_X5,0)
        self.uc.reg_write(UC_ARM64_REG_X6,0)
        self.uc.reg_write(UC_ARM64_REG_X7,0)
        self.uc.reg_write(UC_ARM64_REG_X8,0)

        # General Purpose
        self.uc.reg_write(UC_ARM64_REG_X9,0)
        self.uc.reg_write(UC_ARM64_REG_X10,0)
        self.uc.reg_write(UC_ARM64_REG_X11,0)
        self.uc.reg_write(UC_ARM64_REG_X12,0)
        self.uc.reg_write(UC_ARM64_REG_X13,0)
        self.uc.reg_write(UC_ARM64_REG_X14,0)
        self.uc.reg_write(UC_ARM64_REG_X15,0)
        self.uc.reg_write(UC_ARM64_REG_X16,0)
        self.uc.reg_write(UC_ARM64_REG_X17,0)
        self.uc.reg_write(UC_ARM64_REG_X18,0)

        # stored / restored by functions accross call
        self.uc.reg_write(UC_ARM64_REG_X19,0)
        self.uc.reg_write(UC_ARM64_REG_X20,0)
        self.uc.reg_write(UC_ARM64_REG_X21,0)
        self.uc.reg_write(UC_ARM64_REG_X22,0)
        self.uc.reg_write(UC_ARM64_REG_X23,0)
        self.uc.reg_write(UC_ARM64_REG_X24,0)
        self.uc.reg_write(UC_ARM64_REG_X25,0)
        self.uc.reg_write(UC_ARM64_REG_X26,0)
        self.uc.reg_write(UC_ARM64_REG_X27,0)
        self.uc.reg_write(UC_ARM64_REG_X28,0)

        self.uc.reg_write(UC_ARM64_REG_FP,0)
        self.uc.reg_write(UC_ARM64_REG_LR,0)
        self.uc.reg_write(UC_ARM64_REG_SP,0)
        self.uc.reg_write(UC_ARM64_REG_PC,0)

    @staticmethod
    def reg_convert(reg_id):
        if type(reg_id) == type(str()):
          return Aarch64Corn.str2reg(reg_id)
        elif type(reg_id) == type(int()):
          return Aarch64Corn.int2reg(reg_id)
        else:
          raise Exception('[reg_convert] unhandled conversion for type %s'%type(reg_id))

    def reg_convert_sn(self,reg_id):
        if type(reg_id) == type(str()):
          return self.str2reg(reg_id)
        elif type(reg_id) == type(int()):
          return self.int2reg(reg_id)
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
        else: 
            return UC_ARM64_REG_X0 + reg_id

    @staticmethod           
    def str2reg(r_str):
        if r_str == 'X0':
          return UC_ARM64_REG_X0
        elif r_str == 'X1':
          return UC_ARM64_REG_X1
        elif r_str == 'X2':
          return UC_ARM64_REG_X2
        elif r_str == 'X3':
          return UC_ARM64_REG_X3
        elif r_str == 'X4':
          return UC_ARM64_REG_X4
        elif r_str == 'X5':
          return UC_ARM64_REG_X5
        elif r_str == 'X6':
          return UC_ARM64_REG_X6
        elif r_str == 'X7':
          return UC_ARM64_REG_X7
        elif r_str == 'X8':
          return UC_ARM64_REG_X8

        elif r_str == 'X9':
          return UC_ARM64_REG_X9
        elif r_str == 'X10':
          return UC_ARM64_REG_X10
        elif r_str == 'X11':
          return UC_ARM64_REG_X11
        elif r_str == 'X12':
          return UC_ARM64_REG_X12
        elif r_str == 'X13':
          return UC_ARM64_REG_X13
        elif r_str == 'X14':
          return UC_ARM64_REG_X14
        elif r_str == 'X15':
          return UC_ARM64_REG_X15
        elif r_str == 'X16':
          return UC_ARM64_REG_X16
        elif r_str == 'X17':
          return UC_ARM64_REG_X17
        elif r_str == 'X18':
          return UC_ARM64_REG_X18

        elif r_str == 'X19':
          return UC_ARM64_REG_X19
        elif r_str == 'X20':
          return UC_ARM64_REG_X20
        elif r_str == 'X21':
          return UC_ARM64_REG_X21
        elif r_str == 'X22':
          return UC_ARM64_REG_X22
        elif r_str == 'X23':
          return UC_ARM64_REG_X23
        elif r_str == 'X24':
          return UC_ARM64_REG_X24
        elif r_str == 'X25':
          return UC_ARM64_REG_X25
        elif r_str == 'X26':
          return UC_ARM64_REG_X26
        elif r_str == 'X27':
          return UC_ARM64_REG_X27
        elif r_str == 'X28':
          return UC_ARM64_REG_X28

        elif r_str == 'X29' or 'FP':
          return UC_ARM64_REG_FP
        elif r_str == 'X30' or 'LR':
            return  UC_ARM64_REG_LR
        elif r_str == 'X31' or 'SP':
            return UC_ARM64_REG_SP
        elif r_str == 'PC':
            return UC_ARM64_REG_PC

    def get_alu_info(self): 
        return aarch64CPSR.create(self.uc.reg_read(UC_ARM_REG_CPSR))



    def print_registers(self):
        strout  = 'Registers:\n'
        strout +=  '[X0=%.8X] [X1=%.8X] [X2=%.8X] [X3=%.8X]\n'%(self.uc.reg_read(UC_ARM64_REG_X0),
                                                             self.uc.reg_read(UC_ARM64_REG_X1),
                                                             self.uc.reg_read(UC_ARM64_REG_X2),
                                                             self.uc.reg_read(UC_ARM64_REG_X3))
        strout += '[X4=%.8X] [X5=%.8X] [X6=%.8X] [X7=%.8X]\n'%(self.uc.reg_read(UC_ARM64_REG_X4),
                                                             self.uc.reg_read(UC_ARM64_REG_X5),
                                                             self.uc.reg_read(UC_ARM64_REG_X6),
                                                             self.uc.reg_read(UC_ARM64_REG_X7))
        strout += '[X8=%.8X] [X9=%.8X] [X10=%.8X] [X11=%.8X]\n'%(self.uc.reg_read(UC_ARM64_REG_X8),
                                                               self.uc.reg_read(UC_ARM64_REG_X9),
                                                               self.uc.reg_read(UC_ARM64_REG_X10),
                                                               self.uc.reg_read(UC_ARM64_REG_X11))
        strout += '[X12=%.8X] [X13=%.8X] [X14=%.8X] [X15=%.8X]\n' % (self.uc.reg_read(UC_ARM64_REG_X12), 
                                                                     self.uc.reg_read(UC_ARM64_REG_X13), 
                                                                     self.uc.reg_read(UC_ARM64_REG_X14), 
                                                                     self.uc.reg_read(UC_ARM64_REG_X15))

        strout += '[X16=%.8X] [X17=%.8X] [X18=%.8X] [X19=%.8X]\n' % (self.uc.reg_read(UC_ARM64_REG_X16), 
                                                                     self.uc.reg_read(UC_ARM64_REG_X17),
                                                                     self.uc.reg_read(UC_ARM64_REG_X18),
                                                                     self.uc.reg_read(UC_ARM64_REG_X19))

        strout +=  '[X20=%.8X] [X21=%.8X] [X22=%.8X] [X23=%.8X]\n'%(self.uc.reg_read(UC_ARM64_REG_X20),
                                                             self.uc.reg_read(UC_ARM64_REG_X21),
                                                             self.uc.reg_read(UC_ARM64_REG_X22),
                                                             self.uc.reg_read(UC_ARM64_REG_X23))
        strout += '[X24=%.8X] [X25=%.8X] [X26=%.8X] [X27=%.8X]\n'%(self.uc.reg_read(UC_ARM64_REG_X24),
                                                             self.uc.reg_read(UC_ARM64_REG_X25),
                                                             self.uc.reg_read(UC_ARM64_REG_X26),
                                                             self.uc.reg_read(UC_ARM64_REG_X27))

        strout += '[X28=%.8X] [FP=%.8X] [LR =%.8X] [SP =%.8X]\n'%(self.uc.reg_read(UC_ARM64_REG_X28),
                                                               self.uc.reg_read(UC_ARM64_REG_FP),
                                                               self.uc.reg_read(UC_ARM64_REG_LR),
                                                               self.uc.reg_read(UC_ARM64_REG_SP))
        logger.console(LogType.INFO,strout)





