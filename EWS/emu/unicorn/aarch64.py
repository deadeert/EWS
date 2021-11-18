import ida_segregs
from EWS.emu.unicorn.generic import * 
import string
from EWS.utils.utils import * 
from EWS.utils import consts_aarch64
from EWS.stubs.ELF.allocator import *
from EWS.stubs.ELF import ELF
from EWS.stubs.emu.unicorn.sea import UnicornAarch64SEA
import struct
import lief
from EWS.utils.configuration import *
from EWS.utils.registers import *


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


    def install_hooks(self):
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
          self.stubbit()


   # DEPRECATED, use reset() plugin function

#    def repatch(self):
#        """ when using restart() function from debugger 
#            memory is erased, thus stub instruction has be 
#            to be patch again 
#        """ 
#
#        if not self.conf.s_conf.stub_dynamic_func_tab: 
#          return 
#        self.uc.mem_map(consts_aarch64.ALLOC_BA,
#                        self.conf.p_size*consts_aarch64.ALLOC_PAGES,
#                        UC_PROT_READ | UC_PROT_WRITE)
#
#        self.unstub_all()
#        self.stubbit()
#




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
        return struct.pack('>I',consts_aarch64.ret)

    def get_new_stub(self,stub_func,stub_type):
        stub = ELF.Stub(self.helper,stub_type=stub_type)
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

    def reg_convert_ns(self,reg_id):
        if type(reg_id) == type(str()):
          return Aarch64Corn.str2reg(reg_id)
#        elif type(reg_id) == type(int()):
#          return self.int2reg(reg_id)
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
        if r_str.upper() == 'X0':
          return UC_ARM64_REG_X0
        elif r_str.upper() == 'X1':
          return UC_ARM64_REG_X1
        elif r_str.upper() == 'X2':
          return UC_ARM64_REG_X2
        elif r_str.upper() == 'X3':
          return UC_ARM64_REG_X3
        elif r_str.upper() == 'X4':
          return UC_ARM64_REG_X4
        elif r_str.upper() == 'X5':
          return UC_ARM64_REG_X5
        elif r_str.upper() == 'X6':
          return UC_ARM64_REG_X6
        elif r_str.upper() == 'X7':
          return UC_ARM64_REG_X7
        elif r_str.upper() == 'X8':
          return UC_ARM64_REG_X8
        elif r_str.upper() == 'X9':
          return UC_ARM64_REG_X9
        elif r_str.upper() == 'X10':
          return UC_ARM64_REG_X10
        elif r_str.upper() == 'X11':
          return UC_ARM64_REG_X11
        elif r_str.upper() == 'X12':
          return UC_ARM64_REG_X12
        elif r_str.upper() == 'X13':
          return UC_ARM64_REG_X13
        elif r_str.upper() == 'X14':
          return UC_ARM64_REG_X14
        elif r_str.upper() == 'X15':
          return UC_ARM64_REG_X15
        elif r_str.upper() == 'X16':
          return UC_ARM64_REG_X16
        elif r_str.upper() == 'X17':
          return UC_ARM64_REG_X17
        elif r_str.upper() == 'X18':
          return UC_ARM64_REG_X18
        elif r_str.upper() == 'X19':
          return UC_ARM64_REG_X19
        elif r_str.upper() == 'X20':
          return UC_ARM64_REG_X20
        elif r_str.upper() == 'X21':
          return UC_ARM64_REG_X21
        elif r_str.upper() == 'X22':
          return UC_ARM64_REG_X22
        elif r_str.upper() == 'X23':
          return UC_ARM64_REG_X23
        elif r_str.upper() == 'X24':
          return UC_ARM64_REG_X24
        elif r_str.upper() == 'X25':
          return UC_ARM64_REG_X25
        elif r_str.upper() == 'X26':
          return UC_ARM64_REG_X26
        elif r_str.upper() == 'X27':
          return UC_ARM64_REG_X27
        elif r_str.upper() == 'X28':
          return UC_ARM64_REG_X28
        elif r_str.upper() == 'X29' or  r_str.upper() == 'FP':
          return UC_ARM64_REG_FP
        elif r_str.upper() == 'X30' or r_str.upper() == 'LR':
            return  UC_ARM64_REG_LR
        elif r_str.upper() == 'X31' or r_str.upper() == 'SP':
            return UC_ARM64_REG_SP
        elif r_str.upper() == 'PC':
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
        return strout



    @staticmethod
    def generate_default_config(path=None,
                       arch=None,
                       emulator=None,
                       p_size=None,
                       stk_ba=None,
                       stk_size=None,
                       autoMap=None,
                       showRegisters=None,
                       exec_saddr=None,
                       exec_eaddr=None,
                       mapping_saddr=None,
                       mapping_eaddr=None,
                       segms=None,
                       map_with_segs=None,
                       use_seg_perms=None,
                       useCapstone=None,
                       registers=None,
                       showMemAccess=None,
                       s_conf=None,
                       amap_conf=None,
                       memory_init=None,
                       color_graph=None,
                        breakpoints=None):

      if registers == None:
            registers = Aarch64Registers(0,
                                         1,
                                         2,
                                         3,
                                         4,
                                         5,
                                         6,
                                         7,
                                         8,
                                         9,
                                         10,
                                         11,
                                         12,
                                         13,
                                         14,
                                         15,
                                         16,
                                         17,
                                         18,
                                         19,
                                         20,
                                         21,
                                         22,
                                         23,
                                         24,
                                         25,
                                         26,
                                         27,
                                         28,
                                         29,
                                         e_ea, # LR
                                         consts_aarch64.STACK_BASEADDR+consts_aarch64.STACK_SIZE-consts_aarch64.initial_stack_offset,
                                         exec_saddr # PC
                                         )
      else:
        registers = regs

      if s_conf == None:
        exec_path = search_executable() 
        stub_conf = StubConfiguration(nstubs=dict(),
                                        stub_dynamic_func_tab=True, #True if exec_path != "" else False,
                                        orig_filepath=exec_path,
                                        custom_stubs_file=None,
                                        auto_null_stub=True if exec_path != "" else False,
                                        tags=dict())
      else:
        stub_conf = s_conf

      if amap_conf == None:
        addmap_conf = AdditionnalMapping.create()
      else:
        addmap_conf = amap_conf
      if memory_init == None:
        meminit = AdditionnalMapping.create()
      else:
        meminit = memory_init



      return Configuration(     path=path if path else '',
                              arch='aarch64',
                              emulator='unicorn',
                              p_size=p_size if p_size else consts_aarch64.PSIZE,
                              stk_ba=stk_ba if stk_ba else consts_aarch64.STACK_BASEADDR,
                              stk_size=stk_size if stk_size else consts_aarch64.STACK_SIZE,
                              autoMap=autoMap if autoMap else False,
                              showRegisters=showRegisters if showRegisters else True,
                              exec_saddr=exec_saddr if exec_saddr else 0,
                              exec_eaddr=exec_eaddr if exec_eaddr else 0xFFFFFFFF,
                              mapping_saddr=get_min_ea_idb() if not mapping_saddr else mapping_saddr,
                              mapping_eaddr=get_max_ea_idb() if not mapping_eaddr else mapping_eaddr,
                              segms=segms if segms else [],
                              map_with_segs=map_with_segs if map_with_segs else False,
                              use_seg_perms=use_seg_perms if use_seg_perms else False,
                              useCapstone=useCapstone if useCapstone else True,
                              registers=registers,
                              showMemAccess=showMemAccess if showMemAccess else True,
                              s_conf=stub_conf,
                              amap_conf=addmap_conf,
                              memory_init=meminit,
                              color_graph=False,
                              breakpoints=breakpoints if breakpoints else [])




