import ida_segregs
from emu.unicorn.generic import * 
import string
from utils.utils import * 
from utils import consts_arm
from stubs.ELF.allocator import *
from stubs.ELF import ELF
from stubs.emu.unicorn.sea import UnicornAarch64SEA
import struct




class ArmCorn(Emucorn): 

  def __init__(self,conf):

    super().__init__(conf) 

    # Init engine 
    pinf = proc_inf('arm',conf.exec_saddr)
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
    stk_p = Emucorn.do_mapping(self.uc,self.conf)
    
    # Init capstone engine
    if conf.useCapstone:
      from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN
      if pinf['proc_mode'] == 16:
        self.cs=Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN if pinf['endianness'] else CS_MODE_THUMB + CS_MODE_BIG_ENDIAN)
         
      elif pinf['proc_mode'] == 32:
        self.cs=Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN if pinf['endianness'] else CS_MODE_ARM + CS_MODE_BIG_ENDIAN)
      self.cs.detail=True

    # Setup regs 
    self.setup_regs(stk_p)
    self.pcid = UC_ARM_REG_PC 


#     # Add null stubs 
#     for s_ea in conf.s_conf.nstubs.keys():
#       self.add_null_stub(s_ea)
#    
    # Init stubs engine 
    if self.conf.s_conf.stub_dynamic_func_tab: 
      self.uc.mem_map(consts_arm.ALLOC_BA,conf.p_size*consts_arm.ALLOC_PAGES,UC_PROT_READ | UC_PROT_WRITE)

      self.helper = UnicornArmSEA(uc=self.uc,
                                  allocator=DumpAllocator(consts_arm.ALLOC_BA,consts_arm.ALLOC_PAGES*conf.p_size),
                                  wsize=4)
      self.nstub_obj = ELF.NullStub()
      self.nstub_obj.set_helper(self.helper) 
 
#     self.breakpoints= dict()
#     self.custom_stubs = dict()
    if self.conf.s_conf.stub_dynamic_func_tab:
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

  
  def start(self,cnt=0,saddr=None): 
    """ Need to overload because of thumb mode
    """ 
    if not saddr:
      saddr = self.conf.exec_saddr 
    if self.isThumb():
      saddr |= 1

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


  """ Instructions specifics functions 
  """
#---------------------------------------------------------------------------------------------

  def nop_insn(self,insn):
    i = get_insn_at(insn.ea) 
    if i.size == 2:
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
    if i.size == 2:
      if self.endns == 'little':
        retn = struct.pack('<H',consts_arm.mov_pc_lr_thumb)
      else:
        retn = struct.pack('>H',consts_arm.mov_pc_lr_thumb)
    elif i.size == 4:
      if self.endns == 'little':
        retn = struct.pack('<I',consts_arm.mov_pc_lr)
      else:
        retn = struct.pack('>I',consts_arm.mov_pc_lr)
    else:
      logger.console(LogType.ERRR,'Invalid insn size')
    return retn

  def get_new_stub(self,stub_func):
    stub = ELF.Stub(self.helper)
    stub.do_it = stub_func
    return stub





  """  Register specific functions 
  """
#---------------------------------------------------------------------------------------------
  def setup_regs(self,stk_p):

    self.uc.reg_write(UC_ARM_REG_R0,self.conf.registers.R0)
    self.uc.reg_write(UC_ARM_REG_R1,self.conf.registers.R1)
    self.uc.reg_write(UC_ARM_REG_R2,self.conf.registers.R2)
    self.uc.reg_write(UC_ARM_REG_R3,self.conf.registers.R3)
    self.uc.reg_write(UC_ARM_REG_R4,self.conf.registers.R4)
    self.uc.reg_write(UC_ARM_REG_R5,self.conf.registers.R5)
    self.uc.reg_write(UC_ARM_REG_R6,self.conf.registers.R6)
    self.uc.reg_write(UC_ARM_REG_R7,self.conf.registers.R7)
    self.uc.reg_write(UC_ARM_REG_R8,self.conf.registers.R8)
    self.uc.reg_write(UC_ARM_REG_R9,self.conf.registers.R9)
    self.uc.reg_write(UC_ARM_REG_R10,self.conf.registers.R10)
    self.uc.reg_write(UC_ARM_REG_R11,self.conf.registers.R11)
    self.uc.reg_write(UC_ARM_REG_R12,self.conf.registers.R12)
    if self.conf.registers.R13 in range(self.conf.stk_ba,self.conf.stk_ba+stk_p*self.conf.p_size):
      self.uc.reg_write(UC_ARM_REG_R13,self.conf.registers.R13)
    else:
      warn = '[%s] SP value does not belong to the stack'%'ArmCorn'
      warn += 'using default address : %8X'%(self.conf.stk_ba+stk_p*self.conf.p_size-4)
      logger.console(LogType.WARN,warn)
      self.uc.reg_write(UC_ARM_REG_R13,self.conf.stk_ba+stk_p*self.conf.p_size-4)
    self.uc.reg_write(UC_ARM_REG_R14,self.conf.registers.R14)
    self.uc.reg_write(UC_ARM_REG_R15,self.conf.registers.R15)


  def reset_regs(self):

    self.uc.reg_write(UC_ARM_REG_R0,0)
    self.uc.reg_write(UC_ARM_REG_R1,0)
    self.uc.reg_write(UC_ARM_REG_R2,0)
    self.uc.reg_write(UC_ARM_REG_R3,0)
    self.uc.reg_write(UC_ARM_REG_R4,0)
    self.uc.reg_write(UC_ARM_REG_R5,0)
    self.uc.reg_write(UC_ARM_REG_R6,0)
    self.uc.reg_write(UC_ARM_REG_R7,0)
    self.uc.reg_write(UC_ARM_REG_R8,0)
    self.uc.reg_write(UC_ARM_REG_R9,0)
    self.uc.reg_write(UC_ARM_REG_R10,0)
    self.uc.reg_write(UC_ARM_REG_R11,0)
    self.uc.reg_write(UC_ARM_REG_R12,0)
    self.uc.reg_write(UC_ARM_REG_R13,0)
    self.uc.reg_write(UC_ARM_REG_R14,0)
    self.uc.reg_write(UC_ARM_REG_R15,0)
   

  def isThumb(self):
    return True if self.uc.query(UC_QUERY_MODE) == 0x10 else False 



  @staticmethod
  def reg_convert(reg_id):
    if type(reg_id) == type(str()):
      return ArmCorn.str2reg(reg_id)
    elif type(reg_id) == type(int()):
      return ArmCorn.int2reg(reg_id)
    else:
      raise Exception('[reg_convert] unhandled conversion for type %s'%type(reg_id))

  @staticmethod
  def int2reg(reg_id):
    if reg_id == 13:
      return UC_ARM_REG_SP
    elif reg_id == 14:
      return UC_ARM_REG_LR
    elif reg_id == 15: 
      return UC_ARM_REG_PC 
    return UC_ARM_REG_R0 + reg_id

  @staticmethod           
  def str2reg(r_str):
    if r_str == 'R0':
      return UC_ARM_REG_R0
    elif r_str == 'R1':
      return UC_ARM_REG_R1
    elif r_str == 'R2':
      return UC_ARM_REG_R2
    elif r_str == 'R3':
      return UC_ARM_REG_R3
    elif r_str == 'R4':
      return UC_ARM_REG_R4
    elif r_str == 'R5':
      return UC_ARM_REG_R5
    elif r_str == 'R6':
      return UC_ARM_REG_R6
    elif r_str == 'R7':
      return UC_ARM_REG_R7
    elif r_str == 'R8':
      return UC_ARM_REG_R8
    elif r_str == 'R9':
      return UC_ARM_REG_R9
    elif r_str == 'R10':
      return UC_ARM_REG_R10
    elif r_str == 'R11':
      return UC_ARM_REG_R11
    elif r_str == 'R12':
      return UC_ARM_REG_R12
    elif r_str == 'R13':
      return UC_ARM_REG_R13
    elif r_str == 'R14':
      return UC_ARM_REG_R14
    elif r_str == 'R15':
      return UC_ARM_REG_R15 
      
 

  
  
  def get_alu_info(self): 
    return arm32CPSR.create(self.uc.reg_read(UC_ARM_REG_CPSR))


    

   

  def repatch(self):
    """ when using restart() function from debugger 
        memory is erased, thus stub instruction has be 
        to be patch again 
    """ 
    if not self.conf.stub_pltgot_entries: 
      return 
    
    self.stubbit(ELF.libc_stubs_arm)




  
  def print_registers(self):
    strout  = 'Registers:\n'
    strout +=  '[R0=%.8X] [R1=%.8X] [R2=%.8X] [R3=%.8X]\n'%(self.uc.reg_read(UC_ARM_REG_R0),
                                                         self.uc.reg_read(UC_ARM_REG_R1),
                                                         self.uc.reg_read(UC_ARM_REG_R2),
                                                         self.uc.reg_read(UC_ARM_REG_R3))
    strout += '[R4=%.8X] [R5=%.8X] [R6=%.8X] [R7=%.8X]\n'%(self.uc.reg_read(UC_ARM_REG_R4),
                                                         self.uc.reg_read(UC_ARM_REG_R5),
                                                         self.uc.reg_read(UC_ARM_REG_R6),
                                                         self.uc.reg_read(UC_ARM_REG_R7))
    strout += '[R8=%.8X] [R9=%.8X] [R10=%.8X] [R11=%.8X]\n'%(self.uc.reg_read(UC_ARM_REG_R8),
                                                           self.uc.reg_read(UC_ARM_REG_R9),
                                                           self.uc.reg_read(UC_ARM_REG_R10),
                                                           self.uc.reg_read(UC_ARM_REG_R11))
    strout += '[FP=%.8X] [SP =%.8X] [LR =%.8X]\n'%(self.uc.reg_read(UC_ARM_REG_R12),
                                                           self.uc.reg_read(UC_ARM_REG_R13),
                                                           self.uc.reg_read(UC_ARM_REG_R14))
    logger.console(LogType.INFO,strout)




