import ida_segregs
from emu.unicorn.generic import * 
import string
import consts_arm
from utils import * 
from stubs.allocator import *
# import stubs.Arm
import stubs.Stubs
from stubs.unicstub import UnicornArmSEA
import struct




class ArmCorn(Emucorn): 

  def __init__(self,conf):

    super().__init__(conf) 

    # Init engine 
    pinf = proc_inf('arm',conf.exec_saddr)
    if pinf['endianness'] == 'little':  
      self.uc = Uc(UC_ARCH_ARM,UC_MODE_THUMB + UC_MODE_LITTLE_ENDIAN if pinf['proc_mode'] == 16  else UC_MODE_ARM +  UC_MODE_LITTLE_ENDIAN) 
    elif pinf['endianness'] == 'big':
      self.uc = Uc(UC_ARCH_ARM,UC_MODE_THUMB + UC_MODE_BIG_ENDIAN if   pinf['proc_mode'] == 16 else UC_MODE_ARM + UC_MODE_BIG_ENDIAN) 
    self.endns = pinf['endianness']

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


    # Add null stubs 
    for s_ea in conf.s_conf.nstubs.keys():
      self.add_null_stub(s_ea)
   
    # Init stubs engine 
    if self.conf.s_conf.use_user_stubs or self.conf.s_conf.use_user_stubs: 
      self.uc.mem_map(consts_arm.ALLOC_BA,conf.p_size*consts_arm.ALLOC_PAGES,UC_PROT_READ | UC_PROT_WRITE)

      self.helper = UnicornArmSEA(uc=self.uc,
                                  allocator=DumpAllocator(consts_arm.ALLOC_BA,consts_arm.ALLOC_PAGES*conf.p_size),
                                  wsize=4)
      self.nstub_obj = stubs.Stubs.NullStub('arm')
      self.nstub_obj.set_helper(self.helper) 
 
    self.breakpoints= dict()
    self.custom_stubs = dict()
    if self.conf.s_conf.stub_pltgot_entries:
      self.stubbit(stubs.Stubs.libc_stubs_arm)
      

           
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
      
  

  
  def restart(self,conf=None,cnt=0):

    # unmap & remap 
    for rsta,rsto,rpriv in self.uc.mem_regions():
      self.uc.mem_unmap(rsta,rsto-rsta+1)
    stk_p = Emucorn.do_mapping(self.uc,self.conf)

    # reset register and setup 
    for rid in range(0,16):
      self.uc.reg_write(ArmCorn.int2reg(rid),0)

    self.setup_regs(stk_p)
    
    self.helper.allocator.reset()

    self.start(cnt)


   


  
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



  def stubbit(self,stubs_l):
    """ The strategy is to use ida elf loader and crossreferences 
        to directly stub .plt stubs.  
        We patch first insn in ordr to comeback in caller function. 
        We add "breakpoint" which is catch by hook_code() function.
    """ 


    s = ida_segment.get_segm_by_name('.plt') 
    if s == None:
      logger.console(LogType.WARN,'[!] plt section not found, stubs mechanism not compatible with such binary')
      logger.console(LogType.WARN,'[!] TODO use PT_DYNAMIC->RELRA instead')
      
      return
    fstubbednb = 0
    f = ida_funcs.get_next_func(s.start_ea)
    insn = ida_ua.insn_t()
    while f.start_ea < s.end_ea:
      fname = ida_name.get_ea_name(f.start_ea)
      if fname in stubs_l.keys():
        fstubbednb += 1
        if is_thumb(f.start_ea):
          self.uc.mem_write(f.start_ea,struct.pack('>H' if self.endns == 'little' else '<H',consts_arm.mov_pc_lr_thumb))
        else:
          self.uc.mem_write(f.start_ea,struct.pack('>I' if self.endns == 'little' else '<I',consts_arm.mov_pc_lr))
        stubs_l[fname].set_helper(self.helper)
        self.breakpoints[f.start_ea] = fname
      f = ida_funcs.get_next_func(f.start_ea)
      if f == None: 
        break

    return fstubbednb 
 

  def add_null_stub(self,ea,fname=None):
    """ TODO can be factorised with add_custom_stub
        with func=None
    """
    if not fname:
      try:    fname = ida_funcs.get_func_name(ea)
      except: fname = 'func_%x'%ea
 
    if fname in stubs.Stubs.libc_stubs_arm.keys():
      logger.console(LogType.WARN,'[!] %s belongs to libc stub. It is now null stubbed'%fname)
      stubs.Stubs.libc_stubs_arm[fname] = self.nstub_obj
    else:
      if is_thumb(ea):  
        self.uc.mem_write(f.start_ea,struct.pack('>H' if self.endns == 'little' else '<H',consts_arm.mov_pc_lr_thumb))
      else:
        self.uc.mem_write(ea,struct.pack('>I' if self.endns == 'little' else '<I',consts_arm.mov_pc_lr))
      self.custom_stubs[ea] = self.nstub_obj.do_it

      logger.console(LogType.INFO,'[%x] [%s] is null stubbed'%(ea,fname))

    self.conf.add_null_stub(ea)

  def remove_null_stub(self,ea,fname=None):
  
    if not fname:
      try:    fname = ida_funcs.get_func_name(ea)
      except: fname = 'func_%x'%ea

    if fname in stubs.Stubs.libc_stubs_arm.keys():
      # Needs to reinit the stub
      logger.console(LogType.WARN,'Changes will be effective only after save and reloading the conf')
    else:
      # Restore from IDB
      self.uc.mem_wirte(ea,ida_bytes.get_bytes(ea,4))
      del self.custom_stubs[ea]

    self.conf.remove_null_stub(ea)

  def add_custom_stub(self,ea,func):
    """ function must return True to continue execution
        how to use:
        def custom_stub():
          r0 = emu.helper.get_arg(0)
          emu.helper.set_return(r0+1)
          return True
        emu.add_custom_stub(0xadde,custom_stub)
    """


    try:    fname = ida_funcs.get_func_name(ea)
    except: fname = 'func_%x'%ea 


    aldy_patch = False
    if fname in stubs.Stubs.libc_stubs_arm.keys():
      logger.console(LogType.WARN,'Overriding default stub function %s'%fname)
      aldy_patch = True
    elif fname in self.conf.s_conf.nstubs.values():
      logger.console(LogType.WARN,'Overriding null stubbed function %s'%fname)
      self.remove_null_stub(ea)

    if not aldy_patch:
      if is_thumb(ea):  
        self.uc.mem_write(f.start_ea,struct.pack('>H' if self.endns == 'little' else '<H',consts_arm.mov_pc_lr_thumb))
      else: 
        self.uc.mem_write(ea,struct.pack('>I' if self.endns == 'little' else '<I',consts_arm.mov_pc_lr))
     

    stubs.Stubs.StubsARM.itnum_arm+=1
    new_stub = stubs.Stubs.Stub(stubs.Stubs.StubsARM.itnum_arm,'arm',self.helper)
    new_stub.do_it = func
    self.custom_stubs[ea] = new_stub.do_it

    logger.console(LogType.INFO,'%s is no stubbed with %s'%(fname,func.__name__))

  def remove_custom_stub(self,ea):


    try:    fname = ida_funcs.get_func_name(ea)
    except: fname = 'func_%x'%ea 

    if fname in stubs.Stubs.libc_stubs_arm.keys():
      logger.console(LogType.WARN,'could not unstub, please reload the conf')
    
    self.uc.mem_write(ea,ida_bytes.get_bytes(ea,4))
    del self.custom_stubs[ea]

    
    logger.console(LogType.INFO,'%s function is now unstubbed'%fname)

  def tag_function(self,ea,stubname):
    """ TODO: add to configuration
    """

    if not stubname in stubs.Stubs.libc_stubs_arm.keys():
      logger.console(LogType.WARN,'%s is not among default stubs. Aborting'%stubname)
      return
    stubs.Stubs.libc_stubs_arm[stubname].set_helper(self.helper)
    self.add_custom_stub(ea,stubs.Stubs.libc_stubs_arm[stubname].do_it)


  def remove_tag(self,ea):
    self.remove_custom_stub(ea)
    


######
#
# Legacy functions for old stubs mechanism 
#
#####


  def patch_plt(self,stubs_l):
    """ this mechanism stubs .plt stub.
        it replaces got queries by svc #itnum 
        which is catch by intr_handler() function. 
       
    """
    s = ida_segment.get_segm_by_name('.plt') 
    f = ida_funcs.get_next_func(s.start_ea)
    idx = 0  
    while f.start_ea < s.end_ea:
      fname = ida_name.get_ea_name(f.start_ea)
      if fname in stubs_l.keys():
        
        print('writting %x'%f.start_ea)
#         self.uc.mem_write(f.start_ea,stubs.Arm.libc_stubs_arm[fname].insn_it)
        self.uc.mem_write(f.start_ea,stubs_l[fname].insn_it)
        stubs_l[fname].set_helper(self.helper)
        idx += 4 
        logger.console(LogType.INFO,'[+] %s is not stubbed at '%(fname))
      
      f = ida_funcs.get_next_func(f.start_ea)



 
  @staticmethod
  def intr_handler(uc,intno,user_data):
     """ This function is used to catch svc #itnum 
        It calls the stub routine identified by itnum and 
        changes PC to continues execution
        In unicorn, only arm, aarch64 are compatible with
        such behavior. Indeed registers cannot be modified 
        in mips, x86, x86_64. 
        This is why HOOK_CODE has been used instead at the cost   
        of performance (HOOK_CODE is executed at each insn).
     """
     helper = user_data
     pc = uc.reg_read(UC_ARM_REG_PC)-4
     insn = int.from_bytes(uc.mem_read(pc,4),'little')
     index = insn&0xffff
     lr = uc.reg_read(arm_const.UC_ARM_REG_LR)
     logger.console(LogType.INFO,"[intr_handler] reloc index=%s (pc=%08X) (lr=%08X)"%(index,pc,lr))
     try:
#        stubs.Arm.libc_stubs_arm[index].do_it(helper)
       stubs.Stubs.libc_stubs_arm[index].do_it()
       
     except Exception as e: 
       logger.console(LogType.ERRR,'[intr_handler] error in stubs code')
       raise e
     uc.reg_write(UC_ARM_REG_PC,lr)
     logger.console(LogType.INFO,'[intr_handler] exiting. Restauring PC to %08X'%uc.reg_read(UC_ARM_REG_PC))


  def add_nullstub(self,addr,blx=False,pop_pc=False):
    is_thumb = ida_segregs.get_sreg(addr,ida_idp.str2reg('T')) 
    if blx:
      pass
    elif pop_pc:
      pass
    else:
      if is_thumb:
        self.uc.mem_write(addr,int.to_bytes(0x00B5,4,'big',signed=False)) #push {LR}
        self.uc.mem_write(addr+4,int.to_bytes(0x00BD,4,'big',signed=False)) #pop {PC} 
      else:
        self.uc.mem_write(addr,int.to_bytes(0x2DE9F04D,4,'big',signed=False)) #push R4-48,R10,R11,LR
        self.uc.mem_write(addr+4,int.to_bytes(0xBDE8F08D,4,'big',signed=False)) #pop R4-48,R10,R11,PC





