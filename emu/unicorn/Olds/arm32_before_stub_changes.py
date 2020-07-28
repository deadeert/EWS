import ida_segregs
from emu.unicorn.generic import * 
import string
import consts_arm
from utils import * 
from stubs.allocator import *
# import stubs.Arm
import stubs.Stubs
from stubs.unicstub import UnicornArmSEA




class ArmCorn(Emucorn): 

  def __init__(self,conf):

    super().__init__(conf) 

    # Init engine 
    pinf = proc_inf('arm',conf.exec_saddr)
    if pinf['endianness'] == 'little':  
      self.uc = Uc(UC_ARCH_ARM,UC_MODE_THUMB + UC_MODE_LITTLE_ENDIAN if pinf['proc_mode'] == 16  else UC_MODE_ARM +  UC_MODE_LITTLE_ENDIAN) 
    elif pinf['endianness'] == 'big':
      self.uc = Uc(UC_ARCH_ARM,UC_MODE_THUMB + UC_MODE_BIG_ENDIAN if   pinf['proc_mode'] == 16 else UC_MODE_ARM + UC_MODE_BIG_ENDIAN) 

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


    # Add null stubs 
    for s_ea in conf.s_conf.nstubs.keys():
      self.add_nullstub(s_ea)
   
    # Init stubs engine 
    if self.conf.s_conf.use_user_stubs: 
      self.uc.mem_map(consts_arm.ALLOC_BA,conf.p_size*consts_arm.ALLOC_PAGES,UC_PROT_READ | UC_PROT_WRITE)

      self.helper = UnicornArmSEA(uc=self.uc,
                                  allocator=DumpAllocator(consts_arm.ALLOC_BA,consts_arm.ALLOC_PAGES*conf.p_size),
                                  wsize=4)

    if self.conf.s_conf.stub_pltgot_entries: 
      self.trappage_ba = consts_arm.TRAP_PAGE_BA
      Emucorn.do_required_mappng(self.uc,self.trappage_ba,self.trappage_ba+conf.p_size,self.conf.p_size, UC_PROT_ALL)
      self.patch_plt(stubs.Stubs.libc_stubs_arm)
      logger.console(LogType.INFO,'[%s] add stubbing trap page. plt/got now patched.'%'ArmCorn') 
      logger.console(LogType.INFO,'[%s] fake allocator ready to use.'%'ArmCorn')

    if self.conf.s_conf.stub_pltgot_entries:
        self.uc.hook_add(UC_HOOK_INTR,
                    self.intr_handler, 
                    user_data=self.helper)
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


      #TODO 
      #f <- all functions
      #if f.name belongs stubs_list 
      #patch f.start 


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
      
  

  

  def hook_code(self,uc,addr,size,user_data): 
    self.color_map[addr] = get_insn_color(addr) 
    insn = ida_ua.insn_t() 
    ida_ua.decode_insn(insn,self.uc.reg_read(UC_ARM_REG_PC))
    op_str = 'opcode : %X'%int.from_bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_PC),insn.size),'big',signed=False)
    logger.console(LogType.INFO,op_str)
    insn_str = ''
    if self.conf.useCapstone:
      try:
        insn=next(self.cs.disasm(uc.mem_read(uc.reg_read(UC_ARM_REG_PC),insn.size),uc.reg_read(UC_ARM_REG_PC),count=1))
        insn_str="0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str)
      except StopIteration:
        pass
    else:  
      try: 
        operands = '' 
        i=0
        for x in insn.__get_ops__():
          if x.type > 0:
            operands+=' %s'%ida_ua.print_operand(insn.ea, i).strip()
          i+=1
        insn_str=ida_ua.print_insn_mnem(insn.ea)+' '+operands
      except Exception as e:
        insn_str='[!] Error occured while decoding insn:'+e.__str__()
    
    strout = '[PC=%.8X]'%uc.reg_read(UC_ARM_REG_PC)+' '+insn_str
    
    logger.console(LogType.INFO,strout)
    if self.conf.showRegisters:
      self.print_registers()
    

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

  def patch_plt(self,stubs_l):
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
     """The UnicornArmRunner intr_handler overwrites the default handler
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



