import ida_segment
import ida_ua
import ida_idaapi
import ida_funcs
import ida_bytes
import ida_segregs
import ida_idp 
import ida_name
import os

from unicorn import * 
from unicorn.arm_const import * 
from unicorn.mips_const import * 

import string
import consts_arm
from utils import * 
from stubs.allocator import *
import stubs.Arm
from stubs.unicstub import UnicornArmHelper, ArmSEAUnicorn

class Emucorn(object):

  def __init__(self,conf):
    self.conf = conf

  def start(self):
    pass

  def add_mapping(self,pages):
    pass
  
  @staticmethod
  def reg_convert(r_id): 
    """ match int r_id to corresponding register values in emulator solution. 
        usefull for Stubs abstraction mechanism
    """ 
    pass

  def patch_plt(self,stubs_l):
    pass  

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



  @staticmethod
  def do_mapping(uc,conf): 

    inf = ida_idaapi.get_inf_structure()
  
    # Maps program segment
    if conf.map_with_segs:
      for seg in conf.segms:
        vbase = Emucorn.do_required_mappng(uc,seg.start_ea, seg.end_ea, conf.p_size, UC_PROT_ALL if not conf.use_seg_perms else seg.perm) 
        uc.mem_write(seg.start_ea,ida_bytes.get_bytes(seg.start_ea,seg.end_ea-seg.start_ea))
        logger.console(LogType.INFO,'[%s] Mapping seg %s\n'%('EmuCorn',ida_segment.get_segm_name(seg)))
    else:
        if conf.mapping_eaddr >= inf.max_ea or conf.mapping_saddr < inf.min_ea: 
          raise Exception('Invalid mapping for code section') 
        nb_pages = ((conf.mapping_eaddr - conf.mapping_saddr) // conf.p_size) + 1
        vbase=conf.mapping_saddr&~(conf.p_size-1) 
        uc.mem_map(vbase,nb_pages*conf.p_size,UC_PROT_ALL)
        uc.mem_write(conf.mapping_saddr,ida_bytes.get_bytes(conf.mapping_saddr,conf.mapping_eaddr-conf.mapping_saddr))
        logger.console(LogType.INFO,'[%s] Mapping memory\n\tvbase : 0x%.8X\n\tcode size: 0x%.8X\n\tpage:  %d'%('EmuCorn',
                                                                                                    vbase,
                                                                                                    conf.mapping_eaddr-conf.mapping_saddr,
                                                                                                    nb_pages))
    # Map user provided areas 
    for m_ea in conf.amap_conf.mappings.keys():
      Emucorn.do_required_mappng(uc,m_ea,m_ea+len(conf.amap_conf.mappings[m_ea]),conf.p_size,UC_PROT_ALL)
      uc.mem_write(m_ea,conf.amap_conf.mappings[m_ea]) 
      logger.console(LogType.INFO,'[%s] Additionnal mapping for data at %8X'%('Emucorn',m_ea)) 

    stk_p,r = divmod(conf.stk_size,conf.p_size)
    if r: stk_p+=1 
    uc.mem_map(conf.stk_ba,stk_p*conf.p_size)
    logger.console(LogType.INFO,' [%s] mapped stack at 0x%.8X '%('ArmCorn',conf.stk_ba))
  
    return stk_p 

  @staticmethod
  def mem_read(uc,addr,size):
    return uc.mem_read(addr,size)
  
  @staticmethod
  def mem_write(uc,addr,data):
    uc.mem_write(addr,data)

  @staticmethod
  def reg_read(uc,r_id):
    """ id mapping functions might be call before 
    """
    return uc.reg_read(r_id)
    
  @staticmethod
  def reg_write(uc,r_id,value):
    """ id mapping functions might be call before 
    """
    uc.reg_write(r_id,value)
 
  @staticmethod
  def unmp_read(uc,access,addr,value,size,user_data):
    logger.console(LogType.WARN,'[!] Read Access Exception: cannot read 0x%.8X for size %d (reason: unmapped page)'%(addr,size))
    conf = user_data
    if conf.autoMap:
      base_addr = addr & ~(conf.p_size-1)
      uc.mem_map(base_addr,conf.p_size)
      uc.mem_write(base_addr,b'\xde\xad\xbe\xef'*(conf.p_size//4))
      logger.console(LogType.INFO,'[*] Automap: added page 0x%.8X'%base_addr)
      return True
    logger.console(LogType.ERRR,'Automap is not enabled. Aborting()')
    return False


  @staticmethod
  def unmp_write(uc,access,addr,size,value,user_data):

    logger.console(LogType.WARN,'[!] Write Access Excpetion: cannot write value 0x%.8X at address 0x%.8X (reason: unmapped page)'%(value,addr))
    conf = user_data
    if conf.autoMap:
      base_addr = addr & ~(conf.p_size-1)
      uc.mem_map(base_addr,conf.p_size)
      uc.mem_write(base_addr,b'\xde\xad\xbe\xef'*(conf.p_size//4))
      logger.console(LogType.INFO,'[*] Automap: added page 0x%.8X'%base_addr)
      return True
    logger.console(LogType.ERRR,'Automap is not enabled. Aborting()')
    return False


  @staticmethod
  def hk_read(uc,access,addr,size,value,user_data):
    logger.console(LogType.INFO,'[*] Read access to addr 0x%.8X for size %d. Value: '%(addr,size),uc.mem_read(addr,size))



  @staticmethod
  def hk_write(uc,access,addr,size,value,user_data):
    logger.console(LogType.INFO,'[*] Write access to addr 0x%.8X fro size %d with value 0x%.8X'%(addr,size,value))




class ArmCorn(Emucorn): 

  def __init__(self,conf):

    self.conf = conf
    self.uc = Uc(UC_ARCH_ARM,UC_MODE_THUMB if conf.isThumb else UC_MODE_ARM) 
  
    stk_p = Emucorn.do_mapping(self.uc,self.conf)
    
    if conf.useCapstone:
      from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
#       self.cs=Cs(CS_ARCH_ARM, CS_MODE_THUMB if conf.isThumb else CS_MODE_ARM)
      self.cs=Cs(CS_ARCH_ARM, CS_MODE_ARM)
      self.cs.detail=True

    self.setup_regs(stk_p)

    for s_ea in conf.s_conf.nstubs.keys():
      self.add_nullstub(s_ea)
   
    if self.conf.s_conf.stub_pltgot_entries: 
      self.trappage_ba = consts_arm.TRAP_PAGE_BA
      Emucorn.do_required_mappng(self.uc,self.trappage_ba,self.trappage_ba+conf.p_size,self.conf.p_size, UC_PROT_ALL)
      self.patch_plt(stubs.Arm.libc_stubs)
      logger.console(LogType.INFO,'[%s] add stubbing trap page. plt/got now patched.'%'ArmCorn') 
    if self.conf.s_conf.use_user_stubs: 
      self.uc.mem_map(consts_arm.ALLOC_BA,conf.p_size*consts_arm.ALLOC_PAGES,UC_PROT_READ | UC_PROT_WRITE)
#       self.helper = stubs.Arm.UnicornHelper(self.uc,DumpAllocator(consts_arm.ALLOC_BA,consts_arm.ALLOC_PAGES*conf.p_size))
      self.helper = ArmSEAUnicorn(UnicornArmHelper(self.uc,DumpAllocator(consts_arm.ALLOC_BA,consts_arm.ALLOC_PAGES*conf.p_size)))
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
      
  def start(self,cnt=0): 
    try:
      self.uc.emu_start(self.conf.exec_saddr,self.conf.exec_eaddr,timeout=0,count=cnt)
    except Exception as e:
      logger.console(LogType.WARN,'[!] Exception in execution : %s' % e.__str__())

  def hook_code(self,uc,addr,size,user_data): 
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
        self.uc.mem_write(f.start_ea,stubs.Arm.libc_stubs[fname].insn_it)
        idx += 4 
      
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
       stubs.Arm.libc_stubs[index].do_it(helper)
     except Exception as e: 
       logger.console(LogType.ERRR,'[intr_handler] error in stubs code')
       raise e
     uc.reg_write(UC_ARM_REG_PC,lr)
     logger.console(LogType.INFO,'[intr_handler] exiting. Restauring PC to %08X'%uc.reg_read(UC_ARM_REG_PC))





class MipsCorn(Emucorn): 

  def __init__(self,conf):
    self.conf = conf 
    self.uc = Uc(UC_ARCH_MIPS,UC_MODE_MIPS32)  

    stk_p = Emucorn.do_mapping(self.uc,self.conf)

    if conf.useCapstone:
      from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32
#       self.cs=Cs(CS_ARCH_ARM, CS_MODE_THUMB if conf.isThumb else CS_MODE_ARM)
      self.cs=Cs(CS_ARCH_MIPS, CS_MODE_MIPS32)
      self.cs.detail=True

    self.setup_regs(stk_p)

    for s_ea in conf.s_conf.nstubs.keys():
      self.add_nullstub(s_ea)
      
     
       
    if self.conf.s_conf.stub_pltgot_entries: 
      self.trappage_ba = consts_arm.TRAP_PAGE_BA
      Emucorn.do_required_mappng(self.uc,self.trappage_ba,self.trappage_ba+conf.p_size, self.conf.p_size,UC_PROT_ALL)
      self.patch_plt(stubs.Arm.libc_stubs)
      logger.console(LogType.INFO,'[%s] add stubbing trap page. plt/got now patched.'%'MipsCorn') 
    if self.conf.s_conf.use_user_stubs: 
      self.uc.mem_map(consts_arm.ALLOC_BA,conf.p_size*consts_arm.ALLOC_PAGES,UC_PROT_READ | UC_PROT_WRITE)
      self.helper = stubs.Arm.UnicornHelper(self.uc,DumpAllocator(consts_arm.ALLOC_BA,consts_arm.ALLOC_PAGES*conf.p_size))
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
                self.hk_write,
                self.conf)
      self.uc.hook_add(UC_HOOK_MEM_READ,
                       self.hk_read,
                       self.conf)


  def setup_regs(self,stk_p):
    self.uc.reg_write(UC_MIPS_REG_AT, self.conf.registers.at)
    #arguments)
    self.uc.reg_write(UC_MIPS_REG_A0, self.conf.registers.a0)
    self.uc.reg_write(UC_MIPS_REG_A1, self.conf.registers.a1)
    self.uc.reg_write(UC_MIPS_REG_A2, self.conf.registers.a2)
    self.uc.reg_write(UC_MIPS_REG_A3, self.conf.registers.a3)
    # saved)
    self.uc.reg_write(UC_MIPS_REG_S0, self.conf.registers.s0)
    self.uc.reg_write(UC_MIPS_REG_S1, self.conf.registers.s1)
    self.uc.reg_write(UC_MIPS_REG_S2, self.conf.registers.s2)
    self.uc.reg_write(UC_MIPS_REG_S3, self.conf.registers.s3)
    self.uc.reg_write(UC_MIPS_REG_S4, self.conf.registers.s4)
    self.uc.reg_write(UC_MIPS_REG_S5, self.conf.registers.s5)
    self.uc.reg_write(UC_MIPS_REG_S6, self.conf.registers.s6)
    self.uc.reg_write(UC_MIPS_REG_S7, self.conf.registers.s7)
    # temporary)
    self.uc.reg_write(UC_MIPS_REG_T0, self.conf.registers.t0)
    self.uc.reg_write(UC_MIPS_REG_T1, self.conf.registers.t1)
    self.uc.reg_write(UC_MIPS_REG_T2, self.conf.registers.t2)
    self.uc.reg_write(UC_MIPS_REG_T3, self.conf.registers.t3)
    self.uc.reg_write(UC_MIPS_REG_T4, self.conf.registers.t4)
    self.uc.reg_write(UC_MIPS_REG_T5, self.conf.registers.t5)
    self.uc.reg_write(UC_MIPS_REG_T6, self.conf.registers.t6)
    self.uc.reg_write(UC_MIPS_REG_T7, self.conf.registers.t7)
    # division )
    self.uc.reg_write(UC_MIPS_REG_HI, self.conf.registers.hi)
    self.uc.reg_write(UC_MIPS_REG_LO, self.conf.registers.lo)
    # return values)
    self.uc.reg_write(UC_MIPS_REG_V0, self.conf.registers.v0)
    self.uc.reg_write(UC_MIPS_REG_V1, self.conf.registers.v1)
    # exec )
    self.uc.reg_write(UC_MIPS_REG_GP, self.conf.registers.gp)
    self.uc.reg_write(UC_MIPS_REG_FP, self.conf.registers.fp)
    if self.conf.registers.sp in range(self.conf.stk_ba,self.conf.stk_ba+stk_p*self.conf.p_size):
      self.uc.reg_write(UC_MIPS_REG_SP,self.conf.registers.sp)
    else:
      warn = '[%s] SP value does not belong to the stack'%'MipsCorn'
      warn += 'using default address : %8X'%(self.conf.stk_ba+stk_p*conf.p_size-4)
      logger.console(LogType.WARN,warn)
      self.uc.reg_write(UC_MIPS_REG_SP,self.conf.stk_ba+stk_p*self.conf.p_size-4)
    self.uc.reg_write(UC_MIPS_REG_RA, self.conf.registers.ra)
    # misc (kernel)
    self.uc.reg_write(UC_MIPS_REG_K0, self.conf.registers.k0)
    self.uc.reg_write(UC_MIPS_REG_K1, self.conf.registers.k1)

    


  @staticmethod
  def reg_convert(reg_id):
    if type(reg_id) == type(str()):
      return MipsCorn.str2reg(reg_id)
    elif type(reg_id) == type(int()):
      return MipsCorn.int2reg(reg_id)
    else:
      raise Exception('[reg_convert] unhandled conversion for type %s'%type(reg_id))

  @staticmethod
  def int2reg(reg_id):
    raise NotImplemented

  @staticmethod           
  def str2reg(r_str):

    if r_str == '0':
      return UC_MIPS_REG_0
    elif r_str == 'at':
      return UC_MIPS_REG_AT
    elif r_str == 'a0':
      return UC_MIPS_REG_A0  
    elif r_str == 'a1':
      return UC_MIPS_REG_A1 
    elif r_str == 'a2':
      return UC_MIPS_REG_A2
    elif r_str == 'a3':
      return UC_MIPS_REG_A3  
    elif r_str == 's0':
      return UC_MIPS_REG_S0  
    elif r_str == 's1':
      return UC_MIPS_REG_S1 
    elif r_str == 's2':
      return UC_MIPS_REG_S2
    elif r_str == 's3':
      return UC_MIPS_REG_S3  
    elif r_str == 's4':
      return UC_MIPS_REG_S4  
    elif r_str == 's5':
      return UC_MIPS_REG_S5 
    elif r_str == 's6':
      return UC_MIPS_REG_S6
    elif r_str == 's7':
      return UC_MIPS_REG_S7  
    elif r_str == 't0':
      return UC_MIPS_REG_T0  
    elif r_str == 't1':
      return UC_MIPS_REG_T1 
    elif r_str == 't2':
      return UC_MIPS_REG_T2
    elif r_str == 't3':
      return UC_MIPS_REG_T3  
    elif r_str == 't4':
      return UC_MIPS_REG_T4  
    elif r_str == 't5':
      return UC_MIPS_REG_T5 
    elif r_str == 't6':
      return UC_MIPS_REG_T6
    elif r_str == 't7':
      return UC_MIPS_REG_T7  
    elif r_str == 'v0':
      return UC_MIPS_REG_V0
    elif r_str == 'v1':
      return UC_MIPS_REG_V1
    elif r_str == 'k0':
      return UC_MIPS_REG_K0
    elif r_str == 'k1':
      return UC_MIPS_REG_K1
    elif r_str == 'hi':
      return UC_MIPS_REG_HI
    elif r_str == 'LO':
      return UC_MIPS_REG_LO
    elif r_str == 'ra':
      return UC_MIPS_REG_RA
    elif r_str == 'fp':
      return UC_MIPS_REG_FP
    elif r_str == 'gp':
      return UC_MIPS_REG_GP
    elif r_str == 'sp':
      return UC_MIPS_REG_SP
    elif r_str == 'pc':
      return UC_MIPS_REG_PC

  @staticmethod
  def intr_handler(uc,intno,user_data):
     """The UnicornArmRunner intr_handler overwrites the default handler
     """
     raise NotImplemented
    
  def start(self,cnt=0): 
    try:
      self.uc.emu_start(self.conf.exec_saddr,self.conf.exec_eaddr,timeout=0,count=cnt)
    except Exception as e:
      logger.console(LogType.WARN,'[!] Exception in execution : %s' % e.__str__())




  def hook_code(self,uc,addr,size,user_data): 
    insn = ida_ua.insn_t() 
    ida_ua.decode_insn(insn,self.uc.reg_read(UC_MIPS_REG_PC))    
    op_str = 'opcode: %X'%int.from_bytes(uc.mem_read(uc.reg_read(UC_MIPS_REG_PC),insn.size),'big',signed=False)
    logger.console(LogType.INFO,op_str)
    insn_str = ''
    if self.conf.useCapstone:
      try:
          insn=next(self.cs.disasm(uc.mem_read(uc.reg_read(UC_MIPS_REG_PC),insn.size),uc.reg_read(UC_MIPS_REG_PC),count=1))
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
    
    strout = '[PC=%.8X]'%uc.reg_read(UC_MIPS_REG_PC)+' '+insn_str
    
    logger.console(LogType.INFO,strout)
    if self.conf.showRegisters:
      self.print_registers()
    

  def print_registers(self):
    strout   = 'Registrs:\n' 
    strout  += '[at = %8X] [a1 = %8X] [a2 = %8X] [a3 = %8X] [a4 = %8X]\n'%(self.uc.reg_read(UC_MIPS_REG_AT),
                                                                        self.uc.reg_read(UC_MIPS_REG_A0),
                                                                        self.uc.reg_read(UC_MIPS_REG_A1),
                                                                        self.uc.reg_read(UC_MIPS_REG_A2),
                                                                        self.uc.reg_read(UC_MIPS_REG_A3))

    strout  += '[s0 = %8X] [s1 = %8X] [s2 = %8X] [s3 = %8X] [s4 = %8X]\n'%(self.uc.reg_read(UC_MIPS_REG_S0),
                                                                        self.uc.reg_read(UC_MIPS_REG_S1),
                                                                        self.uc.reg_read(UC_MIPS_REG_S2),
                                                                        self.uc.reg_read(UC_MIPS_REG_S3),
                                                                        self.uc.reg_read(UC_MIPS_REG_S4))

    strout  += '[s5 = %8X] [s6 = %8X] [s7 = %8X] [s8 = %8X] [hi = %8X]\n'%(self.uc.reg_read(UC_MIPS_REG_S5),
                                                                        self.uc.reg_read(UC_MIPS_REG_S6),
                                                                        self.uc.reg_read(UC_MIPS_REG_S7),
                                                                        self.uc.reg_read(UC_MIPS_REG_S8),
                                                                        self.uc.reg_read(UC_MIPS_REG_HI))

    strout  += '[t0 = %8X] [t1 = %8X] [t2 = %8X] [t3 = %8X] [lo = %8X]\n'%(self.uc.reg_read(UC_MIPS_REG_T0),
                                                                        self.uc.reg_read(UC_MIPS_REG_T1),
                                                                        self.uc.reg_read(UC_MIPS_REG_T2),
                                                                        self.uc.reg_read(UC_MIPS_REG_T3),
                                                                        self.uc.reg_read(UC_MIPS_REG_LO))

    strout  += '[t4 = %8X] [t5 = %8X] [t6 = %8X] [t7 = %8X] [t8 = %8X]\n'%(self.uc.reg_read(UC_MIPS_REG_T4),
                                                                        self.uc.reg_read(UC_MIPS_REG_T5),
                                                                        self.uc.reg_read(UC_MIPS_REG_T6),
                                                                        self.uc.reg_read(UC_MIPS_REG_T7),
                                                                        self.uc.reg_read(UC_MIPS_REG_T8))

    strout  += '[v0 = %8X] [v1 = %8X] [k0 = %8X] [k1 = %8X] [ra = %8X]\n'%(self.uc.reg_read(UC_MIPS_REG_V0),
                                                                        self.uc.reg_read(UC_MIPS_REG_V1),
                                                                        self.uc.reg_read(UC_MIPS_REG_K0),
                                                                        self.uc.reg_read(UC_MIPS_REG_K1),
                                                                        self.uc.reg_read(UC_MIPS_REG_RA))

    strout  += '[gp = %8X] [fp = %8X] [sp = %8X]\n'%(self.uc.reg_read(UC_MIPS_REG_GP),
                                                                        self.uc.reg_read(UC_MIPS_REG_FP),
                                                                        self.uc.reg_read(UC_MIPS_REG_SP))
    logger.console(LogType.INFO,strout)




if __name__ == '__main__':

  conf=                    Configuration(p_size=0x400,
                           stk_ba=0x80040000,
                           stk_size=0x1000,
                           autoMap=True,
                           showRegisters=True,
                           exec_saddr=0x8001A2A4,
                           exec_eaddr=0x8001A2C4,
                           mapping_saddr=0x8001A2A4,
                           mapping_eaddr=0x8001B000,
                           segms=[],
                           map_with_segs=False,
                           use_seg_perms=True,
                           isThumb=False,
                           useCapstone=True,
                           registers=MipslRegisters(at=0,a0=0,a1=0,a2=0,a3=0,s0=0,s1=0,s2=0,s3=0,s4=0,s5=0,s6=0,s7=0,k0=0,k1=0,
                                                    t0=0,t1=0,t2=0,t3=0,t4=0,t5=0,t6=0,t7=0,v0=0,v1=0,hi=0,lo=0,sp=0,fp=0,gp=0,ra=0),
                           showMemAccess=True,
                           s_conf=StubConfiguration({},False,False),
                           amap_conf=AdditionnalMapping({}))

  emu = MipsCorn(conf)
  

  emu.start()
