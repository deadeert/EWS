import ida_segment
import ida_ua
import ida_idaapi
import ida_funcs
import ida_bytes
import ida_segregs
import ida_idp 
import ida_name

from unicorn import * 
from unicorn.arm_const import * 

import string
import consts_arm
from utils import Emu
from utils import logger
from utils import LogType
from stubs.allocator import *
import stubs.Arm


class Emucorn(Emu): # TODO Rename EmucornARM

  def __init__(self,conf):

    self.conf = conf
    self.uc = Uc(UC_ARCH_ARM,UC_MODE_THUMB if conf.isThumb else UC_MODE_ARM) 

    if conf.map_with_segs:
      for seg in conf.segms:
#         nb_pages = ((seg.end_ea - seg.start_ea) // conf.p_size) + 1
#         vbase=seg.start_ea&~(conf.p_size-1) 
#         self.uc.mem_map(vbase,nb_pages*conf.p_size,UC_PROT_ALL if not self.conf.use_seg_perms else seg.perm)
        vbase = self.do_required_mappng(seg.start_ea, seg.end_ea,UC_PROT_ALL if not self.conf.use_seg_perms else seg.perm) 
        self.uc.mem_write(seg.start_ea,ida_bytes.get_bytes(seg.start_ea,seg.end_ea-seg.start_ea))
        logger.console(LogType.INFO,'[%s] Mapping seg %s\n'%('Emucorn',ida_segment.get_segm_name(seg)))
    else:
        nb_pages = ((conf.mapping_eaddr - conf.mapping_saddr) // conf.p_size) + 1
        vbase=conf.mapping_saddr&~(conf.p_size-1) 
        self.uc.mem_map(vbase,nb_pages*conf.p_size,UC_PROT_ALL)
        self.uc.mem_write(conf.mapping_saddr,ida_bytes.get_bytes(self.conf.mapping_saddr,self.conf.mapping_eaddr-self.conf.mapping_saddr))
        logger.console(LogType.INFO,'[%s] Mapping memory\n\tvbase : 0x%.8X\n\tcode size: 0x%.8X\n\tpage:  %d'%('Emucorn',
                                                                                                    vbase,
                                                                                                    conf.mapping_eaddr-conf.mapping_saddr,
                                                                                                    nb_pages))
      
    stk_p,r = divmod(conf.stk_size,conf.p_size)
    if r: stk_p+=1 
    self.uc.mem_map(conf.stk_ba,stk_p*conf.p_size)
    self.uc.reg_write(UC_ARM_REG_SP,conf.stk_ba+conf.stk_size)
    logger.console(LogType.INFO,' [%s] mapped stack at 0x%.8X '%('Emucorn',conf.stk_ba))

    if conf.useCapstone:
      from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
#       self.cs=Cs(CS_ARCH_ARM, CS_MODE_THUMB if conf.isThumb else CS_MODE_ARM)
      self.cs=Cs(CS_ARCH_ARM, CS_MODE_ARM)
      self.cs.detail=True

    for s_ea in conf.s_conf.nstubs.keys():
      self.add_nullstub(s_ea)
      
    for m_ea in conf.amap_conf.mappings.keys():
      self.do_required_mappng(m_ea,m_ea+len(self.conf.amap_conf.mappings[m_ea]),UC_PROT_ALL)
      self.uc.mem_write(m_ea,self.conf.amap_conf.mappings[m_ea]) 
      logger.console(LogType.INFO,'[%s] Additionnal mapping for data at %8X'%('Emucorn',m_ea)) 

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
    if conf.registers.R13 in range(conf.stk_ba,conf.stk_ba+stk_p*conf.p_size):
      self.uc.reg_write(UC_ARM_REG_R13,self.conf.registers.R13)
    else:
      warn = '[%s] SP value does not belong to the stack'%'Emucorn'
      warn += 'using default address : %8X'%(conf.stk_ba+stk_p*conf.p_size-4)
      logger.console(LogType.WARN,warn)
      self.uc.reg_write(UC_ARM_REG_R13,conf.stk_ba+stk_p*conf.p_size-4)
    self.uc.reg_write(UC_ARM_REG_R14,self.conf.registers.R14)

   
    if self.conf.s_conf.stub_pltgot_entries: 
      self.trappage_ba = consts_arm.TRAP_PAGE_BA
      self.do_required_mappng(self.trappage_ba,self.trappage_ba+conf.p_size, UC_PROT_ALL)
      self.patch_plt(stubs.Arm.libc_stubs)
      logger.console(LogType.INFO,'[%s] add stubbing trap page. plt/got now patched.'%'Emucorn') 
    if self.conf.s_conf.use_user_stubs: 
      self.uc.mem_map(consts_arm.ALLOC_BA,conf.p_size*consts_arm.ALLOC_PAGES,UC_PROT_READ | UC_PROT_WRITE)
      self.helper = stubs.Arm.UnicornHelper(self.uc,DumpAllocator(consts_arm.ALLOC_BA,consts_arm.ALLOC_PAGES*conf.p_size))
      logger.console(LogType.INFO,'[%s] fake allocator ready to use.'%'Emucorn')
    if self.conf.s_conf.stub_pltgot_entries:
        self.uc.hook_add(UC_HOOK_INTR,
                    self.intr_handler, 
                    user_data=self.helper)
    self.uc.hook_add(UC_HOOK_CODE,
                     self.hook_code,
                     user_data=self.conf)
        
    self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED,
                     self.unmp_read,
                     user_data=self.conf)

    self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED,
                     self.unmp_write,
                     user_data=self.conf)

    if self.conf.showMemAccess:
      self.uc.hook_add(UC_HOOK_MEM_WRITE,
                self.hk_write,
                self.conf)
      self.uc.hook_add(UC_HOOK_MEM_READ,
                       self.hk_read,
                       self.conf)




      #TODO 
      #f <- all functions
      #if f.name belongs stubs_list 
      #patch f.start 

  @staticmethod
  def reg_convert(reg_id):
    if type(reg_id) == type(str()):
      return Emucorn.str2reg(reg_id)
    elif type(reg_id) == type(int()):
      return Emucorn.int2reg(reg_id)
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
    print('opcode',uc.mem_read(uc.reg_read(UC_ARM_REG_PC),4))
    if self.conf.useCapstone:
      try:
        insn=next(self.cs.disasm(uc.mem_read(uc.reg_read(UC_ARM_REG_PC),4),uc.reg_read(UC_ARM_REG_PC),count=1))
        insn_str="0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str)
      except StopIteration:
        pass
    else:  
      try: 
        insn = ida_ua.insn_t() 
        ida_ua.decode_insn(insn,self.uc.reg_read(UC_ARM_REG_PC))
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
    strout =  '[R0=%.8X] [R1=%.8X] [R2=%.8X] [R3=%.8X]'%(self.uc.reg_read(UC_ARM_REG_R0),
                                                         self.uc.reg_read(UC_ARM_REG_R1),
                                                         self.uc.reg_read(UC_ARM_REG_R2),
                                                         self.uc.reg_read(UC_ARM_REG_R3))
    strout += '[R4=%.8X] [R5=%.8X] [R6=%.8X] [R7=%.8X]'%(self.uc.reg_read(UC_ARM_REG_R4),
                                                         self.uc.reg_read(UC_ARM_REG_R5),
                                                         self.uc.reg_read(UC_ARM_REG_R6),
                                                         self.uc.reg_read(UC_ARM_REG_R7))+'\n'
    strout += '[R8=%.8X] [R9=%.8X] [R10=%.8X] [R11=%.8X]'%(self.uc.reg_read(UC_ARM_REG_R8),
                                                           self.uc.reg_read(UC_ARM_REG_R9),
                                                           self.uc.reg_read(UC_ARM_REG_R10),
                                                           self.uc.reg_read(UC_ARM_REG_R11))
    strout += '[R12=%.8X] [R13=%.8X] [R14=%.8X] [PC=%.8X'%(self.uc.reg_read(UC_ARM_REG_R12),
                                                           self.uc.reg_read(UC_ARM_REG_R13),
                                                           self.uc.reg_read(UC_ARM_REG_R14),
                                                           self.uc.reg_read(UC_ARM_REG_R15))
    logger.console(LogType.INFO,strout)




  def mem_read(self,addr,size):
    self.uc.mem_read(addr,size)

  def mem_write(self,addr,data):
    self.uc.mem_write(addr,data)

  def reg_read(self,r_id):
    if isinstance(r_id,int):
      self.uc.reg_read(r_id)
    elif isinstance(r_id,str):
      self.uc.reg_read(self.str2reg(r_id))

  def reg_write(self,r_id,value):
    if isinstance(r_id,int):
      self.uc.reg_write(r_id,value)
    elif isinstance(r_id,str):
      self.uc.reg_write(self.str2reg(r_id),value)
    
  
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
#         self.uc.mem_write(self.trappage_ba+4*idx,stubs.Arm.libc_stubs[fname].insn_it)
#         self.uc.mem_write(f.start_ea,int.to_bytes(self.trappage_ba+4*idx,4,'little'))
        self.uc.mem_write(f.start_ea,stubs.Arm.libc_stubs[fname].insn_it)
        idx += 4 
      
      f = ida_funcs.get_next_func(f.start_ea)



  def do_required_mappng(self,s_ea,e_ea,perms):
    """ Use this function to avoid page mappings
        that already exist. 
        Usefull when mapping user provided ranges,
        or for small sections that will share pages.  
    """ 
    b_page = s_ea & ~(self.conf.p_size -1)
    while b_page < e_ea:  
      alrdy_map = False
      for rsta,rsto,rpriv in self.uc.mem_regions():
        if b_page == rsta:
          alrdy_map = True
          break
      if not alrdy_map: 
        logger.console(LogType.INFO,'[%s] map page %8X'%('Emucorn',b_page))
        self.uc.mem_map(b_page,self.conf.p_size,perms)
      b_page += self.conf.p_size
   
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


  @staticmethod
  def unmp_read(uc,access,addr,value,size,user_data):
    logger.console(LogType.WARN,'[!] Read Access Exception: cannot read 0x%.8X for size %d (reason: unmapped page)'%(addr,size))
    conf = user_data
    if conf.autoMap:
      base_addr = addr & ~(conf.p_size-1)
      uc.mem_map(base_addr,conf.p_size)
      uc.mem_write(base_addr,b'\xff'*conf.p_size)
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
      return True
    logger.console(LogType.ERRR,'Automap is not enabled. Aborting()')
    return False


  @staticmethod
  def hk_read(uc,access,addr,size,value,user_data):
    logger.console(LogType.INFO,'[*] Read access to addr 0x%.8X for size %d. Value: '%(addr,size),uc.mem_read(addr,size))



  @staticmethod
  def hk_write(uc,access,addr,size,value,user_data):
    logger.console(LogType.INFO,'[*] Write access to addr 0x%.8X fro size %d with value 0x%.8X'%(addr,size,value))




