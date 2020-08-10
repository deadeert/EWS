import ida_segment
import ida_ua
import ida_idaapi
import ida_funcs
import ida_bytes
import ida_segregs
import ida_idp 
import ida_name
import ida_segment
import os
import string
from unicorn import * 
from unicorn.arm_const import * 
from unicorn.mips_const import * 
 

from utils import *
from emu.emubase import Emulator


class Emucorn(Emulator):

  def __init__(self,conf):
    super().__init__(conf)

#   def start(self):
#     pass
# 
#   def add_mapping(self,pages):
#     pass
  
#   @staticmethod
#   def reg_convert(r_id): 
#     """ match int r_id to corresponding register values in emulator solution. 
#         usefull for Stubs abstraction mechanism
#     """ 
#     pass
# 
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
        if not Emulator.check_mapping(conf):
          raise ConfigExcption('Invalid mapping for code section') 
        vbase=conf.mapping_saddr&~(conf.p_size-1) 
        nb_pages = ((conf.mapping_eaddr - vbase) // conf.p_size) + 1
        uc.mem_map(vbase,nb_pages*conf.p_size)
        uc.mem_write(conf.mapping_saddr,ida_bytes.get_bytes(conf.mapping_saddr,conf.mapping_eaddr-conf.mapping_saddr))
        logger.console(LogType.INFO,'[%s] Mapping memory\n\tvbase : 0x%.8X\n\tcode size: 0x%.8X\n\tpage:  %d'%('EmuCorn',
                                                                                                    vbase,
                                                                                                    conf.mapping_eaddr-conf.mapping_saddr,
                                                                                                    nb_pages))
    # Map user provided areas 
    for m_ea,content in conf.amap_conf.mappings.items():
      Emucorn.do_required_mappng(uc,m_ea,m_ea+len(content),conf.p_size,UC_PROT_ALL)
      uc.mem_write(m_ea,content) 
      logger.console(LogType.INFO,'[%s] Additionnal mapping for data at %8X'%('Emucorn',m_ea)) 

    stk_p,r = divmod(conf.stk_size,conf.p_size)
    if r: stk_p+=1 
    uc.mem_map(conf.stk_ba,stk_p*conf.p_size)
    logger.console(LogType.INFO,' [%s] mapped stack at 0x%.8X '%('Emucorn',conf.stk_ba))
  
    return stk_p 

  def start(self,cnt=0,saddr=None): 
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
      uc.mem_write(base_addr,b'\xff'*conf.p_size)
      logger.console(LogType.INFO,'[*] Automap: added page 0x%.8X'%base_addr)
      return True
    logger.console(LogType.ERRR,'Automap is not enabled. Aborting()')
    return False


  def display_page(self,p_base,size=None):
    if not size:
      size = self.conf.p_size 
    mem=self.uc.mem_read(p_base,size)
    display_mem(mem) 

  def display_range(self,start_ea,end_ea):
    mem=self.uc.mem_read(start_ea,end_ea-start_ea)  
    display_mem(mem)
   



  @staticmethod
  def unmp_write(uc,access,addr,size,value,user_data):

    logger.console(LogType.WARN,'[!] Write Access Excpetion: cannot write value 0x%.8X at address 0x%.8X (reason: unmapped page)'%(value,addr))
    conf = user_data
    if conf.autoMap:
      base_addr = addr & ~(conf.p_size-1)
      try:
        uc.mem_map(base_addr,conf.p_size)
      except UcError:
        logger.console(LogType.WARN,'[*] Automap not supported for this arch')
        return False  
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


  def display_stack(self,size=None):
    sp = self.helper.get_sp()
    used = (self.conf.stk_ba + self.conf.stk_size) - sp
    logger.console(LogType.INFO,'sp = %x used = %d'%(sp,used))
    if not size:
      mem=self.uc.mem_read(sp,used)
    else:
      if not size > used:
        mem=self.uc.mem_read(sp,size)
      else: 
        logger.console(LogType.WARN,'display size is to big, truncating')
        mem=self.uc.mem_read(sp,used)
    display_mem(mem,ba=sp)

    
      
  def step_n(self,n):
    if self.helper.get_pc() in self.user_breakpoints:
      insn = get_insn_at(self.helper.get_pc())
      self.start(cnt=n,saddr=self.helper.get_pc()+insn.size)
    else: 
      self.start(cnt=n,saddr=self.helper.get_pc())
    logger.console(LogType.INFO,'[+] exectution stopped at 0x%x'%self.helper.get_pc())
    
    
  def step_in(self):
    self.step_n(1)

  def continuee(self):
    self.step_n(0)

  def step_over(self):
    # TODO could be used directly in emubase class 
   
    insn = get_insn_at(self.helper.get_pc()) 
    if ida_idp.is_call_insn(insn): 
      self.add_breakpoint(insn.ea+insn.size)
    # dirty way to assess conditionnal jump, is_conditionnal_jmp would have been appreciated  
    elif ida_idp.has_insn_feature(insn.itype,ida_idp.CF_USE1):
      if idc.get_operand_type(insn.ea,0) == ida_ua.o_near: 
        logger.console(LogType.INFO,'Conditionnal jump detected')
        self.add_breakpoint(insn.ea+insn.size)
        self.add_breakpoint(idc.get_operand_value(insn.ea,0))
    # CF_STOP insn (jump,br,...), indirect jump or simply other insn that does not have cref
    else:
      logger.console(LogType.WARN,'Could not step_over this kind of insn')
    self.continuee()
    


  def restart(self,conf=None,cnt=0):
    # unmap & remap 
    for rsta,rsto,rpriv in self.uc.mem_regions():
      self.uc.mem_unmap(rsta,rsto-rsta+1)
    stk_p = Emucorn.do_mapping(self.uc,self.conf)

    self.reset_regs() 
    self.setup_regs(stk_p)
    
    self.helper.allocator.reset()
    
    logger.console(LogType.INFO,'Restart done. You can start exec (emu.start()/emu.step_{in,...))')

   

  def add_mapping(self,addr,mem):
    """ TODO: handle protection
    """
    for rsta,rsto,rpriv in self.uc.mem_regions():
      if addr in range(rsta,rsto):
        logger.console(LogType.WARN,'0x%x is already map, please use another addr or change mapping using emu.helper.mem_write()'%addr)
        return 
     
    Emucorn.do_required_mappng(self.uc,addr,addr+len(mem),self.conf.p_size,UC_PROT_ALL)
    self.uc.mem_write(addr,mem) 
    logger.console(LogType.INFO,'[%s] Additionnal mapping for data at 0x%x'%('Emucorn',addr)) 


  def hook_code(self,uc,addr,size,user_data): 

    if addr in self.breakpoints.keys():
      try:
        self.stubs[self.breakpoints[addr]].do_it()
#         stubs.Stubs.libc_stubs_arm[self.breakpoints[addr]].do_it()
      except Exception as e:
        logger.console(LogType.WARN,'Error in stub, aborting')
        uc.emu_stop()
        raise e
    elif addr in self.custom_stubs.keys():
      self.custom_stubs[addr]() 
    elif addr in self.user_breakpoints: 
      uc.emu_stop() 
      logger.console(LogType.INFO,'Breakpoint at %x reached.\nType emu.continuee() to pursue execution'%addr)

    self.color_map[addr] = get_insn_color(addr) 
    insn = ida_ua.insn_t() 
    ida_ua.decode_insn(insn,self.uc.reg_read(self.pcid))
    op_str = 'opcode : %X'%int.from_bytes(uc.mem_read(uc.reg_read(self.pcid),insn.size),'big',signed=False)
    logger.console(LogType.INFO,op_str)
    insn_str = ''
    if self.conf.useCapstone:
      try:
        insn=next(self.cs.disasm(uc.mem_read(uc.reg_read(self.pcid),insn.size),uc.reg_read(self.pcid),count=1))
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
    
    strout = '[PC=%.8X]'%uc.reg_read(self.pcid)+' '+insn_str
    
    logger.console(LogType.INFO,strout)
    if self.conf.showRegisters:
      self.print_registers()
      logger.console(LogType.INFO,str(self.get_alu_info()))
    


