import ida_segregs
from emu.unicorn.generic import * 
import string
import consts_x86
from utils import * 
from stubs.allocator import *
import ida_loader
# import stubs.Arm
import stubs.Stubs
#import stubs.PE
# from stubs.unicstub import UnicornArmSEA
from stubs.unicstub import UnicornX86SEA
import struct
from unicorn.x86_const import * 







class x86Corn(Emucorn): 

  def __init__(self,conf):

    super().__init__(conf) 

    self.uc = Uc(UC_ARCH_X86,UC_MODE_32)
    
    if self.conf.p_size != self.uc.query(UC_QUERY_PAGE_SIZE):
      logger.console(LogType.WARN,' invalid page size, using default')
      self.conf.p_size = self.uc.query(UC_QUERY_PAGE_SIZE)

    stk_p = Emucorn.do_mapping(self.uc,self.conf)
    
    if conf.useCapstone:
      from capstone import Cs, CS_ARCH_X86, CS_MODE_32
      self.cs=Cs(CS_ARCH_X86, CS_MODE_32)
       
    # Setup regs 
    self.setup_regs(stk_p)
    self.pcid = UC_X86_REG_EIP 
  

    self.breakpoints = dict()
    self.custom_stubs = dict()


    for s_ea in conf.s_conf.nstubs.keys():
      self.add_null_stub(s_ea)
   
    # Init stubs engine 
    if self.conf.s_conf.use_user_stubs or self.conf.s_conf.use_user_stubs: 
      self.uc.mem_map(consts_x86.ALLOC_BA,conf.p_size*consts_x86.ALLOC_PAGES,UC_PROT_READ | UC_PROT_WRITE)

      self.helper = UnicornX86SEA(uc=self.uc,
                                  allocator=DumpAllocator(consts_x86.ALLOC_BA,consts_x86.ALLOC_PAGES*conf.p_size),
                                  wsize=4)
      self.nstub_obj = stubs.Stubs.NullStub('x86')
      self.nstub_obj.set_helper(self.helper) 
 


    filetype = ida_loader.get_file_type_name()
    if self.conf.s_conf.stub_pltgot_entries:
      if '(PE)' in filetype:
        #Load PE stubs here
        pass
      elif 'ELF' in filetype:
        #Load ELF stubs here 
        pass
      else:
        logger.console(LogType.WARN,'unsupported file type (%s) for stubs'%filetype) 

  
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

    # Segment register might be instancied manually using console
    self.uc.reg_write(UC_X86_REG_EAX,self.conf.registers.EAX)
    self.uc.reg_write(UC_X86_REG_EBX,self.conf.registers.EBX)
    self.uc.reg_write(UC_X86_REG_ECX,self.conf.registers.ECX)
    self.uc.reg_write(UC_X86_REG_EDX,self.conf.registers.EDX)
    self.uc.reg_write(UC_X86_REG_EDI,self.conf.registers.EDI)
    self.uc.reg_write(UC_X86_REG_ESI,self.conf.registers.ESI)
    self.uc.reg_write(UC_X86_REG_ESP,self.conf.registers.ESP)
    self.uc.reg_write(UC_X86_REG_EBP,self.conf.registers.EBP)
    
    
  def print_registers(self):
    strout  = 'Registers:\n'
    strout +=  '[EAX=%.8X] [EBX=%.8X] [ECX=%.8X] [EDX=%.8X]\n'%(self.uc.reg_read(UC_X86_REG_EAX),
                                                         self.uc.reg_read(UC_X86_REG_EBX),
                                                         self.uc.reg_read(UC_X86_REG_ECX),
                                                         self.uc.reg_read(UC_X86_REG_EDX))
    strout += '[EDI=%.8X] [ESI=%.8X] [EBP=%.8X] [ESP=%.8X]\n'%(self.uc.reg_read(UC_X86_REG_EDI),
                                                         self.uc.reg_read(UC_X86_REG_ESI),
                                                         self.uc.reg_read(UC_X86_REG_EBP),
                                                         self.uc.reg_read(UC_X86_REG_ESP))
    logger.console(LogType.INFO,strout)

  
    

  def stubs_PE(self,stubs_l):
 

    s = ida_segment.get_segm_by_name('.idata')
    if s == None:
        print('[!] .idata section not found, stubs mechanism not compatible with such binary')
        return
    cur_ea = s.start_ea
    while cur_ea < s.end_ea:
      name = ida_name.get_name(cur_ea)
      if name in stub_l.keys():
        xref_g = idautils.XrefsTo(cur_ea)
        stubs_l.set_helper(self.helper)
        try:
          while True:
            xref = next(xref_g)
            ida_ua.decode_insn(insn,xref.frm)
            if ida_idp.is_call_insn(insn): 
              # add breakpoint
              self.breakpoints[xref.frm] = name   
              # patch reference 
              for x in range(0,insn.size):
                self.uc.mem_write(xref.frm+x,struct.pack('B',consts_x86.nop))
            logger.console(LogType.INFO,'[+] %s is not stubbed at %x',name,xref.frm)
        except StopIteration:
          pass
      cur_ea += 4


