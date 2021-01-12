import ida_segregs
from emu.unicorn.generic import * 
import string
from utils.utils import * 
from utils import consts_x86
from stubs.ELF.allocator import *
import ida_loader
import idc
import ida_ua
import ida_funcs
import idautils
from stubs.emu.unicorn.sea import UnicornX86SEA
import struct
from unicorn.x86_const import * 
from keystone import * 








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

    self.ks = Ks(KS_ARCH_X86,KS_MODE_32) 

    self.ida_jmp_itype = consts_x86.ida_jmp_itype 
    self.offset_name_size = 4 
       
    # Setup regs 
    self.setup_regs(stk_p)
    self.pcid = UC_X86_REG_EIP 
  

#     self.custom_stubs = dict()


    for s_ea in conf.s_conf.nstubs.keys():
      self.add_null_stub(s_ea)
   
    # Init stubs engine 
    if self.conf.s_conf.stub_dynamic_func_tab:
      self.uc.mem_map(consts_x86.ALLOC_BA,conf.p_size*consts_x86.ALLOC_PAGES,UC_PROT_READ | UC_PROT_WRITE)

      self.helper = UnicornX86SEA(uc=self.uc,
                                  allocator=DumpAllocator(consts_x86.ALLOC_BA,consts_x86.ALLOC_PAGES*conf.p_size),
                                  wsize=4)
      
 


    self.filetype = ida_loader.get_file_type_name()
    if self.conf.s_conf.stub_dynamic_func_tab:
      if '(PE)' in self.filetype:
        from stubs import PE 
        self.stubs = PE.winx86_stubs
        self.nstub_obj = PE.NullStub('x86') 
        self.loader_type = LoaderType.PE
        self.nstub_obj.set_helper(self.helper)
      elif 'ELF' in self.filetype: 
        from Stubs.ELF import ELF
        self.stubs = ELF.libc_stubs_arm 
        self.nstub_obj = ELF.NullStub('x86')
        self.loader_type = LoaderType.ELF 
        self.nstub_obj.set_helper(self.helper)


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
    
  def reset_regs(self):

    self.uc.reg_write(UC_X86_REG_EAX,0)
    self.uc.reg_write(UC_X86_REG_EBX,0)
    self.uc.reg_write(UC_X86_REG_ECX,0)
    self.uc.reg_write(UC_X86_REG_EDX,0)
    self.uc.reg_write(UC_X86_REG_EDI,0)
    self.uc.reg_write(UC_X86_REG_ESI,0)
    self.uc.reg_write(UC_X86_REG_ESP,0)
    self.uc.reg_write(UC_X86_REG_EBP,0)
    self.uc.reg_write(UC_X86_REG_EIP,0)
   

  @staticmethod
  def reg_convert(r_id):
    if r_id.lower() == 'eax':
      return UC_X86_REG_EAX 
    elif r_id.lower() == 'ebx':
      return UC_X86_REG_EBX 
    elif r_id.lower() == 'ecx':
      return UC_X86_REG_ECX 
    elif r_id.lower() == 'edx':
      return UC_X86_REG_EDX 
    elif r_id.lower() == 'edi':
      return UC_X86_REG_EDI
    elif r_id.lower() == 'esi':
      return UC_X86_REG_ESI
    elif r_id.lower() == 'esp':
      return UC_X86_REG_ESP
    elif r_id.lower() == 'ebp':
      return UC_X86_REG_EBP
    elif r_id.lower() == 'eip':
      return UC_X86_REG_EIP
    

    
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

  
    
  def repatch(self):
    if not self.conf.stub_pltgot_entries:
      return 
    if '(PE)' in self.filetype:
        self.stub_PE(self.stubs)
    else:
        self.stub_ELF(self.stubs)
        

  @staticmethod
  def nop_insn(uc,insn):
    for of in range(0,insn.size):
      uc.mem_write(insn.ea+of,struct.pack('B',consts_x86.nop))
    


#   def stub_PE(self,stubs_l):
#  
#     s = ida_segment.get_segm_by_name('.idata')
#     if s == None:
#         print('[!] .idata section not found, stubs mechanism not compatible with such binary')
#         return
#     cur_ea = s.start_ea
#     while cur_ea < s.end_ea:
#       name = ida_name.get_name(cur_ea)
#       if name in stubs_l.keys():
#         xref_g = idautils.XrefsTo(cur_ea)
#         stubs_l[name].set_helper(self.helper)
#         try:
#           while True:
#             xref = next(xref_g)
#             insn = get_insn_at(xref.frm)
#             if ida_idp.is_call_insn(insn): 
#               self.breakpoints[xref.frm] = name   
#               x86Corn.nop_insn(self.uc,insn)
#               logger.console(LogType.INFO,'%s is now stubbed at %x'%(name,insn.ea))
#             elif insn.itype in consts_x86.ida_jmp_itype:
#               xref_jmp_g = idautils.XrefsTo(xref.frm) 
#               try: 
#                while True:
#                 xref_jmp = next(xref_jmp_g)
#                 insn_xrf_jmp = get_insn_at(xref_jmp.frm)
#                 if ida_idp.is_call_insn(insn_xrf_jmp):
#                   self.breakpoints[xref_jmp.frm] = name 
#                   x86Corn.nop_insn(self.uc,insn_xrf_jmp)
#                   logger.console(LogType.INFO,'%s is now stubbed at %x'%(name,insn_xrf_jmp.ea))
#                 else:
#                   logger.console(LogType.WARN,'To many indirection to stub function %s'%name)
#               except StopIteration:
#                 pass
#         except StopIteration:
#           pass
#       cur_ea += 4
# 

  def stub_ELF(self,stubs_l):
    # TODO
    
    pass

  @staticmethod
  def tail_retn(ea):
    """ returns operand of retn <op>
    """

    f = ida_funcs.get_func(ea)
    insn = get_insn_at(f.end_ea)# somehow end_ea does not point to the last insn...
    print('%x'%f.end_ea)
    if insn.itype == consts_x86.ida_retn_itype: # or use ida_idp.is_ret_insn...
      print('found directly retn')
      if not len(insn.__get_ops__()) > 0:
        return 0 
      else:
        return idc.get_operand_value(insn.ea,0)
    # in case, last insn of the funcs is not a retn X, we need
    # to decode insn one by one until find the "good one" 
    else:
      ea = f.start_ea 
      while ea < f.end_ea:
         insn = get_insn_at(ea)
         if insn.itype == consts_x86.ida_retn_itype:  
          if idc.get_operand_type(ea,0) == idc.o_void:  
            return idc.o_void 
          else:
            return idc.get_operand_value(insn.ea,0)
         ea += insn.size
          
    return -1 
   
    


  def get_retn_insn(self,ea):
    f = ida_funcs.get_func(ea)
    n = x86Corn.tail_retn(f.start_ea)
    if n > 0: 
      try: retn = self.ks.asm('ret %d'%n,as_bytes=True)[0]
      except: logger.console(LogType.WARN,'could not compile retn insn'); return -1
    elif n == 0: 
      retn = struct.pack('B',consts_x86.ret)

    return retn


  def get_new_stub(self,stub_func):
    if 'ELF' in self.filetype:
      stub = ELF.Stub(self.helper)
      stub.do_it = stub_func
    elif 'PE' in self.filetype:
      stub = PE.Stub(self.helper)
      stub.do_it = stub_func
    return stub



#   def add_null_stub(self,ea,fname=None):
#     """ TODO can be factorised with add_custom_stub
#         with func=None
#     """
#     if not fname:
#       try:    fname = ida_funcs.get_func_name(ea)
#       except: fname = 'func_%x'%ea
#  
#     f = ida_funcs.get_func(ea)
#     if f == None:
#       logger.console(LogType.WARN,'Could not patch ea %x, please create function before'%ea)
#       return
#     if f.start_ea != ea: 
#       logger.console(LogType.WARN,'%x is not function beginning, using %x instead'%(ea,f.start_ea))
#     if fname in self.stubs.keys():
#       logger.console(LogType.WARN,'[!] %s belongs to libc stub. It is now null stubbed'%fname)
#       self.stubs[fname] = self.nstub_obj 
#     # patch @ with retn and lets the call insn 
#     else:
#       n = x86Corn.tail_retn(f.start_ea)
#       if n > 0: 
#         try: retn = self.ks.asm('ret %d'%n,as_bytes=True)[0]
#         except: logger.console(LogType.WARN,'Could not add null stub, keystone error'); return -1
#       elif n == 0: 
#         retn = struct.pack('B',consts_x86.ret)
#       else:
#         logger.console(LogType.WARN,'could not add null stub, tail insn not found or incompatible')
#         return 
#       self.uc.mem_write(f.start_ea,retn)
#       self.custom_stubs[ea] = self.nstub_obj.do_it
# 
#       logger.console(LogType.INFO,'[%x] [%s] is null stubbed'%(f.start_ea,fname))
# 
#     self.conf.add_null_stub(ea)
# 
#   def remove_null_stub(self,ea,fname=None):
#   
#     if not fname:
#       try:    fname = ida_funcs.get_func_name(ea)
#       except: fname = 'func_%x'%ea
# 
#     if fname in self.stubs.keys():
#       # Needs to reinit the stub
#       logger.console(LogType.WARN,'Changes will be effective only after save and reloading the conf')
#     else:
#       # Restore from IDB
#       self.uc.mem_write(ea,ida_bytes.get_bytes(ea,3))
#       del self.custom_stubs[ea]
# 


  def get_alu_info(self):
    
    return x86EFLAGS.create(self.uc.reg_read(UC_X86_REG_EFLAGS))


