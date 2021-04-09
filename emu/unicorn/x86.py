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
from stubs.ELF import ELF
from stubs import PE


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
    self.pointer_size = 4 
       
    # Setup regs 
    self.setup_regs(stk_p)
    self.pcid = UC_X86_REG_EIP 
  
        # Init stubs engine 
    if self.conf.s_conf.stub_dynamic_func_tab:
      self.uc.mem_map(consts_x86.ALLOC_BA,conf.p_size*consts_x86.ALLOC_PAGES,UC_PROT_READ | UC_PROT_WRITE)

      self.helper = UnicornX86SEA(emu=self,
                                  allocator=DumpAllocator(consts_x86.ALLOC_BA,consts_x86.ALLOC_PAGES*conf.p_size),
                                  wsize=4)
      

    self.filetype = ida_loader.get_file_type_name()
    if self.conf.s_conf.stub_dynamic_func_tab:
      if '(PE)' in self.filetype:
        self.stubs = PE.winx86_stubs
        self.nstub_obj = PE.NullStub() 
        self.loader_type = LoaderType.PE
        self.nstub_obj.set_helper(self.helper)
      elif 'ELF' in self.filetype: 
        self.stubs = ELF.libc_stubs 
        self.nstub_obj = ELF.NullStub()
        self.loader_type = LoaderType.ELF 
        self.nstub_obj.set_helper(self.helper)

        if verify_valid_elf(self.conf.s_conf.orig_filepath):
          self.get_relocs(self.conf.s_conf.orig_filepath,lief.ELF.RELOCATION_X86_64.JUMP_SLOT)

#          self.libc_start_main_trampoline = consts_x86.LIBCSTARTSTUBADDR
#          self.uc.mem_map(consts_x86.LIBCSTARTSTUBADDR,consts_x86.PSIZE, UC_PROT_ALL)
#          self.uc.mem_write(consts_x86.LIBCSTARTSTUBADDR,consts_x86.LIBCSTARTSTUBCODE) 
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
    if not self.conf.s_conf.stub_dynamic_func_tab:
      return 
    self.stubbit()
    
        

  """ Instructions specifics functions 
  """
#---------------------------------------------------------------------------------------------
  def nop_insn(self,insn):
    for of in range(0,insn.size):
      self.uc.mem_write(insn.ea+of,struct.pack('B',consts_x86.nop))
    

  @staticmethod
  def tail_retn(ea):
    """ returns operand of retn <op>
        this is heuristic, should be used carefully.
    """

    f = ida_funcs.get_func(ea)
    insn = get_insn_at(f.end_ea)# somehow end_ea does not point to the last insn...
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
         elif insn.itype in consts_x86.ida_jmp_itype: 
            return idc.o_void
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


  """  Register specific functions 
  """
#---------------------------------------------------------------------------------------------


  def get_alu_info(self):
    
    return x86EFLAGS.create(self.uc.reg_read(UC_X86_REG_EFLAGS))

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


  @staticmethod
  def generate_default_config(s_ea,
                              e_ea,
                              regs=None,
                              s_conf=None,
                              amap_conf=None):
    if regs == None:
        registers = x86Registers(EAX=0,
                                EBX=1,
                                ECX=2,
                                EDX=3,
                                EDI=4,
                                ESI=5,
                                EBP=consts_x86.STACK_BASEADDR+consts_x86.STACK_SIZE-consts_x86.initial_stack_offset,
                                ESP=consts_x86.STACK_BASEADDR+consts_x86.STACK_SIZE-consts_x86.initial_stack_offset,
                                EIP=s_ea)
    else:
        registers = regs

    if s_conf == None:
        exec_path = search_executable()
        stub_conf = StubConfiguration(nstubs=dict(),
                                        stub_dynamic_func_tab=True if exec_path != "" else False,
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


    return Configuration(     path='',
                              arch='x86',
                              emulator='unicorn',
                              p_size=consts_x86.PSIZE,
                              stk_ba=consts_x86.STACK_BASEADDR,
                              stk_size=consts_x86.STACK_SIZE,
                              autoMap=False,
                              showRegisters=True,
                              exec_saddr=s_ea,
                              exec_eaddr=e_ea,
                              mapping_saddr=get_min_ea_idb(),
                              mapping_eaddr=get_max_ea_idb(),
                              segms=[],
                              map_with_segs=False,
                              use_seg_perms=False,
                              useCapstone=True,
                              registers=registers,
                              showMemAccess=True,
                              s_conf=stub_conf,
                              amap_conf=addmap_conf,
                              color_graph=False,
                              breakpoints= [])


