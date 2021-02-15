import ida_segregs
from emu.unicorn.generic import * 
import string
from utils.utils import * 
import ida_loader
import idc
import ida_ua
import ida_funcs
import idautils
from stubs.emu.unicorn.sea import UnicornX64SEA
import struct
from unicorn.x86_const import * 
from keystone import * 
from utils import consts_x64 

from keystone import * 

from emu.unicorn.x86 import x86Corn

from stubs.ELF.allocator import *
from stubs.ELF import ELF








class x64Corn(Emucorn): 

  def __init__(self,conf):

    super().__init__(conf) 

    self.uc = Uc(UC_ARCH_X86,UC_MODE_64)
    
    if self.conf.p_size != self.uc.query(UC_QUERY_PAGE_SIZE):
      logger.console(LogType.WARN,' invalid page size, using default')
      self.conf.p_size = self.uc.query(UC_QUERY_PAGE_SIZE)

    stk_p = Emucorn.do_mapping(self.uc,self.conf)
    
    if conf.useCapstone:
      from capstone import Cs, CS_ARCH_X86, CS_MODE_64
      self.cs=Cs(CS_ARCH_X86, CS_MODE_64)

    self.ks = Ks(KS_ARCH_X86,KS_MODE_64) 
    self.pointer_size = 8 


       
    # Setup regs 
    self.setup_regs(stk_p)
    self.pcid = UC_X86_REG_RIP 
  

    self.breakpoints = dict()
    self.custom_stubs = dict()


    for s_ea in conf.s_conf.nstubs.keys():
      self.add_null_stub(s_ea)
   
    # Init stubs engine 
    if self.conf.s_conf.stub_dynamic_func_tab and verify_valid_elf(self.conf.s_conf.orig_filepath):

      self.get_relocs(self.conf.s_conf.orig_filepath,lief.ELF.RELOCATION_X86_64.JUMP_SLOT)
      self.uc.mem_map(consts_x64.ALLOC_BA,
                      conf.p_size*consts_x64.ALLOC_PAGES,
                      UC_PROT_READ | UC_PROT_WRITE)
      # TODO it is may be a good idea to differ GCC / MSVC here as prolog/epilic might change 
      self.helper = UnicornX64SEA(uc=self.uc,
                                  allocator=DumpAllocator(consts_x64.ALLOC_BA,consts_x64.ALLOC_PAGES*conf.p_size),
                                  wsize=8)

      self.nstub_obj = ELF.NullStub()
      self.nstub_obj.set_helper(self.helper) 
 
      self.stubs = ELF.libc_stubs 
 
      self.filetype = ida_loader.get_file_type_name()


      self.stubbit()

    self.ks = Ks(KS_ARCH_X86,KS_MODE_64) 
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

  def get_retn_insn(self,ea):
    f = ida_funcs.get_func(ea)
    # we can use the same function because itype are the same
    n = x86Corn.tail_retn(f.start_ea)
    if n > 0: 
      try: retn = self.ks.asm('ret %d'%n,as_bytes=True)[0]
      except: logger.console(LogType.WARN,'could not compile retn insn'); return -1
    elif n == 0: 
      retn = self.ks.asm('ret',as_bytes=True)[0]

    return retn

  def get_new_stub(self,stub_func):
    if 'ELF' in self.filetype:
      stub = ELF.Stub(self.helper)
      stub.do_it = stub_func
    elif 'PE' in self.filetype:
      stub = PE.Stub(self.helper)
      stub.do_it = stub_func
    return stub



  def setup_regs(self,stk_p):

    # Segment register might be instancied manually using console
    self.uc.reg_write(UC_X86_REG_RAX,self.conf.registers.RAX)
    self.uc.reg_write(UC_X86_REG_RBX,self.conf.registers.RBX)
    self.uc.reg_write(UC_X86_REG_RCX,self.conf.registers.RCX)
    self.uc.reg_write(UC_X86_REG_RDX,self.conf.registers.RDX)
    self.uc.reg_write(UC_X86_REG_RDI,self.conf.registers.RDI)
    self.uc.reg_write(UC_X86_REG_RSI,self.conf.registers.RSI)
    self.uc.reg_write(UC_X86_REG_RSP,self.conf.registers.RSP)
    self.uc.reg_write(UC_X86_REG_RBP,self.conf.registers.RBP)
    self.uc.reg_write(UC_X86_REG_R8,self.conf.registers.R8)
    self.uc.reg_write(UC_X86_REG_R9,self.conf.registers.R9)
    self.uc.reg_write(UC_X86_REG_R10,self.conf.registers.R10)
    self.uc.reg_write(UC_X86_REG_R11,self.conf.registers.R11)
    self.uc.reg_write(UC_X86_REG_R12,self.conf.registers.R12)
    self.uc.reg_write(UC_X86_REG_R13,self.conf.registers.R13)
    self.uc.reg_write(UC_X86_REG_R14,self.conf.registers.R14)
    self.uc.reg_write(UC_X86_REG_R15,self.conf.registers.R15)
    
    
  def reset_regs(self):

    self.uc.reg_write(UC_X86_REG_RAX,0)
    self.uc.reg_write(UC_X86_REG_RBX,0)
    self.uc.reg_write(UC_X86_REG_RCX,0)
    self.uc.reg_write(UC_X86_REG_RDX,0)
    self.uc.reg_write(UC_X86_REG_RDI,0)
    self.uc.reg_write(UC_X86_REG_RSI,0)
    self.uc.reg_write(UC_X86_REG_RSP,0)
    self.uc.reg_write(UC_X86_REG_RBP,0)
    self.uc.reg_write(UC_X86_REG_RIP,0)
    self.uc.reg_write(UC_X86_REG_R8,0)
    self.uc.reg_write(UC_X86_REG_R9,0)
    self.uc.reg_write(UC_X86_REG_R10,0)
    self.uc.reg_write(UC_X86_REG_R11,0)
    self.uc.reg_write(UC_X86_REG_R12,0)
    self.uc.reg_write(UC_X86_REG_R13,0)
    self.uc.reg_write(UC_X86_REG_R14,0)
    self.uc.reg_write(UC_X86_REG_R15,0)
   

  @staticmethod
  def reg_convert(r_id):
    if r_id.lower() == 'rax':
      return UC_X86_REG_RAX 
    elif r_id.lower() == 'rbx':
      return UC_X86_REG_RBX 
    elif r_id.lower() == 'rcx':
      return UC_X86_REG_RCX 
    elif r_id.lower() == 'rdx':
      return UC_X86_REG_RDX 
    elif r_id.lower() == 'rdi':
      return UC_X86_REG_RDI
    elif r_id.lower() == 'rsi':
      return UC_X86_REG_RSI
    elif r_id.lower() == 'rsp':
      return UC_X86_REG_RSP
    elif r_id.lower() == 'rbp':
      return UC_X86_REG_RBP
    elif r_id.lower() == 'rip':
      return UC_X86_REG_RIP
    elif r_id.lower() == 'r8':
      return UC_X86_REG_R8
    elif r_id.lower() == 'r9':
      return UC_X86_REG_R9
    elif r_id.lower() == 'r10':
      return UC_X86_REG_R10
    elif r_id.lower() == 'r11':
      return UC_X86_REG_R11
    elif r_id.lower() == 'r12':
      return UC_X86_REG_R12
    elif r_id.lower() == 'r13':
      return UC_X86_REG_R13
    elif r_id.lower() == 'r14':
      return UC_X86_REG_R14
    elif r_id.lower() == 'r15':
      return UC_X86_REG_R15
    
  def print_registers(self):
    strout  = 'Registers:\n'
    strout +=  '[RAX=%.8X] [RBX=%.8X] [RCX=%.8X] [RDX=%.8X]\n'%(self.uc.reg_read(UC_X86_REG_RAX),
                                                         self.uc.reg_read(UC_X86_REG_RBX),
                                                         self.uc.reg_read(UC_X86_REG_RCX),
                                                         self.uc.reg_read(UC_X86_REG_RDX))
    strout += '[RDI=%.8X] [RSI=%.8X] [RBP=%.8X] [RSP=%.8X]\n'%(self.uc.reg_read(UC_X86_REG_RDI),
                                                         self.uc.reg_read(UC_X86_REG_RSI),
                                                         self.uc.reg_read(UC_X86_REG_RBP),
                                                         self.uc.reg_read(UC_X86_REG_RSP))
    strout += '[R8=%.8X] [R9=%.8X] [R10=%.8X] [R11=%.8X]\n'%(self.uc.reg_read(UC_X86_REG_R8),
                                                            self.uc.reg_read(UC_X86_REG_R9),
                                                            self.uc.reg_read(UC_X86_REG_R10),
                                                            self.uc.reg_read(UC_X86_REG_R11))
    strout += '[R12=%.8X] [R13=%.8X] [R14=%.8X] [R15=%.8X]\n'%(self.uc.reg_read(UC_X86_REG_R12),
                                                            self.uc.reg_read(UC_X86_REG_R13),
                                                            self.uc.reg_read(UC_X86_REG_R14),
                                                            self.uc.reg_read(UC_X86_REG_R15))
    logger.console(LogType.INFO,strout)


  def get_alu_info(self):
    return x64RFLAGS.create(self.uc.reg_read(UC_X86_REG_EFLAGS))

  @staticmethod
  def generate_default_config(s_ea,
                              e_ea,
                              regs=None,
                              s_conf=None,
                              amap_conf=None):
    if regs == None:
        registers = x64Registers(RAX=0,
                                RBX=1,
                                RCX=2,
                                RDX=3,
                                RDI=4,
                                RSI=5,
                                R8=6,
                                R9=7,
                                R10=8,
                                R11=9,
                                R12=10,
                                R13=11,
                                R14=12,
                                R15=13,
                                RBP=consts_x64.STACK_BASEADDR+consts_x64.STACK_SIZE-consts_x64.initial_stack_offset,
                                RSP=consts_x64.STACK_BASEADDR+consts_x64.STACK_SIZE-consts_x64.initial_stack_offset,
                                RIP=s_ea)
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
                              arch='x86_64',
                              emulator='unicorn',
                              p_size=consts_x64.PSIZE,
                              stk_ba=consts_x64.STACK_BASEADDR,
                              stk_size=consts_x64.STACK_SIZE,
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


