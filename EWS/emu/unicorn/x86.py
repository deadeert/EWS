import ida_segregs
from EWS.emu.unicorn.generic import * 
import string
from EWS.utils.utils import * 
from EWS.utils import consts_x86
from EWS.stubs.allocators.allocator import *
import ida_loader
import idc
import ida_ua
import ida_funcs
import idautils
from EWS. stubs.emu.unicorn.sea import UnicornX86SEA
import struct
from unicorn.x86_const import * 
from keystone import * 
from EWS. stubs.ELF import ELF
from EWS. stubs import PE
from EWS.utils.configuration import *
from EWS.utils.registers import *
from EWS.asm.assembler import *

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
    self.setup_regs(self.conf.registers)

    self.pcid = UC_X86_REG_EIP

    # Init stubs engine 
    if self.conf.s_conf.activate_stub_mechanism:
        self.setup_stub_mechanism()

    self.install_hooks()

    for k,v in self.conf.memory_init.mappings.items():
        self.uc.mem_write(k,v)


    self.assembler = assemblers['x86'][0]

    for k,v in self.conf.patches.items():
            self.patch_mem(k,v) 


    for k,v in self.conf.watchpoints.items():
            self.add_watchpoint(k, v&0xff,mode=v>>24)





  def install_hooks(self):


    self.uc.hook_add(UC_HOOK_CODE,
                     self.hook_code,
                     user_data=self)

    self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED,
                     Emucorn.unmp_read,
                     user_data=self)

    self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED,
                     Emucorn.unmp_write,
                     user_data=self)

    if self.conf.showMemAccess:
      self.uc.hook_add(UC_HOOK_MEM_WRITE,
                Emucorn.hk_write,
                self)
      self.uc.hook_add(UC_HOOK_MEM_READ,
                       Emucorn.hk_read,
                       self)


  def setup_stub_mechanism(self):


        Emucorn.do_required_mappng(self.uc,
                                   consts_x86.ALLOC_BA,
                                   consts_x86.ALLOC_BA+self.conf.p_size*consts_x86.ALLOC_PAGES,
                                   self.conf.p_size,
                                   UC_PROT_READ | UC_PROT_WRITE,
                                   True,
                                   f"Warning map heap in already mapped area {consts_x86.ALLOC_BA:x}, edit utils/const_arm.py to modify this area")



        self.helper = UnicornX86SEA(emu=self,
                                      allocator=DumpAllocator(consts_x86.ALLOC_BA,
                                                              consts_x86.ALLOC_PAGES*self.conf.p_size),
                                      wsize=4)
          

        
        if self.conf.s_conf.activate_stub_mechanism:

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
              self.reloc_map = get_relocs(self.conf.s_conf.orig_filepath,
                                          lief.ELF.RELOCATION_X86_64.JUMP_SLOT)
              # Stub __libc_start_main (experimental)
              self.libc_start_main_trampoline = consts_x86.LIBCSTARTSTUBADDR
              self.uc.mem_map(consts_x86.LIBCSTARTSTUBADDR,consts_x86.PSIZE, UC_PROT_ALL)
              self.uc.mem_write(consts_x86.LIBCSTARTSTUBADDR,consts_x86.LIBCSTARTSTUBCODE) 
              self.stub_PLT()



          for k,v in self.conf.s_conf.tags.items(): 
            self.tag_func(k, v)


  def nop_insn(self,
               insn):

    """ 
    ! nop the instruction 
  
    @param instruction repr by IDA
    """
    for of in range(0,insn.size):
      #self.uc.mem_write(insn.ea+of,struct.pack('B',consts_x86.nop))
      bc,sz = self.ks.asm("nop;"*size,as_bytes=True,addr=insn.ea)
      self.uc.mem_write(insn.ea,bc)


    

  @staticmethod
  def tail_retn(ea):

    """ returns operand of retn <op>
        this is heuristic, should be used carefully.
        
        @param ea Address to start the research 
    """

    f = ida_funcs.get_func(ea)
    insn = get_insn_at(f.end_ea)# somehow end_ea does not point to the last insn...

    if insn.itype == consts_x86.ida_retn_itype: # or use ida_idp.is_ret_insn...

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
   
  def get_retn_insn(self,
                    ea:int):

    f = ida_funcs.get_func(ea)
    n = x86Corn.tail_retn(f.start_ea)

    if n > 0: 
      try: retn = self.ks.asm('ret %d'%n,as_bytes=True)[0]
      except: logger.console(LogType.WARN,'could not compile retn insn'); return -1
    elif n == 0: 
      retn,sz = self.ks.asm("ret;",as_bytes=True)
      #retn = struct.pack('B',consts_x86.ret)

    return retn


  def get_new_stub(self,
                   stub_func,
                   stub_type,
                   name:str=''):

    if 'ELF' in self.filetype:
      stub = ELF.Stub(self.helper,stub_type=stub_type,name=name)
      stub.do_it = stub_func
    elif 'PE' in self.filetype:
      stub = PE.Stub(self.helper,stub_type=stub_type)
      stub.do_it = stub_func
    return stub


  def get_alu_info(self):
    
    return x86EFLAGS.create(self.uc.reg_read(UC_X86_REG_EFLAGS))

  def setup_regs(self,regs):

    for k,v in consts_x86.reg_map_unicorn.items():
            self.uc.reg_write(v,getattr(regs,k.upper())) 

  def get_regs(self):

    regs =x86Registers.create() 

    for k,v in consts_x86.reg_map_unicorn.items():
        setattr(regs,k.upper(),self.uc.reg_read(v))
    return regs
    
  def reset_regs(self):

        for k,v in consts_x86.reg_map_unicorn.items():
            self.uc.reg_write(v,0)
 

  @staticmethod
  def reg_convert(r_id:str):
    return consts_x86.reg_map_unicorn[r_id]
   
  def reg_convert_ns(self,r_id):
    return consts_x86.reg_map_unicorn[r_id]

    
    
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
    return strout



  @staticmethod
  def generate_default_config(
                                 path: str = None,
                                 arch: str = None,
                                 emulator: str = None,
                                 p_size: int = None,
                                 stk_ba: int = None,
                                 stk_size: int = None,
                                 autoMap: bool = None,
                                 showRegisters: bool = None,
                                 exec_saddr: int =None,
                                 exec_eaddr: int =None,
                                 mapping_saddr: int =None,
                                 mapping_eaddr: int =None,
                                 segms: list =None,
                                 map_with_segs: bool = None,
                                 use_seg_perms: bool =None,
                                 useCapstone: bool = None,
                                 registers: Registers = None,
                                 showMemAccess: bool =None,
                                 s_conf: StubConfiguration = None,
                                 amap_conf: AdditionnalMapping = None,
                                 memory_init: AdditionnalMapping =None,
                                 color_graph: bool =None,
                                 breakpoints: list =None,
                                 watchpoints: dict =None) -> Configuration:
      """this method get called by:
            - ui **emulate_function**
            - ui **emulate_selection**
      """

      if not registers: 
        if stk_ba and stk_size: 
            EBP = ESP =  stk_ba + stk_size - consts_x86.initial_stack_offset 
        elif stk_ba and not stk_size: 
            EBP = ESP =  stk_ba +  consts_x86.STACK_SIZE - consts_x86.initial_stack_offset 
        elif stk_size and not stk_ba: 
            EBP = ESP = consts_x86.STACK_BASEADDR + stk_size - consts_x86.initial_stack_offset 
        else:
            EBP = ESP = consts_x86.STACK_BASEADDR+consts_x86.STACK_SIZE-\
                                 consts_x86.initial_stack_offset
        registers = x86Registers.get_default_object(EBP=EBP,ESP=ESP,EIP=exec_saddr)
      return Configuration.generate_default_config(arch='x86',stk_ba=stk_ba if stk_ba\
                                                    else consts_x86.STACK_BASEADDR,
                                                    stk_size=stk_size if stk_size\
                                                    else consts_x86.STACK_SIZE,
                                                    registers=registers,
                                                    exec_saddr=exec_saddr,
                                                    exec_eaddr=exec_eaddr)








