import ida_segregs
from EWS.emu.unicorn.generic import * 
import string
from EWS.utils.utils import * 
from EWS.utils import consts_x86
from EWS.stubs.ELF.allocator import *
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
            self.patch_insn(k,v,update_conf=False)





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
        self.uc.mem_map(consts_x86.ALLOC_BA,
                        self.conf.p_size*consts_x86.ALLOC_PAGES,
                        UC_PROT_READ | UC_PROT_WRITE)

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



   # DEPRECATED, use reset() plugin function

#  def repatch(self):
#    if not self.conf.s_conf.activate_stub_mechanism:
#      return 
#    # need to remap according to the arch settings 
#    self.uc.mem_map(consts_x86.ALLOC_BA,
#                    self.conf.p_size*consts_x86.ALLOC_PAGES,
#                    UC_PROT_READ | UC_PROT_WRITE)
#
#    self.unstub_all()
#    self.stubbit()
#    
        

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


  """  Register specific functions 
  """
#---------------------------------------------------------------------------------------------


  def get_alu_info(self):
    
    return x86EFLAGS.create(self.uc.reg_read(UC_X86_REG_EFLAGS))

  def setup_regs(self,regs):

    # Segment register might be instancied manually using console
    self.uc.reg_write(UC_X86_REG_EAX,regs.EAX)
    self.uc.reg_write(UC_X86_REG_EBX,regs.EBX)
    self.uc.reg_write(UC_X86_REG_ECX,regs.ECX)
    self.uc.reg_write(UC_X86_REG_EDX,regs.EDX)
    self.uc.reg_write(UC_X86_REG_EDI,regs.EDI)
    self.uc.reg_write(UC_X86_REG_ESI,regs.ESI)
    self.uc.reg_write(UC_X86_REG_ESP,regs.ESP)
    self.uc.reg_write(UC_X86_REG_EBP,regs.EBP)
    self.uc.reg_write(UC_X86_REG_EIP,regs.EIP)

  def get_regs(self):
      return x86Registers(
            EAX=self.uc.reg_read(UC_X86_REG_EAX),
            EBX=self.uc.reg_read(UC_X86_REG_EBX),
            ECX=self.uc.reg_read(UC_X86_REG_ECX),
            EDX=self.uc.reg_read(UC_X86_REG_EDX),
            EDI=self.uc.reg_read(UC_X86_REG_EDI),
            ESI=self.uc.reg_read(UC_X86_REG_ESI),
            ESP=self.uc.reg_read(UC_X86_REG_ESP),
            EBP=self.uc.reg_read(UC_X86_REG_EBP),
            EIP=self.uc.reg_read(UC_X86_REG_EIP))
    
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
    
  def reg_convert_ns(self,r_id):
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
      return Configuration.generate_default_config(stk_ba=stk_ba if stk_ba\
                                                    else consts_x86.STACK_BASEADDR,
                                                    stk_size=stk_size if stk_size\
                                                    else consts_x86.STACK_SIZE,
                                                    registers=registers,
                                                    exec_saddr=exec_saddr,
                                                    exec_eaddr=exec_eaddr)








#  @staticmethod
#  def generate_default_config(path=None,
#                       arch=None,
#                       emulator=None,
#                       p_size=None,
#                       stk_ba=None,
#                       stk_size=None,
#                       autoMap=None,
#                       showRegisters=None,
#                       exec_saddr=None,
#                       exec_eaddr=None,
#                       mapping_saddr=None,
#                       mapping_eaddr=None,
#                       segms=None,
#                       map_with_segs=None,
#                       use_seg_perms=None,
#                       useCapstone=None,
#                       registers=None,
#                       showMemAccess=None,
#                       s_conf=None,
#                       amap_conf=None,
#                        memory_init=None,
#                       color_graph=None,
#                        breakpoints=None):
#
#    if registers == None:
#        registers = x86Registers(EAX=0,
#                                EBX=1,
#                                ECX=2,
#                                EDX=3,
#                                EDI=4,
#                                ESI=5,
#                                EBP=consts_x86.STACK_BASEADDR+consts_x86.STACK_SIZE-\
#                                 consts_x86.initial_stack_offset,
#                                ESP=consts_x86.STACK_BASEADDR+consts_x86.STACK_SIZE-\
#                                 consts_x86.initial_stack_offset,
#                                EIP=exec_saddr)
#    else:
#        registers = regs
#
#    if s_conf == None:
#        exec_path = search_executable()
#        stub_conf = StubConfiguration(nstubs=dict(),
#                                      activate_stub_mechanism=True if exec_path != ""
#                                      else False,
#                                      orig_filepath=exec_path,
#                                      custom_stubs_file=None,
#                                      auto_null_stub=True if exec_path != "" else False,
#                                      tags=dict())
#    else:
#        stub_conf = s_conf
#
#    if amap_conf == None:
#        addmap_conf = AdditionnalMapping.create()
#    else:
#        addmap_conf = amap_conf
#
#
#    if memory_init == None:
#        meminit = AdditionnalMapping.create()
#    else:
#        meminit = memory_init
#
#    return Configuration(     path=path if path else '',
#                              arch='x86',
#                              emulator='unicorn',
#                              p_size=p_size if p_size else consts_x86.PSIZE,
#                              stk_ba=stk_ba if stk_ba else consts_x86.STACK_BASEADDR,
#                              stk_size=stk_size if stk_size else consts_x86.STACK_SIZE,
#                              autoMap=autoMap if autoMap else False,
#                              showRegisters=showRegisters if showRegisters else True,
#                              exec_saddr=exec_saddr if exec_saddr else 0,
#                              exec_eaddr=exec_eaddr if exec_eaddr else 0xFFFFFFFF,
#                              mapping_saddr=get_min_ea_idb() if not mapping_saddr else mapping_saddr,
#                              mapping_eaddr=get_max_ea_idb() if not mapping_eaddr else mapping_eaddr,
#                              segms=segms if segms else [],
#                              map_with_segs=map_with_segs if map_with_segs else False,
#                              use_seg_perms=use_seg_perms if use_seg_perms else False,
#                              useCapstone=useCapstone if useCapstone else True,
#                              registers=registers,
#                              showMemAccess=showMemAccess if showMemAccess else True,
#                              s_conf=stub_conf,
#                              amap_conf=addmap_conf,
#                              memory_init=meminit,
#                              color_graph=False,
#                              breakpoints=breakpoints if breakpoints else [])
#
#
