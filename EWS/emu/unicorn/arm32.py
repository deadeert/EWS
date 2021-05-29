import ida_segregs
from EWS.emu.unicorn.generic import * 
import string
from EWS.utils.utils import * 
from EWS.utils import consts_arm
from EWS.stubs.ELF.allocator import *
from EWS.stubs.ELF import ELF
from EWS.stubs.emu.unicorn.sea import UnicornArmSEA
import struct




class ArmCorn(Emucorn): 

  def __init__(self,conf):

    super().__init__(conf) 

    # Init engine 
    pinf = proc_inf('arm',conf.exec_saddr)
    if pinf['endianness'] == 'little':  
      if pinf['proc_mode'] == 16:
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB) 
        self.conf.exec_saddr = self.conf.exec_saddr | 1
      elif pinf['proc_mode'] == 32:
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM) 
    elif pinf['endianness'] == 'big':
      if pinf['proc_mode'] == 16:
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB + UC_MODE_BIG_ENDIAN) 
        self.conf.exec_saddr = self.conf.exec_saddr | 1
      elif pinf['proc_mode'] == 32:
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_BIG_ENDIAN) 

    self.endns = pinf['endianness']
    self.pointer_size = 4 

    # Map pages 
    d,r = divmod(self.conf.p_size,0x400) 
    if r: 
      logger.console(LogType.WARN,'[+] invalid page size, using default')
      self.conf.p_size = uc.query(UC_QUERY_PAGE_SIZE)
    Emucorn.do_mapping(self.uc,self.conf)

    
    # Init capstone engine
    if conf.useCapstone:
      from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN
      if pinf['proc_mode'] == 16:
        self.cs=Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN if pinf['endianness'] else CS_MODE_THUMB + CS_MODE_BIG_ENDIAN)
         
      elif pinf['proc_mode'] == 32:
        self.cs=Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN if pinf['endianness'] else CS_MODE_ARM + CS_MODE_BIG_ENDIAN)
      self.cs.detail=True

    # Setup regs 
    self.setup_regs(self.conf.registers)
    self.pcid = UC_ARM_REG_PC 

    # Init stubs engine 
    if self.conf.s_conf.stub_dynamic_func_tab:

      self.uc.mem_map(consts_arm.ALLOC_BA,conf.p_size*consts_arm.ALLOC_PAGES,UC_PROT_READ | UC_PROT_WRITE)

      self.helper = UnicornArmSEA(emu=self,
                                  allocator=DumpAllocator(consts_arm.ALLOC_BA,consts_arm.ALLOC_PAGES*conf.p_size),
                                  wsize=4)
      self.nstub_obj = ELF.NullStub()
      self.nstub_obj.set_helper(self.helper) 
 
      self.stubs = ELF.libc_stubs 
      if verify_valid_elf(self.conf.s_conf.orig_filepath):
            self.get_relocs(self.conf.s_conf.orig_filepath,lief.ELF.RELOCATION_ARM.JUMP_SLOT)
            self.libc_start_main_trampoline = consts_arm.LIBCSTARTSTUBADDR
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

  
  def start(self,cnt=0,saddr=None): 
    """ Need to overload because of thumb mode
    """ 
    if not saddr:
      saddr = self.conf.exec_saddr 
    if self.isThumb():
      saddr |= 1

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


  def step_over(self):
    """
    need to overload because of Thumb mode
    """



    insn = get_insn_at(self.helper.get_pc())
    bp_addr = []

    if ida_idp.is_call_insn(insn) or ida_idp.has_insn_feature(insn.itype,ida_idp.CF_STOP):
        self.uc.emu_start(insn.ea|1 if self.isThumb() else insn.ea,
                          insn.ea+insn.size,0,0)
    elif ida_idp.is_indirect_jump_insn(insn):
        logger.console(LogType.WARN,
                       "Indirect jump incompatible with step_over feature.",
                       "Please do it manually")
    else:
        self.step_in()



  """ Instructions specifics functions 
  """
#---------------------------------------------------------------------------------------------

  def nop_insn(self,insn):
    i = get_insn_at(insn.ea) 
    if i.size == 2:
      if self.endns == 'little':
        self.uc.mem_write(insn.ea,struct.pack('<H',consts_arm.nop_thumb))
      else:
        self.uc.mem_write(insn.ea,struct.pack('>H',consts_arm.nop_thumb))
    elif i.size == 4: 
      if self.endns == 'little':
        self.uc.mem_write(insn.ea,struct.pack('<I',consts_arm.nop))
      else:
        self.uc.mem_write(insn.ea,struct.pack('>I',consts_arm.nop))
    else:
      logger.console(LogType.ERRR,'Invalid insn size')


  def get_retn_insn(self,ea):
    f = ida_funcs.get_func(ea)
    if f == None:
      logger.console(LogType.WARN,'cannot decode function at specified address %x'%ea)
      return 
    i = get_insn_at(f.start_ea) 
    if i.size == 2:
      if self.endns == 'little':
        retn = struct.pack('<H',consts_arm.mov_pc_lr_thumb)
      else:
        retn = struct.pack('>H',consts_arm.mov_pc_lr_thumb)
    elif i.size == 4:
      if self.endns == 'little':
        retn = struct.pack('<I',consts_arm.mov_pc_lr)
      else:
        retn = struct.pack('>I',consts_arm.mov_pc_lr)
    else:
      logger.console(LogType.ERRR,'Invalid insn size')
    return retn

  def get_new_stub(self,stub_func):
    stub = ELF.Stub(self.helper)
    stub.do_it = stub_func
    return stub





  """  Register specific functions 
  """
#---------------------------------------------------------------------------------------------
  def setup_regs(self,regs):

    self.uc.reg_write(UC_ARM_REG_R0,regs.R0)
    self.uc.reg_write(UC_ARM_REG_R1,regs.R1)
    self.uc.reg_write(UC_ARM_REG_R2,regs.R2)
    self.uc.reg_write(UC_ARM_REG_R3,regs.R3)
    self.uc.reg_write(UC_ARM_REG_R4,regs.R4)
    self.uc.reg_write(UC_ARM_REG_R5,regs.R5)
    self.uc.reg_write(UC_ARM_REG_R6,regs.R6)
    self.uc.reg_write(UC_ARM_REG_R7,regs.R7)
    self.uc.reg_write(UC_ARM_REG_R8,regs.R8)
    self.uc.reg_write(UC_ARM_REG_R9,regs.R9)
    self.uc.reg_write(UC_ARM_REG_R10,regs.R10)
    self.uc.reg_write(UC_ARM_REG_R11,regs.R11)
    self.uc.reg_write(UC_ARM_REG_R12,regs.R12)
    self.uc.reg_write(UC_ARM_REG_R13,regs.R13)
    self.uc.reg_write(UC_ARM_REG_R14,regs.R14)
    self.uc.reg_write(UC_ARM_REG_R15,regs.R15)


  def get_regs(self):
      return ArmRegisters(
            R0=self.uc.reg_read(UC_ARM_REG_R0),
            R1=self.uc.reg_read(UC_ARM_REG_R1),
            R2=self.uc.reg_read(UC_ARM_REG_R2),
            R3=self.uc.reg_read(UC_ARM_REG_R3),
            R4=self.uc.reg_read(UC_ARM_REG_R4),
            R5=self.uc.reg_read(UC_ARM_REG_R5),
            R6=self.uc.reg_read(UC_ARM_REG_R6),
            R7=self.uc.reg_read(UC_ARM_REG_R7),
            R8=self.uc.reg_read(UC_ARM_REG_R8),
            R9=self.uc.reg_read(UC_ARM_REG_R9),
            R10=self.uc.reg_read(UC_ARM_REG_R10),
            R11=self.uc.reg_read(UC_ARM_REG_R11),
            R12=self.uc.reg_read(UC_ARM_REG_R12),
            R13=self.uc.reg_read(UC_ARM_REG_R13),
            R14=self.uc.reg_read(UC_ARM_REG_R14),
            R15=self.uc.reg_read(UC_ARM_REG_R15)
      )

  def reset_regs(self):

    self.uc.reg_write(UC_ARM_REG_R0,0)
    self.uc.reg_write(UC_ARM_REG_R1,0)
    self.uc.reg_write(UC_ARM_REG_R2,0)
    self.uc.reg_write(UC_ARM_REG_R3,0)
    self.uc.reg_write(UC_ARM_REG_R4,0)
    self.uc.reg_write(UC_ARM_REG_R5,0)
    self.uc.reg_write(UC_ARM_REG_R6,0)
    self.uc.reg_write(UC_ARM_REG_R7,0)
    self.uc.reg_write(UC_ARM_REG_R8,0)
    self.uc.reg_write(UC_ARM_REG_R9,0)
    self.uc.reg_write(UC_ARM_REG_R10,0)
    self.uc.reg_write(UC_ARM_REG_R11,0)
    self.uc.reg_write(UC_ARM_REG_R12,0)
    self.uc.reg_write(UC_ARM_REG_R13,0)
    self.uc.reg_write(UC_ARM_REG_R14,0)
    self.uc.reg_write(UC_ARM_REG_R15,0)
   

  def isThumb(self):
    return True if self.uc.query(UC_QUERY_MODE) == 0x10 else False 



  @staticmethod
  def reg_convert(reg_id):
    if type(reg_id) == type(str()):
      return ArmCorn.str2reg(reg_id)
    elif type(reg_id) == type(int()):
      return ArmCorn.int2reg(reg_id)
    else:
      raise Exception('[reg_convert] unhandled conversion for type %s'%type(reg_id))

  def reg_convert_ns(self,reg_id):
    if type(reg_id) == type(str()):
      return self.str2reg(reg_id)
    elif type(reg_id) == type(int()):
      return self.int2reg(reg_id)
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

  def get_alu_info(self): 
    return arm32CPSR.create(self.uc.reg_read(UC_ARM_REG_CPSR))



  def repatch(self):
    """ 
    when using restart() function from debugger 
    memory is erased, thus stub instruction has be 
    to be patch again 
    """

    if not self.conf.s_conf.stub_dynamic_func_tab:
      return
    self.uc.mem_map(consts_arm.ALLOC_BA,self.conf.p_size*consts_arm.ALLOC_PAGES,UC_PROT_READ | UC_PROT_WRITE)
    # this switch is probably useless, cause reloc list is not populated 
    if verify_valid_elf(self.conf.s_conf.orig_filepath):
        self.stubbit()




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


  

  @staticmethod
  def generate_default_config(s_ea,
                              e_ea,
                              regs=None,
                              s_conf=None,
                              amap_conf=None):
    if regs == None:
        registers = ArmRegisters(0x0,
                                  0x1,
                                  0x2,
                                  0x3,
                                  0x4,
                                  0x5,
                                  0x6,
                                  0x7,
                                  0x8,
                                  0x9,
                                  0x10,
                                  0x11,
                                  0x12,
                                  consts_arm.STACK_BASEADDR+consts_arm.STACK_SIZE-consts_arm.initial_stack_offset, #SP
                                  e_ea, #LR
                                  s_ea) # PC
    else:
        registers = regs

    if s_conf == None:
        exec_path = search_executable() 
        stub_conf = StubConfiguration(nstubs=dict(),
                                        stub_dynamic_func_tab=True, #True if exec_path != "" else False,
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
                              arch='arml',
                              emulator='unicorn',
                              p_size=consts_arm.PSIZE,
                              stk_ba=consts_arm.STACK_BASEADDR,
                              stk_size=consts_arm.STACK_SIZE,
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




