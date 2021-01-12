from emu.miasm.generic import Emuiasm
import stubs.ELF.ELF  
from stubs.ELF.allocator import *
from stubs.emu.miasm.sea import MiasmArmSEA
from miasm.analysis.machine import Machine
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC
import struct
from utils.utils import * 
import ida_ua
import ida_idc
import idautils
import ida_idaapi
import ida_segment
import ida_funcs
import ida_name
import idautils
import ida_bytes


class Miarm(Emuiasm):

  def __init__(self,conf):


    super().__init__(conf) 

    pinf = proc_inf('arm',conf.exec_saddr)
    self.endns = pinf['endianness'] 
    if pinf['endianness'] == 'little':  
      machine = Machine('arml')
    elif pinf['endianness'] == 'big':
      machine = Machine('armb')

    self.jitter = machine.jitter('python')

    # Map code section, user provided, and stack 
    self.do_mapping()
    
    # Init regs from conf
    self.setup_regs()

    self.jitter.jit.log_mn = True
    self.jitter.jit.log_regs = True
#     self.jitter.set_trace_log()


    # Init stubs component
    if self.conf.s_conf.stub_pltgot_entries or self.conf.s_conf.use_user_stubs:
       # Allocate allocator pages
       self.jitter.vm.add_memory_page(consts_arm.ALLOC_BA,PAGE_READ|PAGE_WRITE,b'\x00'*conf.p_size*consts_arm.ALLOC_PAGES)
       # Init Stubs Exec. Abstractor 
       self.helper = MiasmArmSEA(uc=self.jitter,
                                  allocator=DumpAllocator(consts_arm.ALLOC_BA,consts_arm.ALLOC_PAGES*conf.p_size),
                                  wsize=4)
    if self.conf.s_conf.use_user_stubs: 
      logger.console(LogType.WARN,'user stubs no supported yet.')

    if self.conf.s_conf.stub_pltgot_entries: 
      self.stubbit(stubs.ELF.ELF.libc_stubs_arm)
      logger.console(LogType.INFO,'[%s] add stubbing trap page. plt/got now patched.'%'ArmCorn') 


    self.nstub_obj = stubs.ELF.ELF.NullStub('arm')
    self.nstub_obj.set_helper(self.helper) 
    for ea,fname in self.conf.s_conf.nstubs.items():
      self.add_null_stub(ea,fname)

    
  

  def setup_regs(self):

    Miarm.reg_write(self.jitter,0,self.conf.registers.R0)
    Miarm.reg_write(self.jitter,1,self.conf.registers.R1)
    Miarm.reg_write(self.jitter,2,self.conf.registers.R2)
    Miarm.reg_write(self.jitter,3,self.conf.registers.R3)
    Miarm.reg_write(self.jitter,4,self.conf.registers.R4)
    Miarm.reg_write(self.jitter,5,self.conf.registers.R5)
    Miarm.reg_write(self.jitter,6,self.conf.registers.R6)
    Miarm.reg_write(self.jitter,7,self.conf.registers.R7)
    Miarm.reg_write(self.jitter,8,self.conf.registers.R8)
    Miarm.reg_write(self.jitter,9,self.conf.registers.R9)
    Miarm.reg_write(self.jitter,10,self.conf.registers.R10)
    Miarm.reg_write(self.jitter,11,self.conf.registers.R11)
    Miarm.reg_write(self.jitter,12,self.conf.registers.R12)
    Miarm.reg_write(self.jitter,13,self.conf.registers.R13)
    Miarm.reg_write(self.jitter,14,self.conf.registers.R14)
    Miarm.reg_write(self.jitter,15,self.conf.registers.R15)

    
  @staticmethod
  def reg_read(jitter,r_id):
    if r_id == 0:
        return jitter.cpu.R0
    elif r_id == 1:
        return jitter.cpu.R1
    elif r_id == 2:
        return jitter.cpu.R2
    elif r_id == 3:
        return jitter.cpu.R3
    elif r_id == 4:
        return jitter.cpu.R4
    elif r_id == 5:
        return jitter.cpu.R5
    elif r_id == 6:
        return jitter.cpu.R6
    elif r_id == 7:
        return jitter.cpu.R7
    elif r_id == 8:
        return jitter.cpu.R8
    elif r_id == 9:
        return jitter.cpu.R9
    elif r_id == 10:
        return jitter.cpu.R10
    elif r_id == 11:
        return jitter.cpu.R11
    elif r_id == 12:
        return jitter.cpu.R12
    elif r_id == 13:
        return jitter.cpu.SP
    elif r_id == 14:
        return jitter.cpu.LR
    elif r_id == 15:
        return jitter.cpu.PC

  @staticmethod
  def reg_write(jitter,r_id,data):
    if r_id == 0:
        jitter.cpu.R0=data
    elif r_id == 1:
        jitter.cpu.R1=data
    elif r_id == 2:
        jitter.cpu.R2=data
    elif r_id == 3:
        jitter.cpu.R3=data
    elif r_id == 4:
        jitter.cpu.R4=data
    elif r_id == 5:
        jitter.cpu.R5=data
    elif r_id == 6:
        jitter.cpu.R6=data
    elif r_id == 7:
        jitter.cpu.R7=data
    elif r_id == 8:
        jitter.cpu.R8=data
    elif r_id == 9:
        jitter.cpu.R9=data
    elif r_id == 10:
        jitter.cpu.R10=data
    elif r_id == 11:
        jitter.cpu.R11=data
    elif r_id == 12:
        jitter.cpu.R12=data
    elif r_id == 13:
        jitter.cpu.SP=data
    elif r_id == 14:
        jitter.cpu.LR=data
    elif r_id == 15:
        jitter.cpu.PC=data

  def stubbit(self,stubs_l):

    s = ida_segment.get_segm_by_name('.plt') 
    if s == None:
      logger.console(LogType.WARN,'[!] plt section not found, stubs mechanism not compatible with such binary')
      logger.console(LogType.WARN,'[!] TODO use PT_DYNAMIC->RELRA instead')
      
      return
    fstubbednb = 0
    f = ida_funcs.get_next_func(s.start_ea)
    insn = ida_ua.insn_t()
    while f.start_ea < s.end_ea:
      fname = ida_name.get_ea_name(f.start_ea)
      if fname in stubs_l.keys():
        fstubbednb += 1
        if is_thumb(f.start_ea):
          self.jitter.vm.set_mem(f.start_ea,struct.pack('>H' if self.endns == 'little' else '<H',consts_arm.mov_pc_lr_thumb))
        else:
          self.jitter.vm.set_mem(f.start_ea,struct.pack('>I' if self.endns == 'little' else '<I',consts_arm.mov_pc_lr))
        stubs_l[fname].set_helper(self.helper)
        xref_g = idautils.XrefsTo(f.start_ea)
        try:
          while True:
            xref = next(xref_g)
            ida_ua.decode_insn(insn,xref.frm)
            if ida_idp.is_call_insn(insn): 
              self.jitter.add_breakpoint(xref.frm,stubs_l[fname].do_it)
              
              print('[+] %s is not stubbed at %8X'%(fname,xref.frm))
        except StopIteration: 
          pass
      f = ida_funcs.get_next_func(f.start_ea)
      if f == None: 
        break

    return fstubbednb 
 

  def add_null_stub(self,ea,fname=None):
    """ TODO can be factorised with add_custom_stub
        with func=None
    """
    if not fname:
      try:    fname = ida_funcs.get_func_name(ea)
      except: fname = 'func_%x'%ea
 
    if fname in stubs.ELF.ELF.libc_stubs_arm.keys():
      logger.console(LogType.WARN,'[!] %s belongs to libc stub. It is now null stubbed'%fname)
      stubs.ELF.ELFlibc_stubs_arm[fname] = self.nstub_obj
    else:
      if is_thumb(ea):
        self.jitter.vm.set_mem(ea,struct.pack('>H' if self.endns == 'little' else '<H',consts_arm.mov_pc_lr_thumb))
      else:
        self.jitter.vm.set_mem(ea,struct.pack('>I' if self.endns == 'little' else '<I',consts_arm.mov_pc_lr))
      self.jitter.add_breakpoint(ea,self.nstub_obj.do_it)

      logger.console(LogType.INFO,'[%x] [%s] is null stubbed'%(ea,fname))


    self.conf.add_null_stub(ea)

  def remove_null_stub(self,ea,fname=None):
  
    if not fname:
      try:    fname = ida_funcs.get_func_name(ea)
      except: fname = 'func_%x'%ea

    if fname in stubs.ELF.ELF.libc_stubs_arm.keys():
      # Needs to reinit the stub
      logger.console(LogType.WARN,'Changes will be effective only after save and reloading the conf')
    else:
      # Restore from IDB
      self.jitter.vm.set_mem(ea,ida_bytes.get_bytes(ea,4))
      self.jitter.remove_breakpoints_by_address(ea)

    self.conf.remove_null_stub(ea)


  def add_custom_stub(self,ea,func):
    """ function must return True to continue execution
        how to use:
        def custom_stub():
          r0 = emu.helper.get_arg(0)
          emu.helper.set_return(r0+1)
          return True
        emu.add_custom_stub(0xadde,custom_stub)
    """


    try:    fname = ida_funcs.get_func_name(ea)
    except: fname = 'func_%x'%ea 
    
    aldy_patch = False
    if fname in stubs.ELF.ELF.libc_stubs_arm.keys():
      logger.console(LogType.WARN,'Overriding default stub function %s'%fname)
      aldy_patch = True
    elif fname in self.conf.s_conf.nstubs.values():
      logger.console(LogType.WARN,'Overriding null stubbed function %s'%fname)
      self.remove_null_stub(ea)

    if not aldy_patch:
      if is_thumb(ea):
        self.jitter.vm.set_mem(ea,struct.pack('>H' if self.endns == 'little' else '<H',consts_arm.mov_pc_lr_thumb))
      else:
        self.jitter.vm.set_mem(ea,struct.pack('>I' if self.endns == 'little' else '<I',consts_arm.mov_pc_lr))

    stubs.ELF.ELF.StubsARM.itnum_arm+=1
    new_stub = stubs.ELF.ELF.Stub(stubs.ELF.ELF.StubsARM.itnum_arm,'arm',self.helper)
    new_stub.do_it = func
    self.jitter.add_breakpoint(ea,new_stub.do_it)

    logger.console(LogType.INFO,'%s is no stubbed with %s'%(fname,func.__name__))


  def remove_custom_stub(self,ea):


    try:    fname = ida_funcs.get_func_name(ea)
    except: fname = 'func_%x'%ea 

    if fname in stubs.ELF.ELF.libc_stubs_arm.keys():
      logger.console(LogType.WARN,'could not unstub, please reload the conf')
    
    self.jitter.vm.set_mem(ea,ida_bytes.get_bytes(ea,4))
    self.jitter.remove_breakpoints_by_address(ea)

    
    logger.console(LogType.INFO,'%s function is now unstubbed'%fname)



  def tag_function(self,ea,stubname):
    """ TODO: add to configuration
    """

    if not stubname in stubs.ELF.ELF.libc_stubs_arm.keys():
      logger.console(LogType.WARN,'%s is not among default stubs. Aborting'%stubname)
      return

    self.add_custom_stub(ea,stubs.ELF.ELF.libc_stubs_arm[stubname].do_it)


  def remove_tag(self,ea):

    
    self.jitter.vm.set_mem(ea,ida_bytes.get_bytes(ea,4))
    try: 
      self.jitter.remove_breakpoints_by_address(ea)
    except:
      logger.console(LogType.WARN,'Cannot remove tag at %x'%ea)
      return

    


  
    
    






 
    
    
    
    
    
      
      
      




    
      

    
    
    
    
    
    

    
    
    


