from EWS.emu.unicorn.generic import * 
import string
from EWS.utils.utils import * 
# from unicorn.mips_const import * 
from EWS.stubs.ELF.allocator import *
from EWS.stubs.ELF import ELF
import EWS.stubs.emu.unicorn.sea 
import ida_ua
import struct


import idautils

class MipsCorn(Emucorn): 

  def __init__(self,conf):

    self.conf = conf 
    pinf=proc_inf('mips',conf.exec_saddr)
    if pinf['proc_mode'] == 16:
      logger.console(LogType.ERRR,'[!] MIPS on unicorn does not support 16bit mode') 
      raise ConfigExcption('Invalid Proc Mode')
    if  pinf['endianness'] == 'little':
      self.uc = Uc(UC_ARCH_MIPS,UC_MODE_MIPS32+UC_MODE_LITTLE_ENDIAN)  
    elif pinf['endianness'] == 'big':
      self.uc = Uc(UC_ARCH_MIPS,UC_MODE_MIPS32+UC_MODE_BIG_ENDIAN)  
    self.endns = pinf['endianness']
    self.pointer_size = 4 


    r,d = divmod(self.conf.p_size,0x1000)
    if d:
      logger.console(LogType.WARN,'[!] MIPS module requires page aligned with 0x1000')
      self.conf.p_size = uc.query(UC_QUERY_PAGE_SIZE)
    stk_p = Emucorn.do_mapping(self.uc,self.conf)

    if conf.useCapstone:
      from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN
      if pinf['endianness'] == 'little':
        self.cs=Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
      elif pinf['endianness'] == 'big': 
        self.cs=Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
      self.cs.detail=True

    self.setup_regs(stk_p)
    self.pcid = UC_MIPS_REG_PC

    for s_ea in conf.s_conf.nstubs.keys():
      self.add_nullstub(s_ea)
      
    if self.conf.s_conf.use_user_stubs or self.conf.s_conf.stub_pltgot_entries: 
      self.uc.mem_map(consts_mips.ALLOC_BA,conf.p_size*consts_mips.ALLOC_PAGES,UC_PROT_READ | UC_PROT_WRITE)
      if pinf['endianness'] == 'little':
        self.helper = stubs.emu.unicorn.sea.UnicornMipslSEA(uc=self.uc,
                                    allocator=DumpAllocator(consts_mips.ALLOC_BA,consts_mips.ALLOC_PAGES*conf.p_size),
                                    wsize=4)
      else:
        self.helper = stubs.emu.unicorn.sea.UnicornMipsbSEA(uc=self.uc,
                                    allocator=DumpAllocator(consts_mips.ALLOC_BA,consts_mips.ALLOC_PAGES*conf.p_size),
                                    wsize=4)
                                  
      logger.console(LogType.INFO,'[%s] fake allocator ready to use.'%'MipsCorn') 
       
        

    self.breakpoints= dict()
    self.custom_stubs = dict()

    if self.conf.s_conf.stub_pltgot_entries: 
      if pinf['endianness'] == 'little':      
        self.stubs = ELF.libc_stubs_mipsl
      else:
        self.stubs = ELF.libc_stubs_mipsb
      self.stubbit()
  
    self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED,
                     Emucorn.unmp_read,
                     user_data=self.conf)


    self.uc.hook_add(UC_HOOK_CODE,
                     self.hook_code,
                     user_data=self.conf)
        
    self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED,
                     Emucorn.unmp_write,
                     user_data=self.conf)

    if self.conf.showMemAccess:
      self.uc.hook_add(UC_HOOK_MEM_WRITE,
                self.hk_write,
                self.conf)
      self.uc.hook_add(UC_HOOK_MEM_READ,
                       self.hk_read,
                       self.conf)


  def stubbit(self):
    """ The choice here is to stub all xref 
        of the symbols that belong to extern section 
        plus that are used through call type insn.
        Other choice, could be to directly load trampoline
        addr to the extern section, but this requires to 
        properly set $gp register. (Canonical value for this
        register can be found using readelf -A command.
    """

    s = ida_segment.get_segm_by_name('extern') 
    if s == None:
      print('[!] extern section not found, stubs mechanism not compatible with such binary')
      return
    fstubbednb = 0
    f = ida_funcs.get_next_func(s.start_ea)
    insn = ida_ua.insn_t()
    while f.start_ea < s.end_ea:
      fname = ida_name.get_ea_name(f.start_ea)
      if fname in self.stubs.keys():
        fstubbednb += 1
        # Assign Helper
        self.stubs[fname].set_helper(self.helper)
        xref_g = idautils.XrefsTo(f.start_ea)
        try:
          while True:
            xref = next(xref_g)
            ida_ua.decode_insn(insn,xref.frm)
            if ida_idp.is_call_insn(insn): 
              self.uc.mem_write(xref.frm,struct.pack('>I',consts_mips.nop))
              self.breakpoints[xref.frm] = fname 
              logger.console(LogType.INFO,'[+] %s is not stubbed at %8X'%(fname,xref.frm))
        except StopIteration: 
          pass
      f = ida_funcs.get_next_func(f.start_ea)
      if f == None: 
        break

    return fstubbednb 
 
 

  def setup_regs(self,stk_p):
    self.uc.reg_write(UC_MIPS_REG_AT, self.conf.registers.at)
    #arguments)
    self.uc.reg_write(UC_MIPS_REG_A0, self.conf.registers.a0)
    self.uc.reg_write(UC_MIPS_REG_A1, self.conf.registers.a1)
    self.uc.reg_write(UC_MIPS_REG_A2, self.conf.registers.a2)
    self.uc.reg_write(UC_MIPS_REG_A3, self.conf.registers.a3)
    # saved)
    self.uc.reg_write(UC_MIPS_REG_S0, self.conf.registers.s0)
    self.uc.reg_write(UC_MIPS_REG_S1, self.conf.registers.s1)
    self.uc.reg_write(UC_MIPS_REG_S2, self.conf.registers.s2)
    self.uc.reg_write(UC_MIPS_REG_S3, self.conf.registers.s3)
    self.uc.reg_write(UC_MIPS_REG_S4, self.conf.registers.s4)
    self.uc.reg_write(UC_MIPS_REG_S5, self.conf.registers.s5)
    self.uc.reg_write(UC_MIPS_REG_S6, self.conf.registers.s6)
    self.uc.reg_write(UC_MIPS_REG_S7, self.conf.registers.s7)
    # temporary)
    self.uc.reg_write(UC_MIPS_REG_T0, self.conf.registers.t0)
    self.uc.reg_write(UC_MIPS_REG_T1, self.conf.registers.t1)
    self.uc.reg_write(UC_MIPS_REG_T2, self.conf.registers.t2)
    self.uc.reg_write(UC_MIPS_REG_T3, self.conf.registers.t3)
    self.uc.reg_write(UC_MIPS_REG_T4, self.conf.registers.t4)
    self.uc.reg_write(UC_MIPS_REG_T5, self.conf.registers.t5)
    self.uc.reg_write(UC_MIPS_REG_T6, self.conf.registers.t6)
    self.uc.reg_write(UC_MIPS_REG_T7, self.conf.registers.t7)
    self.uc.reg_write(UC_MIPS_REG_T7, self.conf.registers.t8)
    self.uc.reg_write(UC_MIPS_REG_T7, self.conf.registers.t9)
    # division )
    self.uc.reg_write(UC_MIPS_REG_HI, self.conf.registers.hi)
    self.uc.reg_write(UC_MIPS_REG_LO, self.conf.registers.lo)
    # return values)
    self.uc.reg_write(UC_MIPS_REG_V0, self.conf.registers.v0)
    self.uc.reg_write(UC_MIPS_REG_V1, self.conf.registers.v1)
    # exec )
    self.uc.reg_write(UC_MIPS_REG_GP, self.conf.registers.gp)
    self.uc.reg_write(UC_MIPS_REG_FP, self.conf.registers.fp)
    if self.conf.registers.sp in range(self.conf.stk_ba,self.conf.stk_ba+stk_p*self.conf.p_size):
      self.uc.reg_write(UC_MIPS_REG_SP,self.conf.registers.sp)
    else:
      warn = '[%s] SP value does not belong to the stack'%'MipsCorn'
      warn += 'using default address : %8X'%(self.conf.stk_ba+stk_p*self.conf.p_size-4)
      logger.console(LogType.WARN,warn)
      self.uc.reg_write(UC_MIPS_REG_SP,self.conf.stk_ba+stk_p*self.conf.p_size-4)
    self.uc.reg_write(UC_MIPS_REG_RA, self.conf.registers.ra)
    # misc (kernel)
    self.uc.reg_write(UC_MIPS_REG_K0, self.conf.registers.k0)
    self.uc.reg_write(UC_MIPS_REG_K1, self.conf.registers.k1)




  def reset_regs(self):
    self.uc.reg_write(UC_MIPS_REG_AT, 0)
    #arguments)
    self.uc.reg_write(UC_MIPS_REG_A0, 0)
    self.uc.reg_write(UC_MIPS_REG_A1, 0)
    self.uc.reg_write(UC_MIPS_REG_A2, 0)
    self.uc.reg_write(UC_MIPS_REG_A3, 0)
    # saved)
    self.uc.reg_write(UC_MIPS_REG_S0, 0)
    self.uc.reg_write(UC_MIPS_REG_S1, 0)
    self.uc.reg_write(UC_MIPS_REG_S2, 0)
    self.uc.reg_write(UC_MIPS_REG_S3, 0)
    self.uc.reg_write(UC_MIPS_REG_S4, 0)
    self.uc.reg_write(UC_MIPS_REG_S5, 0)
    self.uc.reg_write(UC_MIPS_REG_S6, 0)
    self.uc.reg_write(UC_MIPS_REG_S7, 0)
    # temporary)
    self.uc.reg_write(UC_MIPS_REG_T0, 0)
    self.uc.reg_write(UC_MIPS_REG_T1, 0)
    self.uc.reg_write(UC_MIPS_REG_T2, 0)
    self.uc.reg_write(UC_MIPS_REG_T3, 0)
    self.uc.reg_write(UC_MIPS_REG_T4, 0)
    self.uc.reg_write(UC_MIPS_REG_T5, 0)
    self.uc.reg_write(UC_MIPS_REG_T6, 0)
    self.uc.reg_write(UC_MIPS_REG_T7, 0)
    # division )
    self.uc.reg_write(UC_MIPS_REG_HI, 0)
    self.uc.reg_write(UC_MIPS_REG_LO, 0)
    # return values)
    self.uc.reg_write(UC_MIPS_REG_V0, 0)
    self.uc.reg_write(UC_MIPS_REG_V1, 0)
    # exec )
    self.uc.reg_write(UC_MIPS_REG_GP, 0)
    self.uc.reg_write(UC_MIPS_REG_FP, 0)
    self.uc.reg_write(UC_MIPS_REG_RA, 0)
    self.uc.reg_write(UC_MIPS_REG_SP, 0)
    self.uc.reg_write(UC_MIPS_REG_SP, 0)
    self.uc.reg_write(UC_MIPS_REG_PC, 0)
  

    self.uc.reg_write(UC_MIPS_REG_K0, 0)
    self.uc.reg_write(UC_MIPS_REG_K1, 0)

   


    


  @staticmethod
  def reg_convert(reg_id):
    if type(reg_id) == type(str()):
      return MipsCorn.str2reg(reg_id)
    elif type(reg_id) == type(int()):
      return MipsCorn.int2reg(reg_id)
    else:
      raise Exception('[reg_convert] unhandled conversion for type %s'%type(reg_id))

  @staticmethod
  def int2reg(reg_id):
    raise NotImplemented

  @staticmethod           
  def str2reg(r_str):

    if r_str == '0':
      return UC_MIPS_REG_0
    elif r_str == 'at':
      return UC_MIPS_REG_AT
    elif r_str == 'a0':
      return UC_MIPS_REG_A0  
    elif r_str == 'a1':
      return UC_MIPS_REG_A1 
    elif r_str == 'a2':
      return UC_MIPS_REG_A2
    elif r_str == 'a3':
      return UC_MIPS_REG_A3  
    elif r_str == 's0':
      return UC_MIPS_REG_S0  
    elif r_str == 's1':
      return UC_MIPS_REG_S1 
    elif r_str == 's2':
      return UC_MIPS_REG_S2
    elif r_str == 's3':
      return UC_MIPS_REG_S3  
    elif r_str == 's4':
      return UC_MIPS_REG_S4  
    elif r_str == 's5':
      return UC_MIPS_REG_S5 
    elif r_str == 's6':
      return UC_MIPS_REG_S6
    elif r_str == 's7':
      return UC_MIPS_REG_S7  
    elif r_str == 't0':
      return UC_MIPS_REG_T0  
    elif r_str == 't1':
      return UC_MIPS_REG_T1 
    elif r_str == 't2':
      return UC_MIPS_REG_T2
    elif r_str == 't3':
      return UC_MIPS_REG_T3  
    elif r_str == 't4':
      return UC_MIPS_REG_T4  
    elif r_str == 't5':
      return UC_MIPS_REG_T5 
    elif r_str == 't6':
      return UC_MIPS_REG_T6
    elif r_str == 't7':
      return UC_MIPS_REG_T7  
    elif r_str == 'v0':
      return UC_MIPS_REG_V0
    elif r_str == 'v1':
      return UC_MIPS_REG_V1
    elif r_str == 'k0':
      return UC_MIPS_REG_K0
    elif r_str == 'k1':
      return UC_MIPS_REG_K1
    elif r_str == 'hi':
      return UC_MIPS_REG_HI
    elif r_str == 'LO':
      return UC_MIPS_REG_LO
    elif r_str == 'ra':
      return UC_MIPS_REG_RA
    elif r_str == 'fp':
      return UC_MIPS_REG_FP
    elif r_str == 'gp':
      return UC_MIPS_REG_GP
    elif r_str == 'sp':
      return UC_MIPS_REG_SP
    elif r_str == 'pc':
      return UC_MIPS_REG_PC


  @staticmethod
  def skip_intr(uc,intno,user_data):
    return True

    
    

  
  def print_registers(self):
    strout   = 'Registrs:\n' 
    strout  += '[at = %8X] [a0 = %8X] [a1 = %8X] [a2 = %8X] [a3 = %8X]\n'%(self.uc.reg_read(UC_MIPS_REG_AT),
                                                                        self.uc.reg_read(UC_MIPS_REG_A0),
                                                                        self.uc.reg_read(UC_MIPS_REG_A1),
                                                                        self.uc.reg_read(UC_MIPS_REG_A2),
                                                                        self.uc.reg_read(UC_MIPS_REG_A3))

    strout  += '[s0 = %8X] [s1 = %8X] [s2 = %8X] [s3 = %8X] [s4 = %8X]\n'%(self.uc.reg_read(UC_MIPS_REG_S0),
                                                                        self.uc.reg_read(UC_MIPS_REG_S1),
                                                                        self.uc.reg_read(UC_MIPS_REG_S2),
                                                                        self.uc.reg_read(UC_MIPS_REG_S3),
                                                                        self.uc.reg_read(UC_MIPS_REG_S4))

    strout  += '[s5 = %8X] [s6 = %8X] [s7 = %8X] [s8 = %8X] [hi = %8X]\n'%(self.uc.reg_read(UC_MIPS_REG_S5),
                                                                        self.uc.reg_read(UC_MIPS_REG_S6),
                                                                        self.uc.reg_read(UC_MIPS_REG_S7),
                                                                        self.uc.reg_read(UC_MIPS_REG_S8),
                                                                        self.uc.reg_read(UC_MIPS_REG_HI))

    strout  += '[t0 = %8X] [t1 = %8X] [t2 = %8X] [t3 = %8X] [lo = %8X]\n'%(self.uc.reg_read(UC_MIPS_REG_T0),
                                                                        self.uc.reg_read(UC_MIPS_REG_T1),
                                                                        self.uc.reg_read(UC_MIPS_REG_T2),
                                                                        self.uc.reg_read(UC_MIPS_REG_T3),
                                                                        self.uc.reg_read(UC_MIPS_REG_LO))

    strout  += '[t4 = %8X] [t5 = %8X] [t6 = %8X] [t7 = %8X] [t8 = %8X]\n'%(self.uc.reg_read(UC_MIPS_REG_T4),
                                                                        self.uc.reg_read(UC_MIPS_REG_T5),
                                                                        self.uc.reg_read(UC_MIPS_REG_T6),
                                                                        self.uc.reg_read(UC_MIPS_REG_T7),
                                                                        self.uc.reg_read(UC_MIPS_REG_T8))

    strout  += '[v0 = %8X] [v1 = %8X] [k0 = %8X] [k1 = %8X] [ra = %8X]\n'%(self.uc.reg_read(UC_MIPS_REG_V0),
                                                                        self.uc.reg_read(UC_MIPS_REG_V1),
                                                                        self.uc.reg_read(UC_MIPS_REG_K0),
                                                                        self.uc.reg_read(UC_MIPS_REG_K1),
                                                                        self.uc.reg_read(UC_MIPS_REG_RA))

    strout  += '[t9 = %8X] [gp = %8X] [fp = %8X] [sp = %8X] [pc = %8X]\n'%(self.uc.reg_read(UC_MIPS_REG_T9),
                                                                        self.uc.reg_read(UC_MIPS_REG_GP),
                                                                        self.uc.reg_read(UC_MIPS_REG_FP),
                                                                        self.uc.reg_read(UC_MIPS_REG_SP),
                                                                        self.uc.reg_read(UC_MIPS_REG_PC))
    logger.console(LogType.INFO,strout)


  @staticmethod
  def unmp_read(uc,access,addr,value,size,user_data):

    unimips = user_data
    pc = uc.reg_read(UC_MIPS_REG_PC)
    if unimips.conf.s_conf.stub_pltgot_entries: 
      if pc in range(consts_mips.TRAMPOLINE_ADDR, consts_mips.TRAMPOLINE_ADDR+unimips.trampoline_size):
        index = (pc -0x1000) // consts_mips.TRAMPOLINE_SIZE 
        try:
          if unimips.pinf['endianness'] == 'little':
#             stubs.Arm.libc_stubs_mipsl[index].do_it(unimips.helper)
            ELF.libc_stubs_mipsl[index].do_it()
          else: 
#             stubs.Arm.libc_stubs_mipsb[index].do_it(unimips.helper)
            ELF.libc_stubs_mipsb[index].do_it(unimips.helper)
          uc.mem_map(0,unimips.conf.p_size)
          uc.mem_write(0,'trap'.encode('utf-8')*(unimips.conf.p_size//4))
          return True
        except Exception as e: 
          logger.console(LogType.ERRR,'[intr_handler] error in stubs code')
          raise e
       

    Emucorn.unmp_read(uc,access,addr,value,size,unimips.conf) 
    
    


  @staticmethod
  def read_after(uc,access,addr,value,size,user_data):
    p_size = user_data
    print('[!] Read After addr: %x, size: %d'%(addr,size))
    if addr == 0:
      try:
        uc.mem_unmap(0,p_size)
      except:
        print('error unmmap')
    return True
    
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




# if __name__ == '__main__':

    #""" PCSX SSTIC Challenge """ 
#   conf=                    Configuration(p_size=0x100,
#                            stk_ba=0x80040000,
#                            stk_size=0x1000,
#                            autoMap=True,
#                            showRegisters=True,
#                            exec_saddr=0x8001A2A4,
#                            exec_eaddr=0x8001A2C4,
#                            mapping_saddr=0x8001A2A4,
#                            mapping_eaddr=0x8001B000,
#                            segms=[],
#                            map_with_segs=False,
#                            use_seg_perms=True,
#                            useCapstone=True,
#                            registers=MipslRegisters(at=0,a0=0,a1=0,a2=0,a3=0,s0=0,s1=0,s2=0,s3=0,s4=0,s5=0,s6=0,s7=0,k0=0,k1=0,
#                                                     t0=0,t1=0,t2=0,t3=0,t4=0,t5=0,t6=0,t7=0,v0=0,v1=0,hi=0,lo=0,sp=0,fp=0,gp=0,ra=0),
#                            showMemAccess=True,
#                            s_conf=StubConfiguration({},False,False),
#                            amap_conf=AdditionnalMapping({}))
# 
#   conf=                    Configuration(p_size=0x1000,
#                            stk_ba=0x80000000,
#                            stk_size=0x1000,
#                            autoMap=True,
#                            showRegisters=True,
#                            exec_saddr=402500,
#                            exec_eaddr=402530,
#                            mapping_saddr=0x400000,
#                            mapping_eaddr=0x42A600,
#                            segms=[],
#                            map_with_segs=False,
#                            use_seg_perms=True,
#                            useCapstone=True,
#                            registers=MipslRegisters(at=0,a0=0,a1=0,a2=0,a3=0,s0=0,s1=0,s2=0,s3=0,s4=0,s5=0,s6=0,s7=0,k0=0,k1=0,t9=0,
#                                                     t0=0,t1=0,t2=0,t3=0,t4=0,t5=0,t6=0,t7=0,v0=0,v1=0,hi=0,lo=0,sp=0,fp=0,gp=0,ra=0),
#                            showMemAccess=True,
#                            s_conf=StubConfiguration({},False,False),
#                            amap_conf=AdditionnalMapping({}))
# 
#   emu = MipsCorn(conf)
#   
# 
#   emu.start()
