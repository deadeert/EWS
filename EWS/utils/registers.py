from EWS.utils import consts_arm
from EWS.utils import consts_aarch64
from EWS.utils import consts_x86
from EWS.utils import consts_x64

class Registers(object):

  def __init__(self):
    pass
  def __str__(self):
    return '\n'.join(['{}: {}'.format(x,self.__dict__[x]) for x in self.__dict__])
  def get_program_counter(self):
    pass

  def get_register_values_l(self) -> list:
    """
    return a list containing current register values
    of the emulator. Used for the debug_panel.
    [ ['reg1', 'value'], [...], ['regn', 'value'] ]
    """
    pass



class ArmRegisters(Registers):
 
  def __init__(self,R0,R1,R2,R3,R4,R5,R6,R7,R8,R9,R10,R11,R12,R13,R14,R15):
    self.R0=R0
    self.R1=R1
    self.R2=R2
    self.R3=R3
    self.R4=R4
    self.R5=R5
    self.R6=R6
    self.R7=R7
    self.R8=R8
    self.R9=R9
    self.R10=R10
    self.R11=R11
    self.R12=R12
    self.R13=R13
    self.R14=R14
    self.R15=R15


  @classmethod
  def create(cls):
      return ArmRegisters(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

  def get_program_counter(self):
      return self.R15

  def get_register_values_l(self) -> list:

      out = list()

      out.append(['R0', hex(self.R0)])
      out.append(['R1', hex(self.R1)])
      out.append(['R2', hex(self.R2)])
      out.append(['R3', hex(self.R3)])
      out.append(['R4', hex(self.R4)])
      out.append(['R5', hex(self.R5)])
      out.append(['R6', hex(self.R6)])
      out.append(['R7', hex(self.R7)])
      out.append(['R8', hex(self.R8)])
      out.append(['R9', hex(self.R9)])
      out.append(['R10', hex(self.R10)])
      out.append(['R11', hex(self.R11)])
      out.append(['R12', hex(self.R12)])
      out.append(['SP', hex(self.R13)])
      out.append(['LR', hex(self.R14)])
      out.append(['PC', hex(self.R15)])

      return out

  @classmethod
  def get_default_object(cls,
                         r13=0,
                         r14=0,
                         r15=0):
        return ArmRegisters(  0x0,
                              0x1,
                              0x2,
                              0x3,
                              0x4,
                              0x5,
                              0x6,
                              0x7,
                              0x8,
                              0x9,
                              0xA,
                              0xB,
                              0xC,
                              consts_arm.STACK_BASEADDR+\
                              consts_arm.STACK_SIZE-\
                              consts_arm.initial_stack_offset if r13 ==0\
                            else r13,
                              r14,
                              r15)


class arm32CPSR(Registers):
  def __init__(self,N,Z,C,V,I,F):
    self.N = N 
    self.Z = Z
    self.C = C 
    self.V = V 
    self.I = I 
    self.F = F


  @classmethod 
  def create(cls,cpsr):
    return arm32CPSR(N=(cpsr&0x80000000)>>31,
                     Z=(cpsr&0x40000000)>>30,
                     C=(cpsr&0x20000000)>>29,
                     V=(cpsr&0x10000000)>>28,
                     I=(cpsr&0x8000000)>>27,
                     F=(cpsr&0x400000)>>26)

  def __str__(self):
    out = '[N=%d Z=%d C=%d V=%d I=%d F=%d] '%(self.N,self.Z,self.C,self.V,self.I,self.F)
    return out



class Aarch64Registers(Registers):
 
  def __init__(self,X0,X1,X2,X3,X4,X5,X6,X7,X8,X9,
                    X10,X11,X12,X13,X14,X15,X16,X17,X18,X19,
                    X20,X21,X22,X23,X24,X25,X26,X27,X28,X29,X30,X31,PC):
    self.X0=X0
    self.X1=X1
    self.X2=X2
    self.X3=X3
    self.X4=X4
    self.X5=X5
    self.X6=X6
    self.X7=X7
    self.X8=X8
    self.X9=X9
    self.X10=X10
    self.X11=X11
    self.X12=X12
    self.X13=X13
    self.X14=X14
    self.X15=X15
    self.X16=X16
    self.X17=X17
    self.X18=X18
    self.X19=X19
    self.X20=X20
    self.X21=X21
    self.X22=X22
    self.X23=X23
    self.X24=X24
    self.X25=X25
    self.X26=X26
    self.X27=X27
    self.X28=X28
    self.X29=X29
    self.X30=X30
    self.X31=X31
    self.PC=PC

  def get_program_counter(self):
      return self.PC

  @classmethod
  def create(cls):
      return Aarch64Registers(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                          0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

  @classmethod
  def get_default_object(cls,X0=0,X1=0,X2=0,X3=0,X4=0,X5=0,X6=0,X7=0,X8=0,X9=0,
                    X10=0,X11=0,X12=0,X13=0,X14=0,X15=0,X16=0,X17=0,X18=0,X19=0,
                    X20=0,X21=0,X22=0,X23=0,X24=0,X25=0,X26=0,X27=0,X28=0,X29=0,
                         X30=0,X31=0,PC=0):
      return Aarch64Registers(   X0,
                                 X1,
                                 X2,
                                 X3,
                                 X4,
                                 X5,
                                 X6,
                                 X7,
                                 X8,
                                 X9,
                                 X10,
                                 X11,
                                 X12,
                                 X13,
                                 X14,
                                 X15,
                                 X16,
                                 X17,
                                 X18,
                                 X19,
                                 X20,
                                 X21,
                                 X22,
                                 X23,
                                 X24,
                                 X25,
                                 X26,
                                 X27,
                                 X28,
                                 X29,
                                 X30, # X30
                                 consts_aarch64.STACK_BASEADDR+\
                                 consts_aarch64.STACK_SIZE-\
                                 consts_aarch64.initial_stack_offset if X31==0 else X31,
                                 PC)


  def get_register_values_l(self) -> list:

      out = list()

      out.append(['X0', hex(self.X0)])
      out.append(['X1', hex(self.X1)])
      out.append(['X2', hex(self.X2)])
      out.append(['X3', hex(self.X3)])
      out.append(['X4', hex(self.X4)])
      out.append(['X5', hex(self.X5)])
      out.append(['X6', hex(self.X6)])
      out.append(['X7', hex(self.X7)])
      out.append(['X8', hex(self.X8)])
      out.append(['X9', hex(self.X9)])
      out.append(['X10', hex(self.X10)])
      out.append(['X11', hex(self.X11)])
      out.append(['X12', hex(self.X12)])
      out.append(['X13', hex(self.X13)])
      out.append(['X14', hex(self.X14)])
      out.append(['X15', hex(self.X15)])
      out.append(['X16', hex(self.X16)])
      out.append(['X17', hex(self.X17)])
      out.append(['X18', hex(self.X18)])
      out.append(['X19', hex(self.X19)])
      out.append(['X20', hex(self.X20)])
      out.append(['X21', hex(self.X21)])
      out.append(['X22', hex(self.X22)])
      out.append(['X23', hex(self.X23)])
      out.append(['X24', hex(self.X24)])
      out.append(['X25', hex(self.X25)])
      out.append(['X26', hex(self.X26)])
      out.append(['X27', hex(self.X27)])
      out.append(['X28', hex(self.X28)])
      out.append(['SP', hex(self.X31)])
      out.append(['LR', hex(self.X30)])
      out.append(['FP', hex(self.X29)])
      out.append(['PC', hex(self.PC)])

      return out



class aarch64CPSR(Registers):
  def __init__(self,N,Z,C,V,I,F):
    self.N = N 
    self.Z = Z
    self.C = C 
    self.V = V 
    self.I = I 
    self.F = F


  @classmethod 
  def create(cls,cpsr):
    return aarch64CPSR(N=(cpsr&0x80000000)>>31,
                     Z=(cpsr&0x40000000)>>30,
                     C=(cpsr&0x20000000)>>29,
                     V=(cpsr&0x10000000)>>28,
                     I=(cpsr&0x8000000)>>27,
                     F=(cpsr&0x400000)>>26)

  def __str__(self):
    out = '[N=%d Z=%d C=%d V=%d I=%d F=%d] '%(self.N,self.Z,self.C,self.V,self.I,self.F)
    return out




class MipslRegisters(Registers): 
  """ Based on https://en.wikibooks.org/wiki/MIPS_Assembly/Register_File
  """
  def __init__(self,at,a0,a1,a2,a3,s0,s1,s2,s3,s4,s5,s6,s7,k0,k1,pc,
                   t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,v0,v1,hi,lo,sp,fp,gp,ra):
    self.at = at
    #arguments
    self.a0 = a0
    self.a1 = a1 
    self.a2 = a2
    self.a3 = a3
    # saved
    self.s0 = s0
    self.s1 = s1 
    self.s2 = s2 
    self.s3 = s3
    self.s4 = s4
    self.s5 = s5 
    self.s6 = s6
    self.s7 = s7
    # temporary
    self.t0 = t0
    self.t1 = t1 
    self.t2 = t2 
    self.t3 = t3
    self.t4 = t4
    self.t5 = t5 
    self.t6 = t6
    self.t7 = t7
    self.t8 = t8
    self.t9 = t9
    # division 
    self.hi = hi
    self.lo = lo 
    # return values
    self.v0 = v0
    self.v1 = v1
    # exec 
    self.gp = gp
    self.fp = fp
    self.sp = sp
    self.ra = ra
    self.pc = pc
    # misc (kernel)
    self.k0 = k0
    self.k1 = k1 

  def get_program_counter(self):
      return self.pc
 

    
class x86Registers(Registers):

  def __init__(self,EAX,EBX,ECX,EDX,EDI,ESI,EBP,ESP,EIP):

    self.EAX = EAX
    self.EBX = EBX 
    self.ECX = ECX
    self.EDX = EDX
    self.EDI = EDI
    self.ESI = ESI 
    self.ESP = ESP
    self.EBP = EBP
    self.EIP = EIP

  @classmethod
  def create(cls):

      return x86Registers(0,0,0,0,0,0,0,0,0)

  def get_program_counter(self):
      return self.EIP


  def get_register_values_l(self) -> list:

    out = list()
    out.append(['EAX', hex(self.EAX)])
    out.append(['EBX', hex(self.EBX)])
    out.append(['ECX', hex(self.ECX)])
    out.append(['EDX', hex(self.EDX)])
    out.append(['EDI', hex(self.EDI)])
    out.append(['ESI', hex(self.ESI)])
    out.append(['EBP', hex(self.EBP)])
    out.append(['ESP', hex(self.ESP)])
    out.append(['EIP', hex(self.EIP)])


    return out

  @classmethod
  def get_default_object(cls,EAX=0,
                            EBX=1,
                            ECX=2,
                            EDX=3,
                            EDI=4,
                            ESI=5,
                            EBP=consts_x86.STACK_BASEADDR+consts_x86.STACK_SIZE-\
                             consts_x86.initial_stack_offset,
                            ESP=consts_x86.STACK_BASEADDR+consts_x86.STACK_SIZE-\
                             consts_x86.initial_stack_offset,
                            EIP=0):
      return x86Registers(EAX,EBX,ECX,EDX,EDI,ESI,EBP,ESP,EIP)

class x86EFLAGS(Registers):
  def __init__(self,CF,PF,AF,ZF,SF,TF,EIF,DF,OF):
    self.CF = CF
    self.PF = PF 
    self.AF = AF
    self.ZF = ZF
    self.SF = SF
    self.TF = TF
    self.EIF = EIF
    self.DF = DF 
    self.OF = OF 

  @classmethod 
  def create(cls,eflags):
    return x86EFLAGS(CF=(eflags)&0x1,
                     PF=(eflags&0x4)>>2,
                     AF=(eflags&0x10)>>4,
                     ZF=(eflags&0x40)>>6,
                     SF=(eflags&0x80)>>7,
                     TF=(eflags&0x100)>>8,
                     EIF=(eflags&0x200)>>9,
                     DF=(eflags&0x400)>>10,
                     OF=(eflags&0x800)>>11)

  def __str__(self):
    out = '[ZF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d EIF=%d DF=%d OF=%d]'%(self.CF,
                                                                      self.PF,
                                                                      self.AF,
                                                                      self.ZF,
                                                                      self.SF,
                                                                      self.TF,
                                                                      self.EIF,
                                                                      self.DF,
                                                                      self.OF)
    return out


  
class x64Registers(Registers):
  
  def __init__(self,RAX,RBX,RCX,RDX,RDI,RSI,R8,R9,R10,R11,R12,R13,R14,R15,RBP,RSP,RIP):
    self.RAX = RAX
    self.RBX = RBX
    self.RCX = RCX
    self.RDX = RDX
    self.RDI = RDI 
    self.RSI = RSI
    self.R8 = R8
    self.R9 = R9
    self.R10 = R10
    self.R11 = R11
    self.R12 = R12
    self.R13 = R13
    self.R14 = R14
    self.R15 = R15
    self.RBP = RBP 
    self.RSP = RSP 
    self.RIP = RIP 

  def __str__(self) -> str:

    strout =  '[RAX=%.8X] [RBX=%.8X] [RCX=%.8X] [RDX=%.8X]\n'%(self.RAX,
                                                         self.RBX,
                                                         self.RCX,
                                                         self.RDX)
    strout += '[RDI=%.8X] [RSI=%.8X] [RBP=%.8X] [RSP=%.8X]\n'%(self.RDI,
                                                         self.RSI,
                                                         self.RBP,
                                                         self.RSP)
    strout += '[R8=%.8X] [R9=%.8X] [R10=%.8X] [R11=%.8X]\n'%(self.R8,
                                                            self.R9,
                                                            self.R10,
                                                            self.R11)
    strout += '[R12=%.8X] [R13=%.8X] [R14=%.8X] [R15=%.8X]\n'%(self.R12,
                                                            self.R13,
                                                            self.R14,
                                                            self.R15)
    return strout

  def get_program_counter(self):
      return self.RIP
 
  def get_register_values_l(self) -> list:

      out = list()
      out.append(['RAX', hex(self.RAX)])
      out.append(['RBX', hex(self.RBX)])
      out.append(['RCX', hex(self.RCX)])
      out.append(['RDX', hex(self.RDX)])
      out.append(['RDI', hex(self.RDI)])
      out.append(['RSI', hex(self.RSI)])
      out.append(['RBP', hex(self.RBP)])
      out.append(['RSP', hex(self.RSP)])
      out.append(['RIP', hex(self.RIP)])
      out.append(['R8', hex(self.R8)])
      out.append(['R9', hex(self.R9)])
      out.append(['R10', hex(self.R10)])
      out.append(['R11', hex(self.R11)])
      out.append(['R12', hex(self.R12)])
      out.append(['R13', hex(self.R13)])
      out.append(['R14', hex(self.R14)])
      out.append(['R15', hex(self.R15)])

      return out

  @classmethod
  def get_default_object(cls,RAX=0,
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
                             RBP=consts_x64.STACK_BASEADDR+consts_x64.STACK_SIZE-\
                             consts_x64.initial_stack_offset,
                             RSP=consts_x64.STACK_BASEADDR+consts_x64.STACK_SIZE-\
                             consts_x64.initial_stack_offset,
                             RIP=0):
      return x64Registers(RAX,RBX,RCX,RDX,RDI,RSI,R8,R9,R10,R11,R12,R13,R14,R15,RBP,RSP,RIP)




class x64RFLAGS(Registers):
  def __init__(self,CF,PF,AF,ZF,SF,TF,EIF,DF,OF):
    self.CF = CF
    self.PF = PF 
    self.AF = AF
    self.ZF = ZF
    self.SF = SF
    self.TF = TF
    self.EIF = EIF
    self.DF = DF 
    self.OF = OF 

  @classmethod 
  def create(cls,eflags):
    return x64RFLAGS(CF=(eflags)&0x1,
                     PF=(eflags&0x4)>>2,
                     AF=(eflags&0x10)>>4,
                     ZF=(eflags&0x40)>>6,
                     SF=(eflags&0x80)>>7,
                     TF=(eflags&0x100)>>8,
                     EIF=(eflags&0x200)>>9,
                     DF=(eflags&0x400)>>10,
                     OF=(eflags&0x800)>>11)

  def __str__(self):
    out = '[ZF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d EIF=%d DF=%d OF=%d]'%(self.CF,
                                                                      self.PF,
                                                                      self.AF,
                                                                      self.ZF,
                                                                      self.SF,
                                                                      self.TF,
                                                                      self.EIF,
                                                                      self.DF,
                                                                      self.OF)
    return out



