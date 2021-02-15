import ida_kernwin
from ida_kernwin import Form
from utils.utils import * 

class RegArm32Edit(ida_kernwin.Form):


    def __init__(self,regs):
        self.regs = regs
        Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
EWS ARML32
{cbCallback}
Edit Registers
<##R0:{R0}>  |<##R1:{R1}>  |<##R2:{R2}>  |<##R3:{R3}>
<##R4:{R4}>  |<##R5:{R5}>  |<##R6:{R6}>  |<##R7:{R7}>
<##R8:{R8}> |<##R9:{R9}>   |<##R10:{R10}> |<##R11:{R11}>
<##R12:{R12}>|<##SP:{R13}> |<##LR:{R14}>  |<##PC:{R15}>
<## Refresh Button: {refreshButton}>
""",{
            'R0': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R1': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R2': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R3': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R4': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R5': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R6': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R7': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R8': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R9': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R10': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R11': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R12': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R13': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R14': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R15': Form.NumericInput(tp=Form.FT_RAWHEX),
            'cbCallback': Form.FormChangeCb(self.onCallback),
            'refreshButton': Form.ButtonInput(self.onRefreshButton)})



    def onRefreshButton(self,code):
        if self.regs != None:
            self.SetControlValue(self.R0,self.regs.R0)
            self.SetControlValue(self.R1,self.regs.R1)
            self.SetControlValue(self.R2,self.regs.R2)
            self.SetControlValue(self.R3,self.regs.R3)
            self.SetControlValue(self.R4,self.regs.R4)
            self.SetControlValue(self.R5,self.regs.R5)
            self.SetControlValue(self.R6,self.regs.R6)
            self.SetControlValue(self.R7,self.regs.R7)
            self.SetControlValue(self.R8,self.regs.R8)
            self.SetControlValue(self.R9,self.regs.R9)
            self.SetControlValue(self.R10,self.regs.R10)
            self.SetControlValue(self.R11,self.regs.R11)
            self.SetControlValue(self.R12,self.regs.R12)
            self.SetControlValue(self.R13,self.regs.R13)
            self.SetControlValue(self.R14,self.regs.R14)
            self.SetControlValue(self.R15,self.regs.R15)
        return True

    def onCallback(self,fid):
        return True


    @staticmethod
    def create(regs=None):
      regform = RegArm32Edit(regs)
      regform.Compile()
      ok = regform.Execute()
      if ok:
          return ArmRegisters(R0=regform.R0.value,
                              R1=regform.R1.value,
                              R2=regform.R2.value,
                              R3=regform.R3.value,
                              R4=regform.R4.value,
                              R5=regform.R5.value,
                              R6=regform.R6.value,
                              R7=regform.R7.value,
                              R8=regform.R8.value,
                              R9=regform.R9.value,
                              R10=regform.R10.value,
                              R11=regform.R11.value,
                              R12=regform.R12.value,
                              R13=regform.R13.value,
                              R14=regform.R14.value,
                              R15=regform.R15.value)


class RegArm64Edit(ida_kernwin.Form):


    def __init__(self,regs):
        self.regs = regs
        Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
Reg Edit AARCH64
{cbCallback}
<##X0:{X0}>  |<##X1:{X1}>  |<##X2:{X2}>  |<##X3:{X3}> |<##X4:{X4}>
<##X5:{X5}>  |<##X6:{X6}>  |<##X7:{X7}>  |<##X8:{X8}> |<##X9:{X9}>
<##X10:{X10}> |<##X11:{X11}>| <##X12:{X12}>|<##SP:{X13}>
<##X14:{X14}> |<##X15:{X15}>|<##X16:{X16}>|<##X17:{X17}>
<##X18:{X18}> |<##X19:{X19}>|<##X20:{X20}>|<##X21:{X21}>
<##X22:{X22}> |<##X23:{X23}>|<##X24:{X24}>|<##X25:{X25}>
<##X26:{X26}> |<##X27:{X27}>|<##X28:{X28}>|<##FP:{FP}>
<##LR:{LR}>  |<##SP:{SP}>|<##PC:{PC}>
<## Refresh Button: {refreshButton}>
""",{
            'X0': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X1': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X2': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X3': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X4': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X5': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X6': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X7': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X8': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X9': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X10': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X11': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X12': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X13': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X14': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X15': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X16': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X17': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X18': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X19': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X20': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X21': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X22': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X23': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X24': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X25': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X26': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X27': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X28': Form.NumericInput(tp=Form.FT_RAWHEX),
            'FP': Form.NumericInput(tp=Form.FT_RAWHEX),
            'LR': Form.NumericInput(tp=Form.FT_RAWHEX),
            'SP': Form.NumericInput(tp=Form.FT_RAWHEX),
            'PC': Form.NumericInput(tp=Form.FT_RAWHEX),
            'cbCallback': Form.FormChangeCb(self.onCallback),
            'refreshButton': Form.ButtonInput(self.onRefreshButton)})



    def onRefreshButton(self,code):
        if self.regs != None:
          self.SetControlValue(self.X0,self.regs.X0)
          self.SetControlValue(self.X1,self.regs.X1)
          self.SetControlValue(self.X2,self.regs.X2)
          self.SetControlValue(self.X3,self.regs.X3)
          self.SetControlValue(self.X4,self.regs.X4)
          self.SetControlValue(self.X5,self.regs.X5)
          self.SetControlValue(self.X6,self.regs.X6)
          self.SetControlValue(self.X7,self.regs.X7)
          self.SetControlValue(self.X8,self.regs.X8)
          self.SetControlValue(self.X9,self.regs.X9)
          self.SetControlValue(self.X10,self.regs.X10)
          self.SetControlValue(self.X11,self.regs.X11)
          self.SetControlValue(self.X12,self.regs.X12)
          self.SetControlValue(self.X13,self.regs.X13)
          self.SetControlValue(self.X14,self.regs.X14)
          self.SetControlValue(self.X15,self.regs.X15)
          self.SetControlValue(self.X16,self.regs.X16)
          self.SetControlValue(self.X17,self.regs.X17)
          self.SetControlValue(self.X18,self.regs.X18)
          self.SetControlValue(self.X19,self.regs.X19)
          self.SetControlValue(self.X20,self.regs.X20)
          self.SetControlValue(self.X21,self.regs.X21)
          self.SetControlValue(self.X22,self.regs.X22)
          self.SetControlValue(self.X23,self.regs.X23)
          self.SetControlValue(self.X24,self.regs.X24)
          self.SetControlValue(self.X25,self.regs.X25)
          self.SetControlValue(self.X26,self.regs.X26)
          self.SetControlValue(self.X27,self.regs.X27)
          self.SetControlValue(self.X28,self.regs.X28)
          self.SetControlValue(self.FP,self.regs.FP)
          self.SetControlValue(self.LR,self.regs.LR)
          self.SetControlValue(self.SP,self.regs.SP)
          self.SetControlValue(self.PC,self.regs.PC)

    @staticmethod
    def create(regs=None):
      regform = RegArm32Edit(regs)
      regform.Compile()
      ok = regform.Execute()
      if ok:
          return Aarch64Registers(regform.X0.value,
                                                     regform.X1.value,
                                                     regform.X2.value,
                                                     regform.X3.value,
                                                     regform.X4.value,
                                                     regform.X5.value,
                                                     regform.X6.value,
                                                     regform.X7.value,
                                                     regform.X8.value,
                                                     regform.X9.value,
                                                     regform.X10.value,
                                                     regform.X11.value,
                                                     regform.X12.value,
                                                     regform.X13.value,
                                                     regform.X14.value,
                                                     regform.X15.value,
                                                     regform.X16.value,
                                                     regform.X17.value,
                                                     regform.X18.value,
                                                     regform.X19.value,
                                                     regform.X20.value,
                                                     regform.X21.value,
                                                     regform.X22.value,
                                                     regform.X23.value,
                                                     regform.X24.value,
                                                     regform.X25.value,
                                                     regform.X26.value,
                                                     regform.X27.value,
                                                     regform.X28.value,
                                                     regform.FP.value,
                                                     regform.LR.value,
                                                     regform.SP.value,
                                                     regform.PC.value)
class Regx64Edit(ida_kernwin.Form):

    def __init__(self,regs):
        self.regs = regs
        Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
x64 Reg Edit
{cbCallback}
Edit Registers
 <##RAX:{RAX}>  |<##RBX:{RBX}>  |<##RCX:{RCX}>  |<##RDX:{RDX}> 
 <##RDI:{RDI}>  |<##RSI:{RSI}>  |<##RBP:{RBP}>  |<##RSP:{RSP}> 
 <##R8:{R8}>    |<##R9:{R9}>    |<##R10:{R10}>  |<##R11:{R11}>
 <##R12:{R12}>  |<##R13:{R13}>  |<##R14:{R14}>  |<##R15:{R15}>
 <##RIP:{RIP}>
<## Refresh Button: {refreshButton}>
""",{

            'RAX': Form.NumericInput(tp=Form.FT_RAWHEX),
            'RBX': Form.NumericInput(tp=Form.FT_RAWHEX),
            'RCX': Form.NumericInput(tp=Form.FT_RAWHEX),
            'RDX': Form.NumericInput(tp=Form.FT_RAWHEX),
            'RDI': Form.NumericInput(tp=Form.FT_RAWHEX),
            'RSI': Form.NumericInput(tp=Form.FT_RAWHEX),
            'RBP': Form.NumericInput(tp=Form.FT_RAWHEX),
            'RSP': Form.NumericInput(tp=Form.FT_RAWHEX),
            'RIP': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R8': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R9': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R10': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R11': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R12': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R13': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R14': Form.NumericInput(tp=Form.FT_RAWHEX),
            'R15': Form.NumericInput(tp=Form.FT_RAWHEX),
            'cbCallback': Form.FormChangeCb(self.onCallback),
            'refreshButton': Form.ButtonInput(self.onRefreshButton)})



    def onRefreshButton(self,code):
      if self.regs != None:

          self.SetControlValue(self.RAX,self.regs.RAX)
          self.SetControlValue(self.RBX,self.regs.RBX)
          self.SetControlValue(self.RCX,self.regs.RCX)
          self.SetControlValue(self.RDX,self.regs.RDX)
          self.SetControlValue(self.RDI,self.regs.RDI)
          self.SetControlValue(self.RSI,self.regs.RSI)
          self.SetControlValue(self.RBP,self.regs.RBP)
          self.SetControlValue(self.RSP,self.regs.RSP)
          self.SetControlValue(self.RIP,self.regs.RIP)
          self.SetControlValue(self.RIP,self.regs.R8)
          self.SetControlValue(self.RIP,self.regs.R9)
          self.SetControlValue(self.RIP,self.regs.R10)
          self.SetControlValue(self.RIP,self.regs.R11)
          self.SetControlValue(self.RIP,self.regs.R12)
          self.SetControlValue(self.RIP,self.regs.R13)
          self.SetControlValue(self.RIP,self.regs.R14)
          self.SetControlValue(self.RIP,self.regs.R15)
      return True

    def onCallback(self,fid):
        return True


    @staticmethod
    def create(regs=None):
      regform = Regx64Edit(regs)
      regform.Compile()
      ok = regform.Execute()
      if ok:
          return x64Registers(regform.RAX.value,
                            regform.RBX.value,
                            regform.RCX.value,
                            regform.RDX.value,
                            regform.RSI.value,
                            regform.R8.value,
                            regform.R9.value,
                            regform.R10.value,
                            regform.R11.value,
                            regform.R12.value,
                            regform.R13.value,
                            regform.R14.value,
                            regform.R15.value,
                            regform.RBP.value,
                            regform.RSP.value,
                            regform.RIP.value)

class Regx86Edit(ida_kernwin.Form):

    def __init__(self,regs):
        self.regs = regs
        Form.__init__(self, r"""STARTITEM 
x86 Reg Edit
{cbCallback}
 <##EAX:{EAX}>  |<##EBX:{EBX}>  |<##ECX:{ECX}>
 <##EDX:{EDX}>  |<##EDI:{EDI}>  |<##ESI:{ESI}>
 <##EBP:{EBP}>  |<##ESP:{ESP}>  |<##EIP:{EIP}>
<## Refresh Button: {refreshButton}>
""",{
            'EAX': Form.NumericInput(tp=Form.FT_RAWHEX),
            'EBX': Form.NumericInput(tp=Form.FT_RAWHEX),
            'ECX': Form.NumericInput(tp=Form.FT_RAWHEX),
            'EDX': Form.NumericInput(tp=Form.FT_RAWHEX),
            'EDI': Form.NumericInput(tp=Form.FT_RAWHEX),
            'ESI': Form.NumericInput(tp=Form.FT_RAWHEX),
            'EBP': Form.NumericInput(tp=Form.FT_RAWHEX),
            'ESP': Form.NumericInput(tp=Form.FT_RAWHEX),
            'EIP': Form.NumericInput(tp=Form.FT_RAWHEX),
            'cbCallback': Form.FormChangeCb(self.onCallback),
            'refreshButton': Form.ButtonInput(self.onRefreshButton)})

    def onRefreshButton(self,code):
      if self.regs != None:

          self.SetControlValue(self.EAX,self.regs.EAX)
          self.SetControlValue(self.EBX,self.regs.EBX)
          self.SetControlValue(self.ECX,self.regs.ECX)
          self.SetControlValue(self.EDX,self.regs.EDX)
          self.SetControlValue(self.EDI,self.regs.EDI)
          self.SetControlValue(self.ESI,self.regs.ESI)
          self.SetControlValue(self.EBP,self.regs.EBP)
          self.SetControlValue(self.ESP,self.regs.ESP)
          self.SetControlValue(self.EIP,self.regs.EIP)

      return True

    def onCallback(self,fid):
        return True


    @staticmethod
    def create(regs=None):
      regform = Regx86Edit(regs)
      regform.Compile()
      ok = regform.Execute()
      if ok:
            return x86Registers(regform.EAX.value,
                                                    regform.EBX.value,
                                                    regform.ECX.value,
                                                    regform.EDX.value,
                                                    regform.EDI.value,
                                                    regform.ESI.value,
                                                    regform.EBP.value,
                                                    regform.ESP.value,
                                                    regform.EIP.value)


