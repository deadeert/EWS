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


if __name__ == '__main__':
    # test open
    regs = RegArm32Edit.create()
    print('%x'%regs.R0)
    # test passing argument 
    regs = RegArm32Edit.create(regs)
    # test are argument properly refreshed when modified 
    #regs = RegArm32Edit.create(regs) 
class RegArm64Edit(ida_kernwin.Form):


    def __init__(self,regs):
        self.regs = regs
        Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
Reg Edit AARCH64
{cbCallback}
<## AutoMap missing regions## No:{aNo}> <Yes:{aYes}>{cAGrp}> 
Execution Configuration
<##Start address:{sAddr}> | <##End address:{eAddr}>
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
