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
    Edit Registers
 <##R0:{R0}>  |<##R1:{R1}>  |<##R2:{R2}>  |<##R3:{R3}>
 <##R4:{R4}>  |<##R5:{R5}>  |<##R6:{R6}>  |<##R7:{R7}>
 <##R8:{R8}>  |<##R9:{R9}>  |<##R10:{R10}> |<##R11:{R11}>
 <##R12:{R12}>|<##SP:{R13}> |<##LR:{R14}>  |<##PC:{R15}>
 <## Refresh Value {refreshButton}>
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
            'refreshButton': Form.ButtonInput(self.onRefreshButton)})

    def onRefreshButton(self,code):
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


    @staticmethod
    def create(regs=None):
      regform = RegArm32Edit(regs)
      regform.Compile()
      ok = regform.Execute()
      if ok:
          return ArmRegisters(R0=regform.R0,
                              R1=regform.R1,
                              R2=regform.R2,
                              R3=regform.R3,
                              R4=regform.R4,
                              R5=regform.R5,
                              R6=regform.R6,
                              R7=regform.R7,
                              R8=regform.R8,
                              R9=regform.R9,
                              R10=regform.R10,
                              R11=regform.R11,
                              R12=regform.R12,
                              R13=regform.R13,
                              R14=regform.R14,
                              R15=regform.R15)


if __name__ == '__main__':

    # test open
    regs = RegArm32Edit.create()
    # test passing argument 
    regs = RegArm32Edit.create(regs)
    # test are argument properly refreshed when modified 
    regs = RegArm32Edit.create(regs) 

