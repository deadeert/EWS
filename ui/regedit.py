import ida_kernwin
from ida_kernwin import Form
from utils.utils import * 

DescFormARM = r"""STARTITEM 
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
"""


class RegArm32Edit(ida_kernwin.Form):


    def __init__(self,regs):
        self.regs = regs
        if self.regs == None:
            Form.__init__(self, DescFormARM,{
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
            'cbCallback': Form.FormChangeCb(self.onCallback)})
        else:
            Form.__init__(self, DescFormARM,{
            'R0': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R0),
            'R1': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R1),
            'R2': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R2),
            'R3': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R3),
            'R4': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R4),
            'R5': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R5),
            'R6': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R6),
            'R7': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R7),
            'R8': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R8),
            'R9': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R9),
            'R10': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R10),
            'R11': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R11),
            'R12': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R12),
            'R13': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R13),
            'R14': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R14),
            'R15': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R15),
            'cbCallback': Form.FormChangeCb(self.onCallback)})

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


DescFormAarch64 =  r"""STARTITEM 
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
"""



class RegArm64Edit(ida_kernwin.Form):


    def __init__(self,regs):
        self.regs = regs
        if self.regs == None:
            Form.__init__(self,DescFormAarch64,{
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
            'cbCallback': Form.FormChangeCb(self.onCallback)})
        else:
            Form.__init__(self,DescFormAarch64,{
                'X0': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X0),
                'X1': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X1),
                'X2': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X2),
                'X3': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X3),
                'X4': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X4),
                'X5': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X5),
                'X6': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X6),
                'X7': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X7),
                'X8': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X8),
                'X9': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X9),
                'X10': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X10),
                'X11': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X11),
                'X12': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X12),
                'X13': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X13),
                'X14': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X14),
                'X15': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X15),
                'X16': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X16),
                'X17': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X17),
                'X18': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X18),
                'X19': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X19),
                'X20': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X20),
                'X21': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X21),
                'X22': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X22),
                'X23': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X23),
                'X24': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X24),
                'X25': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X25),
                'X26': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X26),
                'X27': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X27),
                'X28': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.X28),
                'FP': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.FP),
                'LR': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.LR),
                'SP': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.SP),
                'PC': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.PC),
                'cbCallback': Form.FormChangeCb(self.onCallback)})





   

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


DescFormx64 = r"""STARTITEM 
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
"""


class Regx64Edit(ida_kernwin.Form):

    def __init__(self,regs):
        self.regs = regs
        if self.regs == None:
            Form.__init__(self, DescFormx64 ,{

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
            'cbCallback': Form.FormChangeCb(self.onCallback)})

        else:
            Form.__init__(self, DescFormx64 ,{

            'RAX': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.RAX),
            'RBX': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.RBX),
            'RCX': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.RCX),
            'RDX': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.RDX),
            'RDI': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.RDI),
            'RSI': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.RSI),
            'RBP': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.RBP),
            'RSP': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.RSP),
            'RIP': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.RIP),
            'R8': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R8),
            'R9': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R9),
            'R10': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R10),
            'R11': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R11),
            'R12': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R12),
            'R13': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R13),
            'R14': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R14),
            'R15': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.R15),
            'cbCallback': Form.FormChangeCb(self.onCallback)})





    

    def onCallback(self,fid):
        return True


    @staticmethod
    def create(regs=None):
      print('regs_rax: %x'%regs.RAX)
      regform = Regx64Edit(regs)
      regform.Compile()
      ok = regform.Execute()
      if ok:
          return x64Registers(RAX=regform.RAX.value,
                            RBX=regform.RBX.value,
                            RCX=regform.RCX.value,
                            RDX=regform.RDX.value,
                            RDI=regform.RDI.value,
                            RSI=regform.RSI.value,
                            R8=regform.R8.value,
                            R9=regform.R9.value,
                            R10=regform.R10.value,
                            R11=regform.R11.value,
                            R12=regform.R12.value,
                            R13=regform.R13.value,
                            R14=regform.R14.value,
                            R15=regform.R15.value,
                            RBP=regform.RBP.value,
                            RSP=regform.RSP.value,
                            RIP=regform.RIP.value)


DescFormx86 = r"""STARTITEM 
x86 Reg Edit
{cbCallback}
 <##EAX:{EAX}>  |<##EBX:{EBX}>  |<##ECX:{ECX}>
 <##EDX:{EDX}>  |<##EDI:{EDI}>  |<##ESI:{ESI}>
 <##EBP:{EBP}>  |<##ESP:{ESP}>  |<##EIP:{EIP}>
"""

class Regx86Edit(ida_kernwin.Form):

    def __init__(self,regs):
        self.regs = regs
        if self.regs == None :
            Form.__init__(self, DescFormx86,{
            'EAX': Form.NumericInput(tp=Form.FT_RAWHEX),
            'EBX': Form.NumericInput(tp=Form.FT_RAWHEX),
            'ECX': Form.NumericInput(tp=Form.FT_RAWHEX),
            'EDX': Form.NumericInput(tp=Form.FT_RAWHEX),
            'EDI': Form.NumericInput(tp=Form.FT_RAWHEX),
            'ESI': Form.NumericInput(tp=Form.FT_RAWHEX),
            'EBP': Form.NumericInput(tp=Form.FT_RAWHEX),
            'ESP': Form.NumericInput(tp=Form.FT_RAWHEX),
            'EIP': Form.NumericInput(tp=Form.FT_RAWHEX),
            'cbCallback': Form.FormChangeCb(self.onCallback)})
        else:
            Form.__init__(self, DescFormx86,{
            'EAX': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.EAX),
            'EBX': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.EBX),
            'ECX': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.ECX),
            'EDX': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.EDX),
            'EDI': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.EDI),
            'ESI': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.ESI),
            'EBP': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.EBP),
            'ESP': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.ESP),
            'EIP': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.regs.EIP),
            'cbCallback': Form.FormChangeCb(self.onCallback)})

   

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


