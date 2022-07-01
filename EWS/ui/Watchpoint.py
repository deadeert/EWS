import ida_kernwin
import binascii


class WatchPoint(ida_kernwin.Form):
    def __init__(self):
        self.ok = False
        ida_kernwin.Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
Edit memory
<## Base Addr: {iAddr}>
<## Rang : {iValue}>
""",{
  'iAddr': ida_kernwin.Form.StringInput(ida_kernwin.Form.FT_ASCII),
  'iValue': ida_kernwin.Form.StringInput(ida_kernwin.Form.FT_ASCII)
})


    @staticmethod
    def fillconfig(emu=None):
        ret = False
        f= WatchPoint()
        f.Compile()
        f.Execute()
        if f.iAddr.value!= None and f.iValue.value != None:
            ba = int(f.iAddr.value,16)
            rg = int(f.iValue.value,16)
            if emu!=None:
                emu.add_watchpoint(ba,rg,mode=0x3)
                ret = True
        f.Free()
        return ret











