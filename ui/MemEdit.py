import ida_kernwin
import binascii


class MemEdit(ida_kernwin.Form):
    def __init__(self,emu=None):
        self.emu = emu
        self.ok = False
        ida_kernwin.Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
Edit memory
{callback}
<## Addr: {iAddr}> 
<## Value: {iValue}> 
""",{
#  'iAddr': ida_kernwin.Form.NumericInput(ida_kernwin.Form.FT_ADDR),
  'iAddr': ida_kernwin.Form.StringInput(ida_kernwin.Form.FT_ASCII),
  'iValue': ida_kernwin.Form.StringInput(ida_kernwin.Form.FT_ASCII),
  'callback': ida_kernwin.Form.FormChangeCb(self.callback),
})

    def callback(self,fid):
      if self.iAddr.id == fid:
        
        try:
            addr = int(self.GetControlValue(self.iAddr),16)
        except:
            if self.emu != None:
                try:
                    r_id= self.emu.reg_convert_ns(self.GetControlValue(self.iAddr))
                    addr = self.emu.reg_read(r_id)
                    self.SetControlValue(self.iAddr,'0x%x'%addr)
                except:
                    return 
            else:
                return


        if self.emu != None:
            try:

                val = self.emu.mem_read(addr,8)
#                val = self.emu.mem_read(self.GetControlValue(self.iAddr),8)
                self.ok = True
            except:
                val=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
                self.ok = False
        else:
            val = b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
            self.ok = False
        try:

            self.SetControlValue(self.iValue,binascii.b2a_hex(val).decode('utf-8'))
        except Exception as e:
            print(e)
            print('Incorrect format, please enter a hex string such as AABBCCDD')
      return 1


    @staticmethod 
    def fillconfig(emu=None):
        f= MemEdit(emu)
        f.Compile()
        ok = f.Execute()
        ret = (False,0,0) 
        if ok:
          ret =  (f.ok,f.iAddr.value,f.iValue.value)
        f.Free()
        return ret 











