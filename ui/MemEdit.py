import ida_kernwin
import binascii

class MemEdit(ida_kernwin.Form):
    def __init__(self,uc=None):
        self.uc = uc
        Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
Edit memory
{callback}
<## Path: {iAddr}> 
<## Value: {iValue}> 
""",{
  'iAddr': ida_kernwin.Form.NumericInput(Form.FT_ADDR),
  'iValue': ida_kernwin.Form.StringInput(Form.FT_ASCII),
  'callback': ida_kernwin.Form.FormChangeCb(self.callback),
})

    def callback(self,fid):
      if self.iAddr.id == fid:
        if self.uc != None:
            val = self.uc.mem_read(self.GetControlValue(self.iAddr),8)
        else:
            val = b'\xFF\xFF\xFF\xFF'
        try:
            self.SetControlValue(self.iValue,binascii.b2a_hex(val).decode('utf-8'))
        except Exception as e:
            print(e)
            print('Incorrect format, please enter a hex string such as AABBCCDD')
      return 1


#
    @staticmethod 
    def fillconfig():
        f= MemEdit()
        f.Compile()
        ok = f.Execute()
        ret = (0,0) 
        if ok:
          ret =  (f.iAddr.value,f.iValue.value)
        f.Free()
        return ret 




if __name__ == '__main__':
  addr,value = MemEdit.fillconfig()
  print('addr : %x'%addr)
  print('hex: ')
  val = binascii.a2b_hex(value.encode('utf-8'))
  print(val)







