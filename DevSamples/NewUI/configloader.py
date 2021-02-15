import ida_kernwin




class FileSelector(ida_kernwin.Form):
  def __init__(self):
    self.invert = False
    self.f_path = ''
    Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
Select a file 
{cbCallback}
<## Path: {iFile}> 
""",{
            'iFile': ida_kernwin.Form.FileInput(open=True,save=False),
            'cbCallback': ida_kernwin.Form.FormChangeCb(self.cb_callback),
})

  def cb_callback(self,fid):
      if fid == self.iFile.id:
          self.f_path = self.GetControlValue(self.iFile) 
      return 1 

     
  @staticmethod 
  def fillconfig():
      f = FileSelector()
      f.Compile()
      
      ok = f.Execute()
      f.Free()

      return f.f_path 



if __name__ ==  '__main__':
    print(FileSelector.fillconfig())
