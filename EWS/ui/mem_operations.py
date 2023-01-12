import ida_kernwin

class ExportMemory(ida_kernwin.Form): 


    def __init__(self):
        self.f_path = None
        ida_kernwin.Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
Export Memory
<Address : {iAddr}> <Export Size : {iSize}>
<## Path: {iFile}>
""",{

   'iAddr': ida_kernwin.Form.NumericInput(ida_kernwin.Form.FT_ADDR),
  'iSize': ida_kernwin.Form.NumericInput(ida_kernwin.Form.FT_RAWHEX),
  'iFile': ida_kernwin.Form.FileInput(open=True,save=False),
})



    @staticmethod
    def fillconfig():
      f = ExportMemory()
      f.Compile()
      ok = f.Execute()
      if ok:
         return f.iAddr.value,f.iSize.value,f.iFile.value
      else:
          raise Exception('[ExportMem]Invalid input parameters.')

class ImportMemory(ida_kernwin.Form): 


    def __init__(self):
        self.f_path = None
        ida_kernwin.Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
Import Memory
<Address : {iAddr}>
<## Path: {iFile}>
""",{

   'iAddr': ida_kernwin.Form.NumericInput(ida_kernwin.Form.FT_ADDR),
  'iFile': ida_kernwin.Form.FileInput(open=True,save=False)
})


    @staticmethod
    def fillconfig():
      f = ImportMemory()
      f.Compile()
      ok = f.Execute()
      if ok:
         return f.iAddr.value,f.iFile.value


