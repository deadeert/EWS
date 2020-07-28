import ida_kernwin 
from ida_kernwin import * 
import ida_segment
import ida_idaapi
import ida_funcs
import ida_idp
import os 

from utils import *

"""                   """
"         GENERIC       "
"""                   """



class Pannel(ida_kernwin.Form):
  
  class segment_chooser(ida_kernwin.Choose):
        """
        A simple chooser to be used as an embedded chooser
        """
        def __init__(self, title, nb=5, flags=ida_kernwin.Choose.CH_MULTI):
            ida_kernwin.Choose.__init__(
                self,
                title,
                [
                    ["Seg Name", 30]
                ],
                flags=flags,
                embedded=True,
                width=10,
                height=6)
            self.items = [ [ida_segment.get_segm_name(x)] for x in get_seg_list() ]
            self.icon = 0
            self.ret = 0

        def OnGetLine(self, n):
            self.ret = self.items[n]
            return self.items[n]

        def OnGetSize(self):
            n = len(self.items)
            return n


  def __init__(self):
    pass

  def onStubButton(self,code):
     
    s_conf = StubForm.fillconfig(self.s_conf.use_user_stubs,
                                 self.s_conf.stub_pltgot_entries)
    self.s_conf += s_conf

  def onaMapButton(self,code):
    
    amap_conf = AddMapping.fillconfig() 
    self.amap_conf += amap_conf


  def onLoadButton(self,code):
    """ For configuration purpose
    """
    pass
  
  def onSaveButton(self,code):
    """ For configuration purpose
    """
    pass

class FileSelector(ida_kernwin.Form):
  def __init__(self):
    self.invert = False
    self.f_path = ''
    Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
Select a file 
<## Path: {iFile}> |  <##Select: {bFile}>
""",{
            'iFile': Form.FileInput(open=True,save=False),
            'bFile': Form.ButtonInput(self.OnbFile),
})
  def OnbFile(self,code):
    self.f_path = self.GetControlValue(self.iFile)
    
  @staticmethod 
  def fillconfig():
      f = FileSelector()
      f.Compile()
      
      ok = f.Execute()
      f.Free()

      logger.console(0,' [%s] f_path: %s'%('UI',f.f_path))
      return f.f_path 
     
  

class AddMapping(ida_kernwin.Form):
  def __init__(self):
    self.invert = False
    self.mappings = dict()
    self.cur_value = b'' 
    self.clicked = False
    Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
Additionnal Mapping
<##Address: {iAddr}>
<## Path: {iFile}> |  <##Add content file: {bFile}>
<##Hex dword: {iString}>
<##Add mapping: {bAdd}>
""",{

            'iAddr': Form.NumericInput(tp=Form.FT_ADDR), 
            'iFile': Form.FileInput(open=True,save=False),
            'bFile': Form.ButtonInput(self.OnbFile),
            'iString': Form.NumericInput(tp=Form.FT_RAWHEX), 
            'bAdd': Form.ButtonInput(self.OnbAdd)
})



  def OnbAdd(self,code):
    self.mappings[self.GetControlValue(self.iAddr)] = self.cur_value if self.cur_value != b'' else self.GetControlValue(self.iString).to_bytes(4,'big',signed=False)
    self.cur_value = b''
    self.clicked = True

  def OnbFile(self,code):
    f_path = self.GetControlValue(self.iFile)
    if os.path.exists(f_path) and not os.path.isdir(f_path):
      try:
        with open(f_path,'rb') as f: self.cur_value = f.read()
      except Exception as e : logger.console(2,e.__str__())
          


  @staticmethod 
  def fillconfig():
      f = AddMapping()
      f.Compile()
      
      ok = f.Execute()
      

      if ok:
          if not f.clicked: 
            logger.console(1,' [Additionnal Mapping Form] no content added, please use Add Mapping button to add selected content')
          ret = AdditionnalMapping(f.mappings)
      f.Free()

      return ret 


class StubForm(ida_kernwin.Form):

  class function_chooser(ida_kernwin.Choose):
        """
        A simple chooser to be used as an embedded chooser
        """
        def __init__(self, title, nb=5, flags=ida_kernwin.Choose.CH_MULTI):
            ida_kernwin.Choose.__init__(
                self,
                title,
                [
                    ["Address", 10],
                    ["Func Name", 30]
                ],
                flags=flags,
                embedded=True,
                width=30,
                height=6)
            self.items = [ ['%.8X' % x.start_ea, '%s' % ida_funcs.get_func_name(x.start_ea)] for x in get_func_list() ]
            self.icon = 0
            self.ret = 0

        def OnGetLine(self, n):
            self.ret = self.items[n]
            return self.items[n]

        def OnGetSize(self):
            n = len(self.items)
            return n


  def __init__(self,splt=False,usrstub=False):
    self.invert = False
    self.nstub = dict()
    self.clicked = False
    Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
Stubbing confiugration
<##Functions: {cFuncChooser}>
<##Add selection: {addButton}>
<##Use user stubs No:{sfNo}> <Yes:{sfYes}>{sfC}>
<##Stub plt/got entries (if available) No:{spgNo}> <Yes:{spgYes}>{spgC}> 
""",{
            'addButton': Form.ButtonInput(self.AddButton),
            'sfC': Form.RadGroupControl(("sfNo","sfYes")),
            'spgC': Form.RadGroupControl(("spgNo","spgYes")),
            'cFuncChooser': Form.EmbeddedChooserControl(StubForm.function_chooser("NullStubfunction"))
})

    self.use_user_stubs = usrstub
    self.stub_pltgot_entries = splt 




  def refresh(self):
    pass
  
#     self.SetControlValue(self.sfC,self.use_user_stubs)
#     self.SetControlValue(self.splgC,self.stub_pltgot_entries)
# 
  



  def AddButton(self,code):
        for x in self.GetControlValue(self.cFuncChooser):
          f = get_func_list()[x]
          self.nstub[f.start_ea] = ida_funcs.get_func_name(f.start_ea)
        self.clicked = True
          

  @staticmethod 
  def fillconfig(splg,usrstub):
      f = StubForm(splg,usrstub)
      f.Compile()

      ok = f.Execute()
      if ok:

          if not f.clicked: 
            logger.console(1,' [%s] no stubs added, please use "Add Selection" button to add selected stubs'%'UI') #WTF IDA does not exports locals()['__name__']
          ret = StubConfiguration(f.nstub,f.sfC.value,f.spgC.value)
      f.Free()
      return ret 




