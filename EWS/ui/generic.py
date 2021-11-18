import ida_kernwin 
from ida_kernwin import * 
import ida_segment
import ida_idaapi
import ida_funcs
import ida_idp
import time
import os 
from EWS.utils.utils import *
from EWS.utils.configuration import *

"""                   """
"         GENERIC       "
"""                   """


#----------------------------------------------------------------------------------------------

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


  def __init__(self,conf):
    self.breakpoints = [] 
    self.conf_path = ''
    self.conf = conf # For refresh purpose. When the windows is re-opened after the first time,
                     # value might be refreshed using the conf object 

  def onStubButton(self,code):
     
    s_conf = StubForm.fillconfig(self.conf)
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



#----------------------------------------------------------------------------------------------
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

#----------------------------------------------------------------------------------------------

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


#----------------------------------------------------------------------------------------------

class StubForm(ida_kernwin.Form):

  class function_chooser(ida_kernwin.Choose):
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


  def __init__(self, conf=None):
    self.invert = False
    self.clicked_ns = False
    self.clicked_ds = False
    self.nstub=dict()
    self.custom_stubs_file = None
    self.tags = dict()
    self.orig_fpath = ""
    if conf == None:
        Form.__init__(self, r"""STARTITEM 
    BUTTON YES Yeah
    BUTTON NO Nope
    BUTTON CANCEL* Nevermind
    Stubbing confiugration
    {cbCallback}
    <##Stub dynamic func tab No:      {sfNo}> <Yes:{sfYes}>{sfC}>
    <##Original filepath:{origFpath}>
    <##Auto null stub missing symbols: {asNo}>< Yes:{asYes}>{saC}>
    <##Add custom stubs file: {customStubFile}>
    """,{
                'sfC': Form.RadGroupControl(("sfNo","sfYes")),
                'customStubFile': Form.ButtonInput(self.CustomStubFile),
                'origFpath': Form.FileInput(open=True,save=False),
                'saC': Form.RadGroupControl(("asNo","asYes")),
                'cbCallback': Form.FormChangeCb(self.cb_callback)
    })
    else:
        Form.__init__(self, r"""STARTITEM 
        BUTTON YES Yeah
        BUTTON NO Nope
        BUTTON CANCEL* Nevermind
        Stubbing confiugration
        {cbCallback}
        <##Stub dynamic func tab No:      {sfNo}> <Yes:{sfYes}>{sfC}>
        <##Original filepath:{origFpath}>
        <##Auto null stub missing symbols: {asNo}>< Yes:{asYes}>{saC}>
        <##Add custom stubs file: {customStubFile}>
        """,{
                    'sfC': Form.RadGroupControl(("sfNo","sfYes"),
                                                value=1 if conf.s_conf.stub_dynamic_func_tab else 0),
                    'customStubFile': Form.ButtonInput(self.CustomStubFile),
                    'origFpath': Form.FileInput(open=True,save=False,
                                                value=conf.s_conf.orig_filepath),
                    'saC': Form.RadGroupControl(("asNo","asYes"),
                                                value=1 if conf.s_conf.auto_null_stub else 0),
                    'cbCallback': Form.FormChangeCb(self.cb_callback)
        })


  def cb_callback(self,fid):
    if fid == self.sfC.id:
        logger.console(LogType.INFO,'Possible file path: %s'%search_executable())
        self.orig_fpath = search_executable()
        logger.console(LogType.INFO,'Found potential matching binary path:%s'%self.orig_fpath)
        self.SetControlValue(self.origFpath,self.orig_fpath)
    if fid == self.origFpath.id:
      self.orig_fpath = self.GetControlValue(self.origFpath)
    return 1


  def CustomStubFile(self,code):

    f_path =  FileSelector.fillconfig()
    if f_path == '' or not os.path.exists(f_path) or os.path.isdir(f_path): 
        logger.console(2,' [Custom Stub File] Invalid file path')
        return 
    self.custom_stubs_file = f_path 
    return 
    
  

  def AddButton(self,code):
        for x in self.GetControlValue(self.cFuncChooser):
          f = get_func_list()[x]
          self.nstub[f.start_ea] = ida_funcs.get_func_name(f.start_ea)
        self.clicked_ns = True

  @staticmethod 
  def fillconfig():
      f = StubForm()
      f.Compile()

      ok = f.Execute()
      if ok:


          if not verify_valid_elf(f.orig_fpath):
              logger.console(LogType.WARN,"Specified original filepath invalid, stubs won't work")
          ret = StubConfiguration(nstubs=f.nstub,
                                stub_dynamic_func_tab=f.sfC.value,
                                orig_filepath=f.orig_fpath,
                                custom_stubs_file=f.custom_stubs_file,
                                auto_null_stub=f.saC.value,
                                tags=f.tags)
          print('orign fpath = %s'%ret.orig_filepath)
          print('custon stub file = ',ret.custom_stubs_file) 
          print('stub dyn func tab = ',ret.stub_dynamic_func_tab)
      f.Free()
      return ret 




