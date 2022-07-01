import ida_kernwin
import ida_funcs
from EWS.utils.configuration import *
from EWS.utils.utils import *



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
            self.items = [ ['%.8X' % x.start_ea, '%s' % ida_funcs.get_func_name(x.start_ea)]
                          for x in get_func_list() ]
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
    <##Activate stub mechanism (allow tagging/stubbing) No : {esNo} <Yes: <{esYes}>{esC}>
    <##Stub dynamic func tabble (ELF/PE) No:      {sfNo}> <Yes:{sfYes}>{sfC}>
    <##Original filepath:{origFpath}>
    <##Auto null stub missing symbols: {asNo}>< Yes:{asYes}>{saC}>
    <##Add custom stubs file: {customStubFile}>
    """,{
                'esC': Form.RadGroupControl(('esNon','esYes')),
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

                    'esC': Form.RadGroupControl(('esNon','esYes'),
                                                value=1 if conf.s_conf.activate_stub_mechanism else 0),
                    'sfC': Form.RadGroupControl(("sfNo","sfYes"),
                                                value=1 if conf.tag_func_tab else 0),
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
  def fillconfig(config=None):
      f = StubForm(config)
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
#          print('orign fpath = %s'%ret.orig_filepath)
#          print('custon stub file = ',ret.custom_stubs_file)
#          print('stub dyn func tab = ',ret.stub_dynamic_func_tab)
      f.Free()
      return ret




