import ida_kernwin 
from ida_kernwin import * 
import ida_segment
import ida_idaapi
import idaapi
import ida_funcs
import ida_idp
import time
import os 
from EWS.utils.utils import *
from EWS.utils.configuration import *
from EWS.ui.stub_configuration import *
from EWS.utils.registers import Registers
from EWS.utils.configuration import Configuration

FormDesc = r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
EWS ARML32
Mapping Configuration
<## Page size  :{iPageSize}> | <## Stack base address: {iStkBA}> | <## Stack size: {iStkSize}>
<## AutoMap missing regions## No:{aNo}> <Yes:{aYes}>{cAGrp}> 
<##Start Mapping (ea in IDB):{sMapping}> | <##End Mapping (ea in IDB):{eMapping}>   
<##Start address:{sAddr}> | <##End address:{eAddr}>
<##Max executed instruction:{maxInsn}>
Display Configuration
<## Show register values## No:{rNo}> <Yes:{rYes}>{cRGrp}> | <## Use Capstone## No:{cNo}> <Yes:{cYes}>{cCGrp}>
<## Show Mem Access## No:{maNo}> <Yes:{maYes}>{maGrp}> | <## Color graph## No:{cgNo}> <Yes:{cgYes}>{cgGrp}>
<## Configure Stub: {stubButton}>
<## Add mapping: {amapButton}>
<## Configure Registers: {registerButton}>
"""


class Pannel(ida_kernwin.Form):


  def __init__(self,
               register_ui_class,
               default_regs_values : Registers,
               arch_name : str  = '',
               emulator_solution: str = '',
               conf : Configuration = None):
    self.breakpoints = []
    self.watchpoints = {}
    self.patches = {}
    self.conf_path = ''
    self.conf = conf # For refresh purpose. When the windows is re-opened after the first time,
                     # value might be refreshed using the conf object 
    self.segs = []
    self.s_conf = StubConfiguration.create()
    self.amap_conf = AdditionnalMapping({})#AdditionnalMapping.create()
    self.memory_init = AdditionnalMapping({})
    self.register_ui_class = register_ui_class
    self.registers = default_regs_values
    self.arch_name = arch_name
    self.emulator_solution = emulator_solution
    self.config_present = False
    if self.conf == None:
        Form.__init__(self, FormDesc,{
            'iPageSize': Form.NumericInput(tp=Form.FT_RAWHEX),
            'iStkBA': Form.NumericInput(tp=Form.FT_RAWHEX),
            'iStkSize': Form.NumericInput(tp=Form.FT_RAWHEX),
            'cAGrp': Form.RadGroupControl(("aNo","aYes")),
            'cRGrp': Form.RadGroupControl(("rNo","rYes")),
            'cCGrp': Form.RadGroupControl(("cNo","cYes")),
            'spCSeg': Form.RadGroupControl(("spNo","spYes")),
            'maGrp': Form.RadGroupControl(("maNo","maYes")),
            'cgGrp': Form.RadGroupControl(("cgNo","cgYes")),
            'sAddr': Form.NumericInput(tp=Form.FT_ADDR),
            'eAddr': Form.NumericInput(tp=Form.FT_ADDR),
            'sMapping': Form.NumericInput(tp=Form.FT_ADDR),
            'eMapping': Form.NumericInput(tp=Form.FT_ADDR),
            'registerButton': Form.ButtonInput(self.registerCallback),
            'stubButton': Form.ButtonInput(self.onStubButton),
            'amapButton': Form.ButtonInput(self.onaMapButton),
            'maxInsn': Form.NumericInput(tp=Form.FT_ADDR),

})
    else:
        Form.__init__(self, FormDesc,{
            'iPageSize': Form.NumericInput(tp=Form.FT_RAWHEX,
                                           value=self.conf.p_size),
            'iStkBA': Form.NumericInput(tp=Form.FT_RAWHEX,
                                        value=self.conf.stk_ba),
            'iStkSize': Form.NumericInput(tp=Form.FT_RAWHEX,
                                          value=self.conf.stk_size),
            'cAGrp': Form.RadGroupControl(("aNo","aYes"),
                                          value=1 if self.conf.autoMap else 0),
            'cRGrp': Form.RadGroupControl(("rNo","rYes"),
                                          value=1 if self.conf.showRegisters else 0),
            'cCGrp': Form.RadGroupControl(("cNo","cYes"),
                                          value=1 if self.conf.useCapstone else 0),
            'spCSeg': Form.RadGroupControl(("spNo","spYes"),
                                           value=1 if self.conf.use_seg_perms else 0),
            'maGrp': Form.RadGroupControl(("maNo","maYes"),
                                          value=1 if self.conf.showMemAccess else 0),
            'cgGrp': Form.RadGroupControl(("cgNo","cgYes"),
                                          value=1 if self.conf.color_graph else 0),
            'sAddr': Form.NumericInput(tp=Form.FT_ADDR,value=self.conf.exec_saddr),
            'eAddr': Form.NumericInput(tp=Form.FT_ADDR,value=self.conf.exec_eaddr),
            'sMapping': Form.NumericInput(tp=Form.FT_ADDR,value=self.conf.mapping_saddr),
            'eMapping': Form.NumericInput(tp=Form.FT_ADDR,value=self.conf.mapping_eaddr),
            'registerButton': Form.ButtonInput(self.registerCallback),
            'stubButton': Form.ButtonInput(self.onStubButton),
            'amapButton': Form.ButtonInput(self.onaMapButton),
            'maxInsn': Form.NumericInput(tp=Form.FT_ADDR,value=self.conf.max_insn),
})


        self.s_conf = conf.s_conf
        self.amap_conf = conf.amap_conf
        self.memory_init = conf.memory_init
        self.registers = conf.registers
        self.breakpoints = conf.breakpoints
        self.watchpoints = conf.watchpoints
        self.patches = conf.patches
        self.config_present = True


  def cb_callback(self,code):
      pass

  def onStubButton(self,code):

    s_conf = StubForm.fillconfig(self.conf)
    self.s_conf += s_conf

  def onaMapButton(self,code):

    amap_conf = AddMapping.fillconfig()
    self.amap_conf += amap_conf

  def registerCallback(self,code):


    if self.config_present:
        self.registers = self.register_ui_class(self.registers)

    else:
        #TODO Add PC, SP information (if available)
        # maybe add method in registers class fix_pc fix_sp fix_link_reg
        #self.getControlControlledValue(self.sAddr) self.getControlControlledValue(self.iStkBA)
        self.registers = self.register_ui_class()
        self.config_present = True # handle case where the user clicks several time the button
   

  @staticmethod
  def fillconfig(register_ui_class,
               default_regs_values : Registers,
               arch_name : str  = '',
               emulator_solution: str = '',
            conf : Configuration = None) -> Configuration:



      f = Pannel(register_ui_class,
                 default_regs_values,
                 arch_name,
                 emulator_solution,
                 conf)

      f.Compile()


      ok = f.Execute()


      if ok == ida_kernwin.ASKBTN_YES: 

          ret = Configuration(path=f.conf_path,arch=ida_idp.get_idp_name(),
                              emulator='unicorn',
                              p_size=f.iPageSize.value,
                              stk_ba=f.iStkBA.value,
                              stk_size=f.iStkSize.value,
                              autoMap=f.cAGrp.value,
                              showRegisters=f.cRGrp.value,
                              exec_saddr=f.sAddr.value,
                              exec_eaddr=f.eAddr.value,
                              mapping_saddr=f.sMapping.value,
                              mapping_eaddr=f.eMapping.value,
                              segms=f.segs, # deprecated to be removed from conf
                              map_with_segs=False, # deprecated to be removed from conf
                              use_seg_perms=f.spCSeg.value,
                              useCapstone=f.cCGrp.value,
                              registers=f.registers,
                              showMemAccess=f.maGrp.value,
                              s_conf=f.s_conf,
                              amap_conf=f.amap_conf,
                              memory_init=f.memory_init,
                              color_graph=f.cgGrp.value,
                              breakpoints = f.breakpoints,
                              watchpoints = f.watchpoints,
                              patches = f.patches,
                              max_insn = f.maxInsn.value)

      else:
        raise Exception("Could not create configuration object")
        return None

      f.Free()

      return ret



#----------------------------------------------------------------------------------------------

FileDesc=r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
Select a file
{cbCallback}
<## Path: {iFile}>
"""
class FileSelector(ida_kernwin.Form):
  def __init__(self):
    self.invert = False
    self.f_path = ''
    Form.__init__(self,FileDesc ,{
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
  def fillconfig() -> AdditionnalMapping:

      f = AddMapping()
      f.Compile()

      ret = AdditionnalMapping.create()
      op = f.Execute()

      if op != 0 and op != idaapi.BADADDR:
          if not f.clicked:
            logger.console(1,' [Additionnal Mapping Form] no content added, please use Add Mapping button to add selected content')
          ret = AdditionnalMapping(f.mappings)
      f.Free()

      return ret

