###
# TODO 
# Add multichooser for segment (create a new form and add it to (open_segments_windows)) OK
# Add form for nullstubing ..............................................................OK 
# Do action in background  ..............................................................NOK
# Add choise to auto stub .pltgot section for ELF........................................OK
# Select Output file (logger)............................................................NOK
# Get the segment protection and use it for unicorn.mem_map..............................OK
# Use form to configure mapping + exec addresses with a function list....................NOK
# Idem for null stub.....................................................................OK
# use decorator to auto look for function and stub them..................................NOK
# Add a save/load configutation .........................................................OK
# Add switch use segment(s) / use custom mapping.........................................OK
# Let the user choose if the perms are considered or perm is 777.........................OK
# Add support for thumb mode on nullstubbing.............................................OK
# Additionnal mapping form...............................................................OK
# Add segment permission for additionnal mapping.........................................NOK
# Add possibility to init additionnal mapping with random memory ........................NOK
# Add checks for emulator config (such as page_size and various base addr)...............NOK
# Add final memory map display ..........................................................NOK
# Add functionnalities to mark registers values accross executed instructions............NOK 
# Add selector for the output (console and or files)
# Add option to map using File format (LOAD sections from ELF)
# Add PE support
# Remove Swich isThumb
# Add dumb fuzzing option
# BUGS: 
# do not display function name in function chooser 
###


import ida_kernwin 
import ida_segment
import ida_idaapi
import ida_funcs

from sys import exit
import json
import time

from utils import * 
from emucorn import *


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


  def __init__(self):
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



  def AddButton(self,code):
        for x in self.GetControlValue(self.cFuncChooser):
          f = get_func_list()[x]
          self.nstub[ida_funcs.get_func_name(f.start_ea)] = f 
        self.clicked = True
          

  @staticmethod 
  def fillconfig():
      f = StubForm()
      f.Compile()
      
      ok = f.Execute()
      

      if ok:

          if not f.clicked: 
            logger.console(1,' [%s] no stubs added, please use "Add Selection" button to add selected stubs'%'UI') #WTF IDA does not exports locals()['__name__']
          ret = StubConfiguration(f.nstub,f.sfC.value,f.spgC.value)

      f.Free()

      return ret 
   
class MyForm(ida_kernwin.Form):

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
    self.invert = False
    self.segs = [] 
    self.s_conf = StubConfiguration.create() 
    self.amap_conf = AdditionnalMapping({})#AdditionnalMapping.create()
    Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
Test
{cbCallback}
Mapping Configuration
<## Page size  :{iPageSize}> | <## Stack base address: {iStkBA}> | <## Stack size: {iStkSize}>
<## AutoMap missing regions## No:{aNo}> <Yes:{aYes}>{cAGrp}> | <## Thumb mode## No:{tNo}> <Yes:{tYes}>{cTGrp}>
<##Start Mapping (ea in IDB):{sMapping}> | <##End Mapping (ea in IDB):{eMapping}>   
<## Map using segments## No:{sNo}> <Yes:{sYes}>{cCSeg}> | <## Use segment perms ## No:{spNo}> <Yes:{spYes}>{spCSeg}>
<Segment: {cSegChooser}>
Execution Configuration
<##Start address:{sAddr}> | <##End address:{eAddr}>
<##R0:{R0}><##R1:{R1}>|<##R2:{R2}>|<##R3:{R3}>|<##R4:{R4}>
<##R5:{R5}>|<##R6:{R6}>|<##R7:{R7}>|<##R8:{R8}|><##R9:{R9}>
<##R10:{R10}>|<##R11:{R11}>|<##R12:{R12}>|<##R13:{R13}>|<##R14:{R14}>
Display Configuration 
<## Show register values## No:{rNo}> <Yes:{rYes}>{cRGrp}> | <## Use Capstone## No:{cNo}> <Yes:{cYes}>{cCGrp}>
<## Show Mem Access## No:{maNo}> <Yes:{maYes}>{maGrp}>
<## Configure Stub: {stubButton}> 
<## Add mapping: {amapButton}> (arguments or missing segms in IDB)
<## Save Configration: {saveButton}> | <## Load Configuration: {loadButton} > 
""",{
            'iPageSize': Form.NumericInput(tp=Form.FT_RAWHEX), 
            'iStkBA': Form.NumericInput(tp=Form.FT_RAWHEX),
            'iStkSize': Form.NumericInput(tp=Form.FT_RAWHEX),
            'cAGrp': Form.RadGroupControl(("aNo","aYes")),
            'cRGrp': Form.RadGroupControl(("rNo","rYes")),
            'cTGrp': Form.RadGroupControl(("tNo","tYes")),
            'cCGrp': Form.RadGroupControl(("cNo","cYes")),
            'cCSeg': Form.RadGroupControl(("sNo","sYes")),
            'spCSeg': Form.RadGroupControl(("spNo","spYes")),
            'maGrp': Form.RadGroupControl(("maNo","maYes")),
            'sAddr': Form.NumericInput(tp=Form.FT_ADDR),
            'eAddr': Form.NumericInput(tp=Form.FT_ADDR),
            'sMapping': Form.NumericInput(tp=Form.FT_ADDR),
            'eMapping': Form.NumericInput(tp=Form.FT_ADDR),
            'cSegChooser': Form.EmbeddedChooserControl(MyForm.segment_chooser("Segmentname")),
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
            'cbCallback': Form.FormChangeCb(self.cb_callback),
            'stubButton': Form.ButtonInput(self.onStubButton),
            'amapButton': Form.ButtonInput(self.onaMapButton),
            'saveButton': Form.ButtonInput(self.onSaveButton),
            'loadButton': Form.ButtonInput(self.onLoadButton)
})


  def onStubButton(self,code):
    
    s_conf = StubForm.fillconfig()
    self.s_conf += s_conf

  def onaMapButton(self,code):
    
    amap_conf = AddMapping.fillconfig() 
    self.amap_conf += amap_conf


  def onSaveButton(self,code):
    conf = Configuration(self.GetControlValue(self.iPageSize),
                              self.GetControlValue(self.iStkBA),
                              self.GetControlValue(self.iStkSize),
                              self.GetControlValue(self.cAGrp),
                              self.GetControlValue(self.cRGrp),
                              self.GetControlValue(self.sAddr),
                              self.GetControlValue(self.eAddr),
                              self.GetControlValue(self.sMapping),
                              self.GetControlValue(self.eMapping),
                              self.segs,
                              self.GetControlValue(self.cCSeg),
                              self.GetControlValue(self.spCSeg),
                              self.GetControlValue(self.cTGrp),
                              self.GetControlValue(self.cCGrp),
                              ArmRegisters(self.GetControlValue(self.R0),self.GetControlValue(self.R1),self.GetControlValue(self.R2),self.GetControlValue(self.R3),
                                           self.GetControlValue(self.R4),self.GetControlValue(self.R5),self.GetControlValue(self.R6),self.GetControlValue(self.R7),
                                           self.GetControlValue(self.R8),self.GetControlValue(self.R9),self.GetControlValue(self.R10),self.GetControlValue(self.R11),
                                           self.GetControlValue(self.R12),self.GetControlValue(self.R13),self.GetControlValue(self.R14)),
                              self.GetControlValue(self.maGrp),
                              self.s_conf,
                              self.amap_conf)


    f_path = FileSelector.fillconfig()
    if f_path.strip() == '':
      f_path = '/tmp/idaemu_conf_'+time.ctime().replace(' ','_')
      logger.console(0,'[Config Save] invalid filepath , use default: %s'%f_path)
    saveconfig(conf,f_path)


  def onLoadButton(self,code): 
    

      f_path = FileSelector.fillconfig()
      if f_path == '' or not os.path.exists(f_path) or os.path.isdir(f_path): 
        logger.console(2,' [Configuration Load] Invalid file path')
        return 
#     conf_apath = '/tmp/idaemu_conf_'+time.ctime().replace(' ','_')
      conf = loadconfig(f_path)

      if not conf.map_with_segs: self.EnableField(self.cSegChooser,False)
      else: 
          self.EnableField(self.sMapping, False)
          self.EnableField(self.eMapping, False)
          self.EnableField(self.cSegChooser,True)


      segms = get_seg_list()
      s_chooser = [] 
      
      i=0 
      for x in segms:
        if x in conf.segms:
          s_chooser.append(i)
        i+=1
    
      self.SetControlValue(self.cSegChooser,s_chooser)

      self.SetControlValue(self.iPageSize,conf.p_size)
      self.SetControlValue(self.iStkBA,conf.stk_ba)
      self.SetControlValue(self.iStkSize,conf.stk_size)
      self.SetControlValue(self.cAGrp,conf.autoMap)
      self.SetControlValue(self.cRGrp,conf.showRegisters)
      self.SetControlValue(self.sAddr,conf.exec_saddr)
      self.SetControlValue(self.eAddr,conf.exec_eaddr)
      self.SetControlValue(self.sMapping,conf.mapping_saddr)
      self.SetControlValue(self.eMapping,conf.mapping_eaddr)
      self.segs = conf.segms
      self.SetControlValue(self.cCSeg,conf.map_with_segs)
      self.SetControlValue(self.spCSeg,conf.use_seg_perms)
      self.SetControlValue(self.cTGrp,conf.isThumb)
      self.SetControlValue(self.cCGrp,conf.useCapstone)
      ArmRegisters(self.SetControlValue(self.R0,conf.registers.R0),
                self.SetControlValue(self.R1,conf.registers.R1),
                self.SetControlValue(self.R2,conf.registers.R2),
                self.SetControlValue(self.R3,conf.registers.R3),
                self.SetControlValue(self.R4,conf.registers.R4),
                self.SetControlValue(self.R5,conf.registers.R5),
                self.SetControlValue(self.R6,conf.registers.R6),
                self.SetControlValue(self.R7,conf.registers.R7),
                self.SetControlValue(self.R8,conf.registers.R8),
                self.SetControlValue(self.R9,conf.registers.R9),
                self.SetControlValue(self.R10,conf.registers.R10),
                self.SetControlValue(self.R11,conf.registers.R11),
                self.SetControlValue(self.R12,conf.registers.R12),
                self.SetControlValue(self.R13,conf.registers.R13),
                self.SetControlValue(self.R14,conf.registers.R14))
      self.SetControlValue(self.maGrp,conf.showMemAccess)
      self.s_conf = conf.s_conf 
      self.amap_conf = conf.amap_conf 


  def cb_callback(self,fid):
    if fid == self.cSegChooser.id:
        if not self.GetControlValue(self.cCSeg): 
          self.EnableField(self.cSegChooser,False)
        self.segs = []  
        for x in self.GetControlValue(self.cSegChooser):
          self.segs.append(get_seg_list()[x])
    elif fid == self.cCSeg.id:
          self.EnableField(self.sMapping,not self.GetControlValue(self.cCSeg))
          self.EnableField(self.eMapping,not self.GetControlValue(self.cCSeg))
          self.EnableField(self.cSegChooser,self.GetControlValue(self.cCSeg))
    return 1 

  @staticmethod
  def fillconfig():
      f = MyForm()
      f.Compile()
      
      ok = f.Execute()
      

      if ok:
          ret = Configuration(f.iPageSize.value,
                              f.iStkBA.value,
                              f.iStkSize.value,
                              f.cAGrp.value,
                              f.cRGrp.value,
                              f.sAddr.value,
                              f.eAddr.value,
                              f.sMapping.value,
                              f.eMapping.value,
                              f.segs,
                              f.cCSeg.value,
                              f.spCSeg.value,
                              f.cTGrp.value,
                              f.cCGrp.value,
                              ArmRegisters(f.R0.value,f.R1.value,f.R2.value,f.R3.value,
                                           f.R4.value,f.R5.value,f.R6.value,f.R7.value,
                                           f.R8.value,f.R9.value,f.R10.value,f.R11.value,
                                           f.R12.value,f.R13.value,f.R14.value),
                              f.maGrp.value,
                              f.s_conf,
                              f.amap_conf)
    
      else:
        logger.console(2,'[Form.execute()] error, aborting...\n please contact maintainer')
        return None
      f.Free()

      return ret

if __name__ == '__main__':

  conf = MyForm.fillconfig() 
  emu = Emucorn(conf)
  emu.add_hook_code()
  emu.start()
  









