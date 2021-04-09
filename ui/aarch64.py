from ui.generic import * 

FormDesc = r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
EWS ARML32
{cbCallback}
Mapping Configuration
<## Page size  :{iPageSize}> | <## Stack base address: {iStkBA}> | <## Stack size: {iStkSize}>
<## AutoMap missing regions## No:{aNo}> <Yes:{aYes}>{cAGrp}> 
<##Start Mapping (ea in IDB):{sMapping}> | <##End Mapping (ea in IDB):{eMapping}>   
<## Map using segments## No:{sNo}> <Yes:{sYes}>{cCSeg}> | <## Use segment perms ## No:{spNo}> <Yes:{spYes}>{spCSeg}>
<Segment: {cSegChooser}>
Execution Configuration
<##Start address:{sAddr}> | <##End address:{eAddr}>
<##X0:{X0}>  |<##X1:{X1}>  |<##X2:{X2}>  |<##X3:{X3}> |<##X4:{X4}>
<##X5:{X5}>  |<##X6:{X6}>  |<##X7:{X7}>  |<##X8:{X8}> |<##X9:{X9}>
<##X10:{X10}> |<##X11:{X11}>| <##X12:{X12}>|<##SP:{X13}>
<##X14:{X14}> |<##X15:{X15}>|<##X16:{X16}>|<##X17:{X17}>
<##X18:{X18}> |<##X19:{X19}>|<##X20:{X20}>|<##X21:{X21}>
<##X22:{X22}> |<##X23:{X23}>|<##X24:{X24}>|<##X25:{X25}>
<##X26:{X26}> |<##X27:{X27}>|<##X28:{X28}>|<##FP:{FP}>
<##LR:{LR}>  |<##SP:{SP}>|<##PC:{PC}>
Display Configuration
<## Show register values## No:{rNo}> <Yes:{rYes}>{cRGrp}> | <## Use Capstone## No:{cNo}> <Yes:{cYes}>{cCGrp}>
<## Show Mem Access## No:{maNo}> <Yes:{maYes}>{maGrp}> | <## Color graph## No:{cgNo}> <Yes:{cgYes}>{cgGrp}>
<## Configure Stub: {stubButton}> 
<## Add mapping: {amapButton}> (arguments or missing segms in IDB)
<## Save Configration: {saveButton}> | <## Load Configuration: {loadButton} > 
"""

class Aarch64Pannel(Pannel):

  def __init__(self,conf):
    super().__init__(conf)
    self.invert = False
    self.segs = [] 
    self.s_conf = StubConfiguration.create() 
    self.amap_conf = AdditionnalMapping({})#AdditionnalMapping.create()
    if self.conf == None:
        Form.__init__(self, FormDesc ,{
            'iPageSize': Form.NumericInput(tp=Form.FT_RAWHEX), 
            'iStkBA': Form.NumericInput(tp=Form.FT_RAWHEX),
            'iStkSize': Form.NumericInput(tp=Form.FT_RAWHEX),
            'cAGrp': Form.RadGroupControl(("aNo","aYes")),
            'cRGrp': Form.RadGroupControl(("rNo","rYes")),
            'cCGrp': Form.RadGroupControl(("cNo","cYes")),
            'cCSeg': Form.RadGroupControl(("sNo","sYes")),
            'spCSeg': Form.RadGroupControl(("spNo","spYes")),
            'maGrp': Form.RadGroupControl(("maNo","maYes")),
            'cgGrp': Form.RadGroupControl(("cgNo","cgYes")),
            'sAddr': Form.NumericInput(tp=Form.FT_ADDR),
            'eAddr': Form.NumericInput(tp=Form.FT_ADDR),
            'sMapping': Form.NumericInput(tp=Form.FT_ADDR),
            'eMapping': Form.NumericInput(tp=Form.FT_ADDR),
            'cSegChooser': Form.EmbeddedChooserControl(Pannel.segment_chooser("Segmentname")),
            'X0': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X1': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X2': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X3': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X4': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X5': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X6': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X7': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X8': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X9': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X10': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X11': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X12': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X13': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X14': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X15': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X16': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X17': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X18': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X19': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X20': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X21': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X22': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X23': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X24': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X25': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X26': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X27': Form.NumericInput(tp=Form.FT_RAWHEX),
            'X28': Form.NumericInput(tp=Form.FT_RAWHEX),
            'FP': Form.NumericInput(tp=Form.FT_RAWHEX),
            'LR': Form.NumericInput(tp=Form.FT_RAWHEX),
            'SP': Form.NumericInput(tp=Form.FT_RAWHEX),
            'PC': Form.NumericInput(tp=Form.FT_RAWHEX),
            'cbCallback': Form.FormChangeCb(self.cb_callback),
            'stubButton': Form.ButtonInput(self.onStubButton),
            'amapButton': Form.ButtonInput(self.onaMapButton),
            'saveButton': Form.ButtonInput(self.onSaveButton),
            'loadButton': Form.ButtonInput(self.onLoadButton)
})
    else:
        Form.__init__(self, FormDesc ,{
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
            'cCSeg': Form.RadGroupControl(("sNo","sYes"),
                                          value=1 if self.conf.map_with_segs else 0),
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
            'cSegChooser': Form.EmbeddedChooserControl(Pannel.segment_chooser("Segmentname")),
            'X0': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X0),
            'X1': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X1),
            'X2': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X2),
            'X3': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X3),
            'X4': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X4),
            'X5': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X5),
            'X6': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X6),
            'X7': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X7),
            'X8': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X8),
            'X9': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X9),
            'X10': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X10),
            'X11': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X11),
            'X12': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X12),
            'X13': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X13),
            'X14': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X14),
            'X15': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X15),
            'X16': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X16),
            'X17': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X17),
            'X18': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X18),
            'X19': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X19),
            'X20': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X20),
            'X21': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X21),
            'X22': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X22),
            'X23': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X23),
            'X24': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X24),
            'X25': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X25),
            'X26': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X26),
            'X27': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X27),
            'X28': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X28),
            'FP': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X29),
            'LR': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X30),
            'SP': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.X31),
            'PC': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.PC),
            'cbCallback': Form.FormChangeCb(self.cb_callback),
            'stubButton': Form.ButtonInput(self.onStubButton),
            'amapButton': Form.ButtonInput(self.onaMapButton),
            'saveButton': Form.ButtonInput(self.onSaveButton),
            'loadButton': Form.ButtonInput(self.onLoadButton)
})





  def onSaveButton(self,code):
    conf = Configuration(     path='',
                              arch=ida_idp.get_idp_name(),
                              emulator='unicorn',
                              p_size=self.GetControlValue(self.iPageSize),
                              stk_ba=self.GetControlValue(self.iStkBA),
                              stk_size=self.GetControlValue(self.iStkSize),
                              autoMap=self.GetControlValue(self.cAGrp),
                              showRegisters=self.GetControlValue(self.cRGrp),
                              exec_saddr=self.GetControlValue(self.sAddr),
                              exec_eaddr=self.GetControlValue(self.eAddr),
                              mapping_saddr=self.GetControlValue(self.sMapping),
                              mapping_eaddr=self.GetControlValue(self.eMapping),
                              segms=self.segs,
                              map_with_segs=self.GetControlValue(self.cCSeg),
                              use_seg_perms=self.GetControlValue(self.spCSeg),
                              useCapstone=self.GetControlValue(self.cCGrp),
                              registers=Aarch64Registers(self.GetControlValue(self.X0),
                                                      self.GetControlValue(self.X1),
                                                      self.GetControlValue(self.X2),
                                                      self.GetControlValue(self.X3),
                                                      self.GetControlValue(self.X4),
                                                      self.GetControlValue(self.X5),
                                                      self.GetControlValue(self.X6),
                                                      self.GetControlValue(self.X7),
                                                      self.GetControlValue(self.X8),
                                                      self.GetControlValue(self.X9),
                                                      self.GetControlValue(self.X10),
                                                      self.GetControlValue(self.X11),
                                                      self.GetControlValue(self.X12),
                                                      self.GetControlValue(self.X13),
                                                      self.GetControlValue(self.X14),
                                                      self.GetControlValue(self.X15),
                                                      self.GetControlValue(self.X16),
                                                      self.GetControlValue(self.X17),
                                                      self.GetControlValue(self.X18),
                                                      self.GetControlValue(self.X19),
                                                      self.GetControlValue(self.X20),
                                                      self.GetControlValue(self.X21),
                                                      self.GetControlValue(self.X22),
                                                      self.GetControlValue(self.X23),
                                                      self.GetControlValue(self.X24),
                                                      self.GetControlValue(self.X25),
                                                      self.GetControlValue(self.X26),
                                                      self.GetControlValue(self.X27),
                                                      self.GetControlValue(self.X28),
                                                      self.GetControlValue(self.FP),
                                                      self.GetControlValue(self.LR),
                                                      self.GetControlValue(self.SP),
                                                      self.GetControlValue(self.PC)),
                              showMemAccess=self.GetControlValue(self.maGrp),
                              s_conf=self.s_conf,
                              amap_conf=self.amap_conf,
                              color_graph=self.GetControlValue(self.cgGrp),
                              breakpoints= self.breakpoints)


    f_path = FileSelector.fillconfig()
    if f_path.strip() == '':
      f_path = '/tmp/idaemu_conf_'+time.ctime().replace(' ','_')
      logger.console(0,'[Config Save] invalid filepath , use default: %s'%f_path)
    conf.path = f_path
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
      self.SetControlValue(self.cCGrp,conf.useCapstone)
      self.SetControlValue(self.X0,conf.registers.X0)
      self.SetControlValue(self.X1,conf.registers.X1)
      self.SetControlValue(self.X2,conf.registers.X2)
      self.SetControlValue(self.X3,conf.registers.X3)
      self.SetControlValue(self.X4,conf.registers.X4)
      self.SetControlValue(self.X5,conf.registers.X5)
      self.SetControlValue(self.X6,conf.registers.X6)
      self.SetControlValue(self.X7,conf.registers.X7)
      self.SetControlValue(self.X8,conf.registers.X8)
      self.SetControlValue(self.X9,conf.registers.X9)
      self.SetControlValue(self.X10,conf.registers.X10)
      self.SetControlValue(self.X11,conf.registers.X11)
      self.SetControlValue(self.X12,conf.registers.X12)
      self.SetControlValue(self.X13,conf.registers.X13)
      self.SetControlValue(self.X14,conf.registers.X14)
      self.SetControlValue(self.X15,conf.registers.X15)
      self.SetControlValue(self.X16,conf.registers.X16)
      self.SetControlValue(self.X17,conf.registers.X17)
      self.SetControlValue(self.X18,conf.registers.X18)
      self.SetControlValue(self.X19,conf.registers.X19)
      self.SetControlValue(self.X20,conf.registers.X20)
      self.SetControlValue(self.X21,conf.registers.X21)
      self.SetControlValue(self.X22,conf.registers.X22)
      self.SetControlValue(self.X23,conf.registers.X23)
      self.SetControlValue(self.X24,conf.registers.X24)
      self.SetControlValue(self.X25,conf.registers.X25)
      self.SetControlValue(self.X26,conf.registers.X26)
      self.SetControlValue(self.X27,conf.registers.X27)
      self.SetControlValue(self.X28,conf.registers.X28)
      self.SetControlValue(self.FP,conf.registers.FP)
      self.SetControlValue(self.LR,conf.registers.LR)
      self.SetControlValue(self.SP,conf.registers.SP)
      self.SetControlValue(self.maGrp,conf.showMemAccess)
      self.s_conf = conf.s_conf 
      self.amap_conf = conf.amap_conf 
      self.breakpoints = conf.breakpoints
      self.SetControlValue(self.cgGrp,conf.color_graph)



  def cb_callback(self,fid):
    if fid == self.sAddr.id:
          self.SetControlValue(self.PC,self.GetControlValue(self.sAddr))
    return 1 

  @staticmethod
  def fillconfig(conf=None):
      f = Aarch64Pannel(conf)
      f.Compile()
      
      ok = f.Execute()
      if ok:
      
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
                              segms=f.segs,
                              map_with_segs=f.cCSeg.value,
                              use_seg_perms=f.spCSeg.value,
                              useCapstone=f.cCGrp.value,
                              registers=Aarch64Registers(f.X0.value,
                                                     f.X1.value,
                                                     f.X2.value,
                                                     f.X3.value,
                                                     f.X4.value,
                                                     f.X5.value,
                                                     f.X6.value,
                                                     f.X7.value,
                                                     f.X8.value,
                                                     f.X9.value,
                                                     f.X10.value,
                                                     f.X11.value,
                                                     f.X12.value,
                                                     f.X13.value,
                                                     f.X14.value,
                                                     f.X15.value,
                                                     f.X16.value,
                                                     f.X17.value,
                                                     f.X18.value,
                                                     f.X19.value,
                                                     f.X20.value,
                                                     f.X21.value,
                                                     f.X22.value,
                                                     f.X23.value,
                                                     f.X24.value,
                                                     f.X25.value,
                                                     f.X26.value,
                                                     f.X27.value,
                                                     f.X28.value,
                                                     f.FP.value,
                                                     f.LR.value,
                                                     f.SP.value,
                                                     f.PC.value),
                              showMemAccess=f.maGrp.value,
                              s_conf=f.s_conf,
                              amap_conf=f.amap_conf,
                              color_graph=f.cgGrp.value,
                              breakpoints = f.breakpoints)
    
      else:
        logger.console(2,'[Form.execute()] error, aborting...\n please contact maintainer')
        return None
      f.Free()

      return ret


