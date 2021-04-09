from ui.generic import * 


FormDesc=r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
EWS x86
{cbCallback}
Mapping Configuration
<## Page size  :{iPageSize}> | <## Stack base address: {iStkBA}> | <## Stack size: {iStkSize}>
<## AutoMap missing regions## No:{aNo}> <Yes:{aYes}>{cAGrp}> 
<##Start Mapping (ea in IDB):{sMapping}> | <##End Mapping (ea in IDB):{eMapping}>   
<## Map using segments## No:{sNo}> <Yes:{sYes}>{cCSeg}> | <## Use segment perms ## No:{spNo}> <Yes:{spYes}>{spCSeg}>
<Segment: {cSegChooser}>
Execution Configuration
<##Start address:{sAddr}> | <##End address:{eAddr}>
 <##EAX:{EAX}>  |<##EBX:{EBX}>  |<##ECX:{ECX}>  |<##EDX:{EDX}> 
 <##EDI:{EDI}>  |<##ESI:{ESI}>  |<##EBP:{EBP}>  |<##ESP:{ESP}> 
 <##EIP:{EIP}>
Display Configuration 
<## Show register values## No:{rNo}> <Yes:{rYes}>{cRGrp}> | <## Use Capstone## No:{cNo}> <Yes:{cYes}>{cCGrp}>
<## Show Mem Access## No:{maNo}> <Yes:{maYes}>{maGrp}> | <## Color graph## No:{cgNo}> <Yes:{cgYes}>{cgGrp}>
<## Configure Stub: {stubButton}> 
<## Add mapping: {amapButton}> (arguments or missing segms in IDB)
<## Save Configration: {saveButton}> | <## Load Configuration: {loadButton} > 
"""

class x86Pannel(Pannel):

  def __init__(self,conf):
    super().__init__(conf)
    self.invert = False
    self.segs = [] 
    self.s_conf = StubConfiguration.create() 
    self.amap_conf = AdditionnalMapping({})#AdditionnalMapping.create()
    if self.conf == None:
        Form.__init__(self, FormDesc,{
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
            'EAX': Form.NumericInput(tp=Form.FT_RAWHEX),
            'EBX': Form.NumericInput(tp=Form.FT_RAWHEX),
            'ECX': Form.NumericInput(tp=Form.FT_RAWHEX),
            'EDX': Form.NumericInput(tp=Form.FT_RAWHEX),
            'EDI': Form.NumericInput(tp=Form.FT_RAWHEX),
            'ESI': Form.NumericInput(tp=Form.FT_RAWHEX),
            'EBP': Form.NumericInput(tp=Form.FT_RAWHEX),
            'ESP': Form.NumericInput(tp=Form.FT_RAWHEX),
            'EIP': Form.NumericInput(tp=Form.FT_RAWHEX),
            'cbCallback': Form.FormChangeCb(self.cb_callback),
            'stubButton': Form.ButtonInput(self.onStubButton),
            'amapButton': Form.ButtonInput(self.onaMapButton),
            'saveButton': Form.ButtonInput(self.onSaveButton),
            'loadButton': Form.ButtonInput(self.onLoadButton)
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
            'EAX': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.EAX),
            'EBX': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.EBX),
            'ECX': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.ECX),
            'EDX': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.EDX),
            'EDI': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.EDI),
            'ESI': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.ESI),
            'EBP': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.EBP),
            'ESP': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.ESP),
            'EIP': Form.NumericInput(tp=Form.FT_RAWHEX,value=self.conf.registers.EIP),
            'cbCallback': Form.FormChangeCb(self.cb_callback),
            'stubButton': Form.ButtonInput(self.onStubButton),
            'amapButton': Form.ButtonInput(self.onaMapButton),
            'saveButton': Form.ButtonInput(self.onSaveButton),
            'loadButton': Form.ButtonInput(self.onLoadButton)
        })




  

  def onSaveButton(self,code):
    conf = Configuration(     path='',
                              arch='x86',
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
                              registers=x86Registers(self.GetControlValue(self.EAX),
                                                      self.GetControlValue(self.EBX),
                                                      self.GetControlValue(self.ECX),
                                                      self.GetControlValue(self.EDX),
                                                      self.GetControlValue(self.EDI),
                                                      self.GetControlValue(self.ESI),
                                                      self.GetControlValue(self.EBP),
                                                      self.GetControlValue(self.ESP),
                                                      self.GetControlValue(self.EIP)),
                              showMemAccess=self.GetControlValue(self.maGrp),
                              s_conf=self.s_conf,
                              amap_conf=self.amap_conf,
                              color_graph=self.GetControlValue(self.cgGrp),
                              breakpoints=self.breakpoints)


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

      self.conf_path = conf.path
    
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
      self.SetControlValue(self.EAX,conf.registers.EAX)
      self.SetControlValue(self.EBX,conf.registers.EBX)
      self.SetControlValue(self.ECX,conf.registers.ECX)
      self.SetControlValue(self.EDX,conf.registers.EDX)
      self.SetControlValue(self.EDI,conf.registers.EDI)
      self.SetControlValue(self.ESI,conf.registers.ESI)
      self.SetControlValue(self.EBP,conf.registers.EBP)
      self.SetControlValue(self.ESP,conf.registers.ESP)
      self.SetControlValue(self.EIP,conf.registers.EIP)
      self.SetControlValue(self.maGrp,conf.showMemAccess)
      self.s_conf = conf.s_conf 
      self.amap_conf = conf.amap_conf 
      self.breakpoints = conf.breakpoints
      self.SetControlValue(self.cgGrp,conf.color_graph)



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
    elif fid == self.sAddr.id:
          self.SetControlValue(self.EIP,self.GetControlValue(self.sAddr))
    elif fid == self.iStkSize.id or fid == self.iStkBA.id:
          sp = self.GetControlValue(self.iStkSize) + self.GetControlValue(self.iStkBA) 
          self.SetControlValue(self.ESP,sp)

    return 1 

  @staticmethod
  def fillconfig(conf=None):
      f = x86Pannel(conf)
      f.Compile()
      
      ok = f.Execute()
      if ok:
          ret = Configuration(path=f.conf_path,arch='x86',
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
                              registers=x86Registers(f.EAX.value,f.EBX.value,f.ECX.value,f.EDX.value,
                                           f.EDI.value,f.ESI.value,f.EBP.value,f.ESP.value,f.EIP.value),
                              showMemAccess=f.maGrp.value,
                              s_conf=f.s_conf,
                              amap_conf=f.amap_conf,
                              color_graph=f.cgGrp.value,
                              breakpoints=f.breakpoints)
    
      else:
        logger.console(2,'[Form.execute()] error, aborting...\n please contact maintainer')
        return None
      f.Free()

      return ret


