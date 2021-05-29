from EWS.ui.generic import * 
from EWS.utils import consts_x86 

class x86Pannel(Pannel):

  def __init__(self,conf):
    super().__init__(conf)
    self.invert = False
    self.segs = [] 
    self.s_conf = StubConfiguration.create() 
    self.amap_conf = AdditionnalMapping({})#AdditionnalMapping.create()
    Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
EWS x86
{cbCallback}
Mapping Configuration
<## AutoMap missing regions## No:{aNo}> <Yes:{aYes}>{cAGrp}> 
Execution Configuration
<##Start address:{sAddr}> | <##End address:{eAddr}>
 <##EAX:{EAX}>  |<##EBX:{EBX}>  |<##ECX:{ECX}>
 <##EDX:{EDX}>  |<##EDI:{EDI}>  |<##ESI:{ESI}>
 <##EBP:{EBP}>  |<##ESP:{ESP}>  |<##EIP:{EIP}>
Display Configuration 
<## Show register values## No:{rNo}> <Yes:{rYes}>{cRGrp}> | <## Use Capstone## No:{cNo}> <Yes:{cYes}>{cCGrp}>
<## Show Mem Access## No:{maNo}> <Yes:{maYes}>{maGrp}> | <## Color graph## No:{cgNo}> <Yes:{cgYes}>{cgGrp}>
<## Configure Stub: {stubButton}>
<## Add mapping: {amapButton}> (arguments or missing segms in IDB)
<## Save Configration: {saveButton}> | <## Load Configuration: {loadButton} > 
""",{
            'cAGrp': Form.RadGroupControl(("aNo","aYes")),
            'maGrp': Form.RadGroupControl(("maNo","maYes")),
            'cRGrp': Form.RadGroupControl(("rNo","rYes")),
            'cCGrp': Form.RadGroupControl(("cNo","cYes")),
            'cgGrp': Form.RadGroupControl(("cgNo","cgYes")),
            'sAddr': Form.NumericInput(tp=Form.FT_ADDR),
            'eAddr': Form.NumericInput(tp=Form.FT_ADDR),
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




  def onSaveButton(self,code):
    conf = Configuration(     path='',
                              arch='x86',
                              emulator='unicorn',
                              p_size=consts_x86.PSIZE,
                              stk_ba=consts_x86.STACK_BASEADDR,
                              stk_size=consts_x86.STACK_SIZE,
                              autoMap=self.GetControlValue(self.cAGrp),
                              showRegisters=self.GetControlValue(self.cRGrp),
                              exec_saddr=self.GetControlValue(self.sAddr),
                              exec_eaddr=self.GetControlValue(self.eAddr),
                              mapping_saddr=get_min_ea_idb(),
                              mapping_eaddr=get_max_ea_idb(),
                              segms=[],
                              map_with_segs=False,
                              use_seg_perms=False,
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


      self.SetControlValue(self.cAGrp,conf.autoMap)
      self.SetControlValue(self.cRGrp,conf.showRegisters)
      self.SetControlValue(self.sAddr,conf.exec_saddr)
      self.SetControlValue(self.eAddr,conf.exec_eaddr)
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

   if fid == self.sAddr.id:
          self.SetControlValue(self.EIP,self.GetControlValue(self.sAddr))
   return 1 

  @staticmethod
  def fillconfig(conf=None):
      f = x86Pannel(conf)
      f.Compile()
      
      ok = f.Execute()
      if ok:
          ret = Configuration(path=f.conf_path,
                              arch='x86',
                              emulator='unicorn',
                              p_size=consts_x86.PSIZE,
                              stk_ba=consts_x86.STACK_BASEADDR,
                              stk_size=consts_x86.STACK_SIZE,
                              autoMap=f.cAGrp.value,
                              showRegisters=f.cRGrp.value,
                              exec_saddr=f.sAddr.value,
                              exec_eaddr=f.eAddr.value,
                              mapping_saddr=get_min_ea_idb(),
                              mapping_eaddr=get_max_ea_idb(),
                              segms=[],
                              map_with_segs=False,
                              use_seg_perms=False,
                              useCapstone=f.cCGrp.value,
                              registers=x86Registers(f.EAX.value,
                                                    f.EBX.value,
                                                    f.ECX.value,
                                                    f.EDX.value,
                                                    f.EDI.value,
                                                    f.ESI.value,
                                                    f.EBP.value,
                                                    f.ESP.value,
                                                    f.EIP.value),

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


