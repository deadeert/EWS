from ui.generic import * 
from utils.consts_arm import STACK_BASEADDR, STACK_SIZE 

class Arm32Pannel(Pannel):

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
EWS ARML32
{cbCallback}
Mapping Configuration
<## AutoMap missing regions## No:{aNo}> <Yes:{aYes}>{cAGrp}> 
<##Start address:{sAddr}> | <##End address:{eAddr}>
Execution Configuration
 <##R0:{R0}>  |<##R1:{R1}>  |<##R2:{R2}>  |<##R3:{R3}> |<##R4:{R4}>
 <##R5:{R5}>  |<##R6:{R6}>  |<##R7:{R7}>  |<##R8:{R8}> |<##R9:{R9}>
<##R10:{R10}> |<##R11:{R11}>| <##R12:{R12}>|<##SP:{R13}>
<##LR:{R14}>  |<##PC:{R15}>
Display Configuration 
<## Show register values## No:{rNo}> <Yes:{rYes}>{cRGrp}> | <## Use Capstone## No:{cNo}> <Yes:{cYes}>{cCGrp}>
<## Show Mem Access## No:{maNo}> <Yes:{maYes}>{maGrp}> | <## Color graph## No:{cgNo}> <Yes:{cgYes}>{cgGrp}>
<## Configure Stub: {stubButton}> 
<## Add mapping: {amapButton}> (arguments or missing segms in IDB)
<## Save Configration: {saveButton}> | <## Load Configuration: {loadButton} > 
""",{
            'cAGrp': Form.RadGroupControl(("aNo","aYes")),
            'cRGrp': Form.RadGroupControl(("rNo","rYes")),
            'cCGrp': Form.RadGroupControl(("cNo","cYes")),
            'maGrp': Form.RadGroupControl(("maNo","maYes")),
            'cgGrp': Form.RadGroupControl(("cgNo","cgYes")),
            'sAddr': Form.NumericInput(tp=Form.FT_ADDR),
            'eAddr': Form.NumericInput(tp=Form.FT_ADDR),
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
            'R15': Form.NumericInput(tp=Form.FT_RAWHEX),
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
                              p_size=0x400,
                              stk_ba=STACK_BASEADDR,
                              stk_size=STACK_SIZE,
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
                              registers=ArmRegisters(self.GetControlValue(self.R0),
                                                      self.GetControlValue(self.R1),
                                                      self.GetControlValue(self.R2),
                                                      self.GetControlValue(self.R3),
                                                      self.GetControlValue(self.R4),
                                                      self.GetControlValue(self.R5),
                                                      self.GetControlValue(self.R6),
                                                      self.GetControlValue(self.R7),
                                                      self.GetControlValue(self.R8),
                                                      self.GetControlValue(self.R9),
                                                      self.GetControlValue(self.R10),
                                                      self.GetControlValue(self.R11),
                                                      self.GetControlValue(self.R12),
                                                      self.GetControlValue(self.R13),
                                                      self.GetControlValue(self.R14),
                                                      self.GetControlValue(self.R15)),
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


      segms = get_seg_list()
      s_chooser = [] 
      
      i=0 
      for x in segms:
        if x in conf.segms:
          s_chooser.append(i)
        i+=1
    
      self.SetControlValue(self.cAGrp,conf.autoMap)
      self.SetControlValue(self.cRGrp,conf.showRegisters)
      self.SetControlValue(self.sAddr,conf.exec_saddr)
      self.SetControlValue(self.eAddr,conf.exec_eaddr)
      self.SetControlValue(self.cCGrp,conf.useCapstone)
      self.SetControlValue(self.R0,conf.registers.R0)
      self.SetControlValue(self.R1,conf.registers.R1)
      self.SetControlValue(self.R2,conf.registers.R2)
      self.SetControlValue(self.R3,conf.registers.R3)
      self.SetControlValue(self.R4,conf.registers.R4)
      self.SetControlValue(self.R5,conf.registers.R5)
      self.SetControlValue(self.R6,conf.registers.R6)
      self.SetControlValue(self.R7,conf.registers.R7)
      self.SetControlValue(self.R8,conf.registers.R8)
      self.SetControlValue(self.R9,conf.registers.R9)
      self.SetControlValue(self.R10,conf.registers.R10)
      self.SetControlValue(self.R11,conf.registers.R11)
      self.SetControlValue(self.R12,conf.registers.R12)
      self.SetControlValue(self.R13,conf.registers.R13)
      self.SetControlValue(self.R13,conf.registers.R14)
      self.SetControlValue(self.R13,conf.registers.R15)
      self.SetControlValue(self.maGrp,conf.showMemAccess)
      self.s_conf = conf.s_conf 
      self.amap_conf = conf.amap_conf 
      self.breakpoints = conf.breakpoints
      self.SetControlValue(self.cgGrp,conf.color_graph)



  def cb_callback(self,fid):
    return 1 

  @staticmethod
  def fillconfig(conf=None):
      f = Arm32Pannel(conf)
      f.Compile()
      
      ok = f.Execute()
      if ok:
      
          ret = Configuration(path=f.conf_path,arch=ida_idp.get_idp_name(),
                              emulator='unicorn',
                              p_size=0x400,
                              stk_ba=STACK_BASEADDR,
                              stk_size=STACK_SIZE,
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
                              registers=ArmRegisters(f.R0.value,f.R1.value,f.R2.value,f.R3.value,
                                           f.R4.value,f.R5.value,f.R6.value,f.R7.value,
                                           f.R8.value,f.R9.value,f.R10.value,f.R11.value,
                                           f.R12.value,f.R13.value,f.R14.value,f.R15.value),
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


