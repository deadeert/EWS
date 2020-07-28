from ui.generic import * 
from utils import *

"""                   """
"         MIPS          "
"""                   """
class Mipsl32Pannel(Pannel):

  def __init__(self):
    print(self.__dir__)
    self.invert = False
    self.segs = [] 
    self.s_conf = StubConfiguration.create() 
    self.amap_conf = AdditionnalMapping({})#AdditionnalMapping.create()
    Form.__init__(self, r"""STARTITEM 
BUTTON YES Run
BUTTON NO No
BUTTON CANCEL* Cancel
EWS MIPSL32
{cbCallback}
Mapping Configuration
<## Page size  :{iPageSize}> | <## Stack base address: {iStkBA}> | <## Stack size: {iStkSize}>
<##Start Mapping (ea in IDB):{sMapping}> | <##End Mapping (ea in IDB):{eMapping}>   
<## Map using segments## No:{sNo}> <Yes:{sYes}>{cCSeg}> | <## Use segment perms ## No:{spNo}> <Yes:{spYes}>{spCSeg}>
<## AutoMap missing regions## No:{aNo}> <Yes:{aYes}>{cAGrp}>
<Segment: {cSegChooser}>
Execution Configuration
<##Start address:{sAddr}> | <##End address:{eAddr}>
<##at:{at}>|<##a0:{a0}>|<##a1:{a1}>|<##a2:{a2}>|<##a3:{a3}>
<##s0:{s0}>|<##s1:{s1}>|<##s2:{s2}>|<##s3:{s3}>|<##s4:{s4}>
<##s5:{s5}>|<##s6:{s6}>|<##s7:{s7}>|<##hi:{hi}>|<##lo:{lo}>
<##t0:{t0}>|<##t1:{t1}>|<##t2:{t2}>|<##t3:{t3}>|<##t4:{t4}>
<##t5:{t5}>|<##t6:{t6}>|<##t7:{t7}>|<##t8:{t8}>|<##t9:{t9}>
<##gp:{gp}>|<##fp:{fp}>|<##ra:{ra}>|<##sp:{sp}>|<##pc:{pc}>
<##v0:{v0}>|<##v1:{v1}>|<##k0:{k0}>|<##k1:{k1}>
Display Configuration 
<## Show register values## No:{rNo}> <Yes:{rYes}>{cRGrp}> | <## Use Capstone## No:{cNo}> <Yes:{cYes}>{cCGrp}>
<## Show Mem Access## No:{maNo}> <Yes:{maYes}>{maGrp}> | <## Color graph## No:{cgNo}> <Yes:{cgYes}>{cgGrp}>
<## Configure Stub: {stubButton}> 
<## Add mapping: {amapButton}> (arguments or missing segms in IDB)
<## Save Configration: {saveButton}> | <## Load Configuration: {loadButton} > 
""",{
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
            'at': Form.NumericInput(tp=Form.FT_RAWHEX),
            'a0': Form.NumericInput(tp=Form.FT_RAWHEX),
            'a1': Form.NumericInput(tp=Form.FT_RAWHEX),
            'a2': Form.NumericInput(tp=Form.FT_RAWHEX),
            'a3': Form.NumericInput(tp=Form.FT_RAWHEX),
            's0': Form.NumericInput(tp=Form.FT_RAWHEX),
            's1': Form.NumericInput(tp=Form.FT_RAWHEX),
            's2': Form.NumericInput(tp=Form.FT_RAWHEX),
            's3': Form.NumericInput(tp=Form.FT_RAWHEX),
            's4': Form.NumericInput(tp=Form.FT_RAWHEX),
            's5': Form.NumericInput(tp=Form.FT_RAWHEX),
            's6': Form.NumericInput(tp=Form.FT_RAWHEX),
            's7': Form.NumericInput(tp=Form.FT_RAWHEX),
            't0': Form.NumericInput(tp=Form.FT_RAWHEX),
            't1': Form.NumericInput(tp=Form.FT_RAWHEX),
            't2': Form.NumericInput(tp=Form.FT_RAWHEX),
            't3': Form.NumericInput(tp=Form.FT_RAWHEX),
            't4': Form.NumericInput(tp=Form.FT_RAWHEX),
            't5': Form.NumericInput(tp=Form.FT_RAWHEX),
            't6': Form.NumericInput(tp=Form.FT_RAWHEX),
            't7': Form.NumericInput(tp=Form.FT_RAWHEX),
            't8': Form.NumericInput(tp=Form.FT_RAWHEX),
            't9': Form.NumericInput(tp=Form.FT_RAWHEX),
            'v0': Form.NumericInput(tp=Form.FT_RAWHEX),
            'v1': Form.NumericInput(tp=Form.FT_RAWHEX),
            'k0': Form.NumericInput(tp=Form.FT_RAWHEX),
            'k1': Form.NumericInput(tp=Form.FT_RAWHEX),
            'hi': Form.NumericInput(tp=Form.FT_RAWHEX),
            'lo': Form.NumericInput(tp=Form.FT_RAWHEX),
            'gp': Form.NumericInput(tp=Form.FT_RAWHEX),
            'fp': Form.NumericInput(tp=Form.FT_RAWHEX),
            'ra': Form.NumericInput(tp=Form.FT_RAWHEX),
            'sp': Form.NumericInput(tp=Form.FT_RAWHEX),
            'pc': Form.NumericInput(tp=Form.FT_RAWHEX),
            'cbCallback': Form.FormChangeCb(self.cb_callback),
            'stubButton': Form.ButtonInput(self.onStubButton),
            'amapButton': Form.ButtonInput(self.onaMapButton),
            'saveButton': Form.ButtonInput(self.onSaveButton),
            'loadButton': Form.ButtonInput(self.onLoadButton)
})



  def onSaveButton(self,code):
    conf = Configuration(arch=ida_idp.get_idp_name(),
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
                              registers=MipslRegisters(at=self.GetControlValue(self.at),
                                            a0=self.GetControlValue(self.a0),
                                            a1=self.GetControlValue(self.a1),
                                            a2=self.GetControlValue(self.a2),
                                            a3=self.GetControlValue(self.a3),
                                            s0=self.GetControlValue(self.s0),
                                            s1=self.GetControlValue(self.s1),
                                            s2=self.GetControlValue(self.s2),
                                            s3=self.GetControlValue(self.s3),
                                            s4=self.GetControlValue(self.s4),
                                            s5=self.GetControlValue(self.s5),
                                            s6=self.GetControlValue(self.s6),
                                            s7=self.GetControlValue(self.s7),
                                            t0=self.GetControlValue(self.t0),
                                            t1=self.GetControlValue(self.t1),
                                            t2=self.GetControlValue(self.t2),
                                            t3=self.GetControlValue(self.t3),
                                            t4=self.GetControlValue(self.t4),
                                            t5=self.GetControlValue(self.t5),
                                            t6=self.GetControlValue(self.t6),
                                            t7=self.GetControlValue(self.t7),
                                            t8=self.GetControlValue(self.t8),
                                            t9=self.GetControlValue(self.t9),
                                            v0=self.GetControlValue(self.v0),
                                            v1=self.GetControlValue(self.v1),
                                            hi=self.GetControlValue(self.hi),
                                            lo=self.GetControlValue(self.lo),
                                            k0=self.GetControlValue(self.k0),
                                            k1=self.GetControlValue(self.k1),
                                            gp=self.GetControlValue(self.gp),
                                            fp=self.GetControlValue(self.fp),
                                            ra=self.GetControlValue(self.ra),
                                            sp=self.GetControlValue(self.sp),
                                            pc=self.GetControlValue(self.pc)),
                              showMemAccess=self.GetControlValue(self.maGrp),
                              s_conf=self.s_conf,
                              amap_conf=self.amap_conf,
                              color_graph=self.GetControlValue(self.cgGrp))


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
      self.SetControlValue(self.cCGrp,conf.useCapstone)
      self.SetControlValue(self.at,conf.registers.at)
      self.SetControlValue(self.a0,conf.registers.a0)
      self.SetControlValue(self.a1,conf.registers.a1)
      self.SetControlValue(self.a2,conf.registers.a2)
      self.SetControlValue(self.a3,conf.registers.a3)
      self.SetControlValue(self.s0,conf.registers.s0)
      self.SetControlValue(self.s1,conf.registers.s1)
      self.SetControlValue(self.s2,conf.registers.s2)
      self.SetControlValue(self.s3,conf.registers.s3)
      self.SetControlValue(self.s4,conf.registers.s4)
      self.SetControlValue(self.s5,conf.registers.s5)
      self.SetControlValue(self.s6,conf.registers.s6)
      self.SetControlValue(self.s7,conf.registers.s7)
      self.SetControlValue(self.t0,conf.registers.t0)
      self.SetControlValue(self.t1,conf.registers.t1)
      self.SetControlValue(self.t2,conf.registers.t2)
      self.SetControlValue(self.t3,conf.registers.t3)
      self.SetControlValue(self.t4,conf.registers.t4)
      self.SetControlValue(self.t5,conf.registers.t5)
      self.SetControlValue(self.t6,conf.registers.t6)
      self.SetControlValue(self.t7,conf.registers.t7)
      self.SetControlValue(self.t8,conf.registers.t8)
      self.SetControlValue(self.t9,conf.registers.t9)
      self.SetControlValue(self.hi,conf.registers.hi)
      self.SetControlValue(self.lo,conf.registers.lo)
      self.SetControlValue(self.k0,conf.registers.k0)
      self.SetControlValue(self.k1,conf.registers.k1)
      self.SetControlValue(self.gp,conf.registers.gp)
      self.SetControlValue(self.fp,conf.registers.fp)
      self.SetControlValue(self.ra,conf.registers.ra)
      self.SetControlValue(self.sp,conf.registers.sp)
      self.SetControlValue(self.pc,conf.registers.pc)
      self.SetControlValue(self.maGrp,conf.showMemAccess)
      self.s_conf = conf.s_conf 
      self.amap_conf = conf.amap_conf 
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
          self.SetControlValue(self.pc,self.GetControlValue(self.sAddr))
    elif fid == self.iStkSize.id or fid == self.iStkBA.id:
          sp = self.GetControlValue(self.iStkSize) + self.GetControlValue(self.iStkBA) 
          self.SetControlValue(self.sp,sp)
    return 1 

  @staticmethod
  def fillconfig():
      f = Mipsl32Pannel()
      f.Compile()
      
      ok = f.Execute()
      if ok:
      
          ret = Configuration(arch=ida_idp.get_idp_name(),
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
                              registers=MipslRegisters(at=f.at.value,
                                            a0=f.a0.value,
                                            a1=f.a1.value,
                                            a2=f.a2.value,
                                            a3=f.a3.value,
                                            s0=f.s0.value,
                                            s1=f.s1.value,
                                            s2=f.s2.value,
                                            s3=f.s3.value,
                                            s4=f.s4.value,
                                            s5=f.s5.value,
                                            s6=f.s6.value,
                                            s7=f.s7.value,
                                            t0=f.t0.value,
                                            t1=f.t1.value,
                                            t2=f.t2.value,
                                            t3=f.t3.value,
                                            t4=f.t4.value,
                                            t5=f.t5.value,
                                            t6=f.t6.value,
                                            t7=f.t7.value,
                                            t8=f.t8.value,
                                            t9=f.t9.value,
                                            v0=f.v0.value,
                                            v1=f.v1.value,
                                            hi=f.hi.value,
                                            lo=f.lo.value,
                                            k0=f.k0.value,
                                            k1=f.k1.value,
                                            gp=f.gp.value,
                                            fp=f.fp.value,
                                            ra=f.ra.value,
                                            sp=f.sp.value,
                                            pc=f.sp.value),
                              showMemAccess=f.maGrp.value,
                              s_conf=f.s_conf,
                              amap_conf=f.amap_conf,
                              color_graph=f.cgGrp.value)
    
      else:
        logger.console(2,'[Form.execute()] error, aborting...\n please contact maintainer')
        return None
      f.Free()

      return ret
  
 

