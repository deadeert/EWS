import idaapi
import idc
import ida_funcs
import ida_idp
import ida_ua
import ida_segment
from ui.arm32_simplified import Arm32Pannel
from ui.mipsl32 import Mipsl32Pannel
from ui.x86_simplified import x86Pannel
from ui.x64_simplified import x64Pannel
from ui.aarch64_simplified import Aarch64Pannel
from ui.arm32 import Arm32Pannel as Arm32PannelFull
from ui.aarch64 import Aarch64Pannel as Aarch64CornFull
from ui.x86 import x86Pannel as x86PannelFull
from ui.x64 import x64Pannel as x64PannelFull
from ui.regedit import RegArm32Edit, RegArm64Edit, Regx86Edit, Regx64Edit
from ui.MemEdit import MemEdit
from ui.tag_func_ui import TagForm
from ui.DisplayMem import SelectSegment, MemDisplayer, asciify, space
import ui
import binascii

from emu.unicorn.arm32 import ArmCorn
from emu.unicorn.aarch64 import Aarch64Corn
from emu.unicorn.mipsl32 import MipsCorn
from emu.unicorn.x86 import x86Corn
from emu.unicorn.x64 import x64Corn
from emu.miasm.arm32 import Miarm

from utils.utils import *
import os.path


def get_user_select():

    p0 = idaapi.twinpos_t()
    p1 = idaapi.twinpos_t()
    view = idaapi.get_current_viewer()
    if not idaapi.read_selection(view, p0, p1):
        return (idaapi.BADADDR,idaapi.BADADDR)

    return (p0.at.toea(),p1.at.toea())


def get_func_boundaries():

    ea = idc.get_screen_ea()
    f = ida_funcs.get_func(ea)
    return (f.start_ea,f.end_ea)



def get_emul(s_ea,
             e_ea,
             regs=None,
             stub_conf=None,
             amap_config=None):

  emu = None
  procname = idaapi.get_idp_name()
  if procname == 'arm':
    if idc.__EA64__:
        conf = Aarch64Corn.generate_default_config(s_ea,
                                                   e_ea,
                                                   regs,
                                                   stub_conf,
                                                   amap_config)

        logger.console(LogType.INFO,"Configuration:\n",conf)
        if conf:
            emu = Aarch64Corn(conf)
    else:
        conf = ArmCorn.generate_default_config(s_ea,
                                                   e_ea,
                                                   regs,
                                                   stub_conf,
                                                   amap_config)

        logger.console(LogType.INFO,"Configuration:\n",conf)
        if conf: 
          emu = ArmCorn(conf)
  elif procname == 'pc':
      if idc.__EA64__:
          conf = x64Corn.generate_default_config(s_ea,
                                                 e_ea,
                                                 regs,
                                                 stub_conf,
                                                 amap_config)
          logger.console(LogType.INFO,"Configuration:\n",conf)
          if conf:
              emu = x64Corn(conf)
      else:
        conf = x86Corn.generate_default_config(s_ea,
                                               e_ea,
                                               regs,
                                               stub_conf,
                                               amap_config)

        logger.console(LogType.INFO,"Configuration:\n",conf)
        if conf:
              emu = x86Corn(conf)

  else:
    logger.console(LogType.ERRR,"Sorry %s is not currently supported at this stage" % procname)

  return emu

def get_emul_conf(simplified=True, conf=False):

  emu = None
  procname = idaapi.get_idp_name()
  if procname == 'arm':
    if idc.__EA64__:
        if simplified:
            conf = Aarch64Pannel.fillconfig() 
        else:
            conf = Aarch64CornFull.fillconfig(conf)
        if conf:
            emu = Aarch64Corn(conf)
    else:
        if simplified:
            conf = Arm32Pannel.fillconfig()
        else:
            conf = Arm32PannelFull.fillconfig(conf)
        if conf: 
            emu = ArmCorn(conf)
  elif procname == 'pc':
   if idc.__EA64__: # assess if ida is running in 64bits
     if simplified:
        conf = x64Pannel.fillconfig()
     else:
         conf = x64PannelFull.fillconfig(conf)
     if conf:
       emu = x64Corn(conf)
   else:
       if simplified:
        conf = x86Pannel.fillconfig()
       else:
        conf = x86PannelFull.fillconfig(conf)
       if conf:
         emu = x86Corn(conf)
  else:
      logger.console(LogType.ERRR,"Current architecture not yet supported")


  return emu




def get_regedit_func():
    procname = idaapi.get_idp_name()
    if procname == 'arm':
        if idc.__EA64__:
            return RegArm32Edit.create
        else:
            return RegArm64Edit.create

    elif procname == 'pc':
       if idc.__EA64__: # assess if ida is running in 64bits
            return Regx64Edit.create
       else:

            return Regx86Edit.create
    else:
        logger.console(LogType.ERRR,"Current architecture not yet supported")

def get_tag_name(tag_list):
    ea = idc.get_screen_ea()
    i = ida_ua.insn_t()
    ida_ua.decode_insn(i,ea)
    if ida_idp.is_call_insn(i):
        idx = TagForm.create(tag_list)
        return tag_list[idx]
    else:
        logger.console(LogType.ERRR,'Selected address does not represent a function')
        logger.console(LogType.ERRR,'Please use a CALL insn to tag a function')




def loadconfig():
    conf_path = ui.generic.FileSelector.fillconfig()
    if os.path.exists(conf_path):
        import utils
        conf = utils.utils.loadconfig(conf_path)
    else:
        logger.console(LogType.ERRR,'Config file does not exist')

    if conf.arch == 'arm':
        return ArmCorn(conf)
    elif conf.arch == 'aarch64':
        return Aarch64Corn(conf)
    elif conf.arch == 'x86':
        return x86Corn(conf)
    elif conf.arch == 'x64':
        return x64Corn(conf)
    else:
        logger.console(LogType.ERRR,'Specified architecture not valid')
        return None

def patch_mem(emu):
    ok,addr,bytesval = MemEdit.fillconfig(emu)
    print(ok,addr,bytesval)
    if ok:
       import binascii
       try:
            emu.mem_write(addr,binascii.a2b_hex(bytesval))
       except:
            ok=False
    return ok



def displaymem(emu):

    seg = SelectSegment.fillconfig()
    if seg == None:
        return False
    p_base = seg.start_ea & ~ (emu.conf.p_size -1)
    seg_size = seg.end_ea - p_base
    d,r = divmod(seg_size,emu.conf.p_size)
    if r:
        logger.console(LogType.WARN,'Weird segment size to display, should be aligned')
        d+=1
    content = emu.mem_read(p_base,d*emu.conf.p_size)
    values = []
    for i in range(0,len(content),16):
        values.append(['0x%x'%(p_base+i),
                      space(binascii.b2a_hex(content[i:i+16]).decode('utf-8')),
                      asciify(content[i:i+16])])

    md = MemDisplayer("%s Memory"%ida_segment.get_segm_name(seg),
                      values,
                      emu)
    md.show()




