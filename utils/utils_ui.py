import idaapi
import idc
import ida_funcs
import ida_idp
import ida_ua
from ui.arm32_simplified import Arm32Pannel
from ui.mipsl32 import Mipsl32Pannel
from ui.x86 import x86Pannel
from ui.x64 import x64Pannel
from ui.aarch64_simplified import Aarch64Pannel
from ui.regedit import RegArm32Edit, RegArm64Edit
from ui.tag_func_ui import TagForm

from emu.unicorn.arm32 import ArmCorn
from emu.unicorn.aarch64 import Aarch64Corn
from emu.unicorn.mipsl32 import MipsCorn
from emu.unicorn.x86 import x86Corn
from emu.unicorn.x64 import x64Corn
from emu.miasm.arm32 import Miarm



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

  procname = idaapi.get_idp_name()
  if procname == 'arm':
    if idc.__EA64__:
        conf = Aarch64Corn.generate_default_config(s_ea,
                                                   e_ea,
                                                   regs,
                                                   stub_conf,
                                                   amap_config)
        if conf:
            emu = Aarch64Corn(conf)
    else:
        conf = ArmCorn.generate_default_config(s_ea,
                                                   e_ea,
                                                   regs,
                                                   stub_conf,
                                                   amap_config)
        print(conf)
        if conf: 
          emu = ArmCorn(conf)
  else:
    logger.console(LogType.ERRR,"Sorry %s is not currently supported at this stage" % procname)
    return None

  return emu

def get_emul_fullconf():

  emu = None
  procname = idaapi.get_idp_name()
  if procname == 'arm':
    if idc.__EA64__:
        conf = Aarch64Pannel.fillconfig() 
        if conf:
            emu = Aarch64Corn(conf)
    else:
        conf = Arm32Pannel.fillconfig()
        if conf: 
          emu = ArmCorn(conf)
  else:
      logger.console(LogType.ERRR,"Current architecture not yet supported")

  return emu
#  elif procname == 'mips':
#    conf = Mipsl32Pannel.fillconfig()
#    if conf:
#      emu = MipsCorn(conf)
#  elif procname == 'pc':
#   if idc.__EA64__: # assess if ida is running in 64bits
#    conf = x64Pannel.fillconfig()
#    if conf:
#      emu = x64Corn(conf)
#   else:
#      conf = x86Pannel.fillconfig()
#      if conf:
#        emu = x86Corn(conf)
#

def get_regedit_func():
    procname = idaapi.get_idp_name()
    if procname == 'arm':
        if idc.__EA64__:
            return RegArm32Edit.create
        else:
            return RegArm64Edit.create
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





