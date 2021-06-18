import idaapi
import idc
import ida_funcs
import ida_idp
import ida_ua
import ida_segment
import ida_kernwin
from EWS.ui.arm32_simplified import Arm32Pannel
from EWS.ui.mipsl32 import Mipsl32Pannel
from EWS.ui.x86_simplified import x86Pannel
from EWS.ui.x64_simplified import x64Pannel
from EWS.ui.aarch64_simplified import Aarch64Pannel
from EWS.ui.arm32 import Arm32Pannel as Arm32PannelFull
from EWS.ui.aarch64 import Aarch64Pannel as Aarch64CornFull
from EWS.ui.x86 import x86Pannel as x86PannelFull
from EWS.ui.x64 import x64Pannel as x64PannelFull
from EWS.ui.regedit import RegArm32Edit, RegArm64Edit, Regx86Edit, Regx64Edit
from EWS.ui.MemEdit import MemEdit
from EWS.ui.tag_func_ui import TagForm
from EWS.ui.DisplayMem import SelectSegment, MemDisplayer, asciify, space, AddrNBPages
from EWS.ui.Watchpoint import WatchPoint
import EWS.ui
import binascii

from EWS.emu.unicorn.arm32 import ArmCorn
from EWS.emu.unicorn.aarch64 import Aarch64Corn
from EWS.emu.unicorn.mipsl32 import MipsCorn
from EWS.emu.unicorn.x86 import x86Corn
from EWS.emu.unicorn.x64 import x64Corn

from EWS.utils.utils import *
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

        if conf:
            emu = Aarch64Corn(conf)
    else:
        conf = ArmCorn.generate_default_config(s_ea,
                                                   e_ea,
                                                   regs,
                                                   stub_conf,
                                                   amap_config)

        if conf: 
          emu = ArmCorn(conf)
  elif procname == 'pc':
      if idc.__EA64__:
          conf = x64Corn.generate_default_config(s_ea,
                                                 e_ea,
                                                 regs,
                                                 stub_conf,
                                                 amap_config)
          if conf:
              emu = x64Corn(conf)
      else:
        conf = x86Corn.generate_default_config(s_ea,
                                               e_ea,
                                               regs,
                                               stub_conf,
                                               amap_config)

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
            return RegArm64Edit.create
        else:
            return RegArm32Edit.create

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
    conf_path = EWS.ui.generic.FileSelector.fillconfig()
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
    ok,addr,bytesvalstr = MemEdit.fillconfig(emu)
    if ok:
       import binascii
       try:
            bytesval = binascii.a2b_hex(bytesvalstr)
            emu.mem_write(int(addr,16),bytes(bytesval))
       except Exception as e:
            print(e.__str__())
            ok=False
    return ok



def displaymem(emu,content,name,base_addr):

    values = []
    for i in range(0,len(content),16):
        values.append(['0x%x'%(base_addr+i),
                      space(binascii.b2a_hex(content[i:i+16]).decode('utf-8')),
                      asciify(content[i:i+16])])

    md = MemDisplayer("%s Memory"%name,
                      values,
                      emu)
    md.show()


def display_section(emu):
    seg = SelectSegment.fillconfig()
    if seg == None:
        return False
    p_base = seg.start_ea & ~ (emu.conf.p_size -1)
    seg_size = seg.end_ea - p_base
    d,r = divmod(seg_size,emu.conf.p_size)
    if r:
        logger.console(LogType.WARN,'Weird segment size to display, should be aligned')
        d+=1

    # todo: replace with emu.helper.mem_read
    content = emu.mem_read(p_base,d*emu.conf.p_size)
    displaymem(emu,
               content,
               ida_segment.get_segm_name(seg),
               p_base)

def display_addr(emu):
    addr,nbpages = AddrNBPages.fillconfig()
    p_base = addr & ~ (emu.conf.p_size -1)
    try:
        # todo: replace with emu.helper.mem_read
        content = emu.mem_read(p_base,nbpages*emu.conf.p_size)
    except:
        logger.console(LogType.ERRR,"Invalid parameters for addr displaying.")
        return
    displaymem(emu,
               content,
               "%x Memory"%p_base,
               p_base)

def add_mapping(emu):

    addmap = EWS.ui.generic.AddMapping.fillconfig()
    for k,v in addmap.mappings.items():
        emu.add_mapping(k,v)


def display_stack(emu):
    content = emu.mem_read(emu.conf.stk_ba,
                           emu.conf.stk_size)
    displaymem(emu,
               content,
               "Stack",
               emu.conf.stk_ba)


    



def watchpoint(emu):
    return WatchPoint.fillconfig(emu)

