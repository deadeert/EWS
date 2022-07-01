import idaapi
import idc
import ida_funcs
import ida_idp
import ida_ua
import ida_segment
import ida_kernwin
import ida_bytes
from EWS.ui.generic import Pannel
#from EWS.ui.arm32_simplified import Arm32Pannel
#from EWS.ui.mipsl32 import Mipsl32Pannel
#from EWS.ui.x86_simplified import x86Pannel
#from EWS.ui.x64_simplified import x64Pannel
#from EWS.ui.aarch64_simplified import Aarch64Pannel
#from EWS.ui.arm32 import Arm32Pannel as Arm32PannelFull
#from EWS.ui.aarch64 import Aarch64Pannel as Aarch64CornFull
#from EWS.ui.x86 import x86Pannel as x86PannelFull
#from EWS.ui.x64 import x64Pannel as x64PannelFull
from EWS.ui.regedit import RegArm32Edit, RegArm64Edit, Regx86Edit, Regx64Edit
from EWS.ui.MemEdit import MemEdit
from EWS.ui.MemOperations import ExportMemory, ImportMemory 
from EWS.ui.tag_func_ui import TagForm
from EWS.ui.DisplayMem import SelectSegment, MemDisplayer, asciify, space, AddrNBPages
from EWS.ui.Watchpoint import WatchPoint
import EWS.ui
import binascii
import json
from unicorn import UcError
from EWS.emu.unicorn.arm32 import ArmCorn
from EWS.emu.unicorn.aarch64 import Aarch64Corn
from EWS.emu.unicorn.mipsl32 import MipsCorn
from EWS.emu.unicorn.x86 import x86Corn
from EWS.emu.unicorn.x64 import x64Corn
from EWS.utils.configuration import *


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




def get_conf_for_area(s_ea,
                      e_ea):

  procname = idaapi.get_idp_name()
  if procname == 'arm':
    if idc.__EA64__:
        return Aarch64Corn.generate_default_config(exec_saddr=s_ea,
                                                   exec_eaddr=e_ea)
    else:
        return ArmCorn.generate_default_config(exec_saddr=s_ea,
                                                   exec_eaddr=e_ea)

  elif procname == 'pc':
      if idc.__EA64__:
          return x64Corn.generate_default_config(exec_saddr=s_ea,
                                                 exec_eaddr=e_ea)
      else:
        return x86Corn.generate_default_config(exec_saddr=s_ea,
                                               exec_eaddr=e_ea)
  else:
    logger.console(LogType.ERRR,"Sorry %s is not currently supported at this stage" % procname)

  return emu

def get_emul_from_conf(conf):


  procname = idaapi.get_idp_name()
  if procname == 'arm':
    if idc.__EA64__:
        return Aarch64Corn(conf)
    else:
        return ArmCorn(conf)

  elif procname == 'pc':
      if idc.__EA64__:
          return x64Corn(conf)
      else:
          return x86Corn(conf)



def get_emul_conf(simplified : bool = True,
                  conf: EWS.utils.configuration.Configuration = None):

  emu = None
  procname = idaapi.get_idp_name()
  if procname == 'arm':
      #TODO MODIF HERE PANNEL
    if idc.__EA64__: # TODO it checks if the instance of IDA is ida64 or ida. 
                     # in case a 32bit arch is opened with ida64 this will 
                     # bug. FIXME find another way to probe the arch. 
        return Pannel.fillconfig(register_ui_class=RegArm64Edit.create,
                          default_regs_values=Aarch64Registers.get_default_object(),
                                 conf=conf if conf else None)
    else:
        return Pannel.fillconfig(register_ui_class=RegArm32Edit.create,
                          default_regs_values=ArmRegisters.get_default_object(),
                                 conf=conf if conf else None)
  elif procname == 'pc':
   if idc.__EA64__: # assess if ida is running in 64bits
        return Pannel.fillconfig(register_ui_class=Regx64Edit.create,
                          default_regs_values=x64Registers.get_default_object(),
                                 conf=conf if conf else None)
   else:

        return Pannel.fillconfig(register_ui_class=Regx86Edit.create,
                          default_regs_values=x64Registers.get_default_object(),
                                 conf=conf if conf else None)
  else:
      logger.console(LogType.ERRR,"Current architecture not yet supported")
      return None
#  if procname == 'arm':
#      #TODO MODIF HERE PANNEL
#    if idc.__EA64__:
#        if simplified:
#            return Aarch64Pannel.fillconfig() 
#        else:
#            return Aarch64CornFull.fillconfig(conf)
#    else:
#        if simplified:
#            return Arm32Pannel.fillconfig()
#        else:
#            return Arm32PannelFull.fillconfig(conf)
#  elif procname == 'pc':
#   if idc.__EA64__: # assess if ida is running in 64bits
#     if simplified:
#        return x64Pannel.fillconfig()
#     else:
#        return x64PannelFull.fillconfig(conf)
#   else:
#       if simplified:
#            return x86Pannel.fillconfig()
#       else:
#            return x86PannelFull.fillconfig(conf)
#  else:
#      logger.console(LogType.ERRR,"Current architecture not yet supported")
#


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
    if does_file_exist(conf_path):
        return  EWS.utils.configuration.loadconfig(conf_path)

    else:
        ida_kernwin.warning('Config file does not exist')
        #logger.console(LogType.ERRR,'Config file does not exist')

def saveconfig(config):
    conf_path = EWS.ui.generic.FileSelector.fillconfig()
    if does_file_exist(conf_path):
        if (not ida_kernwin.ask_yn(False,'%s already exists. Replace?'%conf_path)):
            return
    try:
        EWS.utils.configuration.saveconfig(config,conf_path) 
    except Exception as e:
        ida_kernwin.warning('Could not save config: %s'%str(e))



def patch_mem(emu):
    ok,addr,bytesvalstr = MemEdit.fillconfig(emu)
    if ok:
       import binascii
       try:
            bytesval = binascii.a2b_hex(bytesvalstr)
            emu.mem_write(int(addr,16),bytes(bytesval))
       except Exception as e:
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
    #view_to_dock_with = idaapi.get_widget_title(idaapi.get_current_viewer())
    md.show()
    #idaapi.set_dock_pos('%s Memory'%name,view_to_dock_with,idaapi.DP_RIGHT)



def display_section(emu):
    seg = SelectSegment.fillconfig()
    if seg == None:
        return False
    p_base = seg.start_ea & ~(emu.conf.p_size -1)
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

def display_exec_trace():
    """
    view_to_dock_with idaapi.get_widget_title(idaapi.get_current_viewer())
    # create dock object (exec_trace XXXX)
    Python>widt=idaapi.find_widget('exec_trace XXXX')
    #idview=idaapi.find_widget('IDA View-A')
    Python>idaapi.set_dock_pos('exec_trace XXXX',view_to_dock_with,idaapi.DP_RIGHT)
    True
    """
    pass


def display_addr(emu):
    addr,nbpages = AddrNBPages.fillconfig()
    p_base = addr & ~ (emu.conf.p_size -1)
    try:
        # todo: replace with emu.helper.mem_read
        content = emu.mem_read(p_base,nbpages*emu.conf.p_size)
    except Exception as e:
        print(str(e))
        logger.console(LogType.ERRR,"Invalid parameters for addr displaying.")
        return
    displaymem(emu,
               content,
               "%x Memory"%p_base,
               p_base)


def get_add_mappings():
    return EWS.ui.generic.AddMapping.fillconfig()

def add_mapping(emu,addmap):
    for k,v in addmap.mappings.items():
        emu.add_mapping(k,v)


def display_stack(emu):
    print("display_stack %x %x"%(emu.conf.stk_ba,emu.conf.stk_ba+emu.conf.stk_size))
    content = emu.mem_read(emu.conf.stk_ba,
                           emu.conf.stk_size)
    displaymem(emu,
               content,
               "Stack",
               emu.conf.stk_ba)

def export_mem(emu):
    try:
        (addr,size,f_path) = EWS.ui.MemOperations.ExportMemory.fillconfig()
    except Exception as e:
        return
    try:
        with open(f_path,'wb+') as fout:
            fout.write(emu.mem_read(addr,size))
        logger.console(LogType.INFO,'[+] exported %x (size: %d) to file %s '%(addr,size,f_path))
    except UcError:
        logger.console(LogType.ERRR,"Error accessing memory for range [%x : %x]"%(addr,
                                                                                  addr+size))
    except Exception as e:
        logger.console(LogType.ERRR,"Error opening file: %s"%str(e))


def import_mem(emu):
    (addr,f_path) = EWS.ui.MemOperations.ImportMemory.fillconfig()
    content_b = None
    if not does_file_exist(f_path) : 
        logger.console(LogType.ERRR,"Could not import: file %s not found"%f_path)
        return
    try:
        with open(f_path,'rb') as fin:
            content_b = fin.read()
    except:
        logger.console(LogType.ERRR,"Could not import %s: check permissions ?"%f_path)
        return 
    try:
        emu.mem_read(addr,len(content_b))
    except:
        logger.console(LogType.ERRR,"Could not import %s: memory unmapped?",f_path)
        return
    try:
        emu.mem_write(addr,content_b)
    except:
        logger.console(LogType.ERRR,"Could not import %s: unproper permission?",f_path)
        return
    logger.console(LogType.INFO,"File %s imported into [%x %x]"%(f_path,addr,addr+len(content_b)))

    emu.conf.memory_init += AdditionnalMapping({addr:content_b})


def watchpoint(emu):
    return WatchPoint.fillconfig(emu)


def add_insn_patch(emu):
    addr = idc.get_screen_ea()
    #TODO add check to verify that addr is on a code area ? 
    try:
        asm = ida_kernwin.ask_str('Insn Patch',False,"Please enter the assembly to replace insn at %x"%addr)
        emu.patch_insn(addr,asm,True)
    except Exception as e:
        ida_kernwin.warning("Could not patch insn at %x.Reason: %s"%(addr,str(e)))

def is_arch_supported():
    return idaapi.get_idp_name() in ['pc', 'arm']


def is_code(ea):
    return ida_bytes.is_code(ida_bytes.get_flags(ea))

def add_patch_file(engine):

    f_path = EWS.ui.generic.FileSelector.fillconfig()
    if not does_file_exist(f_path):
        ida_kernwin.warning('File %s does not exist.'%f_path)
        return

    update_conf = ida_kernwin.ask_yn(False,"Do you want to update the conf?")

    with open(f_path, 'r') as fpatch:
        patches = json.load(fpatch)

    for addr,insn in dict(patches).items():
        addr = int(addr,16)
        engine.patch_insn(addr,insn,update_conf)



