import idaapi
import idc
import ida_funcs
import ida_idp
import ida_ua
import ida_segment
import ida_kernwin
import ida_bytes
from EWS.ui.generic import Pannel
from EWS.ui.regedit import RegArm32Edit, RegArm64Edit, Regx86Edit, Regx64Edit
from EWS.ui.mem_edit import MemEdit
from EWS.ui.mem_operations import ExportMemory, ImportMemory 
from EWS.ui.tag_func_ui import TagForm
from EWS.ui.display_mem import SelectSegment, MemDisplayer, asciify, space, AddrNBPages
from EWS.ui.watchpoint import WatchPoint
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
from typing import Tuple,Dict,List

from EWS.utils.utils import *
import os.path


def get_user_select() -> Tuple:

    """ 
    !Extract the user selection from the current UI. 

    @return User Selected Range. 

    """ 

    p0 = idaapi.twinpos_t()
    p1 = idaapi.twinpos_t()
    view = idaapi.get_current_viewer()
    if not idaapi.read_selection(view, p0, p1):
        return (idaapi.BADADDR,idaapi.BADADDR)

    return (p0.at.toea(),p1.at.toea())


def get_func_boundaries() -> Tuple:

    """ 

    !Extract the function boundaries.

    @return The function boundaries.

    
    """

    ea = idc.get_screen_ea()
    f = ida_funcs.get_func(ea)
    return (f.start_ea,f.end_ea)




def get_conf_for_area(s_ea:int,
                      e_ea:int) :

  """  
  !Generate a default configuration from a starting and ending address.

  @param s_ea: Effective Address of the first instruction to be executed. 
  @param e_ea: Effective Address of the last instruction to be executed.

  @return Configuration object.

  """

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

def get_emul_from_conf(conf) -> EWS.emu.emubase.Emulator:

  """
  !This function initialize the engine from a configuration object.
  In case several options are available, this function must ask the user 
  to choose among the candidates.

  @param Configuration object

  @param Emulator wrapper.

  """


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

  """ 
  ! This function helps to edit configuration. 
  """

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



def get_regedit_func():

    """ 
    !Return the right function to edit the register according the binary architecture
    @return The function pointer to edit registers.

    """
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

def get_tag_name(tag_list:List[str])->str:

    """ 
    !Allow the user to choose a tag when using tag_func feature. 

    @param tag_list: List of available tags.

    @return User selected tag.
    """
    


    ea = idc.get_screen_ea()
    i = ida_ua.insn_t()
    ida_ua.decode_insn(i,ea)
    if ida_idp.is_call_insn(i):
        idx = TagForm.create(tag_list)
        return tag_list[idx]
    else:
        logger.console(LogType.ERRR,'Selected address does not represent a function')
        logger.console(LogType.ERRR,'Please use a CALL insn to tag a function')




def loadconfig() :

    """ 
    !Load config from user select file.

    @return The configuration deserialized. 

    """

    conf_path = EWS.ui.generic.FileSelector.fillconfig()
    if does_file_exist(conf_path):
        return  EWS.utils.configuration.loadconfig(conf_path)

    else:
        raise Exception("Config loading error")

def saveconfig(config):

    """
    !Dump the specified config object in a file.

    @param config: Configurtation obj.
    """

    conf_path = EWS.ui.generic.FileSelector.fillconfig()
    if does_file_exist(conf_path):
        if (not ida_kernwin.ask_yn(False,'%s already exists. Replace?'%conf_path)):
            return
    try:
        EWS.utils.configuration.saveconfig(config,conf_path) 
    except Exception as e:
        ida_kernwin.warning('Could not save config: %s'%str(e))



def patch_mem(emu:EWS.emu.emubase.Emulator):

    """ 
    !Patch memory 

    @param emu: Pointer to a emu.emubase instance.

    """

    ok,addr,bytesvalstr = MemEdit.fillconfig(emu)
    if ok:
        try:
            import binascii
            bytesval = binascii.a2b_hex(bytesvalstr)
            emu.patch_mem(int(addr,16),bytes(bytesval))
        except:
            ok=False
    return ok



def displaymem(emu:EWS.emu.emubase.Emulator,
               content:bytes,
               name:str,
               base_addr:int):

    """ 
    !Display content memory by opening MemDisplayer widget. 

    @param emu: Pointer to a emu.emubase instance.
    @param content: Bytes to display.
    @param name: Name of the section*. 
    @param base_addr: Effective Address of the first byte. 

    """

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



def display_section(emu:EWS.emu.emubase.Emulator):

    """ 
    !Display a specific memory section taken from the IDB. 

    @param emu: Pointer to a emu.emubase instance.

    """
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


def display_addr(emu:EWS.emu.emubase.Emulator):

    try:
        addr,nbpages = AddrNBPages.fillconfig()
    except: 
        return 
    p_base = addr & ~ (emu.conf.p_size -1)
    try:
        # todo: replace with emu.helper.mem_read
        content = emu.mem_read(p_base,nbpages*emu.conf.p_size)
    except Exception as e:
        logger.console(LogType.ERRR,"Invalid parameters for addr displaying.")
        return
    displaymem(emu,
               content,
               "%x Memory"%p_base,
               p_base)


def get_add_mappings():

    """ 
    !Get a pointer to UI pannel AddMapping

    @return UI pannel ref.

    """

    return EWS.ui.generic.AddMapping.fillconfig()

def add_mapping(emu:EWS.emu.emubase.Emulator,
                addmap):

    """ 
    !Map a page and init its content 

    @param emu: Pointer to Emulator object.
    @param addmap: Additional Mapping items
    """

    for k,v in addmap.mappings.items():
        emu.add_mapping(k,v)


def display_stack(emu:EWS.emu.emubase.Emulator):
    """ 
    !Display the stack

    @param emu: Pointer to an emulator object.

    """

    content = emu.mem_read(emu.conf.stk_ba,
                           emu.conf.stk_size)
    displaymem(emu,
               content,
               "Stack",
               emu.conf.stk_ba)

def export_mem(emu:EWS.emu.emubase.Emulator):
    """ 
    !Dump memory to a file from user specified content

    @param emu: Pointer to Emulator object. 

    """

    try:
        (addr,size,f_path) = ExportMemory.fillconfig()
    except Exception as e:
        print(e)
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


def import_mem(emu:EWS.emu.emubase.Emulator):

    """ 
    !Import memory from a file

    @param emu: Emulator pointer.
    """
    try: 
        (addr,f_path) = ImportMemory.fillconfig()
    except:
        ida_kernwin.warning("Could not import invalid params")
        return 
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
        ida_kernwin.warning("Could not write file content into memory, are you sure the page is mapped ?")
        return
    try:
        emu.mem_write(addr,content_b)
    except:
        logger.console(LogType.ERRR,"Could not import %s: unproper permission?",f_path)
        return
    logger.console(LogType.INFO,"File %s imported into [%x %x]"%(f_path,addr,addr+len(content_b)))

    emu.conf.memory_init += AdditionnalMapping({addr:content_b})


def watchpoint(emu:EWS.emu.emubase.Emulator):

    """ 
    !Returns the watchpoint pannel

    @return pointer
    """
    return WatchPoint.fillconfig(emu)


def add_insn_patch(emu:EWS.emu.emubase.Emulator):

    """ 
    !Patch the insn 

    @param emu: Emulator Pointer 

    """
    addr = idc.get_screen_ea()
    #TODO add check to verify that addr is on a code area ? 
    try:
        asm = ida_kernwin.ask_str('Insn Patch',False,"Please enter the assembly to replace insn at %x"%addr)
        emu.patch_insn(addr,asm)
    except Exception as e:
        ida_kernwin.warning("Could not patch insn at %x.Reason: %s"%(addr,str(e)))

def is_arch_supported()->bool:
    """ 
    !Return either or not arch is supported by EWS. 
    
    @return The support 
    """

    return idaapi.get_idp_name() in ['pc', 'arm']


def is_code(ea:int) -> bool:
    """ 
    !Return True if the ea is flagged as code in IDB.

    @param ea: Effective Address of the supposed code.

    @return The answer.

    """
    return ida_bytes.is_code(ida_bytes.get_flags(ea))

def add_patch_file(engine:EWS.emu.emubase.Emulator):

    """ 
    !Load a json file containing records {"addr":"assembly text"}.

    @param engine: Pointer to a Emulator instance. 

    """

    f_path = EWS.ui.generic.FileSelector.fillconfig()

    if not does_file_exist(f_path):

        ida_kernwin.warning('File %s does not exist.'%f_path)
        return

    update_conf = ida_kernwin.ask_yn(False,"Do you want to update the conf?")

    with open(f_path, 'r') as fpatch:
        patches = json.load(fpatch)

    for addr,insn in dict(patches).items():
        addr = int(addr,16)
        engine.patch_insn(addr,insn)



