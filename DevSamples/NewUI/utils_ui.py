import idaapi
import idc
import ida_funcs


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

  procname = get_idp_name()
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
  else:
    logger.console(LogType.ERRR,"Sorry %s is not currently supported at this stage" % procname)
    return None

  return emu
 
