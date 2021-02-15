import ida_kernwin
import idaapi 
import idautils
from utils import utils_ui 
from utils.utils import * 
from ui import *

PLUGNAME="ews"
EMULLAUNCHER=PLUGNAME+":defaultlauncher"
EMULF=PLUGNAME+":emulfunc"
EMULSELECT=PLUGNAME+":emulselection"
EDITREG=PLUGNAME+":regedit"
EDITSTUBCONF=PLUGNAME+"stubconfedit"
NSTUB=PLUGNAME+":nullstubfunc"
TAGFUNC=PLUGNAME+":tagfunc"
LOADCONF=PLUGNAME+":loadconf"
EXECFROMSTART=PLUGNAME+":execfrmstart"


emu = None

class menu_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for menu actions
    """

    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action

    def activate(self, ctx):
        if self.action == EMULLAUNCHER: 
            self.emul_launcher()
        elif self.action == EMULF:
            self.emul_func()
        elif self.action == EMULSELECT: 
            self.emul_selection()
        elif self.action == EDITREG:
            self.edit_registers()
        elif self.action == TAGFUNC:
            self.tag_func()
        elif self.action == LOADCONF:
            self.loadconf()
        else:
            logger.console(LogType.ERRR,"Function not yet implemented")
            return 0
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

    def emul_func(self):
        global emu
        s_ea, e_ea = utils_ui.get_func_boundaries()
        emu = utils_ui.get_emul(s_ea,e_ea)

        logger.console(LogType.INFO,'[+] Ready to start, type emu.start() to launch')

    def emul_selection(self):
        global emu
        s_ea, e_ea = utils_ui.get_user_select()
        emu = utils_ui.get_emul(s_ea,e_ea)

        logger.console(LogType.INFO,'[+] Ready to start, type emu.start() to launch')

    def emul_launcher(self):
        global emu
        emu = utils_ui.get_emul_fullconf()

    def edit_registers(self):
        global emu
        if emu == None:
            logger.console(LogType.ERRR,"Please initiate an emulator before using this function")
            return

        regedit_func  = utils_ui.get_regedit_func()
        emu.conf.registers = regedit_func(emu.conf.registers)


    def tag_func(self):
        """
        Tag a function when cursor is on call type insn (call/br 0x...) 
        """
        global emu
        if emu == None:
            logger.console(LogType.ERRR,
                           "Please initiate an emulator before using this function")
            return

        tag_list = [ k for k in emu.stubs.keys() ]
        tag_name = utils_ui.get_tag_name(tag_list)
        if tag_name == None:
            logger.console(LogType.ERRR,'Invalid tag name')
        # get the target of the call insn
        # somehow, it does not work using insn.Op1 
        try:
            ea=next(idautils.CodeRefsFrom(idc.get_screen_ea(),False))
        except StopIteration:
            logger.console(LogType.ERRR,
                           'Could not find valid function to tag')
            return 
        if ea != None  and ea != idc.BADADDR:
            emu.tag_func(ea,tag_name)
            logger.console(LogType.INFO,
                           'Function at %x now tagger with %s'%(ea,tag_name))

    def loadconf(self):
        global emu
        emu = utils_ui.loadconfig()

    def patchmem(self):
        global emu
        utils_ui.patch_mem(emu)



class UI_Hook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

    def finish_populating_widget_popup(self, form, popup):
        form_type = idaapi.get_widget_type(form)

        if form_type == idaapi.BWN_DISASM or form_type == idaapi.BWN_DUMP:
                idaapi.attach_action_to_popup(form, popup, EMULLAUNCHER,None)
                idaapi.attach_action_to_popup(form, popup, EMULF, None)
                idaapi.attach_action_to_popup(form, popup, EMULSELECT, None)
                idaapi.attach_action_to_popup(form, popup, EDITREG, None)
                idaapi.attach_action_to_popup(form, popup, EDITSTUBCONF, None)
                idaapi.attach_action_to_popup(form, popup, NSTUB, None)
                idaapi.attach_action_to_popup(form, popup, TAGFUNC, None)
                idaapi.attach_action_to_popup(form, popup, LOADCONF, None)


menu_actions = [

            idaapi.action_desc_t(EMULLAUNCHER, "EWS Launcher",
                                 menu_action_handler_t(EMULLAUNCHER), 'Alt+Ctrl+L',
                                 "S", 8),
            idaapi.action_desc_t(EMULF, "Emulate Function",
                                 menu_action_handler_t(EMULF), 'Alt+Ctrl+F',
                                 "S", 9),
            idaapi.action_desc_t(EMULSELECT, "Emulate Selection",
                                 menu_action_handler_t(EMULSELECT), 'Alt+Ctrl+S',
                                 "T", 10),
            idaapi.action_desc_t(EDITREG, "Edit registers",
                                 menu_action_handler_t(EDITREG), 'Alt+Ctrl+R',
                                 "T", 11),
            idaapi.action_desc_t(EDITSTUBCONF, "Edit Stub conf",
                                 menu_action_handler_t(EDITSTUBCONF), 'Alt+Ctrl+G',
                                 "T", 12),
            idaapi.action_desc_t(NSTUB, "Null Stub function",
                                 menu_action_handler_t(NSTUB), 'Alt+Ctrl+N',
                                 "T", 12),
            idaapi.action_desc_t(TAGFUNC, "Tag function",
                                 menu_action_handler_t(TAGFUNC), 'Alt+Ctrl+T',
                                 "T", 12),
            idaapi.action_desc_t(LOADCONF, "Load Config",
                                 menu_action_handler_t(LOADCONF), 'Alt+Ctrl+C',
                                 "T", 12)
            ]
for action in menu_actions:
            idaapi.register_action(action)


ui_hook = UI_Hook()
ui_hook.hook()


logger.console(LogType.INFO,'[+] Plugins Launched')
