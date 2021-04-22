import ida_kernwin
import idaapi 
import idautils
from utils import utils_ui 
from utils.utils import * 
from ui import *

PLUGNAME="ews"
EMULLAUNCHER=PLUGNAME+":defaultlauncher"
EMULADVANCECONF=PLUGNAME+":advancelauncher"
EMULF=PLUGNAME+":emulfunc"
EMULSELECT=PLUGNAME+":emulselection"
EDITREG=PLUGNAME+":regedit"
EDITCONF=PLUGNAME+":editconf"
EDITSTUBCONF=PLUGNAME+"stubconfedit"
NSTUB=PLUGNAME+":nullstubfunc"
TAGFUNC=PLUGNAME+":tagfunc"
LOADCONF=PLUGNAME+":loadconf"
EXECFROMSTART=PLUGNAME+":execfrmstart"
PATCHMEM=PLUGNAME+":patchmem"
DISPLAYMEM=PLUGNAME+":displaymem"
DISPLAYSTK=PLUGNAME+":displaystack"
DISPLAYADDR=PLUGNAME+":displayaddr"
STEPIN=PLUGNAME+":stepin"
STEPOVER=PLUGNAME+":stepover"
CONTINUE=PLUGNAME+":continue"
RESTART=PLUGNAME+":restart"
ADDMAPPNG=PLUGNAME+":addmapping"


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
            self.emul_launcher(simplified=True)
        elif self.action == EMULADVANCECONF:
            self.emul_launcher(simplified=False)
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
        elif self.action == EDITCONF:
            self.editconf()
        elif self.action == PATCHMEM:
            self.patchmem()
        elif self.action == DISPLAYMEM:
            self.displaymem()
        elif self.action == DISPLAYSTK:
            self.displaystack()
        elif self.action == DISPLAYADDR:
            self.displayaddr()
        elif self.action == STEPIN:
            self.stepin()
        elif self.action == STEPOVER:
            self.stepover()
        elif self.action == CONTINUE:
            self.continuee()
        elif self.action == RESTART:
            self.restart()
        elif self.action == ADDMAPPNG:
            self.add_mapping()
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

    def emul_launcher(self,simplified=True):
        global emu
        emu = utils_ui.get_emul_conf(simplified=simplified)

    def edit_registers(self):
        global emu 
        if emu == None:
            logger.console(LogType.ERRR,"Please initiate an emulator before using this function")
            return

        regedit_func  = utils_ui.get_regedit_func()
        new_regs = regedit_func(emu.get_regs())
        emu.setup_regs(new_regs)
        # for restart function
        emu.conf.registers = new_regs 



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

    def editconf(self):
        global emu
        if emu == None:
            logger.console(LogType.ERRR,
                           "Please initiate an emulator before using this function")
            return
        emu = utils_ui.get_emul_conf(simplified=False,
                                     conf=emu.conf)
        if emu.is_running:
            logger.console(LogType.WARN,
                           "Modification requires to reload emulator")
        


    def patchmem(self):
        global emu
        if emu == None:
            logger.console(LogType.ERRR,
                           "Please initiate an emulator before using this function")
            return

        if not utils_ui.patch_mem(emu):
            logger.console(LogType.WARN,
                           "An error occuring while patching memory")

    def displaymem(self):
        global emu
        if emu == None:
            logger.console(LogType.ERRR,
                           "Please initiate an emulator before using this function")
            return

        utils_ui.display_section(emu)

    def displaystack(self):
        global emu
        if emu == None:
            logger.console(LogType.ERRR,
                           "Please initiate an emulator before using this function")
            return

        utils_ui.display_stack(emu)

    def displayaddr(self):
        global emu
        if emu == None:
            logger.console(LogType.ERRR,
                           "Please initiate an emulator before using this function")
            return
        utils_ui.display_addr(emu) 

    def stepin(self):
        global emu
        if emu == None:
            logger.console(LogType.ERRR,
                           "Please initiate an emulator before using this function")
            return

        if emu.is_running:
            emu.step_in()
        else:
            emu.start()

    def stepover(self):
        global emu
        if emu == None:
            logger.console(LogType.ERRR,
                           "Please initiate an emulator before using this function")
            return

        
        if emu.is_running:
            emu.step_over()
        else:
            emu.start()

    def continuee(self):
        global emu
        if emu == None:
            logger.console(LogType.ERRR,
                           "Please initiate an emulator before using this function")
            return

        if emu.is_running:
            emu.continuee()
        else:
            emu.start()

    def restart(self):
        global emu
        if emu == None:
            logger.console(LogType.ERRR,
                           "Please initiate an emulator before using this function")
            return
        if emu.is_running:
            emu.restart()
        else:
            emu.start()

    def add_mapping(self):
        global emu

        if emu == None:
            logger.console(LogType.ERRR,
                           "Please initiate an emulator before using this function")
            return
        utils_ui.add_mapping(emu)
        

       




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
                idaapi.attach_action_to_popup(form, popup, EDITCONF, None)
                idaapi.attach_action_to_popup(form, popup, PATCHMEM, None)
                idaapi.attach_action_to_popup(form, popup, DISPLAYMEM, None)
                idaapi.attach_action_to_popup(form, popup, DISPLAYSTK, None)
                idaapi.attach_action_to_popup(form, popup, DISPLAYADDR, None)
                idaapi.attach_action_to_popup(form, popup, ADDMAPPNG, None)


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
                                 "T", 12),
            idaapi.action_desc_t(EDITCONF, "Edit Config",
                                 menu_action_handler_t(EDITCONF), 'Alt+Ctrl+E',
                                 "T", 12),
            idaapi.action_desc_t(PATCHMEM, "Patch Mem",
                                 menu_action_handler_t(PATCHMEM), 'Alt+Ctrl+M',
                                 "T", 12),
            idaapi.action_desc_t(DISPLAYMEM, "Display Mem",
                                 menu_action_handler_t(DISPLAYMEM), 'Alt+Ctrl+D',
                                 "T", 12),
             idaapi.action_desc_t(DISPLAYSTK, "Display Stack",
                                 menu_action_handler_t(DISPLAYSTK), 'Alt+Ctrl+D+S',
                                 "T", 12),
             idaapi.action_desc_t(DISPLAYADDR, "Display Addr",
                                 menu_action_handler_t(DISPLAYADDR), 'Alt+Ctrl+D+S',
                                 "T", 12),
             idaapi.action_desc_t(STEPIN, "Start / Step IN",
                                 menu_action_handler_t(STEPIN), 'Alt+Ctrl+I',
                                 "T", 12),
             idaapi.action_desc_t(STEPOVER, "Step OVER",
                                 menu_action_handler_t(STEPOVER), 'Alt+Ctrl+O',
                                 "T", 12),
             idaapi.action_desc_t(CONTINUE, "Continue",
                                 menu_action_handler_t(CONTINUE), 'Alt+Ctrl+C',
                                 "T", 12),
             idaapi.action_desc_t(RESTART, "Continue",
                                 menu_action_handler_t(RESTART), 'Alt+Ctrl+J',
                                 "T", 12),
             idaapi.action_desc_t(ADDMAPPNG, "Continue",
                                 menu_action_handler_t(ADDMAPPNG), 'Alt+Ctrl+A',
                                 "T", 12)

            ]
for action in menu_actions:
            idaapi.register_action(action)


ui_hook = UI_Hook()
ui_hook.hook()


logger.console(LogType.INFO,'[+] Plugins Launched')
