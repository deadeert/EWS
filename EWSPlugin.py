#------------------------------------
# EWS [ Emulation Wrapper System ]
#------------------------------------



import idaapi
from EWS.ews_new import * 
from EWS.utils.utils import logger,LogType



class EWS_Plugin(idaapi.plugin_t):
    """
    Load EWS Plugin
    """
    comment="Emulator Wrapper System"
    help="Emulate code using your favorite emulator"
    wanted_name="EWS"
    wanted_hotkey="Ctrl-Alt+E"
    flags= idaapi.PLUGIN_KEEP


    def init(self):
        for action in menu_actions:
            idaapi.register_action(action)

        self.ui_hook = UI_Hook()
        self.ui_hook.hook()

        return ida_idaapi.PLUGIN_OK

    def run(self,arg):

        logger.console(LogType.INFO,'[+] EWS Plugin Launched')

    def term(self):
        self.ui_hook.unhook()




def PLUGIN_ENTRY():
    return EWS_Plugin()

