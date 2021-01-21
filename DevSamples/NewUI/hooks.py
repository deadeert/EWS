import ida_kernwin
import idaapi 
import utils_ui 
from emu.unicorn.arm32 import ArmCorn
from emu.unicorn.aarch64 import Aarch64Corn

PLUGNAME="ews"
EMULF=PLUGNAME+":emulfunc"
EMULSELECT=PLUGNAME+":emulselection"





class menu_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for menu actions
    """

    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action

    def activate(self, ctx):
        if self.action == EMULF:
            self.emul_func()
        elif self.action == EMULSELECT: 
            self.emul_selection()
        else:
            return 0
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

    def emul_func(self):
        s_ea, e_ea = utils_ui.get_func_boundaries()
        print('%x:%x'%(s_ea,e_ea))

    def emul_selection(self):
        s_ea, e_ea = utils_ui.get_user_select()
        print('%x:%x'%(s_ea,e_ea))









class UI_Hook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

    def finish_populating_widget_popup(self, form, popup):
        form_type = idaapi.get_widget_type(form)

        if form_type == idaapi.BWN_DISASM or form_type == idaapi.BWN_DUMP:
#            t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(
#            ), idaapi.get_current_viewer()
#            if idaapi.read_selection(view, t0, t1) \
#                    or idc.get_item_size(idc.get_screen_ea()) > 1:
                idaapi.attach_action_to_popup(form, popup, EMULF, None)
                idaapi.attach_action_to_popup(form, popup, EMULSELECT, None)


menu_actions = [
            idaapi.action_desc_t(EMULF, "Emulate Function",
                                 menu_action_handler_t(EMULF), None,
                                 "S", 9),
            idaapi.action_desc_t(EMULSELECT, "Emulate Selection",
                                 menu_action_handler_t(EMULSELECT), None,
                                 "T", 10)
            ]
for action in menu_actions:
            idaapi.register_action(action)


ui_hook = UI_Hook()
ui_hook.hook()


