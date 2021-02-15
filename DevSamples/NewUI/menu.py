

class Handler(idaapi.action_handler_t):

    def __init__(self, callback):
        """Create a Handler calling @callback when activated"""
        super(Handler, self).__init__()
        self.callback = callback

    def activate(self, ctx):
        return self.callback()

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

    def register(self, name, label, shortcut=None, tooltip=None, icon=-1):
        action = idaapi.action_desc_t(
            name,    # The action name. This acts like an ID and must be unique
            label,   # The action text.
            self,    # The action handler.
            shortcut,# Optional: the action shortcut
            tooltip, # Optional: the action tooltip (available in menus/toolbar)
            icon,    # Optional: the action icon (shows when in menus/toolbars)
        )
        idaapi.register_action(action)
        self.name = name
        return action

    def attach_to_menu(self, menu):
        assert hasattr(self, "name")
        idaapi.attach_action_to_menu(menu, self.name, idaapi.SETMENU_APP)

idaapi.create_menu("EWS", "EWS")

handler_symb = Handler(test)
handler_symb.register("ews:conf_for_func", "Configure to exec function", shortcut="F3", icon=81)
handler_symb.attach_to_menu("EWS/Configure to exec function")

ida_kernwin.attach_action_to_menu("Edit/Plugins/EWS/suce",handler_symb.name,idaapi.SETMENU_APP)



