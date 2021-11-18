#-----------------------------------
# EWS [ Emulation Wrapper System ]
#------------------------------------
import idaapi
import ida_kernwin
import idautils
import ida_idaapi
from EWS.utils import utils_ui 
from EWS.utils.utils import * 
from EWS.utils.configuration import *
from EWS.ui import *
from EWS.ui.debug_view import *
from EWS.utils.utils import logger,LogType
from EWS.utils.consts_ida import *


class menu_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for menu actions
    """

    def __init__(self, action,plug):
        idaapi.action_handler_t.__init__(self)
        self.action = action
        self.plug = plug

    def activate(self, ctx):
        if self.action == EMULLAUNCHER: 
            self.emul_launcher()
        elif self.action == EMULF:
            self.emul_func()
        elif self.action == EMULSELECT: 
            self.emul_selection()
        elif self.action == EMULINIT:
            self.emul_init()
        elif self.action == RESET:
            self.reset()
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
        elif self.action == IMPORTMEM: 
            self.mem_import()
        elif self.action == EXPORTMEM:
            self.mem_export()
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
        elif self.action == WATCHPOINT:
            self.watchpoint()
        else:
            logger.console(LogType.ERRR,"Function not yet implemented")
            return 0
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


    def reset(self):
        
        self.plug.emu.reset_color_graph()
        self.plug.conf = None
        self.plug.emu = None 
        self.plug.reset_view()

        logger.console(LogType.INFO,"Plugin was properly reset")

    def emul_func(self):
        
        s_ea, e_ea = utils_ui.get_func_boundaries()
        self.plug.conf = utils_ui.get_conf_for_area(s_ea,e_ea) 
        #self.emu = utils_ui.get_emul(s_ea,e_ea)

        logger.console(LogType.INFO, "Configuration generated for area [0x%x 0x%x] "%
                       (self.plug.conf.exec_saddr,self.plug.conf.exec_eaddr))

    def emul_selection(self):
        
        s_ea, e_ea = utils_ui.get_user_select()
        self.plug.conf = utils_ui.get_conf_for_area(s_ea,e_ea)
        logger.console(LogType.INFO, "Configuration generated for area [0x%x 0x%x] "%
                       (s_ea,e_ea))
        return 1

    def emul_init(self):
        
        
        if self.plug.conf == idaapi.BADADDR:
            logger.console(LogType.WARN,"Please init a configuration (Alt+Ctrl+{L,S,F})")
            return

        self.plug.emu = utils_ui.get_emul_from_conf(self.plug.conf)

        if self.plug.emu == idaapi.BADADDR:
            logger.console(LogType.ERRR,"Could not initiate self.emulator")
            return

        if not self.plug.view_intialized:
            self.plug.init_view()
        if not self.plug.view_enabled:
            self.plug.enable_view()

        logger.console(LogType.INFO,"Emulator ready to run (Alt+Shift+{C,I})")




    def emul_launcher(self):
        
        self.plug.conf = utils_ui.get_emul_conf(simplified=ida_kernwin.ask_yn(0,"Advance Mode?"))

    def edit_registers(self):
        

        if self.plug.conf == idaapi.BADADDR:
            logger.console(LogType.WARN,"Please init a configuration (Alt+Ctrl+{L,S,F})")
            return


        regedit_func  = utils_ui.get_regedit_func()

        if not self.plug.emu:
            new_regs = regedit_func(self.plug.conf.registers)
        else:
            new_regs = regedit_func(self.plug.emu.get_regs())

        self.plug.conf.registers = new_regs

        if self.plug.emu:
            self.plug.emu.conf= self.plug.conf
            self.plug.emu.setup_regs(self.plug.emu.conf.registers)

        #self.plug.emu.setup_regs(new_regs)
        # for restart function
        #self.plug.emu.self.conf.registers = new_regs 



    def tag_func(self):
        """
        Tag a function when cursor is on call type insn (call/br 0x...) 
        """
        
        if self.plug.emu == idaapi.BADADDR:
            logger.console(LogType.ERRR,
                           "Please initiate an self.plug.emulator before using this function (Alt+Ctrl+I)")
            return

        tag_list = [ k for k in self.plug.emu.stubs.keys() ]
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
        if ea != None  and ea != idaapi.BADADDR:
            self.plug.emu.tag_func(ea,tag_name)
            logger.console(LogType.INFO,
                           'Function at %x now tagger with %s'%(ea,tag_name))

            # update self.plug.conf (tagging is auto updating self.plug.conf)
            self.plug.conf = self.plug.emu.conf


    def loadconf(self):
        
        self.plug.conf = utils_ui.loadconfig()

        if self.plug.emu != idaapi.BADADDR:
            logger.console(LogType.WARN,"Emulator is already available, please re-init (Alt+Ctrl+I)")

    def editconf(self):
        
        self.plug.conf = utils_ui.get_emul_conf(simplified=False,
                                     conf=self.plug.conf)
        if self.plug.emu == idaapi.BADADDR:
            return

        self.plug.emu.conf = self.plug.conf
        if self.plug.emu != idaapi.BADADDR:
            logger.console(LogType.WARN,
                           "Warning editing self.plug.configuration may have some unpredictable",
                           " behavior if self.plug.emulator is running or even is already instancied",
                           " reinit Alt+Ctrl+I for a safer usage.")


    def patchmem(self):
        
        if self.plug.emu == idaapi.BADADDR:

            logger.console(LogType.ERRR,
                           "Please initiate an self.plug.emulator before using this function (Alt+Ctrl+I)")
            return

        if not utils_ui.patch_mem(self.plug.emu):
            logger.console(LogType.WARN,
                           "An error occuring while patching memory")

    def displaymem(self):
        
        if self.plug.emu == idaapi.BADADDR:
            logger.console(LogType.ERRR,
                           "Please initiate an self.plug.emulator before using this function (Alt+Ctrl+I)")
            return

        utils_ui.display_section(self.plug.emu)

    def displaystack(self):
        
        if self.plug.emu == idaapi.BADADDR:

            logger.console(LogType.ERRR,
                           "Please initiate an self.plug.emulator before using this function (Alt+Ctrl+I)")
            return

        utils_ui.display_stack(self.plug.emu)

    def displayaddr(self):
        
        if self.plug.emu == idaapi.BADADDR:
            logger.console(LogType.ERRR,
                           "Please initiate an self.plug.emulator before using this function (Alt+Ctrl+I)")
            return
        utils_ui.display_addr(self.plug.emu) 


    def mem_import(self):
        

        if self.plug.emu == idaapi.BADADDR:
            logger.console(LogType.ERRR,
                           "Please initiate an self.plug.emulator before using this function (Alt+Ctrl+I)")
            return

        utils_ui.import_mem(self.plug.emu)

        #TODO modifiy self.plug.configuration to track memory init
        self.plug.conf.memory_init += self.plug.emu.conf.memory_init
        

    def mem_export(self):
        

        if self.plug.emu == idaapi.BADADDR:
            logger.console(LogType.ERRR,
                           "Please initiate an self.plug.emulator before using this function (Alt+Ctrl+I)")
            return

        utils_ui.export_mem(self.plug.emu)



    def stepin(self):
        
        if self.plug.emu == idaapi.BADADDR:
            logger.console(LogType.ERRR,
                           "Please initiate an self.plug.emulator before using this function")
            return

        if self.plug.emu.is_running:
            self.plug.emu.step_in()
            self.plug.refresh_view()
        else:
            if not self.plug.view_intialized: 
                self.plug.init_view()
            if not self.plug.view_enabled:
                self.plug.enable_view()
            self.plug.emu.start()
            self.plug.refresh_view()

        

    def stepover(self):
        
        if self.plug.emu == idaapi.BADADDR:
            logger.console(LogType.ERRR,
                           "Please initiate an self.plug.emulator before using this function (Alt+Ctrl+I)")
            return

        if self.plug.emu.is_running:
            self.plug.emu.step_over()
            self.refresh_view()
       
    def continuee(self):

        
        if self.plug.emu == idaapi.BADADDR:
            self.plug.emu = utils_ui.get_emul_from_conf(self.plug.conf)

        if not self.plug.view_intialized:
            self.plug.init_view()
        if not self.plug.view_enabled:
            self.plug.enable_view()

        if self.plug.emu.is_running:
            logger.console(LogType.INFO,"Exec continues")
            self.plug.emu.continuee()
            self.plug.refresh_view()
        else:
            logger.console(LogType.INFO,"Exec starts")
            self.plug.emu.start()
            self.plug.refresh_view()


        
    def restart(self):
        
        if self.plug.emu == idaapi.BADADDR:
            logger.console(LogType.ERRR,
                           "Please initiate an self.plug.emulator before using this function (Alt+Ctrl+I)")
            return
        if self.plug.emu.is_running:
            self.plug.emu.restart()
        else:
            self.plug.emu.start()

    def add_mapping(self):
        

        if self.plug.conf == idaapi.BADADDR:
            logger.console(LogType.ERRR,
                           "Please initiate an self.plug.emulator before using this function (Alt+Ctrl+I)")
            return 

        new_mappings = utils_ui.get_add_mappings()
        self.plug.conf.amap_conf+= new_mappings
        if self.plug.emu != idaapi.BADADDR:
            idaapi.show_wait_box("Adding mapping, could take time")
            utils_ui.add_mapping(self.plug.emu,new_mappings)
            idaapi.hide_wait_box()

    def watchpoint(self):
        

        if self.plug.emu == idaapi.BADADDR:
            logger.console(LogType.ERRR,
                           "Please initiate an self.plug.emulator before using this function (Alt+Ctrl+I)")
            return


        utils_ui.watchpoint(self.plug.emu)




class EWS_Plugin(idaapi.plugin_t, idaapi.UI_Hooks):
    """
    Load EWS Plugin
    """
    comment="Emulator Wrapper System"
    help="Emulate code using your favorite emulator"
    wanted_name="EWS"
    wanted_hotkey="Ctrl-Alt+E"
    flags= idaapi.PLUGIN_KEEP



    def __init__(self):

        self.emu=idaapi.BADADDR
        self.conf=idaapi.BADADDR
        self.debug_panel_regs = idaapi.BADADDR
        self.trace_panel = idaapi.BADADDR
        self.view_intialized = False
        self.view_enabled = False

        idaapi.UI_Hooks.__init__(self)


        self.menu_actions = [

            idaapi.action_desc_t(EMULLAUNCHER, "Configure Emulation",
                                 menu_action_handler_t(EMULLAUNCHER,self), 'Alt+Ctrl+L',
                                 "S", 8),
            idaapi.action_desc_t(EMULF, "Emulate Function",
                                 menu_action_handler_t(EMULF,self), 'Alt+Ctrl+F',
                                 "S", 9),
            idaapi.action_desc_t(EMULSELECT, "Emulate Selection",
                                 menu_action_handler_t(EMULSELECT,self), 'Alt+Ctrl+S',
                                 "T", 10),
            idaapi.action_desc_t(EMULINIT, "Init Emulator",
                                 menu_action_handler_t(EMULINIT,self), 'Alt+Ctrl+I',
                                 "T", 10),
            idaapi.action_desc_t(RESET, "Reset Emulator",
                                 menu_action_handler_t(RESET,self), '',
                                 "T", 10),
            idaapi.action_desc_t(EDITREG, "Edit registers",
                                 menu_action_handler_t(EDITREG,self), 'Alt+Ctrl+R',
                                 "T", 11),
            idaapi.action_desc_t(EDITCONF, "Edit Config",
                                 menu_action_handler_t(EDITCONF,self), 'Alt+Ctrl+C',
                                 "T", 12),
#            idaapi.action_desc_t(EDITSTUBCONF, "Edit Stub conf",
#                                 menu_action_handler_t(EDITSTUBCONF), '',
#                                 "T", 12),
            idaapi.action_desc_t(NSTUB, "Null Stub function",
                                 menu_action_handler_t(NSTUB,self), 'Alt+Shift+N',
                                 "T", 12),
            idaapi.action_desc_t(TAGFUNC, "Tag function",
                                 menu_action_handler_t(TAGFUNC,self), 'Alt+Shift+T',
                                 "T", 12),
            idaapi.action_desc_t(LOADCONF, "Load Config",
                                 menu_action_handler_t(LOADCONF,self), 'Alt+Shift+L',
                                 "T", 12),
            idaapi.action_desc_t(PATCHMEM, "Patch Mem",
                                 menu_action_handler_t(PATCHMEM,self), 'Alt+Ctrl+M',
                                 "T", 12),
            idaapi.action_desc_t(DISPLAYMEM, "Display Mem",
                                 menu_action_handler_t(DISPLAYMEM,self), 'Alt+Ctrl+D',
                                 "T", 12),
            idaapi.action_desc_t(DISPLAYSTK, "Display Stack",
                                 menu_action_handler_t(DISPLAYSTK,self), 'Alt+Shift+S',
                                 "T", 12),
            idaapi.action_desc_t(DISPLAYADDR, "Display Addr",
                                 menu_action_handler_t(DISPLAYADDR,self), 'Alt+Shift+M',
                                 "T", 12),
            idaapi.action_desc_t(IMPORTMEM, "Import Memory From File",
                                 menu_action_handler_t(IMPORTMEM,self), 'Alt+Shift+I',
                                 "T", 12),
            idaapi.action_desc_t(EXPORTMEM, "Export Memory To File",
                                 menu_action_handler_t(EXPORTMEM,self), 'Alt+Shift+E',
                                 "T", 12),
            idaapi.action_desc_t(STEPIN, "Start / Step IN",
                                 menu_action_handler_t(STEPIN,self), 'Alt+Shift+I',
                                 "T", 12),
            idaapi.action_desc_t(STEPOVER, "Step OVER",
                                 menu_action_handler_t(STEPOVER,self), 'Alt+Shift+O',
                                 "T", 12),
            idaapi.action_desc_t(CONTINUE, "Run/Continue",
                                 menu_action_handler_t(CONTINUE,self), 'Alt+Shift+C',
                                 "T", 12),
            idaapi.action_desc_t(RESTART, "Restart",
                                 menu_action_handler_t(RESTART,self), 'Alt+Shift+R',
                                 "T", 12),
            idaapi.action_desc_t(ADDMAPPNG, "Add Mapping",
                                 menu_action_handler_t(ADDMAPPNG,self), 'Alt+Ctrl+A',
                                 "T", 12),
            idaapi.action_desc_t(WATCHPOINT, "Watchpoint",
                                 menu_action_handler_t(WATCHPOINT,self), 'Alt+Ctrl+W',
                                 "T", 12)

            ]

    
    def init(self):
        if not utils_ui.is_arch_supported():
            return idaapi.PLUGIN_SKIP

        for action in self.menu_actions:
            idaapi.register_action(action)

        #self.ui_hook = EWS()
        ida_kernwin.UI_Hooks.hook(self)
        #self.ui_hook.hook()

        return ida_idaapi.PLUGIN_OK

    def run(self,arg):
        logger.console(LogType.INFO,'[+] EWS Plugin Launched')

    def term(self):
        """
        TODO
        here should be removed all plugin artefacts (color, ...)
        """
        ida_kernwin.UI_Hooks.unhook(self)
#        self.terminate()
#        
#    def terminate(self):
#        self.emu.reset_color_graph()


    def finish_populating_widget_popup(self, form, popup):
        form_type = idaapi.get_widget_type(form)

        if form_type == idaapi.BWN_DISASM or form_type == idaapi.BWN_DUMP:

                idaapi.attach_action_to_popup(form, popup, EMULLAUNCHER,'%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, EMULF, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, EMULSELECT, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, EMULINIT, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, RESET, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, EDITREG, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, EDITSTUBCONF, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, NSTUB, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, TAGFUNC, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, LOADCONF, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, EDITCONF, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, PATCHMEM, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, DISPLAYMEM, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, DISPLAYSTK, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, DISPLAYADDR, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, EXPORTMEM, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, IMPORTMEM, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, ADDMAPPNG, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, CONTINUE, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, RESTART, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, STEPIN, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, STEPOVER, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, WATCHPOINT, '%s/'%PLUGNAME)


    def init_view(self):
        self.debug_panel_regs = Debug_View_Registers("Registers",
                                                     self.emu,
                                                     width=50,
                                                     height=50)
        self.trace_panel = Debug_View_Trace("Trace",
                                            self.emu,
                                            self.debug_panel_regs, 
                                                     width=50,
                                                     height=50)
        self.view_intialized = True

    def enable_view(self):

        if not self.view_intialized:
            return

        view_to_dock_with = idaapi.get_widget_title(idaapi.get_current_viewer())
        self.debug_panel_regs.show()
        idaapi.set_dock_pos('Registers',view_to_dock_with,idaapi.DP_RIGHT)
        self.trace_panel.show()
        idaapi.set_dock_pos('Trace','Registers',idaapi.DP_BOTTOM)

        self.view_enabled = True

    def refresh_view(self):
        self.debug_panel_regs.refresh()
        self.trace_panel.refresh()




    def reset_view(self):
        ida_kernwin.close_widget(idaapi.find_widget('Registers'),0)
        ida_kernwin.close_widget(idaapi.find_widget('Trace'),0)
        self.debug_panel_regs = None
        self.trace_panel = None
        self.view_intialized = False
        self.view_enabled = False






def PLUGIN_ENTRY():
    return EWS_Plugin()

