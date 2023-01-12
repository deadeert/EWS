#-----------------------------------
# EWS [ Emulation Wrapper System ]
#------------------------------------
import idaapi
import ida_kernwin
import idautils
import ida_idaapi
import ida_name
from EWS.utils import utils_ui 
from EWS.utils.utils import * 
from EWS.utils.configuration import *
from EWS.ui import *
from EWS.ui.debug_view import *
from EWS.utils.utils import logger,LogType
from EWS.utils.consts_ida import *
from EWS.ui.generic import FileSelector
from EWS.utils.configuration import saveconfig
from unicorn import UcError


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
        elif self.action == SAVECONF:
            self.saveconf()
        elif self.action == PATCHFILE:
            self.patch_file()
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
        elif self.action == ADDMAPPNG:
            self.add_mapping()
        elif self.action == WATCHPOINT:
            self.watchpoint()
        elif self.action == NSTUB:
            self.add_nstub()
        elif self.action == PATCH:
            self.patch_insn()
        else:
            logger.console(LogType.ERRR,"Function not yet implemented")
            return 0
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


    def reset(self):

        if self.plug.emulator_initialized :
            self.plug.emu.flush() ##FIXME is that necessary?
            self.plug.emu.reset_color_graph()
            self.plug.reset()
        elif self.plug.config_initialized:
            self.plug.config = None
            self.plug.config_initialized = False
           
        if self.plug.view_enabled:
            self.plug.reset_view()

        logger.console(LogType.INFO,"Plugin was properly reset")

    def emul_func(self):

        """
        ! Emulate current function 

        """ 


        if self.plug.config_initialized:

            ida_kernwin.warning("Configuration Object already exist, please reset the plugin before using this function.")
            return 

        s_ea, e_ea = utils_ui.get_func_boundaries()
        self.plug.conf = utils_ui.get_conf_for_area(s_ea,e_ea) 

        logger.console(LogType.INFO, "Configuration generated for area [0x%x 0x%x] "%
                       (self.plug.conf.exec_saddr,self.plug.conf.exec_eaddr))

        self.plug.config_initialized = True

    def emul_selection(self):

        """
        ! Emulate the current selected assembly in UI_Hooks

        """


        if self.plug.config_initialized:

            ida_kernwin.warning("Configuration Object already exist, please reset the plugin before using this function.")
            return 


        s_ea, e_ea = utils_ui.get_user_select()
        self.plug.conf = utils_ui.get_conf_for_area(s_ea,e_ea)
        logger.console(LogType.INFO, "Configuration generated for area [0x%x 0x%x] "%
                       (s_ea,e_ea))

        self.plug.config_initialized = True

    def emul_init(self):


        """ 
        ! Initialise the emulator and the debug views. 

        """



        if not self.plug.config_initialized:
            logger.console(LogType.WARN,"Please init a configuration")
            return

        if self.plug.emulator_initialized: 
            ida_kernwin.warning('Emulator is already initialized. Please reset to load a new configuration')
            return

        try:
            self.plug.emu = utils_ui.get_emul_from_conf(self.plug.conf)
        except Exception as e:
           logger.console(LogType.ERRR,"An error occured while initializing the emulator",
                           "\nReason is : %s"%str(e))
           return

        self.plug.emulator_initialized = True

        if not self.plug.view_intialized:
            self.plug.init_view()
        if not self.plug.view_enabled:
            self.plug.enable_view()

        logger.console(LogType.INFO,"Emulator ready to run (Alt+Shift+{C,I})")

    def emul_launcher(self):


        """ 
        ! Create a configuration from scratch.

        """

        if self.plug.config_initialized == True:
            ida_kernwin.warning("A configuration object is already instancied.\n\
                                Please use edit feature to edit the current config")
            return

        if self.plug.emulator_initialized  == True:
            ida_kernwin.warning("Emulator is already initialized.\n\
                                Please reset the emulator before using this feature")
            return

        try:
            self.plug.conf = utils_ui.get_emul_conf()
            self.config_initialized = True
        except:
            logger.console(LogType.ERRR,"Error occured while creating configuration object")


    def edit_registers(self):

        """ 
        ! Edit registers. 
        
        """

        if not self.plug.config_initialized:
            logger.console(LogType.WARN,"Please init the configuration before using this function")
            return


        regedit_func  = utils_ui.get_regedit_func()

        if not self.plug.emulator_initialized:
            new_regs = regedit_func(self.plug.conf.registers)
            self.plug.conf.registers = new_regs
        else:
            new_regs = regedit_func(self.plug.emu.get_regs())
            if not new_regs is None:  
                self.plug.emu.setup_regs(new_regs)

    def tag_func(self):

        """
        !Tag a function when cursor is on call type insn (call/br 0x...) 

        """

        if not self.plug.emulator_initialized:
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


    def loadconf(self):

        """ 
        ! Load configuration from file. 

        """ 

        if self.plug.emulator_initialized or self.plug.config_initialized:
            ida_kernwin.warning("Please reset plugin to load new configuration")
            return

        try: 
            self.plug.conf = utils_ui.loadconfig()
        except:
            ida_kernwin.warning('Config file does not exist')
            return 


        self.plug.config_initialized = True

        ida_kernwin.info("Config file has been loaded")


    def saveconf(self):
        
        """
        ! saveconf 


        """

        if not self.plug.config_initialized:

            ida_kernwin.warning('No configuration object available')
            return

        if self.plug.emulator_initialized:

            conf_path =FileSelector.fillconfig()
            config = self.plug.emu.extract_current_configuration()


            saveconfig(config,conf_path) 

                    
        else:

            utils_ui.saveconfig(self.plug.conf)


    def editconf(self):


        """ 
        !editconf 

        
        """
        
        if self.plug.emulator_initialized:
            ida_kernwin.warning("Configuration cannot be edited when emulator is initalized"
                                +"Advise: store current config (if necessary) and reset the plugin.")

            uret = ida_kernwin.ask_yn(False,"Emulator being already instancied,"
            +"editing configuration will extract current emulator state in a new"
            +"configuration object and allow you to edit it. Is that what you want")
            
            if uret == ida_kernwin.ASKBTN_YES: 
                conf = self.plug.emu.extract_current_configuration() 
            else:
                return
            
        elif not self.plug.config_initialized:
            ida_kernwin.warning("Please create/load a configuration before using this function")
            return

        try:
            new_conf = utils_ui.get_emul_conf(simplified=False,
                                         conf=self.plug.conf)
            self.plug.conf = new_conf
        except Exception as e:
            ida_kernwin("Something wrong happened while loading the config, please reset the plug and retry")
            

       
    def patchmem(self):

        """ 
        ! Patch memory

        """
        
        if not self.plug.emulator_initialized: 
            ida_kernwin.warning("Please init the emulator before using this function")

        if not utils_ui.patch_mem(self.plug.emu):
            pass


    def displaymem(self):
        
        """ 
        ! Display memory 
        """

        if not self.plug.emulator_initialized: 
            ida_kernwin.warning("Nothing to display, init the emulator before using this function.")
            return

        utils_ui.display_section(self.plug.emu)

    def displaystack(self):

        """ 
        !Display the stack

        """
        
        if not self.plug.emulator_initialized: 
            ida_kernwin.warning("Nothing to display, init the emulator before using this function.")
            return


        utils_ui.display_stack(self.plug.emu)

    def displayaddr(self):

        """
        ! Display a specific address.

        """

        if not self.plug.emulator_initialized: 
            ida_kernwin.warning("Nothing to display, init the emulator before using this function.")
            return
        
        utils_ui.display_addr(self.plug.emu) 


    def mem_import(self):

        """ 
        ! Import memory to emulator
        """
        

        if not self.plug.emulator_initialized: 
            ida_kernwin.warning("Init an emulator before using this function")
            return

        utils_ui.import_mem(self.plug.emu)

        

    def mem_export(self):
        

        """ 
        ! Dump emulator memory in a file. 
        """

        if not self.plug.emulator_initialized: 
            ida_kernwin.warning("Init an emulator before using this function")
            return

        utils_ui.export_mem(self.plug.emu)



    def stepin(self):

        """
        ! Step in function
        """
        
        if not self.plug.emulator_initialized: 
            ida_kernwin.warning("Please initiate an self.plug.emulator before using this function")
            return
        try:
            self.plug.emu.step_in()
        except UcError as e:
            ida_kernwin.warning('An error occured during the step. Reason: %s'%str(e))
        finally:
            self.plug.refresh_view()

        

    def stepover(self):
        
        """ 
        ! Step over function
        """
        
        if not self.plug.emulator_initialized: 
            logger.console(LogType.ERRR,
                           "Please initiate an self.plug.emulator before using this function (Alt+Ctrl+I)")
            return

        if self.plug.emu.is_running:
            self.plug.emu.step_over()
            self.refresh_view()
       
    def continuee(self):

        """ 
        ! Run / Continue
        """

        
        if not self.plug.emulator_initialized: 
            self.plug.emu = utils_ui.get_emul_from_conf(self.plug.conf)
            self.plug.emulator_initialized = True

        if not self.plug.view_intialized:
            self.plug.init_view()
        if not self.plug.view_enabled:
            self.plug.enable_view()

        if self.plug.emu.is_running:
            logger.console(LogType.INFO,"Exec continues")
            try:
                self.plug.emu.continuee()
            except Exception as e:
                logger.console(LogType.ERRR,"Execution run out of control.",
                               "Reason: %s"%e.__str__())
            finally:
                self.plug.refresh_view()
        else:
            logger.console(LogType.INFO,"Exec starts")
            try:
                self.plug.emu.start()
            except Exception as e:
                logger.console(LogType.ERRR,"Execution run out of control.",
                               "Reason: %s"%e.__str__())
            finally:
                self.plug.refresh_view()



    def add_mapping(self):

        """ 
        ! Add a mapping and optionally init memory

        """
        

        if not self.plug.emulator_initialized: 

            ida_kernwin.warning("Require the emulator to be init")
            return 

        new_mappings = utils_ui.get_add_mappings()
        self.plug.conf.amap_conf+= new_mappings

        if self.plug.emu != idaapi.BADADDR:

            idaapi.show_wait_box("Adding mapping, could take time")
            utils_ui.add_mapping(self.plug.emu,new_mappings)
            idaapi.hide_wait_box()

    def watchpoint(self):

        """
        ! Add read/write watchpoint.
        
        """
        
        if not self.plug.emulator_initialized: 
            ida_kernwin.warning("Could not set breakpoint. Require the emulator to be init")
            return


        utils_ui.watchpoint(self.plug.emu)

    def add_nstub(self):

        """ 
        ! Add a null stub.

        """

        if not self.plug.emulator_initialized: 
            ida_kernwin.warning("Stubing require emulator init")
            return

        if not self.plug.emu.conf.s_conf.activate_stub_mechanism:
            ida_kernwin.warning("Current config does not allow stubbing.")
            return

        cur_ea = ida_kernwin.get_screen_ea()
        if (ida_kernwin.ask_yn(False,"Null-stub function %x"%cur_ea)):
            self.plug.emu.add_null_stub(cur_ea)
        logger.console(LogType.INFO,"Null stub added to function %s"%ida_name.get_name(cur_ea),
                       "at addr %x"%cur_ea)

    def patch_insn(self):

        """ 
        ! Patch instructions 

        """

        if not self.plug.emulator_initialized:
            ida_kernwin.warning('Please init the emulator before using this function')
            return

        utils_ui.add_insn_patch(self.plug.emu)


    def patch_file(self):

        """ 
        ! Patch file

        """

        if not self.plug.emulator_initialized:
            ida_kernwin.warning('Please init the emulator before using this function')
            return

        utils_ui.add_patch_file(self.plug.emu)





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
        self.emulator_initialized = False
        self.config_initialized = False
        self.view_intialized = False
        self.view_enabled = False

        idaapi.UI_Hooks.__init__(self)


        self.menu_actions = [

            idaapi.action_desc_t(EMULLAUNCHER, "Configure Emulation",
                                 menu_action_handler_t(EMULLAUNCHER,self), 'Alt+Ctrl+L',
                                 "S", 8),
            idaapi.action_desc_t(LOADCONF, "Load Config",
                                 menu_action_handler_t(LOADCONF,self), 'Alt+Shift+L',
                                 "T", 12),
            idaapi.action_desc_t(EDITCONF, "Edit Config",
                                 menu_action_handler_t(EDITCONF,self), 'Alt+Ctrl+C',
                                 "T", 12),
            idaapi.action_desc_t(SAVECONF, "Save Config",
                                 menu_action_handler_t(SAVECONF,self), 'Alt+Shift+D',
                                 "T", 12),
            idaapi.action_desc_t(EMULF, "Emulate Function",
                                 menu_action_handler_t(EMULF,self), 'Alt+Ctrl+F',
                                 "S", 9),
            idaapi.action_desc_t(EMULSELECT, "Emulate Selection",
                                 menu_action_handler_t(EMULSELECT,self), 'Alt+Ctrl+S',
                                 "T", 10),
            ##########################################################################
            idaapi.action_desc_t(EMULINIT, "Init Emulator",
                                 menu_action_handler_t(EMULINIT,self), 'Alt+Ctrl+I',
                                 "T", 10),
            idaapi.action_desc_t(RESET, "Reset",
                                 menu_action_handler_t(RESET,self), 'Alt+Shift+R',
                                 "T", 10),
            ##########################################################################
            idaapi.action_desc_t(EDITREG, "Edit registers",
                                 menu_action_handler_t(EDITREG,self), 'Alt+Ctrl+R',
                                 "T", 11),
            idaapi.action_desc_t(NSTUB, "Null Stub function",
                                 menu_action_handler_t(NSTUB,self), 'Alt+Shift+N',
                                 "T", 12),
            idaapi.action_desc_t(TAGFUNC, "Tag function",
                                 menu_action_handler_t(TAGFUNC,self), 'Alt+Shift+T',
                                 "T", 12),
            idaapi.action_desc_t(PATCHMEM, "Patch Mem",
                                 menu_action_handler_t(PATCHMEM,self), 'Alt+Ctrl+M',
                                 "T", 12),
            idaapi.action_desc_t(PATCHFILE, "Add Patch File",
                                 menu_action_handler_t(PATCHFILE,self), '',
                                 "T", 12),
            idaapi.action_desc_t(DISPLAYMEM, "Display Segment",
                                 menu_action_handler_t(DISPLAYMEM,self), 'Alt+Ctrl+D',
                                 "T", 12),
            idaapi.action_desc_t(DISPLAYSTK, "Display Stack",
                                 menu_action_handler_t(DISPLAYSTK,self), 'Alt+Shift+S',
                                 "T", 12),
            idaapi.action_desc_t(DISPLAYADDR, "Display Addr",
                                 menu_action_handler_t(DISPLAYADDR,self), 'Alt+Shift+M',
                                 "T", 12),
            idaapi.action_desc_t(IMPORTMEM, "Import Memory From File",
                                 menu_action_handler_t(IMPORTMEM,self), 'Ctrl+Shift+I',
                                 "T", 12),
            idaapi.action_desc_t(EXPORTMEM, "Export Memory To File",
                                 menu_action_handler_t(EXPORTMEM,self), 'Ctrl+Shift+E',
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
            idaapi.action_desc_t(ADDMAPPNG, "Add Mapping",
                                 menu_action_handler_t(ADDMAPPNG,self), 'Alt+Ctrl+A',
                                 "T", 12),
            idaapi.action_desc_t(WATCHPOINT, "Watchpoint",
                                 menu_action_handler_t(WATCHPOINT,self), 'Alt+Ctrl+W',
                                 "T", 12),
            idaapi.action_desc_t(PATCH, "Patch Instruction",
                                 menu_action_handler_t(PATCH,self), 'Alt+Ctrl+P',
                                 "T", 12)
            ]

    def init(self):
        if not utils_ui.is_arch_supported():
            return idaapi.PLUGIN_SKIP

        for action in self.menu_actions:
            idaapi.register_action(action)

        ida_kernwin.UI_Hooks.hook(self)

#        ida_kernwin.warning('The plugin is still on developpment. It\'s strongly advised to backup your IDB before running it. Your are forewarned!')

        return ida_idaapi.PLUGIN_OK

    def run(self,arg):
        logger.console(LogType.INFO,'[+] EWS Plugin Launched')

    def term(self):
        """
        TODO
        here should be removed all plugin artefacts (color, ...)
        """
        ida_kernwin.UI_Hooks.unhook(self)
        
    def finish_populating_widget_popup(self, form, popup):

        form_type = idaapi.get_widget_type(form)
        if form_type == idaapi.BWN_DISASM or form_type == idaapi.BWN_DUMP:

                # Configuration & Launch
                idaapi.attach_action_to_popup(form, popup, EMULLAUNCHER,'%s/init/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, EMULF, '%s/init/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, EMULSELECT, '%s/init/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, EMULINIT, '%s/init/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, RESET, '%s/init/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, EXPORTMEM, '%s/init/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, IMPORTMEM, '%s/init/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, ADDMAPPNG, '%s/init/'%PLUGNAME)

                # Configuration 
                idaapi.attach_action_to_popup(form, popup, LOADCONF, '%s/config/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, EDITCONF, '%s/config/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, SAVECONF, '%s/config/'%PLUGNAME)

                # Debugging 
                idaapi.attach_action_to_popup(form, popup, CONTINUE, '%s/debug/'%PLUGNAME)
#                idaapi.attach_action_to_popup(form, popup, RESTART, '%s/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, STEPIN, '%s/debug/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, STEPOVER, '%s/debug/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, WATCHPOINT, '%s/debug/'%PLUGNAME)

                # Memory 
                idaapi.attach_action_to_popup(form, popup, EDITREG, '%s/memory/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, PATCHMEM, '%s/memory/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, PATCH, '%s/memory/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, DISPLAYMEM, '%s/memory/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, DISPLAYSTK, '%s/memory/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, DISPLAYADDR, '%s/memory/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, PATCHFILE, '%s/memory/'%PLUGNAME)

                # Stubs
                idaapi.attach_action_to_popup(form, popup, EDITSTUBCONF, '%s/stubs/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, NSTUB, '%s/stubs/'%PLUGNAME)
                idaapi.attach_action_to_popup(form, popup, TAGFUNC, '%s/stubs/'%PLUGNAME)


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
        self.trace_panel.Close()
        self.trace_panel.flush() # FIXME is that necessary IDTS
        self.debug_panel_regs = None
        self.trace_panel = None
        self.view_intialized = False
        self.view_enabled = False


    def reset(self):
        self.emu = None
        self.conf = None
        self.emulator_initialized = False
        self.config_initialized = False

def PLUGIN_ENTRY():
    return EWS_Plugin()

