from ida_kernwin import *
from EWS.utils.registers import x64Registers
from EWS.utils.exec_trace import *
import idaapi

class Debug_View_Registers(idaapi.Choose):

    def __init__(self,
                 title : str,
                 emu,
                 flags: int = CH_CAN_REFRESH|CH_CAN_EDIT|CH_NO_STATUS_BAR,
                 width: int = None,
                 height:int = None,
                 embedded:bool = False,
                 modal:bool= False):

        idaapi.Choose.__init__(self,
                               title,
                               [
                                   ["Register", idaapi.Choose.CHCOL_HEX|8],
                                   ["Value", idaapi.Choose.CHCOL_PLAIN|20],
                               ],
                               flags=flags,
                               width=width,
                               height=height,
                               embedded=embedded)

        self.emu = emu

        self.items = self.emu.get_regs().get_register_values_l()

        self.selcount = 0

        self.n = len(self.items)

    def OnClose(self):
            return

    def OnGetLine(self,n):
        res = self.items[n]
        res = [ res[0], res[1] ]
        return res

    def OnSelectLine(self,n):
        self.selcount+=1
        val = ask_str(self.items[n][1],
                                  False,
                                  self.items[n][0])
        if val is None:
            return
        self.items[n][1] = val
         
        #TODO update emu value with self.emu.reg_write(val)/
        self.emu.reg_write(self.emu.reg_convert_ns(self.items[n][0]),
                           int(val,16))

        self.Refresh()

    def OnGetSize(self):
        n = len(self.items)
        return n

    def refresh(self):
        """
        it could be confusing. 
        but this method allow to directly update
        registers value on the form from the internal
        emulator pointer 
        """
        # empty the list but keep the reference of 
        # the internal object

        for n,x in enumerate(self.emu.get_regs().get_register_values_l()):
            self.items[n] = x
        self.Refresh()

    def update_with_regs(self,regs):

        for n,x in enumerate(regs.get_register_values_l()):
            self.items[n] = x

        self.Refresh()

    def insert_value(self,value:list):
        self.items.append(value)
        self.Refresh()

    def test(self,extra=None):
        pass

    def OnPopup(self,form, popup_handle):
        actname = "test:%s" % self.title
        desc = action_desc_t(actname, "Test: %s" % self.title, self.test)
        attach_dynamic_action_to_popup(form, popup_handle, desc,'ews_action/')

    def show(self):
        return self.Show() >= 0

class Debug_View_Trace(idaapi.Choose):

    def __init__(self,
                 title,
                 emu,
                 register_view, 
                 flags=CH_NO_STATUS_BAR|CH_CAN_REFRESH|CH_CAN_EDIT, # must be able to insert
                 width=None,
                 height=None,
                 embedded=False,
                 modal=False):

        idaapi.Choose.__init__(self,
                               title,
                               [
                                   ["Address", idaapi.Choose.CHCOL_HEX|8],
                                   ["Operation", idaapi.Choose.CHCOL_PLAIN|20],
                               ],
                               flags=flags,
                               width=width,
                               height=height,
                               embedded=embedded)
        
        self.emu = emu
        self.items = []

        for k,v in self.emu.exec_trace.content.items():

            
            addr = int()
            self.items.append( [ f"0x{v['addr']:x}",
                                ''.join(v['assembly'].split(':')[1:]) ])
        self.selcount = 0
        self.n = len(self.items)
        self.register_view = register_view

    def OnClose(self):

            return

    def OnGetLine(self,n):

        res = self.items[n]
        res = [ res[0], res[1] ]

        return res

    def OnSelectLine(self,n):

        self.selcount+=1

        element = list(self.emu.exec_trace.content.values())[n]
        

        regs = element['regs']
        self.register_view.update_with_regs(regs)

        addr = self.emu.exec_trace.content[n]['addr']

        jumpto(addr)



    def OnGetSize(self):
        n = len(self.items)
        return n


    def refresh(self):

        """
            call this function everytime exec_trace has
            been modified
        """

        n = 0
        last_size = len(self.items)

        for k,v in self.emu.exec_trace.content.items():
            if k >= last_size:
                addr = v['addr']
                self.items.append( [ '0x%x'%addr,
                                    ''.join(v['assembly'].split(':')[1:]) ])
            n+=1
            # no need to update last instructions
#            else:
#                self.items[n] = [ v['assembly'] ]

        self.Refresh()

    def insert_value(self,value:list):

        self.items.append(value)
        self.Refresh() # no need to update n value? 

    def test(self,extra=None):

        pass
#        print('%s: %s'%(self.title,extra))

    def OnPopup(self,form, popup_handle):

        actname = "test:%s" % self.title
        desc = action_desc_t(actname, "Test: %s" % self.title, self.test)

        attach_dynamic_action_to_popup(form, popup_handle, desc,'ews_action/')


    def flush(self):

        self.items = []
        self.n = 0
        self.refresh()

    def show(self):

        return self.Show() >= 0


