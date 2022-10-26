import idaapi
import binascii
import ida_kernwin
import ida_segment
from EWS.utils.utils import *
from EWS.utils.utils_ui import * 

class SelectSegment(ida_kernwin.Form):

  class segment_chooser(ida_kernwin.Choose):
        """
        A simple chooser to be used as an embedded chooser
        """
        def __init__(self, title, nb=5, flags=ida_kernwin.Choose.CH_MODAL):
            ida_kernwin.Choose.__init__(
                self,
                title,
                [
                    ["Seg Name", 30]
                ],
                flags=flags,
                embedded=True,
                width=10,
                height=6)
            self.items = [ [ida_segment.get_segm_name(x)] for x in get_seg_list() ]
            self.icon = 0
            self.ret = 0

        def OnGetLine(self, n):
            self.ret = self.items[n]
            return self.items[n]

        def OnGetSize(self):
            n = len(self.items)
            return n


  def __init__(self):
    self.segname =None 
    ida_kernwin.Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
EWS ARML32
{cbCallback}
Select Segment
<Segment: {cSegChooser}>""",
{
            'cSegChooser': ida_kernwin.Form.EmbeddedChooserControl(SelectSegment.segment_chooser("Segment Name")),
            'cbCallback': ida_kernwin.Form.FormChangeCb(self.cb_callback)
})


  def cb_callback(self,fid):
    if fid == self.cSegChooser.id:
        x = self.GetControlValue(self.cSegChooser)
        self.segname = get_seg_list()[x[0]]

    return 1 

  @staticmethod
  def fillconfig():
      f = SelectSegment()
      f.Compile()
      ok = f.Execute()
      if ok == ida_kernwin.ASKBTN_YES:
         return f.segname


class AddrNBPages(ida_kernwin.Form): 


    def __init__(self):
        ida_kernwin.Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
Show Memory
<Address : {iAddr}> <Number of Pages : {iValue}>
""",{

   'iAddr': ida_kernwin.Form.NumericInput(ida_kernwin.Form.FT_ADDR),
  'iValue': ida_kernwin.Form.NumericInput(ida_kernwin.Form.FT_RAWHEX)
})



    @staticmethod
    def fillconfig():
      f = AddrNBPages()
      f.Compile()
      ok = f.Execute()
      if ok == ida_kernwin.ASKBTN_YES:
         return f.iAddr.value,f.iValue.value







 
class MemDisplayer(idaapi.Choose):

    def __init__(self,
                 title,
                 items,
                 emu,
                 flags=ida_kernwin.CH_CAN_REFRESH,
                 width=None,
                 height=None,
                 embedded=False,
                 modal=False):

        idaapi.Choose.__init__(self,
                               title,
                               [
                                   ["Address", idaapi.Choose.CHCOL_HEX|8],
                                   ["Hex", idaapi.Choose.CHCOL_PLAIN|20],
                                   ["ASCII", idaapi.Choose.CHCOL_PLAIN|20]
                               ],
                               flags=flags,
                               width=width,
                               height=height,
                               embedded=embedded)
        self.emu = emu
        self.items = items
        self.selcount = 0
        self.n = len(items)

    def OnClose(self):
            return



    def OnGetLine(self,n):
        res = self.items[n]
        res = [ res[0], res[1], res[2] ]
        return res

    def OnSelectLine(self,n):
        self.selcount+=1
        val = ida_kernwin.ask_str(self.items[n][1],
                                  False,
                                  self.items[n][0])
        if val!= None:
            hexx=binascii.a2b_hex(val.replace(' ',''))
            self.emu.mem_write(int(self.items[n][0],16),hexx)
            row = space(binascii.b2a_hex(hexx).decode('utf-8'))

        
        


    def OnGetSize(self):
        n = len(self.items)
        return n

    def test(self,extra=None):
        pass

    def OnPopup(self,form, popup_handle):
        actname = "test:%s" % self.title
        desc = ida_kernwin.action_desc_t(actname, "Test: %s" % self.title, self.test)
        ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, desc,'ews_action/')

    def show(self):
        return self.Show() >= 0




import string 
def asciify(val):
    out = []
    for v in val:
        if v in [ord(x) for x in string.ascii_letters]:
          out.append(chr(v))
        else:
          out.append('.')
    return ''.join(out)


def space(chain):
    out = []
    for i,c in enumerate(chain):
        if i % 2 == 1:
            out.append('%s '%c)
        else:
            out.append(c)
    return ''.join(out)




if __name__ == '__main__':

#    lol = SelectSegment.fillconfig()
#    print(lol.start_ea)
#
    
    addr,nbpages = AddrNBPages.fillconfig()


#    values = []
#    v1 = b'\x11\x12\x13\x14\x52\x12\xFF\x41'
#    values.append(['0x%x'%0x83450340,
#                   space(binascii.b2a_hex(v1).decode('utf-8')), 
#                   asciify(v1)])
#    v2 = b'\x33\x24\x67\x12\x98\x80\x80\x7F'
#    values.append(['%x'%0x83450348,
#                   space(binascii.b2a_hex(v2).decode('utf-8')),
#                   asciify(v2)])
#    md = MemDisplayer("Test",values)
#    md.show()
#

