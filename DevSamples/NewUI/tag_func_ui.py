import ida_kernwin

class TagForm(ida_kernwin.Form):

  class tag_chooser(ida_kernwin.Choose):
        def __init__(self, title, tag_list, nb=5):
            print(tag_list)
            ida_kernwin.Choose.__init__(
                self,
                title,
                [
                    ["Tag Name", 30]
                ],
                deflt=0,
                flags=ida_kernwin.CH_MODAL,
                embedded=True,
                width=10,
                height=6)
            self.items = [[tag_name] for tag_name in tag_list]
            self.icon = 0
            self.ret = 0

        def OnGetLine(self, n):
            self.ret = self.items[n]
            return self.items[n]

        def OnGetSize(self):
            n = len(self.items)
            return n

  def __init__(self,tag_list):
        self.tag_list = tag_list 
        self.tag_name = None # final value returned
        ida_kernwin.Form.__init__(self, r"""STARTITEM 
BUTTON YES Yeah
BUTTON NO Nope
BUTTON CANCEL* Nevermind
Tag Func
{cbCallback}
Available Tags
<Select tag: {cSegChooser}>
""",{
            'cSegChooser': ida_kernwin.Form.EmbeddedChooserControl(TagForm.tag_chooser("Available Tags",tag_list)),
            'cbCallback': ida_kernwin.Form.FormChangeCb(self.cb_callback)})


  def cb_callback(self,fid):
        if fid == self.cSegChooser.id:
            print('changing tag')
            self.tag_name = self.GetControlValue(self.cSegChooser)
        return 1

  @staticmethod
  def create(tag_list):
      f  = TagForm(tag_list) 
      f.Compile()
      ok = f.Execute()
      if ok:
          return f.tag_name


if __name__ == '__main__':

    tags = ['siuc','ta','gra','mer']
    id= TagForm.create(tags)
    if id != None:
        print(tags[id.pop()])











