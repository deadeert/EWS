from ida_kernwin import Form, Choose, ask_str	



class MyForm(Form):
	def __init__(self):
		self.invert = False
		Form.__init__(self, r"""STARTITEM 
BUTTON YES* Yeah
BUTTON NO Nope
BUTTON CANCEL Nevermind
Load Documentation Data
<##Format 1= @-Desc 2=[@-@]-Desc :{iRawHex}>
<#Select a file to open#Browse to open:{iFileOpen}>
<##Add:{iButton1}>
The end!
""",({
						'iRawHex': Form.NumericInput(tp=Form.FT_RAWHEX), 
            'iFileOpen': Form.FileInput(open=True),
 						'iButton1': Form.ButtonInput(self.OnButton1)}))
            

 #	  #        'cHtml1': Form.StringLabel("<span style='color: red'>Is this red?<span>", tp=Form.FT_HTML_LABEL),
      #      'cVal1' : Form.NumericLabel(99, Form.FT_HEX),
      #     'iFileOpen': Form.FileInput(open=True),
      #      'iButton1': Form.ButtonInput(self.OnButton1),
			#       }



	def OnButton1(self, code=0):
		optype=self.GetControlValue(self.iRawHex)
		fpath=self.GetControlValue(self.iFileOpen)
 		print("%si, %x"%(fpath,optype))

def ida_main():
    # Create form
	global f
	f = MyForm()

# Compile (in order to populate the controls)
	f.Compile()
	f.Execute()

	f.Free()	


ida_main()





