import idautils
import ida_idp
from utils.utils import * 



def stub_func_by_xref(ea):
   """ deref ea corresponding to a function reference
        until a call insn is found. Nop it and add it 
        to stub breakpoint dict with corresponding stub func. 
   """ 


   xref_g = idautils.XrefsTo(ea)
   try:
     while True:
      xref = next(xref_g)
      insn = get_insn_at(xref.frm)
      print(xref.frm)
      if ida_idp.is_call_insn(insn):
          print('detect call insn at %x'%xref.frm)
#        self.stub_breakpoints[xref.frm] = stub_func
#        self.nop_insn(insn)
      elif insn.itype == 0x58:
        xref_jmp_g = idautils.XrefsTo(xref.frm)
        try:
         while True:
          xref_jmp = next(xref_jmp_g)
          print('recalling with ea %x'%xref_jmp.frm)
          stub_func_by_xref(xref_jmp.frm)
        except StopIteration:
          pass
      else:
        print('could not find valid call insn for stub at ea %x'%ea)
        return
   except StopIteration:
    pass




if __name__ =='__main__':
    stub_func_by_xref(0x8049EAC)


