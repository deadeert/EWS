import ida_segment
from ida_ua import * 
import unipy
from utils import *
import string




class RegMon:
    def __init__(self, reg):
        self.reg, self.value = reg, None

    def check(self, ctx, address, size):
        value = unipy.EMU_reg_read(ctx, unipy.EMU_ARM_REG_R(self.reg))
        if value != self.value:
            print(">>> r%d=%#x\n" % (self.reg,value))
        self.value = value


class HookCode:
    def __init__(self,conf,cs):
      self.conf = conf
      self.cs=cs
    def doit(self,ctx,addr,size):
      if self.conf.useCapstone:
        try:
          insn = ida_ua.insn_t()
          insn=tuple(self.cs.disasm(unipy.EMU_mem_read(ctx,unipy.EMU_reg_read(ctx,unipy.EMU_ARM_REG_R(15)),4),unipy.EMU_reg_read(ctx,unipy.EMU_ARM_REG_R(15)),count=1))[0]
          insn_str="0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str)
        except Exception as e:
          print(e)
          insn_str='[!] Error in disassembly'
      else:  
        try: 
          insn = ida_ua.insn_t() 
          decode_insn(insn,unipy.EMU_reg_read(ctx,unipy.EMU_ARM_REG_R(15)))
          insn_str=''.join([x for x in (print_insn_mnem(insn.ea)+' '.join([print_operand(insn.ea, x).strip() for x in range(0,len(insn.__get_ops__()))])) if x in string.printable]).replace('\'','').replace('*','').replace('\t','')
        except Exception as e:
          print(e)
          insn_str='[!] Error occured while decoding insn'
      
      strout = '[PC=%.8X]'%unipy.EMU_reg_read(ctx,unipy.EMU_ARM_REG_R(15))+' '+insn_str

      print(strout)
      if self.conf.showRegisters:
        for x in range(0,15):
          print('R%d: 0x%.8X'%(x,unipy.EMU_reg_read(ctx,unipy.EMU_ARM_REG_R(x))))
      



class Emusim(Emu):

  def __init__(self,conf,_so_path_):
    Emu.__init__(self,conf) 
    unipy.bind(_so_path_)
    self.ctx = unipy.EMU_open_arm()
    

    if self.conf.map_with_seg: 
      for x in conf.segnames:
        info = ida_segment.get_segm_by_name(x)
        nb_pages = ((info.end_ea - info.start_ea) // conf.p_size) + 1
        vbase=info.start_ea&~(conf.p_size-1) 
        unipy.EMU_mem_init(self.ctx,vbase,nb_pages*conf.p_size) 
        unipy.EMU_mem_write(self.ctx,info.start_ea,get_bytes(info.start_ea,info.end_ea-info.start_ea))
    else:
        nb_pages = ((conf.mapping_eaddr - conf.mapping_saddr) // conf.p_size) + 1
        vbase=conf.mapping_saddr&~(conf.p_size-1) 
        unipy.EMU_mem_init(self.ctx,vbase,nb_pages*conf.p_size)
        unipy.EMU_mem_write(self.ctx,conf.mapping_saddr,get_bytes(self.conf.mapping_saddr,self.conf.mapping_eaddr-self.conf.mapping_saddr))

    unipy.EMU_mem_init(self.ctx,conf.stk_ba,conf.stk_size)
    unipy.EMU_reg_write(self.ctx,unipy.EMU_ARM_REG_R(13),conf.stk_ba+conf.stk_size)
  
    if self.conf.useCapstone:
      self.cs=Cs(CS_ARCH_ARM, CS_MODE_THUMB if conf.isThumb else CS_MODE_ARM)
      self.cs.detail=True
    else :
      self.cs == None
      unipy.EMU_set_disasm(self.ctx, True)
    

  def start(self):
    unipy.EMU_start(self.ctx, self.conf.exec_saddr, self.conf.exec_eaddr)
    unipy.EMU_close(self.ctx)


      

  def add_hook_code(self):
     unipy.EMU_hook_code(self.ctx, HookCode(self.conf,self.cs).doit)

def nope():
  pass

def hook_code(ctx,addr,size,user_arg,**userargs): 
    if not userargs.has_attr('conf'):
      print('requires configuration object')
      return
    


if __name__ == '__main__':
  

  
  emu = Emusim(Configuration(0x400,0,0x1000,True,True,0x19FD7A4,0x19FD9BC,0x19FA000,0x1BFC7EE,set(),False,set(),True,False,True,ArmRegisters(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)),'/home/d33d34rt/Filer/Scripts/IDA/Unicorn/unisimv010.so')
  emu.add_hook_code()
  emu.start()





    

  


    
 
     
  

  

  
 

 

    
    
