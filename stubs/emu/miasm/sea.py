from stubs.emu.generic import StubEngineAbstractor
import emu



class MiasmSEA(StubEngineAbstractor):

  def __init__(self,emu,allocator,wsize):
    super().__init__(emu,allocator,wsize)
  def mem_read(self,addr,size):
    return self.emu.mem_read(addr,size) 
  def mem_write(self,addr,data):
    self.emu.mem_write(addr,data)
  def reg_read(self,reg_id):
    return self.emu.reg_read(reg_id)
  def reg_write(self,reg_id,data):
    self.emu.reg_write(reg_id,data)
  def push(self,sp_id,value,endianness='little'):
    sp = self.reg_read(sp_id)
    sp -= self.wsize
    self.mem_write(sp,int.to_bytes(value,self.wsize,endianness,signed=False))
    self.reg_write(sp_id,sp)
  def pop(self,sp_id,reg_return,endianness='little'):
    sp = self.reg_read(sp_id)
    value = self.mem_read(sp,self.wsize)
    sp += self.wsize
    self.reg_write(reg_return,int.from_bytes(value,endianness,signed=False))
    self.reg_write(sp_id,sp)
 
class MiasmArmSEA(MiasmSEA):

  def __init__(self,jitter,allocator,wsize):
    super().__init__(jitter,allocator,wsize)


  def get_arg(self,arg_num):
    if arg_num == 0:
      return self.reg_read(0)
    elif arg_num == 1:
      return self.reg_read(1)
    elif arg_num == 2: 
      return self.reg_read(2)
    elif arg_num == 3:
      return self.reg_read(3)
    else:
      return self.pop(13,0) 

  def set_return(self,value):
    self.reg_write(0,value)
  
  def get_pc(self):
    return self.reg_read(15)

  def get_sp(self):
    return self.reg_read(13)


