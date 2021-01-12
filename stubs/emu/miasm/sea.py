from stubs.emu.generic import StubEngineAbstractor
import emu



class MiasmSEA(StubEngineAbstractor):

  def __init__(self,jitter,allocator,wsize):
    super().__init__(jitter,allocator,wsize)
  def mem_read(self,addr,size):
    return emu.miasm.generic.Emuiasm.mem_read(self.runner,addr,size)
  def mem_write(self,addr,data):
    emu.miasm.generic.Emuiasm.mem_write(self.runner,addr,data)
  def reg_read(self,reg_id):
    raise NotImplemented
  def reg_write(self,reg_id,data):
    raise NotImplemented
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

  def __init__(self,uc,allocator,wsize):
    super().__init__(uc,allocator,wsize)

  def reg_read(self,reg_id):
    return emu.miasm.arm32.Miarm.reg_read(self.runner,reg_id)

  def reg_write(self,reg_id,data):
    emu.miasm.arm32.Miarm.reg_write(self.runner,reg_id,data)

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

