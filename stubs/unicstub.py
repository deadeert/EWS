from stubs.generic import StubEngineAbstractor  
from emu.unicorn.generic import Emucorn
import emu.unicorn.arm32 
import emu.unicorn.mipsl32
import emu.unicorn.generic 


class UnicornSEA(StubEngineAbstractor):
  
  def __init__(self,uc,allocator,wsize):
    super().__init__(uc,allocator,wsize)
  def mem_read(self,addr,size):
    return Emucorn.mem_read(self.runner,addr,size)
  def mem_write(self,addr,data):
    Emucorn.mem_write(self.runner,addr,data)
  def reg_read(self,reg_id):
    raise NotImplemented
  def reg_write(self,reg_id,data):
    raise NotImplemented
  def reg_conv(self,reg_id):
    raise NotImplemented
  def push(self,sp_id,value,endianness='little'):
    sp = self.reg_read(sp_id)
    sp -= self.wsize
    self.mem_write(sp,int.to_bytes(value,self.wsize,endianness,signed=False))
    self.reg_write(sp_id,sp)
  def pop(self,sp_id,reg_return,endianness='little'):
    # use reg_return == -1 to not pop value to a register  
    sp = self.reg_read(self.reg_conv(sp_id))
    value = self.mem_read(sp,self.wsize)
    sp += self.wsize
    self.reg_write(sp_id,sp)
    if reg_return == -1:
      return value  
    self.reg_write(reg_return,int.from_bytes(value,endianness,signed=False))
    
"""          """
"     ARM      "
"""          """


class UnicornArmSEA(UnicornSEA):

  def __init__(self,uc,allocator,wsize):
    super().__init__(uc,allocator,wsize)


  def reg_conv(self,r_id):
    return emu.unicorn.arm32.ArmCorn.reg_convert(r_id)
   
  def reg_read(self,reg_id):
    return Emucorn.reg_read(self.runner,self.reg_conv(reg_id))

  def reg_write(self,reg_id,data):
    Emucorn.reg_write(self.runner,self.reg_conv(reg_id),data)

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
      return self.pop(13,-1) 

  def set_return(self,value):
    self.reg_write(0,value)
  
  def get_pc(self):
    return self.reg_read(15)

  def get_sp(self):
    return self.reg_read(13)

"""          """
"     MIPS     "
"""          """


class UnicornMipslSEA(UnicornSEA):
  def __init__(self,uc,allocator,wsize):
    super().__init__(uc,allocator,wsize)


  def reg_conv(self,r_id):
    return emu.unicorn.mipsl32.MipsCorn.reg_convert(r_id)

  def reg_read(self,reg_id):
    return Emucorn.reg_read(self.runner,self.reg_conv(reg_id))

  def reg_write(self,reg_id,data):
    Emucorn.reg_write(self.runner,self.reg_conv(reg_id),data)

  def get_arg(self,arg_num):
    if arg_num == 0:
      return self.reg_read('a0')
    elif arg_num == 1:
      return self.reg_read('a1')
    elif arg_num == 2: 
      return self.reg_read('a2')
    elif arg_num == 3:
      return self.reg_read('a3')
    else:
      return self.pop('sp',-1,'little') 

  def set_return(self,value):
    self.reg_write('v0',value)

  def get_pc(self):
    return self.reg_read('pc')

  def get_sp(self):
    return self.reg_read('sp')
  


class UnicornMipsbSEA(UnicornSEA):
  def __init__(self,uc,allocator,wsize):
    super().__init__(uc,allocator,wsize)


  def reg_conv(self,r_id):
    return emu.unicorn.mipsl32.MipsCorn.reg_convert(r_id)
  
  def reg_read(self,reg_id):
    return Emucorn.reg_read(self.runner,self.reg_conv(reg_id))

  def reg_write(self,reg_id,data):
    Emucorn.reg_write(self.runner,self.reg_conv(reg_id),data)

  def get_arg(self,arg_num):
    if arg_num == 0:
      return self.reg_read('a0')
    elif arg_num == 1:
      return self.reg_read('a1')
    elif arg_num == 2: 
      return self.reg_read('a2')
    elif arg_num == 3:
      return self.reg_read('a3')
    else:
      return self.pop('sp',-1,'big') 

  def set_return(self,value):
    self.reg_write('v0',value)

  def get_pc(self):
    return self.reg_read('pc')

  def get_sp(self):
    return self.reg_read('sp')



"""          """
"     X86      "
"""          """


  
class UnicornX86SEA(UnicornSEA):

  def __init__(self,uc,allocator,wsize):
    super().__init__(uc,allocator,wsize)


  def reg_conv(self,r_id):
    return emu.unicorn.x86.x86Corn.reg_convert(r_id)

  def reg_read(self,reg_id):
    return Emucorn.reg_read(self.runner,self.reg_conv(reg_id))

  def reg_write(self,reg_id,data):
    Emucorn.reg_write(self.runner,self.reg_conv(reg_id),data)

  def get_arg(self,arg_num):
    esp = self.reg_read('esp')
    return self.mem_read(esp+arg_num*self.wsize,self.wsize)
     

  def set_return(self,value):
    self.reg_write('eax',value)
  
  def get_pc(self):
    return self.reg_read('eip')

  def get_sp(self):
    return self.reg_read('esp')


