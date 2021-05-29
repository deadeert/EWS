class StubEngineAbstractor(object):
  """ Mother class for all operation exposed to the stubs
      It also define the calling convention th. get_arm()
      and set_return() functions. 
      This interface defines: 
        - runner : a reference to the emu object 
        - allocator : a reference to the alloc mechanism
        - wsize : 16/32/64 bit value for pop/push ops.  
  """ 
  def __init__(self,emu,allocator,wsize):
    self.emu = emu
    self.allocator = allocator
    self.wsize = wsize

  def mem_read(self,addr,size):
    """ return value from emulator memory """
    pass
  def mem_write(self,addr,value): 
    """ write value to emulator memory """ 
    pass
  def reg_read(self,reg_id): 
    """ return register value from reg_id (int) """
    pass
  def reg_write(self,reg_id,value):
    """ write value to reg_id register """ 
    #Use EmuXXX.reg_convert static method
    pass
  def get_arg(self,arg_num):
    """ returns the value of the number arg_num register
        according to the calling convention. 
    """
    raise NotImplemented

  def set_return(self,value):
    """ set the returns value according
        to the calling convention.
    """ 
    raise NotImplemented

  def cleanstuff(self,nbytes):
    """ for cdecl functions 
      nbytes: int number of bytes to add to SP clean
    """
    raise NotImplemented

  def malloc(self,size):
    return self.allocator.malloc(size)
  def free(self,addr):
    self.allocator.free(addr) 
  def push(self,sp_id,value):
    pass
  def pop(self,sp_id,reg_return):
    pass
  def get_pc(self):
    """ returns program counter value
    """
    raise NotImplemented
  def get_sp(self):
    """ return the stack pointer value
    """ 
    raise NotImplemented


 

 


