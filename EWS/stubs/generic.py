from EWS.stubs.allocators.allocator import Allocator
from EWS.emu.emubase import Emulator


class StubEngineAbstractor(object):
  
  """ 
  !Mother class for all operation exposed to the stubs
      It also define the calling convention th. get_arm()
      and set_return() functions. 
      This interface defines: 
        - emu : a reference to the emu object 
        - allocator : a reference to the alloc mechanism
        - wsize : 16/32/64 bit value for pop/push ops.  

  """ 

  def __init__(self,
               emu: Emulator,
               allocator:Allocator,
               wsize:int):

    """ 
    !Constructor of the Stub Engine Abstractor class. 

    @param emu Reference to the current emulator solution
    @param allocator Reference to the allocator 
    @param wsize Word Size  

    @return New helper 

    """

    self.emu = emu
    self.allocator = allocator
    self.wsize = wsize

  def mem_read(self,
               addr:int,
               size:int) -> bytes:

    """ 
    !returns value from emulator memory 
    
    @param addr Effective Address to read from
    @param size Size of the read operation 

    @return read bytes

    """

    pass


  def mem_write(self,
                addr:int,
                value:bytes) -> None: 
    """ 
    !write value to emulator memory 

    @param addr Effective Address of the write operation
    @param value Data to be written 


    """ 

    pass


  def reg_read(self,
               reg_id) -> int: 

    """ 
    !Returns register value from reg_id (int) 
    
    @param reg_id Register identified in the emulator solution (either string or int)

    @retun content value of the register 

    """

    pass


  def reg_write(self,
                reg_id,
                value:int) -> None:

    """ 
    !Write value to reg_id register 

    @param reg_id Register identified in the emulator solution (either string or int)
    @param value Register to write inside to the register 

    
    """ 

    pass


  def get_arg(self,
              arg_num:int) -> int:

    """ 
    !returns the value of the number arg_num register
        according to the calling convention. 

    @param arg_num argument number to unpack 

    @return value of the argument 

    """

    raise NotImplemented

  def set_return(self,
                 value:int) -> None:

    """ 
    !Set the return value according
        to the calling convention.

    @param value Return value 

    """ 
    raise NotImplemented

  def cleanstuff(self,
                 nbytes:int) -> None:

    """ 
    !for cdecl functions 
      nbytes: int number of bytes to add to SP clean

    @param nbytes Number of byte to clean from the stack

    """

    raise NotImplemented


  def malloc(self,
             size:int):
    """ 
    !Do an allocation within the allocator memory. 

    @param size Size of the allocation to be performed. 

    """


    return self.allocator.malloc(size)



  def free(self,
           addr:int) -> None:

      """ 
      ! Call free method of the allocator 

      @param addr Effective Address of the first byte of the allocator.
      """
      
      self.allocator.free(addr) 

  def push(self,
           sp_id,
           value:int) -> None:
      """ 
      !Push operation 

      @param sp_id Identifier of the Stack Pointer within the emulator solution 
      @param value Value to be pushed onto the stack 

      """
      pass

  def pop(self,
          sp_id,
          reg_return) -> None:
    """ 
    !Pop Value from the stack 

    @param sp_id Identifier of the Stack Pointer within the emulator solution 
    @param reg_return identifier of the register receiving the data

    """

    pass


  def get_pc(self):

    """ 
    !returns program counter value

    """
    raise NotImplemented


  def get_sp(self):

    """ 
    !returns the stack pointer value

    """ 

    raise NotImplemented


 

 


