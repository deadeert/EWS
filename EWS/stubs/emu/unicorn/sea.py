from EWS.stubs.generic import StubEngineAbstractor  
#from EWS.stubs.emu.generic import StubEngineAbstractor  
from EWS.emu.unicorn.generic import Emucorn
import EWS.emu.unicorn.arm32 
import EWS.emu.unicorn.mipsl32
import EWS.emu.unicorn.generic 
import struct 


class UnicornSEA(StubEngineAbstractor):
  
  def __init__(self,emu,allocator,wsize):

    super().__init__(emu,allocator,wsize)

  def mem_read(self,
               addr:int,
               size:int)->bytes:

    return self.emu.mem_read(addr,size)

  def mem_write(self,addr:int,
              data:bytes):

    self.emu.mem_write(addr,data)

  def reg_read(self,
               reg_id) -> int:

    return self.emu.reg_read(self.reg_conv(reg_id))


  def reg_write(self,
                reg_id,
                data:int):

    self.emu.reg_write(self.reg_conv(reg_id),data)


  def reg_conv(self,
               reg_id):

    raise NotImplemented

  def get_arg(self,
              arg_num:int) -> int:

    #NOTE: must return an integer, not bytes   

    raise NotImplemented 

  def push(self,
           sp_id,
           value:int,
           endianness='little'):
      
    sp = self.reg_read(sp_id)
    sp -= self.wsize
    self.mem_write(sp,int.to_bytes(value,self.wsize,endianness,signed=False))
    self.reg_write(sp_id,sp)

  def pop(self,
          sp_id,
          reg_return,
          endianness='little'):


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

  def __init__(self,emu,allocator,wsize):
    super().__init__(emu,allocator,wsize)


  def reg_conv(self,r_id):
    return EWS.emu.unicorn.arm32.ArmCorn.reg_convert(r_id)
   

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

"""             """
"     AARCH64     "
"""             """

class UnicornAarch64SEA(UnicornSEA):

  def __init__(self,emu,allocator,wsize):
    super().__init__(emu,allocator,wsize)


  def reg_conv(self,r_id):
    return EWS.emu.unicorn.aarch64.Aarch64Corn.reg_convert(r_id)
   
  def get_arg(self,arg_num):
    if arg_num == 0:
      return self.reg_read(0)
    elif arg_num == 1:
      return self.reg_read(1)
    elif arg_num == 2: 
      return self.reg_read(2)
    elif arg_num == 3:
      return self.reg_read(3)
    elif arg_num == 4:
      return self.reg_read(4)
    elif arg_num == 5:
      return self.reg_read(5)
    elif arg_num == 6:
      return self.reg_read(6)
    elif arg_num == 7:
      return self.reg_read(7)
    elif arg_num == 8:
      return self.reg_read(8)
    else:
      return self.pop(31,-1) 

  def set_return(self,value):
    self.reg_write(0,value)
  
  def get_pc(self):
    return self.reg_read(260) # pc

  def get_sp(self):
    return self.reg_read(31)



"""          """
"     MIPS     "
"""          """


class UnicornMipslSEA(UnicornSEA):
  def __init__(self,emu,allocator,wsize):
    super().__init__(emu,allocator,wsize)


  def reg_conv(self,r_id):
    return EWS.emu.unicorn.mipsl32.MipsCorn.reg_convert(r_id)

  
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
  def __init__(self,emu,allocator,wsize):
    super().__init__(emu,allocator,wsize)


  def reg_conv(self,r_id):
    return EWS.emu.unicorn.mipsl32.MipsCorn.reg_convert(r_id)
  
  
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

  def __init__(self,emu,allocator,wsize):
    super().__init__(emu,allocator,wsize)


  def reg_conv(self,r_id):
    return EWS.emu.unicorn.x86.x86Corn.reg_convert(r_id)

 
  def get_arg(self,arg_num):
    esp = self.reg_read('esp')
    # TODO may add heuristic to detect compiler/linker 
    # Warning: May change accordingly to the compiler/linker. 
    # here it correspond to a plt that perform jmp [got_addr] 
    # if call [got_addr] is used, this is invalid 
    return struct.unpack('<I',self.mem_read(esp+arg_num*self.wsize+self.wsize,
                                            self.wsize))[0] 

  def set_return(self,value):
    self.reg_write('eax',value)
  
  def get_pc(self):
    return self.reg_read('eip')

  def get_sp(self):
    return self.reg_read('esp')

"""             """
"     X86_64      "
"""             """


#TODO create other instance for GCC compiler
class UnicornX64SEA(UnicornSEA):

  def __init__(self,emu,allocator,wsize):
    super().__init__(emu,allocator,wsize)

  def reg_conv(self,r_id):
    return EWS.emu.unicorn.x64.x64Corn.reg_convert(r_id)


  def get_arg(self,arg_num):
    if arg_num == 0:
      return self.reg_read('rdi')
    elif arg_num == 1:
      return self.reg_read('rsi')
    elif arg_num == 2:
      return self.reg_read('rdx')
    elif arg_num == 3:
      return self.reg_read('rcx')
    elif arg_num == 4:
      return self.reg_read('r8')
    elif arg_num == 5:
      return self.reg_read('r9')
    else:
      rsp = self.reg_read('rsp')
      # PLT stubbed, so when the call is performed
      # at call pomoent looks like:
      # ret @ <---- rsp
      # arg(6)
      return struct.unpack('<Q',self.mem_read(rsp+(arg_num-5)*self.wsize,self.wsize)) 
  def set_return(self,value):
    self.reg_write('rax',value)
  
  def get_pc(self):
    return self.reg_read('rip')

  def get_sp(self):
    return self.reg_read('rsp')

class UnicornX64MSVCSEA(UnicornSEA):
  def __init__(self,emu,allocator,wsize):
    super().__init__(emu,allocator,wsize)

  def reg_conv(self,r_id):
    return EWS.emu.unicorn.x64.x64Corn.reg_convert(r_id)


  def get_arg(self,arg_num):
    if arg_num == 0:
      return self.reg_read('rcx')
    elif arg_num == 1:
      return self.reg_read('rdx')
    elif arg_num == 2:
      return self.reg_read('r8')
    elif arg_num == 3:
      return self.reg_read('r9')
    else:
      rsp = self.reg_read('rsp')
      # call insn is nopped hence ret @ is not pushed on the stack
      return struct.unpack('<Q',self.mem_read(rsp+(arg_num-4)*self.wsize,self.wsize)) 

  def set_return(self,value):
    self.reg_write('rax',value)
  
  def get_pc(self):
    return self.reg_read('rip')

  def get_sp(self):
    return self.reg_read('rsp')



