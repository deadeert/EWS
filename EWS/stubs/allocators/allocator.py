from EWS.utils.utils import *


class Allocator(object):
    pass



class DumpAllocator(Allocator):

  """ 
  !keep tracks of allocation 
  """

  class Chunck():



      """ 
      !create a memory chunk

      @param addr effective address of the allocation
      @param size size of the chunk

      """ 

      def __init__(self,addr,size):
        self.addr = addr 
        self.size = size
   
   
  def __init__(self,base_addr,max_size):

    """ 
    !create a memory chunk

    @param addr effective address of the allocation
    @param size size of the chunk

    """ 


    self.max_addr = base_addr + max_size
    self.last_alloc = base_addr
    self.base_addr = base_addr
    self.allocs = list()
    self.freelist = list() 

  def malloc(self,size):

    """ 
    !perform malloc ops

    @param size requested size 

    @return Effective Address of the new allocated chunk
    
    """



    idx = 0 
    for c in self.freelist:
      if c.size >= size: 
        addr = c.addr 
        self.allocs.append(c)
        del self.freelist[idx]
        return addr  
      idx+=1
    addr = self.last_alloc 
    assert addr + size < self.max_addr
    self.last_alloc += size 
    self.allocs.append(DumpAllocator.Chunck(addr,size))
    return addr

  def free(self,addr):


    """ 
    !free op 

    @param addr Effective Address of the allocated chunk to be freed

    """


    if addr in [ x.addr for x in self.freelist ]:
      raise Exception('[free] attempting to free a free chunck') 

    if addr not in [ x.addr for x in self.allocs ] : 
      raise Exception('[free] attempting to free unbased chunck addr') 

    idx = 0 

    for c in self.allocs:
      if c.addr == addr: 
        self.freelist.append(c)
        del self.allocs[idx]
        break 
      idx +=1 
    
  def find_adj(self,addr):
    """ 
    !find_adj find adjacent block given addr 

    @param addr Effective Address
    """

    l_k = -1
    for k in self.allocs.keys():
      if k > addr:
        l_k = k 
      if k == addr:
        return k 
    return l_k

  def __str__(self) -> str:

    """
    !str() method implementation 

    """ 


    for c in self.allocs:
      logger.console(LogType.INFO,'[+]Chunck at 0x%x with size %d'%(c.addr,c.size))
    return ''

  def reset(self):

    """ 
    !resets the allocator structure. Caution: it does not clean the emualor memory.

    """

    self.allocs = list()
    self.freelist = list()
    self.last_allocs = self.base_addr
 


if __name__ == '__main__':
  alloc = DumpAllocator(0x80000000,0x2000)
  addr= alloc.malloc(100)
  addr2 = alloc.malloc(200)
  alloc.free(addr)
  addr3 = alloc.malloc(100)
  addr4 = alloc.malloc(240)
  

