from utils.utils import *

class DumpAllocator(object):
  """ keep tracks of allocation 
  """

  class Chunck():
    def __init__(self,addr,size):
      self.addr = addr 
      self.size = size
   
   
  def __init__(self,base_addr,max_size):
    self.max_addr = base_addr + max_size
    self.last_alloc = base_addr
    self.base_addr = base_addr
    self.allocs = list()
    self.freelist = list() 

  def malloc(self,size):
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
    l_k = -1
    for k in self.allocs.keys():
      if k > addr:
        l_k = k 
      if k == addr:
        return k 
    return l_k

  def __str__(self):
    for c in self.allocs:
      logger.console(LogType.INFO,'[+]Chunck at 0x%x with size %d'%(c.addr,c.size))
    return ''

  def reset(self):
    self.allocs = list()
    self.freelist = list()
    self.last_allocs = self.base_addr
 


if __name__ == '__main__':
  alloc = DumpAllocator(0x80000000,0x2000)
  addr= alloc.malloc(100)
  print('%x'%addr)
  addr2 = alloc.malloc(200)
  print('%x'%addr2)
  alloc.free(addr)
  addr3 = alloc.malloc(100)
  print('%x'%addr3)
  addr4 = alloc.malloc(240)
  print('%x'%addr4)
  

