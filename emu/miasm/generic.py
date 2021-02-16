from emu.emubase import Emulator
from miasm.analysis.machine import Machine
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC
from utils.utils import *
import ida_segment
import ida_ua
import ida_idaapi
import ida_funcs
import ida_bytes
import ida_segregs
import ida_idp 
import ida_name
import ida_segment
import os
import string



class Emuiasm(Emulator):

  def __init__(self,conf):

    super().__init__(conf) 

  def do_mapping(self):


    inf = ida_idaapi.get_inf_structure()

    # Map with IDB
    if self.conf.map_with_segs:
      for seg in self.conf.segms:
        self.jitter.vm.add_memory_page(seg.start_ea,
                                       seg.perm if self.conf.use_seg_perms else PAGE_READ|PAGE_EXEC,
                                       ida_bytes.get_bytes(seg.start_ea,seg.end_ea-seg.start_ea))
        logger.console(LogType.INFO,'Sucessfully mapped [%X-%X]'%(seg.start_ea,seg.end_ea))
    else:
      if not Emulator.check_mapping(self.conf):
        raise ConfigExcption('Invalid mapping for code section')
      self.jitter.vm.add_memory_page(self.conf.mapping_saddr,
                                     ida_bytes.get_bytes(self.conf.mapping_saddr,
                                                        self.conf.mapping_eaddr-self.conf.mapping_saddr),
                                     PAGE_READ|PAGE_WRITE)
      
      logger.console(LogType.INFO,'Sucessfully mapped [%X-%X]'%(seg.start_ea,sef.end_ea))
      
    
    # Map user provided content
    for m_ea,content in self.conf.amap_conf.mappings.items():
      self.jitter.vm.add_memory_page(m_ea,
                                     PAGE_READ|PAGE_WRITE|PAGE_EXEC,
                                     content)
      logger.console(LogType.INFO,'[%s] Additionnal mapping for data at %8X'%('Emuiasm',m_ea)) 

    # Init stack 
    self.jitter.vm.add_memory_page(self.conf.stk_ba,PAGE_READ|PAGE_WRITE,b'\x00'*self.conf.stk_size)

  @staticmethod
  def mem_read(jitter,addr,size):
    return jitter.vm.get_mem(addr,size) 
  @staticmethod
  def mem_write(jitter,addr,data):
    jitter.vm.set_mem(addr,value) 
  
  def mem_read(self,addr,size):
    return self.jitter.vm.get_mem(addr,size) 
  
  def mem_write(self,addr,data):
    self.jitter.vm.set_mem(addr,data)


    
  def start(self):
    def end_mapping(jitter):
      logger.console(LogType.WARN,'[!] end mapping reached, stop execution')
      return False

    def end_exec(jitter):
      logger.console(LogType.INFO,'[+] specified execution end address reached')
      return False

    self.jitter.add_breakpoint(self.conf.mapping_eaddr,end_mapping)
    self.jitter.add_breakpoint(self.conf.exec_eaddr,end_exec)
    self.jitter.init_run(self.conf.exec_saddr)
    self.jitter.continue_run()




  
  def display_page(self,p_base,size=None):
    if not size: 
      size = self.conf.p_size 
    mem=self.jitter.vm.get_mem(p_base,size)
    display_mem(mem)

    



   
                                     
      
      
      
      
