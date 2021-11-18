from EWS.utils.utils import * 




class Emulator(object):
  """ Base class for all engine emulator
      all these methods must be implemented 
      and respect the argument to ensure compatibility 
      with stubs mechanism. 
  """


  def __init__(self,conf):
    """ init object
        args: 
          conf: configuration derivated from utils.Configuration
    """
    self.conf = conf
    self.color_map = dict()
    self.user_breakpoints = list()
    self.ida_breakpoints = list()
    self.reloc_map = dict()
    self.last_pc = None
    self.is_running = False
    self.stubbed_bytes = dict() # records of {ea : original instruction
    for ea in self.conf.breakpoints:
      self.add_breakpoint(ea,update_conf=False)
    

    
  def start(self):
    """ method responsive for execution launch
    """
    pass

  def display_page(self,p_base):
    """ prints to console page content 
        in a hexviewer fashion
        args:
          p_base:  page' base address
    """ 
      
    pass

  def display_range(self,start_ea,end_ea):
    """ display memory content from 
        start_ea to end_ea
    """
    pass

  def display_stack(self):
    pass

  @staticmethod 
  def do_required_mapping(emu,s_ea,_e_ea,p_size,perms):
    """ performs the required mapping. 
        must be called when consecutive areas maller than 
        p_size are required. These area must benefit from 
        the same permission. 
        args:
          s_ea:   beginning of the mapping
          e_ea:   end of the mapping
          p_size: page size
          perms:  permission to set on mapping
    """ 
    pass

  def add_mapping(self,addr,mem,perms):
    """ Add mapping
        params: 
            addr: base address
            mem: bytes content
            perms (optnal) : permissions
    """
    pass

  @staticmethod
  def reg_convert(r_id):
    """ maps generic register id r_id to the one 
        used by emulator solution 
        args: 
          r_id: generic register id 
    """
    pass

  @staticmethod
  def mem_read(emu,addr,size):
    """ returns memory data 
        from the emulator
        args:
          emu :   pointer to the emulator engine 
          addr:   addr to read from 
          size:   size of the read operation
    """
    pass
  
  @staticmethod
  def mem_write(emu,addr,data):
    """ write data to emulator' memory
        args:
          emu :   pointer to the emulator engine 
          addr:   addr to write to 
          data:   data to write to emulator memory 
    """
    pass
  
  @staticmethod
  def reg_read(emu,r_id):
    """ return emulator' register value corresponding 
        to generic register id r_id
        args:
          emu :   pointer to the emulator engine 
          r_id:   generic id of register to read from
    """
    pass

  @staticmethod
  def reg_write(emu,r_id,data):
    """ write data to emulator ' register value 
        corresponding to generic register id r_id
        args:
          emu :   pointer to the emulator engine 
          r_id:   generic id of register to write to
          data:   data to write to register 
    """
    pass


  def get_alu_info(self,flags):
    """ return  of ALU flags
    """
    pass

  @staticmethod
  def check_mapping(conf):
    inf = ida_idaapi.get_inf_structure()
    return conf.mapping_eaddr <= inf.max_ea and conf.mapping_saddr >= inf.min_ea and conf.mapping_saddr < conf.mapping_eaddr 

  def restore_graph_color(self,purge_db=False):
    """ restore default color of executed insn. 
        purge_db will empty the insn db
    """ 
    restore_graph_color(self.color_map,purge_db)


  def add_null_stub(self,ea,fname=None):
    """ stub function for direct return (cdecl only)
    """
    pass

  def remove_null_stub(self,ea):
    """ remove a null stub
    """
    pass


  def add_custom_stub(self,ea,func):
    """ add a custom stub 
    """
    pass

  def remove_custom_stub(self,ea,func):
    """ inverse of add_custom_stub
    """
    pass

  def tag_function(self,ea,stubname):
    """ tag a function with an already implemented
        stub. 
        ex: func_1234 is a memcpy
            tag_function(ea,'memcpy')
    """
    pass

  def remove_tag(self,ea):
    """ inverse of tag_function
    """
    pass

  def display_stack(self,size=None):
    """ display stack content
    """ 
    pass 


  def display_allocations(self):
    """ display allocator "chuncks" 
    """
#    self.helper.allocator.__str__() 
    for c in self.helper.allocator.allocs:
        logger.console(LogType.INFO,"================")
        logger.console(LogType.INFO,"[+] Chunck(%x,%d)"%(c.addr,c.size))
        self.display_range(c.addr,c.addr+c.size)
        logger.console(LogType.INFO,"================")

  def restart(self,conf=None,cnt=0):
    """ restart exec engine and execute cnt insns
    """
    pass

  def step_in(self):
    """ exec one insn   
    """
    pass 

  def step_n(self,n):
    """ exec n insn 
        use is_call_insn to set breakpoint to proper ea  
    """ 
    pass

  def add_breakpoint(self,ea,update_conf=True):
    """ setup a breakpoint for insn x 
    """
    self.user_breakpoints.append(ea)
    if update_conf: self.conf.add_breakpoint(ea)
    logger.console(LogType.INFO,'Breakpoint added to %x'%ea)
    
      

  def del_breakpoint(self,ea,update_conf=True):
    try:
      self.user_breakpoints.remove(ea)
      if update_conf: self.conf.remove_breakpoint(ea)
    except ValueError:
      logger.console(LogType.WARN,'no breakpoint at specified address %x'%ea)

  def list_breakpoints(self):
      for ea in self.user_breakpoints:
        logger.console(LogType.INFO,"bp at %x"%ea)

  def del_breakpoints(self):
      for ea in self.user_breakpoints:
          self.del_breakpoint(ea)
      logger.console(LogType.INFO,"All breakpoint were removed")
        
  def step_over(self):
    """ stop at next function return 
        works also with conditionnal jump  
    """
    pass 

  def save_config(self,filepath=None):
    """ save current configuration in selected file. 
        @params: 
            filepath: path of the selected file. 
    """

    saveconfig(self.conf,filepath) 


  def get_relocs(self,fpath):
      """ get the relocs for GOT entries (JMP_SLOT)
          for stub purpose
      """
      pass

  def add_watchpoint(self,base_addr, rang, mode=0x3):
      """
      add watchpoint for [base_addr:base_addr+range]
      mode & 0x1 : read
      mode >> 1 & 0x1: write
      """
      pass










