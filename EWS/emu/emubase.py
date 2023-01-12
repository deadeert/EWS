from EWS.utils.utils import * 
import ida_idaapi





class Emulator(object):

  """ Base class for all engine emulator
      all these methods must be implemented 
      and respect the argument to ensure compatibility 
      with stubs mechanism. 
  """


  def __init__(self,
               conf):

    """ 
    !Init object
    
    @param conf: configuration derivated from utils.Configuration

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
      self.add_breakpoint(ea)
    

    
  def start(self):

    """ 
    !Method responsive for execution launch
 
    """
    pass

  @staticmethod 
  def do_required_mapping(emu,
                          s_ea:int,
                          e_ea:int,
                          p_size:int,
                          perms:int):


    """ 
    !performs the required mapping. 
    must be called when consecutive areas maller than 
    p_size are required. These area must benefit from 
    the same permission. 

    @param s_ea:   beginning of the mapping.
    @param e_ea:   end of the mapping
    @param p_size: page size
    @param perms:  permission to set on mapping

    """ 
    pass

  def add_mapping(self,
                  addr:int,
                  mem:bytes,
                  perms:int):
    """ 
    ! Add mapping

    @param addr: Effective Address. 
    @param mem: Bytes. 
    @param perms: Permissions

    """
    pass

  @staticmethod
  def reg_convert(r_id):
    """ 
    !Maps generic register id r_id to the one 
    used by emulator solution 
    
    @param r_id: generic register id 

    """
    pass

  @staticmethod
  def mem_read(emu,addr,size):
    """ 
    !Returns memory data 
    from the emulator
    
    @param emu :   pointer to the emulator engine 
    @param addr:   addr to read from 
    @param size:   size of the read operation

    """
    pass
  
  @staticmethod
  def mem_write(emu,
                addr:int,
                data:bytes):
    """ 
    !Write data to emulator' memory

    @param emu :   pointer to the emulator engine 
    @param addr:   addr to write to 
    @param data:   data to write to emulator memory 

    """
    pass
  
  @staticmethod
  def reg_read(emu,
               r_id):
    """ 
    !Return emulator' register value corresponding 
        to generic register id r_id
    @param emu :   pointer to the emulator engine 
    @param r_id:   generic id of register to read from
    """
    pass

  @staticmethod
  def reg_write(emu,
                r_id,
                data:int):
      
    """ 

    !Write data to emulator ' register value 
        corresponding to generic register id r_id
    @param emu :   pointer to the emulator engine 
    @param r_id:   generic id of register to write to
    @param data:   data to write to register 
    
    """
    pass


  def get_alu_info(self,flags):

    """ 
    !Returns  of ALU flags

    """
    pass

  @staticmethod
  def check_mapping(conf):

    """ 
    !Check specified memory mapping in configration against
    the smallest and biggest Effective Addresses registred inside the 
    IDB.

    @param conf: Configuration object.
    
    """
    inf = ida_idaapi.get_inf_structure()
    return conf.mapping_eaddr <= inf.max_ea and conf.mapping_saddr >= inf.min_ea and conf.mapping_saddr < conf.mapping_eaddr 

  def restore_graph_color(self,purge_db=False):

    """ 
    !Restore default color of executed insn. 
    purge_db will empty the insn database.

    @Deprecated 

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


  def add_custom_stub(self,
                      ea:int,
                      func):

    """ 
    !add a custom stub 

    @param ea: Effective Address to apply the stub on. 
    @param func: Python Code describing the stub. 

    """
    pass

  def remove_custom_stub(self,
                         ea:int):

    """ 
    !inverse of add_custom_stub

    @param ea: Effective Address to remove the stub from. 

    """
    pass

  def tag_function(self,
                   ea:int,
                   stub_name:str):
    """ 
    !tag a function with an already implemented
        stub. 

    @param ea: Effective Address to apply the stub on. 
    @param stub_name: Symbol Name for the stub.

    """

    pass

  def remove_tag(self,ea):

    """ 
    !reciproque of tag_function

    @param ea: Effective Address to remove the stub from. 

    """
    pass

  def display_allocations(self):

    """ 
    !display allocator "chuncks" 

    """
    for c in self.helper.allocator.allocs:
        logger.console(LogType.INFO,"================")
        logger.console(LogType.INFO,"[+] Chunck(%x,%d)"%(c.addr,c.size))
        self.display_range(c.addr,c.addr+c.size)
        logger.console(LogType.INFO,"================")


  def step_in(self):
    """ 
    !exec one insn   

    """
    pass 

  def step_n(self,n:int):

    """ 
    !exec n insntructions 

    @param n: Number of instructions

    """ 
    pass

  def add_breakpoint(self,
                   ea:int):
    """ 
    !setup a breakpoint for insn x 

    @param ea: Effective Address to aaply the breakpoint on.

    """
    self.user_breakpoints.append(ea)
    self.conf.add_breakpoint(ea)
    logger.console(LogType.INFO,'Breakpoint added to %x'%ea)
    
      

  def del_breakpoint(self,
                     ea:int):
     
    """
    !Delete breakpoint at specified address.

    @param ea: Effective Address of the breakpoint.

    """

    try:
      self.user_breakpoints.remove(ea)
      
    except ValueError:
      logger.console(LogType.WARN,'no breakpoint at specified address %x'%ea)

  def list_breakpoints(self):
      """ 
      !List all registred breakpoints. 

      """

      for ea in self.user_breakpoints:
        logger.console(LogType.INFO,"bp at %x"%ea)

  def del_breakpoints(self):

      """
      !Delete all registred breakpoints 

      """ 

      for ea in self.user_breakpoints:
          self.del_breakpoint(ea)
      logger.console(LogType.INFO,"All breakpoint were removed")
        
  def step_over(self):

    """ 
    !Stop at next function return: 
    Works also with conditionnal jump  

    """
    pass 

  def save_config(self,
                  filepath:str=None):
    """ 
    !Save the current configuration in selected file. 

    @param filepath: path of the selected file. 

    """

    saveconfig(self.conf,filepath) 


  def get_relocs(self,
                 fpath:str):

      """ 
      !get the relocs for GOT entries (JMP_SLOT)
          for stub purpose
      
      @param fpath: Filepath of the ELF file. 

      """
      pass

  def add_watchpoint(self,base_addr, rang, mode=0x3):
      """
      !add watchpoint for [base_addr:base_addr+range]
      mode & 0x1 : read
      mode >> 1 & 0x1: write

      @param base_addr: Effective Address to apply the watchpoint on.
      @apram rang: size of the data to monitor. 
      @param mod: 1 read, 2 write, 3 both


      """
      pass

  def patch_mem(self,
                addr:int,
                bytecode:bytes):

      self.mem_write(addr,bytecode)
      self.patches[addr] = bytecode










