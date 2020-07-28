from utils import * 




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
    self.helper.allocator.__str__() 


  def restart(self,conf=None,cnt=0):
    """ restart exec engine and execute cnt insns
    """

  def step_in(self):
    """ exec one insn   
    """
    pass 

  def step_n(self):
    """ exec n insn 
    """ 
    pass
      

  def step_over(self):
    """ TODO, use ida_idp.is_call_insn 
        then add custom breakpoint to PC+x
    """
    raise NotImplemented 
    

  
  

  
  
