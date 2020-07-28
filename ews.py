###
# TODO 
# Add multichooser for segment (create a new form and add it to (open_segments_windows)) OK
# Add form for nullstubing ..............................................................OK 
# Do action in background  ..............................................................NOK
# Add choise to auto stub .pltgot section for ELF........................................OK
# Select Output file (logger)............................................................NOK
# Get the segment protection and use it for unicorn.mem_map..............................OK
# Use form to configure mapping + exec addresses with a function list....................NOK
# Idem for null stub.....................................................................OK
# use decorator to auto look for function and stub them..................................NOK
# Add a save/load configutation .........................................................OK
# Add switch use segment(s) / use custom mapping.........................................OK
# Let the user choose if the perms are considered or perm is 777.........................OK
# Add support for thumb mode on nullstubbing.............................................OK
# Additionnal mapping form...............................................................OK
# Add segment permission for additionnal mapping.........................................NOK
# Add possibility to init additionnal mapping with random memory ........................NOK
# Add checks for emulator config (such as page_size and various base addr)...............NOK
# Add final memory map display ..........................................................NOK
# Add functionnalities to mark registers values accross executed instructions............NOK 
# Add selector for the output (console and or files)
# Add inspect capacity from mappng in memory (in hexview)................................NOK
# Modify stkSize in StkPages.............................................................NOK
# Add debug point .......................................................................NOK 
    # This feature to add callback when some address are reached (like a dbg)
# Add option to map using File format (LOAD sections from ELF)
# Add PE support
# Remove Swich isThumb
# Add dumb fuzzing option
# Add display of function arguments (insn isTail? getfunc()->getarg (dig IDA API)........NOK
# Add ida_graph.GraphViewer for tracing execution ? .....................................NOK
# BUGS: 
# do not display function name in function chooser 
# NEVERMIND crash 
# map with seg crash IDA with big binary
###


from ui.arm32 import Arm32Pannel
from ui.mipsl32 import Mipsl32Pannel 
from ui.x86 import x86Pannel 
from emu.unicorn.arm32 import ArmCorn
from emu.unicorn.mipsl32 import MipsCorn
from emu.unicorn.x86 import x86Corn
from emu.miasm.arm32 import Miarm
from ida_idp import get_idp_name 
from utils import logger,LogType

"""
Emulation Wrapper Solution
Fancy Description here()
"""

if __name__ == '__main__':

  procname = get_idp_name()
  if procname == 'arm':
    conf = Arm32Pannel.fillconfig() 
    if conf: 
      emu = ArmCorn(conf)
#       emu = Miarm(conf)
  elif procname == 'mips':
    conf = Mipsl32Pannel.fillconfig()
    if conf:
      emu = MipsCorn(conf)
  elif procname == 'pc': 
    conf = x86Pannel.fillconfig()
    if conf: 
      emu = x86Corn(conf)
    

  logger.console(LogType.INFO,'[+] Ready to start, type emu.start() to launch')
#   emu.start()


  
  


