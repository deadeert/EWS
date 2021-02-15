### ARM SPECIFICS #######
TRAP_PAGE_BA = 0xFFFFE000
SVC_INSN_ARM   = 0xEF000000
TRAP_INS_SIZE  = 2
TRAP_INX_SIZE  = 2
ALLOC_BA = 0x80000000
ALLOC_PAGES = 0x10
mov_pc_lr = 0xe1a0f00e # big end. 
mov_pc_lr_thumb = 0x46f7  # big end. 
nop_thumb = 0xBF00
nop=0x00000000
STACK_BASEADDR = 0x7FF00000
STACK_SIZE = 0x10000

initial_stack_offset=0x10
### END ARM SPECIFICS ####



