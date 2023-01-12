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
PSIZE=0x400

initial_stack_offset=0x10

LIBCSTARTSTUBADDR=STACK_BASEADDR-PSIZE

### END ARM SPECIFICS ####

from unicorn.arm_const import *

reg_map_unicorn = {}
reg_map_unicorn['R0']=UC_ARM_REG_R0
reg_map_unicorn['R1']=UC_ARM_REG_R1
reg_map_unicorn['R2']=UC_ARM_REG_R2
reg_map_unicorn['R3']=UC_ARM_REG_R3
reg_map_unicorn['R4']=UC_ARM_REG_R4
reg_map_unicorn['R5']=UC_ARM_REG_R5
reg_map_unicorn['R6']=UC_ARM_REG_R6
reg_map_unicorn['R7']=UC_ARM_REG_R7
reg_map_unicorn['R8']=UC_ARM_REG_R8
reg_map_unicorn['R9']=UC_ARM_REG_R9
reg_map_unicorn['R10']=UC_ARM_REG_R10
reg_map_unicorn['R11']=UC_ARM_REG_R11
reg_map_unicorn['R12']=UC_ARM_REG_R12
reg_map_unicorn['R13']=UC_ARM_REG_R13
reg_map_unicorn['R14']=UC_ARM_REG_R14
reg_map_unicorn['R15']=UC_ARM_REG_R15
