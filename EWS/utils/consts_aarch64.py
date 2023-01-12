nop=0x1f2003d5
ALLOC_BA = 0x80000000
ALLOC_PAGES = 0x10
ret=0xc0035fd6
STACK_BASEADDR = 0x7FFFFFFF00000000
STACK_SIZE = 0x10000
PSIZE=0x1000
LIBCSTARTSTUBADDR=STACK_BASEADDR-PSIZE
initial_stack_offset = 0x20

from unicorn.arm64_const import *

reg_map_unicorn = {}

reg_map_unicorn['X0']=UC_ARM64_REG_X0
reg_map_unicorn['X1']=UC_ARM64_REG_X1
reg_map_unicorn['X2']=UC_ARM64_REG_X2
reg_map_unicorn['X3']=UC_ARM64_REG_X3
reg_map_unicorn['X4']=UC_ARM64_REG_X4
reg_map_unicorn['X5']=UC_ARM64_REG_X5
reg_map_unicorn['X6']=UC_ARM64_REG_X6
reg_map_unicorn['X7']=UC_ARM64_REG_X7
reg_map_unicorn['X8']=UC_ARM64_REG_X8
reg_map_unicorn['X9']=UC_ARM64_REG_X9
reg_map_unicorn['X10']=UC_ARM64_REG_X10
reg_map_unicorn['X11']=UC_ARM64_REG_X11
reg_map_unicorn['X12']=UC_ARM64_REG_X12
reg_map_unicorn['X13']=UC_ARM64_REG_X13
reg_map_unicorn['X14']=UC_ARM64_REG_X14
reg_map_unicorn['X15']=UC_ARM64_REG_X15
reg_map_unicorn['X16']=UC_ARM64_REG_X16
reg_map_unicorn['X17']=UC_ARM64_REG_X17
reg_map_unicorn['X18']=UC_ARM64_REG_X18
reg_map_unicorn['X19']=UC_ARM64_REG_X19
reg_map_unicorn['X20']=UC_ARM64_REG_X20
reg_map_unicorn['X21']=UC_ARM64_REG_X21
reg_map_unicorn['X22']=UC_ARM64_REG_X22
reg_map_unicorn['X23']=UC_ARM64_REG_X23
reg_map_unicorn['X24']=UC_ARM64_REG_X24
reg_map_unicorn['X25']=UC_ARM64_REG_X25
reg_map_unicorn['X26']=UC_ARM64_REG_X26
reg_map_unicorn['X27']=UC_ARM64_REG_X27
reg_map_unicorn['X28']=UC_ARM64_REG_X28
reg_map_unicorn['X29']=UC_ARM64_REG_X29
reg_map_unicorn['X30']=UC_ARM64_REG_X30
reg_map_unicorn['PC']=UC_ARM64_REG_PC
