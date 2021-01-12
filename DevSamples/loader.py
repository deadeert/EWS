from ida_loader import get_path,PATH_TYPE_CMD
from os.path import exists, isdir
from sys import exit
from lief import *
from ida_utils import XrefsTo



# to parse in utils file 

file_path = get_path(PATH_TYPE_CMD).split('.')[0:][0] # remove extension 
print('file path : %s'%file_path)

if not exists(file_path) or isdir(file_path):
    print('file does not exist')
    exit(1)

elf_l = ELF.parse(file_path)
#if elf_l == None:
#    print('invalid file format')
#

# attribut of emubase 
r_map = dict()

# overload get_reloc of emubase
relocs = elf_l.relocations
for r in relocs:
    if r.type == int(ELF.RELOCATION_AARCH64.JUMP_SLOT):
        r_map[r.symbol.name] = r.address


for k,v in r_map.items():
    print(k,' at ', '%x' % v)
    xref_g =  XrefsTo(k)











