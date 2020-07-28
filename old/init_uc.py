from unicorn import * 
from unicorn.arm_const import * 
import ida_bytes
from ida_segment import get_segm_by_name
from ida_ua import decode_insn, insn_t,print_operand, print_insn_mnem
import string


PAGE_SIZE = 0x1000
STACK_ADDR = 0xFFFF0000
STACK_SIZE = PAGE_SIZE
MAP_IF_REQUIRED=True
USE_CAPSTONE=True
SHOW_REGISTERS=True
START_EXEC=0xAD90A4
END_EXEC=0xAD94C4 
START_MAPPING=0x9F0000
END_MAPPING=0xC00000



THUMB=True


if USE_CAPSTONE: 
	from capstone.arm_const import *
	from capstone import *



class Emulator(object):


	def __init__(self,start_ea,end_ea,MODE,additionnal_pages=None):


		self.sea = start_ea
		self.eea = end_ea 
		self.uc = Uc(UC_ARCH_ARM,MODE) 
		nb_pages = ((end_ea - start_ea) // PAGE_SIZE) + 1
		vbase=start_ea&~(PAGE_SIZE-1) 
		print('[*] vbase : 0x%.8X, code size: 0x%.8X, page:  %d'%(vbase,end_ea-start_ea,nb_pages))


		self.uc.mem_map(vbase,nb_pages*PAGE_SIZE,UC_PROT_ALL)
		self.uc.mem_write(start_ea,get_bytes(self.sea,self.eea-self.sea))


		self.uc.mem_map(STACK_ADDR,STACK_SIZE)
		self.uc.reg_write(UC_ARM_REG_SP,STACK_ADDR+STACK_SIZE)
		print('[*] mapped stack at 0x%.8X '%STACK_ADDR)

		if USE_CAPSTONE:
			if MODE == UC_MODE_THUMB:
				self.cs=Cs(CS_ARCH_ARM, CS_MODE_THUMB)
			else: 
				self.cs=Cs(CS_ARCH_ARM, CS_MODE_ARM)
			self.cs.detail=True
	
	
		if additionnal_pages: 

			for addr in additionnal_pages.keys():
				self.uc.mem_map(addr,PAGE_SIZE)
				self.uc.mem_write(addr,additionnal_pages[addr])
				print('[*] mapped 0x%.8X '%addr)




	def start(self,s_ea,e_ea,cnt=0): 
		self.uc.emu_start(s_ea,e_ea,timeout=0,count=cnt)
		

	def hook_code(self,uc,addr,size,usr_data): 
		if USE_CAPSTONE:
			try:
				insn=tuple(self.cs.disasm(uc.mem_read(uc.reg_read(UC_ARM_REG_PC),4),uc.reg_read(UC_ARM_REG_PC),count=1))[0]
				insn_str="0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str)
			except:
				insn_str='[!] Error in disassembly'
		else:	
			try: 
				insn = insn_t() 
				decode_insn(insn,self.uc.reg_read(UC_ARM_REG_PC))
				insn_str=''.join([x for x in (print_insn_mnem(insn.ea)+' '.join([print_operand(insn.ea, x).strip() for x in range(0,len(insn.__get_ops__()))])) if x in string.printable]).replace('\'','').replace('*','').replace('\t','')
			except:
				insn_str='[!] Error occured while decoding insn'
		
		strout = '[PC=%.8X]'%uc.reg_read(UC_ARM_REG_PC)+' '+insn_str
		print(strout)
		if SHOW_REGISTERS:
			self.print_registers()
		
		
	

	def print_registers(self):
		strout = '[R0=%.8X] [R1=%.8X] [R2=%.8X] [R3=%.8X]'%(self.uc.reg_read(UC_ARM_REG_R0),self.uc.reg_read(UC_ARM_REG_R1),self.uc.reg_read(UC_ARM_REG_R2),self.uc.reg_read(UC_ARM_REG_R3))
		strout += '[R4=%.8X] [R5=%.8X] [R6=%.8X] [R7=%.8X]'%(self.uc.reg_read(UC_ARM_REG_R4),self.uc.reg_read(UC_ARM_REG_R5),self.uc.reg_read(UC_ARM_REG_R6),self.uc.reg_read(UC_ARM_REG_R7))+'\n'
		strout += '[R8=%.8X] [R9=%.8X] [R10=%.8X] [R11=%.8X]'%(self.uc.reg_read(UC_ARM_REG_R8),self.uc.reg_read(UC_ARM_REG_R9),self.uc.reg_read(UC_ARM_REG_R10),self.uc.reg_read(UC_ARM_REG_R11))
		strout += '[R12=%.8X] [R13=%.8X] [R14=%.8X]'%(self.uc.reg_read(UC_ARM_REG_R12),self.uc.reg_read(UC_ARM_REG_R13),self.uc.reg_read(UC_ARM_REG_R14))
		print(strout)




	def read_mem(self,addr,len):
			
		for x in range(0,(len//4),4):
			print('0x%.8X'%self.uc_mem_read(addr,x*4))


	def add_hook_code(self,callback=None,usr_data=None):
			self.uc.hook_add(UC_HOOK_CODE,self.hook_code,None)
				
	def add_hook_uread(self,func,usr_data=None):
		self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED,func,usr_data)

	def add_hook_uwrite(self,func,usr_data=None):
		self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED,func,usr_data)

	def add_hook_write(self,func,user_data=None):
		self.uc.hook_add(UC_HOOK_MEM_WRITE,func,user_data)

	def add_hook_read(self,func,user_data=None):
		self.uc.hook_add(UC_HOOK_MEM_READ,func,user_data)


	def add_nullstub(self,addr,blx=False,pop_pc=False):
		if blx:
			print('[!] Nullstub for BLX instruction is not yet supported')
		
		elif pop_pc:
			print('[!] Nullstub for pop pc instruction is not yet supported')
		
		else:
			self.uc.mem_write(addr,int.to_bytes(0x2DE9F04D,4,'big',signed=False)) #push R4-48,R10,R11,PC
			self.uc.mem_write(addr+4,int.to_bytes(0xBDE8F08D,4,'big',signed=False)) #pop R4-48,R10,R11,PC

		
		 
		
		
		
def ump_read(uc,access,addr,value,size,user_data):
	print('[!] Read Access Exception: cannot read 0x%.8X for size %d (reason: unmapped page)'%(addr,size))
	if MAP_IF_REQUIRED:
		base_addr = addr & ~(PAGE_SIZE-1)
		uc.mem_map(base_addr,PAGE_SIZE)
		uc.mem_write(base_addr,b'\xff'*PAGE_SIZE)
		print('[+] Add additionnal page')
		return True


		

def ump_write(uc,access,addr,size,value,user_data):
	print('[!] Write Access Excpetion: cannot write value 0x%.8X at address 0x%.8X (reason: unmapped page)'%(value,addr))
	if MAP_IF_REQUIRED:
		base_addr = addr & ~(PAGE_SIZE-1)
		uc.mem_map(base_addr,PAGE_SIZE)
		print('[+] Add additionnal page')
		return True


def hk_read(uc,access,addr,size,value,user_data):
	print('[*] Read access to addr 0x%.8X for size %d. Value: 0x%.8X'%(addr,size,value))

def hk_write(uc,access,addr,size,value,user_data):
	print('[*] Write access to addr 0x%.8X with value 0x%.8X'%(addr,value))





if __name__ == '__main__':

	mappings = {}	
	for x in range(0,0xFFFF,PAGE_SIZE): # MAP RAM from 0x0, 0xFFFF
		mappings[x] = b'0'*PAGE_SIZE




	info = get_segm_by_name('ROM')
	

# 	em = Emulator(info.start_ea,info.end_ea,mappings)

	if THUMB: 
		em = Emulator(START_MAPPING,END_MAPPING,UC_MODE_THUMB,mappings)
	else: 
		em = Emulator(START_MAPPING,END_MAPPING,UC_MODE_ARM,mappings)
	

	em.uc.mem_write(0xAAAA,b'tititoto')
	


	em.uc.reg_write(UC_ARM_REG_R0,0xBBBB)	
	em.uc.reg_write(UC_ARM_REG_R1,0xAAAA)	
	em.uc.reg_write(UC_ARM_REG_R2,8)	
	em.uc.reg_write(UC_ARM_REG_R3,0)
	em.uc.reg_write(UC_ARM_REG_R5,0)
	em.uc.reg_write(UC_ARM_REG_R6,0)
	em.uc.reg_write(UC_ARM_REG_R7,0)
	em.uc.reg_write(UC_ARM_REG_R8,0)
	em.uc.reg_write(UC_ARM_REG_R9,0)
	em.uc.reg_write(UC_ARM_REG_R10,0)
	em.uc.reg_write(UC_ARM_REG_R11,0)
	em.uc.reg_write(UC_ARM_REG_R12,0)
	em.add_hook_code()
	em.add_hook_uread(ump_read)
	em.add_hook_uwrite(ump_write)
	em.add_hook_write(hk_write)
	em.add_hook_read(hk_read)
	em.add_nullstub(0xB10152) #TODO add nullstubing for ARM insn. 
	em.uc.reg_write(UC_ARM_REG_R14,END_EXEC) # value for push {lr}, pop {pc} 
	if THUMB: 
		em.start(START_EXEC+1,END_EXEC)
	else:	
		em.start(START_EXEC,END_EXEC)
	
	print('[0xAAAA]:',em.uc.mem_read(0xAAAA,8))
	print('[0xBBBB]:',em.uc.mem_read(0xBBBB,8))

	


	

