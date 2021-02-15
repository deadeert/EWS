nop = 0x90
ida_retn_itype = 0x9F
ida_jmp_itype = [ 0x56, 0x58]
ida_jmp_conditional_itype = 0x55
ret = 0xC3
ALLOC_BA = 0x80000000
ALLOC_PAGES = 0x10
STACK_BASEADDR = 0x7FF00000
STACK_SIZE = 0x10000
PSIZE=0x1000
LIBCSTARTSTUBADDR=STACK_BASEADDR-PSIZE
"""
STATIC int LIBC_START_MAIN (int (*main) (int, char **, char **
					 MAIN_AUXVEC_DECL),
			    int argc,
			    char **argv,
#ifdef LIBC_START_MAIN_AUXVEC_ARG
			    ElfW(auxv_t) *auxvec,
#endif
			    __typeof (main) init,
			    void (*fini) (void),
			    void (*rtld_fini) (void),
			    void *stack_end)
     __attribute__ ((noreturn));
"""
# without calling init function  
"""
mov eax, [esp+4] ;ptr_main 
push [esp+8] ;ptr argc
push [esp+0xC] ; ptr argv
push [esp+0x10] ; ptr init 
call eax 
"""
#LIBCSTARTSTUBCODE=b"\x8b\x44\x24\x04\xff\x74\x24\x08\xff\x74\x24\x0c\xff\x74\x24\x10\xff\xd0"
# calling init function (warning: no check on ptr init.)
"""
mov ebx, [esp+0x10]  ; ptr_init
push [esp+8] ; ptr argc
push [esp+0xC]  : ptr argv
call ebx 
mov eax, [esp+12] ; ptr_main
call eax 
"""
LIBCSTARTSTUBCODE=b"\x8b\x5c\x24\x10\xff\x74\x24\x08\xff\x74\x24\x0c\xff\xd3\x8b\x44\x24\x0c\xff\xd0"

initial_stack_offset=0x10 # in case of pop instructions when starting emulation. 

