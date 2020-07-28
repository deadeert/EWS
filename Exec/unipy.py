###################################
# UNIPY UniSIM-VP python bindings #
# with support for                #
# - ARMv7 (arm32 and thumb)       #
# - PPC (vle)                     #
###################################

import ctypes

emuerr = ctypes.c_int
emu_engine = ctypes.c_void_p

_so = None

def bind( shared_object ):
#    if not shared_object.endswith('.so'):
#        raise exception('bad cannot locate fuzr shared object (either define VLE4FUZR_SO or pass an argument)')
    global _so
    _so = ctypes.cdll.LoadLibrary(shared_object)
    if _so is None:
        raise ImportError("ERROR: fail to load the dynamic library.")

    # setup all the function prototype (helper func)
    def _setup_prototype(lib, fname, restype, *argtypes):
        getattr(lib, fname).restype = restype
        getattr(lib, fname).argtypes = argtypes
    
    _setup_prototype(_so, "emu_open_arm", emuerr, ctypes.c_uint, ctypes.POINTER(emu_engine))
    _setup_prototype(_so, "emu_open_vle", emuerr, ctypes.POINTER(emu_engine))
    _setup_prototype(_so, "emu_start", emuerr, emu_engine, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_size_t)
    _setup_prototype(_so, "emu_stop", emuerr, emu_engine)
    _setup_prototype(_so, "emu_close", emuerr, emu_engine)
    _setup_prototype(_so, "emu_reg_read", emuerr, emu_engine, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, ctypes.c_int, ctypes.POINTER(ctypes.c_uint64))
    _setup_prototype(_so, "emu_reg_write", emuerr, emu_engine, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, ctypes.c_int, ctypes.c_uint64)
    _setup_prototype(_so, "emu_mem_map", emuerr, emu_engine, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint, ctypes.c_void_p)
    _setup_prototype(_so, "emu_mem_write", emuerr, emu_engine, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
    _setup_prototype(_so, "emu_mem_read", emuerr, emu_engine, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
    _setup_prototype(_so, "emu_mem_chprot", emuerr, emu_engine, ctypes.c_uint64, ctypes.c_uint)
    _setup_prototype(_so, "emu_mem_chhook", emuerr, emu_engine, ctypes.c_uint64, ctypes.c_void_p)
    _setup_prototype(_so, "emu_set_disasm", emuerr, emu_engine, ctypes.c_int)
    _setup_prototype(_so, "emu_hook_add", emuerr, emu_engine, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64)


EMU_ERR_OK = 0

class EmuError(Exception):
    def __init__(self, errno):
        self.errno = errno

    def __str__(self):
        return 'EmuError(%r)' % self.errno

def _EmuCheck(status):
    if status != EMU_ERR_OK:
        raise EmuError(status)
    
class MemHook:
    CBTYPE = ctypes.CFUNCTYPE(ctypes.c_uint64, emu_engine, ctypes.c_uint, ctypes.c_uint64, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint64)
    def __init__(self, dev):
        self.dev, self.callback = dev, ctypes.cast(self.CBTYPE(self.action), self.CBTYPE)
        global EMU_HOOK_POOL
        EMU_HOOK_POOL.add(self)
        
    def action(self, ctx, access, address, size, endianness, value):
        if access == 0:
            return self.dev.read(ctx, address, size, endianness)
        elif access == 1:
            self.dev.write(ctx, address, size, endianness, value)
        elif access == 2:
            return self.dev.fetch(ctx, address, size, endianness)
        return 0

class CodeHook:
    CBTYPE = ctypes.CFUNCTYPE(None, emu_engine, ctypes.c_uint64, ctypes.c_uint)

    def __init__(self, cb, cbargs):
        self.cb, self.cbargs, self.callback = cb, cbargs, ctypes.cast(self.CBTYPE(self.action), self.CBTYPE)
        global EMU_HOOK_POOL
        EMU_HOOK_POOL.add(self)

    def action(self, ctx, address, size):
        self.cb( ctx, address, size, **self.cbargs )
    
EMU_HOOK_POOL = set()

def EMU_close(ctx):
    # closes an EMU_CTX
    status = _so.emu_close(ctx)
    _EmuCheck(status)

def EMU_reg_read(ctx, reg_id):
    # Read a register
    reg = ctypes.c_uint64(0)
    rstr, rnum = reg_id
    status = _so.emu_reg_read(ctx, rstr.encode('ascii'), len(rstr), rnum, ctypes.byref(reg))
    _EmuCheck(status)
    return reg.value

def EMU_reg_write(ctx, reg_id , value):
    # Write a register
    rstr, rnum = reg_id
    status = _so.emu_reg_write(ctx, rstr.encode('ascii'), len(rstr), rnum, value)
    _EmuCheck(status)

# INFO: permissions: bit flags {1=read, 2=write, 4=execute}
# WARNING:
#  - a size argument has been added
#  - now using keyword arguments
#    - perms become a keyword arguments, defaulting to 7 (rwx)
#    - a hook keyword argument have been added to place a callback
#    - a zero perms if a pure python-hooked memory region (no memory will ever be allocated)
#    - non zero perm memory region may (or not) have a hook
def EMU_mem_init(ctx, address, size, **opts ):
    # initialize a page
    perms = opts.get('perms',7)
    hook = opts.get('hook',None)
    if hook is None:
        hook = ctypes.cast(None, MemHook.CBTYPE)
    else:
        hook = MemHook(hook).callback
    status = _so.emu_mem_map(ctx, address, size, perms, hook)
    _EmuCheck(status)

def EMU_mem_write(ctx, address, data, size=None):
    # write data to memory
    if size is None:
        size = len(data)
    status = _so.emu_mem_write(ctx, address, data, size)
    _EmuCheck(status)

def EMU_mem_read(ctx, address, size):
    # read data from memory
    data = ctypes.create_string_buffer(size)
    status = _so.emu_mem_read(ctx, address, data, size)
    _EmuCheck(status)
    return bytearray(data)

def EMU_mem_prot(ctx, addr, new_prot):
    # change page permissions
    status = _so.emu_mem_chprot(ctx, address, new_prot)
    _EmuCheck(status)

def EMU_mem_hook(ctx, addr, new_hook):
    # change page hook
    status = _so.emu_mem_chhook(ctx, address, MemHook(new_hook).callback)
    if status != EMU_ERR_OK:
        raise EmuError(status)  

# emulate from @begin, and stop when reaching address @until
def EMU_start(ctx, begin, until, timeout=0, count=0):
    status = _so.emu_start(ctx, begin, until, timeout, count)
    _EmuCheck(status)

# emergency stop (callable from inside hook)
def EMU_stop(ctx):
    status = _so.emu_stop(ctx)
    _EmuCheck(status)

# (de)activate instruction disassembly
def EMU_set_disasm(ctx, disasm):
    status = _so.emu_set_disasm(ctx, disasm)
    _EmuCheck(status)


EMU_HOOK_INTR = 1
EMU_HOOK_CODE = 4
EMU_HOOK_BLOCK = 8
EMU_HOOK_MEM = 16

def EMU_hook_code(ctx, callback, begin=1, end=0, **cbargs):
    status = _so.emu_hook_add(ctx, EMU_HOOK_CODE, CodeHook(callback, cbargs).callback, begin, end)
    _EmuCheck(status)

def EMU_hook_BB(ctx, callback, begin=1, end=0, **cbargs):
    status = _so.emu_hook_add(ctx, EMU_HOOK_BLOCK, CodeHook(callback, cbargs).callback, begin, end)
    _EmuCheck(status)

def EMU_hook_excpt(ctx, callback, begin=1, end=0, **cbargs):
    status = _so.emu_hook_add(ctx, EMU_HOOK_INTR, CodeHook(callback, cbargs).callback, begin, end)

######################
# ARM specific stuff #
######################

def EMU_open_arm():
    # Create an arm EMU_CTX
    ctx = emu_engine()
    # arg0=is_thumb: {0: arm, 1: thumb}
    status = _so.emu_open_arm(0, ctypes.byref(ctx))
    _EmuCheck(status)
    return ctx

EMU_ARM_REG_APSR = ('apsr',0)
def EMU_ARM_REG_R(idx):
    return ('gpr',idx)
EMU_ARM_REG_SP = ('gpr',13)
EMU_ARM_REG_LR = ('gpr',14)
EMU_ARM_REG_PC = ('gpr',15)

######################
# VLE specific stuff #
######################

def EMU_open_vle():
    # Create a vle EMU_CTX
    ctx = emu_engine()
    status = _so.emu_open_vle(ctypes.byref(ctx))
    _EmuCheck(status)
    return ctx

def EMU_VLE_REG_R(idx):
    return ('gpr',idx)

EMU_VLE_REG_LR = ('lr',0)
