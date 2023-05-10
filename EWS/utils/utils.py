import ida_idaapi
import ida_bytes
import ida_funcs
import ida_segment
import ida_segregs
import ida_ida
import ida_idp
import ida_ua
import ida_loader
import idc 
import string
import ida_nalt
import os
import lief
import struct
from enum import Enum
from re import compile
import ida_kernwin
import EWS.emu.emubase

# based on x64
MAX_INSN_SIZE=15


class plug_mode(Enum):

    DEFAULT=0
    TRACEVIEWER=1
 

def get_seg_list() -> list:

    """
    !get_seg_list returns the list of available segments
    in IDB.

    @return A list of registred segments in IDB.

    """

    info = ida_idaapi.get_inf_structure()
    seg_l = []
    s = ida_segment.getseg(info.min_ea)
    if s == None:
        print('[!] Please make sure that all the memory belongs to a segment')
        exit(1)
    seg_l.append(s)
    while True:
        s = ida_segment.get_next_seg(s.end_ea-1)
        if s == None:
            break
        seg_l.append(s)
    return seg_l


def get_func_list() -> list:

    """
    !get_func_list return the list of available functions
        in IDB.

    @return List of functions registred inside the IDB.

    """

    info = ida_idaapi.get_inf_structure()
    fun_l = []
    f = ida_funcs.get_next_func(info.min_ea)

    if f == None:
        return fun_l
    fun_l.append(f)
    while True:
        f = ida_funcs.get_next_func(f.start_ea)
        if f == None:
            break
        fun_l.append(f)
    return fun_l




def proc_inf(arch: str,
             addr: int) -> dict:

    """
    !proc_inf returns a dictionnary containing information
    regarding processor' address size and endianess.

    @param arch: The current binary architecture. 
    @param addr: The current address. 

    @return A dictionnary with processor mode, endianness, ...

    """

    ret = dict()

    if arch == 'arm':

            if ida_segregs.get_sreg(addr,ida_idp.str2reg('T')):
                logger.console(LogType.INFO,"Thumb mode detected")
                ret['proc_mode']=16
            else:
                ret['proc_mode']=32
            if ida_ida.inf_get_procname() == 'armb':
                ret['endianness'] = 'big'
            else :
                ret['endianness'] = 'little'

    if arch == 'mips':
        if ida_segregs.get_sreg(addr,ida_idp.str2reg('mips16')):
                ret['proc_mode']=16
        else:
                ret['proc_mode']=32
        if ida_ida.inf_get_procname() == 'mipsb':
                ret['endianness'] = 'big'
        else : #"mipsl" 
                ret['endianness'] = 'little'

    return ret



class SockMode(Enum):

    """
    !SockMode is used in stub mechanism for
    socket related functions.
    """

    UKN=2
    READ=0
    WRITE=1


class LogType(Enum):

    """
    !LogType indicate the verbose level
    of a logging information.
    """

    INFO = 0
    WARN = 1
    ERRR = 2

class LoaderType(Enum):

    """
    LoaderType indicated which kind of
    file is currently handled
    """

    ELF = 0
    PE    = 1
    UNDEF = 2

class StubType(Enum):

    """
    StubType indicates which stubbing mechanism
    is referenced inside a Stub object.
    """

    BUILTIN = 0
    TAG = 1
    USER = 2
    NULL = 3



class Logger():

    """
    !Logger intend to logs the different event, with different verbose
    mode.
    It can either log information on the console, or directly on the file.
    """

    def __init__(self,VERBOSE:int,
                 fpath=''):

        """
            int value VERBOSE indicate the verbose of the plugin (0 : none to X: a lot)
        """

        self.VERBOSE = VERBOSE


        if fpath == '':

            from dateutil import utils as utilsdate

            d=utilsdate.today()
            dt=d.now()

            from tempfile import NamedTemporaryFile
            if not os.path.exists("/tmp/EWS"): 
                os.mkdir("/tmp/EWS")
            

            self.fpath = NamedTemporaryFile(dir="/tmp/EWS/",delete=False,mode='w+',
                                        prefix='EWS',
                                        suffix='%d-%d-%d-%d-%d-%d'%(dt.year,
                                                                    dt.month,
                                                                    dt.day,
                                                                    dt.hour,
                                                                    dt.minute,
                                                                    dt.second))

            self.console(LogType.WARN,
                         'No log file provided, ',
                         'logs will be written to %s file.'%self.fpath.name)


    def console(self,
                type : LogType,
                *msg : list):

        """
        !Log event to the console

        @param type: The log type. 
        @param msg: list of print arguments.

        """

        if type == LogType.INFO and self.VERBOSE > 1:
            print('[INFO] ',*msg)

        if type == LogType.WARN and self.VERBOSE > 0:
            print('[WARN] ',*msg)

        if type == LogType.ERRR:
            print('[ERRR] ',*msg)

    def logfile(self,
                type: LogType,
                *msg: list):

        """
            log event to logfile.
        """

        msg = ' '.join(msg)

        if type == LogType.INFO :
            self.fpath.write('[INFO] %s\n'%msg)
            self.fpath.flush()

        if type == LogType.WARN :
            self.fpath.write('[WARN] %s\n'%msg)
            self.fpath.flush()

        if type == LogType.ERRR:
            self.fpath.write('[ERRR] %s\n'%msg)
            self.fpath.flush()



logger = Logger(2)


class ConfigExcption(Exception):

    def __init__(self,str):
        super().__init__(str)


def get_insn_color(eaddr: int):

    """
    !get_insn_color returns the color associated to the instruction
    at address eaddr.

    @param eaddr: Effective Address to extract the insn color from.

    """

    return idc.get_color(eaddr,idc.CIC_ITEM)

def colorate_graph(color_map:dict):

    """
    colorate_graph takes a dictionnary referencing addresses and
    their associated color. It paints the graph according these information.

    @DEPRECATED
    """

    for addr in color_map.keys():

        try:
            idc.set_color(addr,idc.CIC_ITEM,0xAAAAAA)

        except:
            logger.logfile(LogType.WARN,'Could not colorate the graph at %x'%addr)


def restore_graph_color(color_map: dict,
                        purge_db=False):

    """
    !restore_graph_color restores the color of the referenced instructions.
    There are provided by a dictionnary referencing addresses and their original
    color.

    @DEPRECATED
    """

    for addr,color in color_map.items():
        try:
            if color != 0xFFFFFF and color != 0xAAAAAA: 
                idc.set_color(addr,idc.CIC_ITEM,color)
            else:
                idc.set_color(addr,idc.CIC_ITEM,0x242424) # TODO: get default color from idc ? 
        except:
            pass

    if purge_db:
        color_map = dict()


def is_thumb(addr:int) -> bool:

    """
    !is_thumb indicates if the current address recorded in IDB
    reference thumb instruction.

    @param addr: Effective Address to get the Thumb flag from.

    @return Thumb or not Thumb

    """

    return True if ida_segregs.get_sreg(addr,
                                        ida_idp.str2reg('T')) == 1 else False


def get_insn_at(ea: int) -> ida_ua.insn_t:

    """
    !Returns an instruction object given the address *ea*

    @param ea: Effective Address to get the insn object from.

    @return a insn object.

    """


    insn = ida_ua.insn_t()
    ida_ua.decode_insn(insn,ea)

    return insn

def get_insn_bytecode(ea: int,
                      helper= None) -> bytes :
    """
    Return the bytecode at address *ea*.

    @param ea: Effective Address to extract the bytecode from.
    @param helper: SEA object to read memory from.

    @return The bytecode.

    """

    insn = get_insn_at(ea)

    if not helper:
            return ida_bytes.get_bytes(ea,insn.size)

    else:
            return helper.mem_read(ea,insn.size)


def get_captsone_repr(emu:EWS.emu.emubase.Emulator,
                      addr: int) -> str:

    """
    !get_captsone_repr uses captsone engine to return 
    the syntax associated to the bytecode referenced 
    at address *addr*.

    @param emu: Emulator Object 
    @param addr: Effective Address of the code.  
    
    @return capstone representation.

    """

    try:
        opline = emu.mem_read(addr,MAX_INSN_SIZE)
        insn_cpst=next(emu.cs.disasm(opline,addr,count=1))
        insn_str="0x%x:\t%s\t%s" %(insn_cpst.address,
                                     insn_cpst.mnemonic,
                                     insn_cpst.op_str)

    except Exception as e:
        logger.console(LogType.ERRR,
                                     "Capstone cannot decode bytecode:",
                                     opline, 'at ea %x'%addr)
        return ''

    return insn_str


def build_insn_repr(emu:EWS.emu.emubase.Emulator,
                    addr: int) -> str:

    """
    !build_insn_repr return the syntax associated to the instruction
    referenced at address *addr*.
    It is involved in trace outputing mechanism.

    @param emu: Pointer to Emulator object
    @param addr: Effective Addres of the instruction. 

    @param string repr of the instruction. 

    """

    strout=''

    if emu.conf.useCapstone:
            insn_str = get_captsone_repr(emu,addr)

    if emu.conf.showRegisters:
            strout+= emu.print_registers()
            strout+= str(emu.get_alu_info())
            strout+= '\n'
            strout+= '------------------------\n'

    # This becomes incorrect if assembly has been patched. BUG
    bytecode= emu.mem_read(addr,get_insn_at(addr).size)

    strout+= '[opcode=%X] '% int.from_bytes(bytecode,'big',signed=False)
    strout += '[PC=%.8X]  '%  addr
    strout+= insn_str

    return strout


def build_func_name(ea: int) -> str:

    """
    !build_func_name returns the name of the function 
    recorded in IDB for address *addr*. If no function
    is associated to the address, a name is built.

    @param ea: Effective Address

    @return function name
    """

    fn = ida_funcs.get_func_name(ea)

    if fn == None: 
        fn = 'func_%x'%ea

    return fn


def get_min_ea_idb() -> int:

    """
        !get_min_ea_idb returns the minimal Effective Address recorded in the IDB.

        @return int value of min ea
    """

    return ida_idaapi.get_inf_structure().min_ea


def get_max_ea_idb() -> int:

    """
        !get_min_ea_idb returns the biggest Effective Address 
        recorded in the IDB.

        @return max ea value
    """

    return ida_idaapi.get_inf_structure().max_ea






def search_executable() -> str:

        """ 

            !search_executable tries to locate the binary corresponding to the IDB
            in order to parse dynamic information.

            @return filepath 
        """

        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_CMD)
        if idc.__EA64__: 
            pat = compile("(.*)(.i64)$")
        else:
            pat = compile("(.*)(.idb)$")
        f_pat = pat.search(idb_path) 
        if not f_pat is None:

            if idc.__EA64__: 
                return f_pat.group(0).replace('.i64','')
            else:
                return f_pat.group(0).replace('.idb','')
        else: 

                ida_kernwin.warning("Could not find executable file, please enter its location")
                file = ida_kernwin.ask_file(1,"","Please locate original executable")
                if file != "": 
                    return file
                else:
                    ida_kernwin.warning("Could not locate original executable file, so mechanism won't work") 
                    return ""
            

def does_file_exist(f_path: str) -> bool:

    """
    does_file_exist indicate if the specified file in path f_path does exist.
  
    @return Indicate if the file exists.

    """

    
    return f_path != None and os.path.exists(f_path) and not os.path.isdir(f_path)




def verify_valid_elf(candidate: str) -> bool:
    """
    !verify_valid_elf indicate if the file specified in *f_path* is a valid
    ELF.

    @param candidate: Path of the ELF file. 

    @return Indicate if LIEF managed to parse the file.

    """

    try:
        
        return candidate != None and\
            does_file_exist(candidate) and\
            lief.ELF.parse(candidate)

    except AttributeError:
        return False



def verify_valid_PE(candidate: str) -> bool:

    """
    !Verify_valid_PE indicate if the file specified in *f_path* is a valid
    PE.

    @param candidate: Path of the ELF file. 

    @return Indicate if LIEF managed to parse the file.
    """


    try: 
        return does_file_exist(candidate) and lief.PE.parse(candidate) != None
    except AttributeError:
        return False


def get_next_pc(insn: ida_ua.insn_t) -> int:

    """
    get_next_pc uses metainformation provided by instruction object
    *insn* to determinate potential future program counter value.
    TODO: returns a list of potential values.

    @return Next PC address.

    """

    if ida_idp.is_call_insn(insn) or ida_idp.has_insn_feature(insn.itype,ida_idp.CF_STOP):

        xf_ea = ida_xref.get_first_cref_from(insn.ea)
        xf_ea = ida_xref.get_next_cref_from(insn.ea,xf_ea)

        if xf_ea != idaapi.BADADDR:
                    return xf_ea

        else:
                    raise Exception('[+] Could not determine target of the call/jmp insn')

    elif ida_idp.is_indirect_jump_insn(insn):

            #see ev_calc_next_insn and ev_calc_step_over
            raise Exception('NotImplemented')
    # TODO 
    # elif as_feature CF_JF CF_JN pour les sauts conditionnels
    else:
            return insn.ea + insn.size


def breakpoints_all_insn_target(insn: ida_ua.insn_t):

        """
        This function will add breakpoint to all potential target ea. 
        Usefull for jump table. 

        @param insn: Instruction to use.
        """

        xf_ea = ida_xref.get_first_cref_from(insn.ea)
        while (xf_ea != idaapi.BADADDR):
                bp_addr.append(xf_ea)
                xf_ea = ida_xref.get_next_cref_from(insn.ea,xf_ea)
        for bp_ea in bp_addr:
                ida_dbg.add_bpt(bp_ea,0,idc.BPT_SOFT)


def get_imports(fpath: str) -> dict:

    """
    get_imports returns a dictionnary object referencing
    the symbol' address resolutions.
    It is associated to PE object.

    @param File path

    @return PE imports 

    """

    reloc_map = dict()
    info = ida_idaapi.get_inf_structure()

    PE_obj = lief.PE.parse(fpath)

    if str(PE_obj) != 'None':

            for f in PE_obj.imported_functions:
                    reloc_map[f.name] = f.address + ida_nalt.get_imagebase()

    return reloc_map

def get_relocs(fpath: str,
               RTYPE_ID: int) -> dict:

    """
    get_relocs returns a dictionnary providing
    information concerning symbols and their address given
    the expected kind of relocation RTYPE_ID.
    It is associated to ELF object.

    @param ELF path.
    @param Type of RELOC

    @return The relocations 


    """

    reloc_map = dict()

    elf_l = lief.ELF.parse(fpath)

    if str(elf_l) != 'None':

        relocs = elf_l.relocations

        for r in relocs:

                if r.type == int(RTYPE_ID):
                    reloc_map[r.symbol.name] = r.address


    return reloc_map





def int_to_bytes(value:int,
                size: int)-> bytes:

    """ 
    !Various integer/bytes converter

    @param the int value
    @param the size object in return 

    @return the bytes. 

    """

    value = abs(value) 
    if size == 1:
        return struct.pack('B',value&0xFF)
    elif size == 2:
        return struct.pack('<H',value&0xFFFF)
    elif size == 4:
        return struct.pack('<I',value&0xFFFFFFFF)
    elif size == 8:
        return struct.pack('<Q',value&0xFFFFFFFFFFFFFFFF)
