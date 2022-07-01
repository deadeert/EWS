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
#from EWS.stubs.emu.unicorn.sea import UnicornSEA


MAX_INSN_SIZE=8

def get_seg_list() -> list:

    """
    get_seg_list returns the list of available segments
    in IDB.
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
        get_func_list return the list of available functions
        in IDB.
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
        proc_inf returns a dictionnary containing information
        regarding processor' address size and endianess.
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
        SockMode is used in stub mechanism for
        socket related functions.
    """

    UKN=2
    READ=0
    WRITE=1


class LogType(Enum):

    """
        LogType indicate the verbose level
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
        Logger intend to logs the different event, with different verbose
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

            self.fpath = NamedTemporaryFile(delete=False,mode='w+',
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
            log event to the console
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



# Create the logger.
# TODO: move it to the plugin object? will be cleaner. 
logger = Logger(2)


class ConfigExcption(Exception):

    def __init__(self,str):
        super().__init__(str)


def get_insn_color(eaddr: int):

    """
        get_insn_color returns the color associated to the instruction
        at address eaddr.
    """

    return idc.get_color(eaddr,idc.CIC_ITEM)

def colorate_graph(color_map:dict):

    """
        colorate_graph takes a dictionnary referencing addresses and
        their associated color. It paints the graph according these information.
    """

    for addr in color_map.keys():

        try:
            idc.set_color(addr,idc.CIC_ITEM,0xAAAAAA)

        except:
            logger.logfile(LogType.WARN,'Could not colorate the graph at %x'%addr)


def restore_graph_color(color_map: dict,
                        purge_db=False):

    """
        restore_graph_color restores the color of the referenced instructions.
        There are provided by a dictionnary referencing addresses and their original
        color.
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


# DEPRECATED use UI function from plugin

#def display_mem(mem,ba=None,direction=0):
#    
#    if len(mem) % 8 != 0:
#        dist = 8 - (len(mem)%8)
#        logger.console(LogType.INFO,'[!] content not aligned. Adding %d extra bytes to output'%(dist))
#        fmem = bytes(mem)+b'\x00'*(dist)
#    else: fmem = mem
#        
#    for l in range(0,len(fmem),8):
#            out = ''
#            if ba: out += '0x%x: '%ba
#            out+=' '.join(['%2x'%fmem[l+i] for i in range(0,8)])
#            rep=[]
#            for i in range(0,8):
#                if fmem[l+i] in [ord(x) for x in string.ascii_letters]:
#                    rep.append(int.to_bytes(fmem[l+i],1,'little').decode('utf-8'))
#                else:
#                    rep.append('.')
#            out+='\t\t'
#            out+=' '.join(rep)
#            if ba: ba += 8
#            logger.console(LogType.INFO,out)

def is_thumb(addr:int) -> bool:

    """
        is_thumb indicates if the current address recorded in IDB
        reference thumb instruction.
    """

    return True if ida_segregs.get_sreg(addr,
                                        ida_idp.str2reg('T')) == 1 else False


def get_insn_at(ea: int) -> ida_ua.insn_t:

    """
        returns an instruction object given the address *ea*
    """


    insn = ida_ua.insn_t()
    ida_ua.decode_insn(insn,ea)

    return insn

def get_insn_bytecode(ea: int,
                      helper= None) -> bytes :
    """
        return the bytecode at address *ea*.
    """

    insn = get_insn_at(ea)

    if not helper:
            return ida_bytes.get_bytes(ea,insn.size)

    else:
            return helper.mem_read(ea,insn.size)


def get_captsone_repr(emu,
                      addr: int) -> str:

    """
        get_captsone_repr uses captsone engine to return 
        the syntax associated to the bytecode referenced 
        at address *addr*.
    """

    insn = get_insn_at(addr)

    # it means code in idb is different from the code in emulator
    line_size = insn.size if insn.size > 0 else MAX_INSN_SIZE
    insn_str = ''

    try:
        opline = emu.mem_read(addr,line_size)
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


#TODO: move to utils.emulator ??
def build_insn_repr(emu,
                    addr: int) -> str:

    """
        build_insn_repr return the syntax associated to the instruction
        referenced at address *addr*.
        It is involved in trace outputing mechanism.
    """

    strout=''

    if emu.conf.useCapstone:
            insn_str = get_captsone_repr(emu,addr)

    if emu.conf.showRegisters:
            strout+= emu.print_registers()
            strout+= str(emu.get_alu_info())
            strout+= '\n'
            strout+= '------------------------\n'

    bytecode= emu.mem_read(addr,get_insn_at(addr).size)

    strout+= '[opcode=%X] '% int.from_bytes(bytecode,'big',signed=False)
    strout += '[PC=%.8X]  '%  addr
    strout+= insn_str

    return strout


def build_func_name(ea: int) -> str:

    """
        build_func_name returns the name of the function 
        recorded in IDB for address *addr*. If no function
        is associated to the address, a name is built.
    """

    fn = ida_funcs.get_func_name(ea)

    if fn == None: 
        fn = 'func_%x'%ea

    return fn


def get_min_ea_idb() -> int:

    """
        get_min_ea_idb returns the minimal address recorded in the IDB.
    """

    return ida_idaapi.get_inf_structure().min_ea


def get_max_ea_idb() -> int:

    """
        get_min_ea_idb returns the biggest address recorded in the IDB.
    """

    return ida_idaapi.get_inf_structure().max_ea






def search_executable() -> str:

        """ 
            search_executable tries to locate the binary corresponding to the IDB
            in order to parse dynamic information.
        """

        f_path = ida_loader.get_path(ida_loader.PATH_TYPE_CMD)

        if '.idb' in f_path: 
            f_path_l = f_path.split('.')[:-1] 
        else:
            f_path_l = f_path.split('.')

        ntry=1
        f_path=''

        while ntry<=len(f_path_l):

                candidate='.'.join(f_path_l[0:ntry]) 

                if os.path.exists(candidate):
                        f_path=candidate 
                        break
                else:
                        ntry+=1


        if f_path == "":
                logger.console(LogType.WARN,
                               "cannot find suitable executable, please enter manually")


        return f_path


def does_file_exist(f_path: str) -> bool:

    """
        does_file_exist indicate if the specified file in path f_path does exist.
    """

    
    return f_path != None and os.path.exists(f_path) and not os.path.isdir(f_path)




def verify_valid_elf(candidate: str) -> bool:
    """
        verify_valid_elf indicate if the file specified in *f_path* is a valid
        ELF.
    """

    try:
        return candidate != None and\
            does_file_exist(candidate) and\
            lief.ELF.parse(candidate)
    except AttributeError:
        return False



def verify_valid_PE(candidate: str) -> bool:

    """
        verify_valid_elf indicate if the file specified in *f_path* is a valid
        PE.
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

    if size == 1:
        return struct.pack('B',value)
    elif size == 2:
        return struct.pack('<H',value)
    elif size == 4:
        return struct.pack('<I',value)
    elif size == 8:
        return struct.pack('<Q',value)
