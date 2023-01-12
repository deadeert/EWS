from EWS.utils.registers import *
from EWS.utils.utils import *
import json



class AdditionnalMapping():

    @staticmethod
    def create():

        return AdditionnalMapping(mappings={})

    def __init__(self,mappings):

        """ 
        !class constructor 

        @param mappings is a record of {addr: bytes}

        """

        self.mappings = mappings

    def __str__(self):

        return '\n'.join(['{}: {}'.format(x,self.__dict__[x])
                          for x in self.__dict__])

    def __add__(self,addm):

        ret = {**self.mappings, **addm.mappings}
        return AdditionnalMapping(ret)

 
class StubConfiguration():

    @staticmethod #should move to classmethod see https://www.geeksforgeeks.org/classmethod-in-python/
    def create():
        cls = StubConfiguration(nstubs={},
                                activate_stub_mechanism=True,
                                tag_func_tab=True,
                                orig_filepath=None,
                                custom_stubs_file=None,
                                auto_null_stub=False,
                                tags={})
        return cls

    def __init__(self,nstubs,
                 activate_stub_mechanism: bool,
                 tag_func_tab: bool,
                 orig_filepath: str,
                 custom_stubs_file: str =None,
                 auto_null_stub: bool=False,
                 tags: dict = None):
        """
        !

        @param activate_stub_mechanism: create helper for stubs
        @param tag_func_tab:            stub ELF(GOT)/PE(IAT) table (when available)
        @param orig_filepath:           name of the original binary
        @param custom_stubs_file:       file that specify special behavior for certain function
        @param autonull stub:           null stubs symbols that are not currently supported
        @param tags :                   dict {ea:stub_name}
        @param nstubs                   null stub dictionnary
        """

        self.tag_func_tab = tag_func_tab
        self.activate_stub_mechanism = activate_stub_mechanism
        self.orig_filepath = orig_filepath
        self.custom_stubs_file = custom_stubs_file
        self.auto_null_stub = auto_null_stub
        self.nstubs = nstubs
        if tags == None:
            self.tags = dict()
        else: self.tags = tags

    def __str__(self):
        return '\n'.join(['{}: {}'.format(x,self.__dict__[x]) for x in self.__dict__])


    def __add__(self,sconf):
        nstubs = {**self.nstubs, **sconf.nstubs}
        tags = {**self.tags, **sconf.tags}
        return StubConfiguration(nstubs=nstubs,
                                 activate_stub_mechanism=sconf.activate_stub_mechanism,
                                 tag_func_tab=sconf.tag_func_tab,
                                 orig_filepath=sconf.orig_filepath,
                                 custom_stubs_file=sconf.custom_stubs_file,
                                 auto_null_stub=sconf.auto_null_stub,
                                 tags=tags)



class Configuration():
    """ Configuration as follow
            arch:                     str             idp name 
            emulator                str             emulation solution name 
            stk_ba:                 int             for stack base address 
            stk_size:             int             for stack size (curved with p_size)    
            autoMap:                boolean     if true when a insn hit unmapped page, the page will be mapped by the engine(if available)    
            showRegisters:    boolean     if true registers value will be displayed on the console and/or file 
            exec_saddr:         int             start address of the execution
            exec_eaddr:         int             stop address of the execution
            mapping_saddr     int             offset in binary where the mapping starts 
            mapping_eaddr     int             offset in binary where the mapping ends
            map_with_segs     boolean     allow selecting segm. to map among list (disable two previous options)
            use_seg_perms     boolean     use segment permission(s) of the file format (if available)
            useCapstone         boolean     use capstone to generate insn disassembly output
            registers:            [int]         init values of regsiters
            s_conf:
            showMemAccess     boolean     when activated display all memory accesses on logger
            amap_conf:            [mapping] allow addit. mappings (not belonging to the binary) 
                                                                usefull for arguments mapping etc... 
            memory_init         [mapping] allow to store memory initialization
            filepath:             str             path of the origianl executable (for stubs)
            breakpoint:         list of breakpoints
            watchpoints:         dict of {watchpoint_addr: size} #  it does not record fashion access (read/write)
            patches:            dict of {addr: asm}

    """
    
    def __init__(self,
                 path: str = None,
                 arch: str = None,
                 emulator: str = None,
                 p_size: int = None,
                 stk_ba: int = None,
                 stk_size: int = None,
                 autoMap: bool = None,
                 showRegisters: bool = None,
                 exec_saddr: int =None,
                 exec_eaddr: int =None,
                 mapping_saddr: int =None,
                 mapping_eaddr: int =None,
                 segms: list =None,
                 map_with_segs: bool = None,
                 use_seg_perms: bool =None,
                 useCapstone: bool = None,
                 registers: Registers = None,
                 showMemAccess: bool =None,
                 s_conf: StubConfiguration = None,
                 amap_conf: AdditionnalMapping = None,
                 memory_init: dict =None,
                 color_graph: bool =None,
                 breakpoints: list =None,
                 watchpoints: dict =None,
                 patches: dict = None,
                 max_insn: int = 0x10000):

        self.path = path 
        self.arch = arch
        self.emulator = emulator
        self.p_size = p_size 
        self.stk_ba = stk_ba
        self.stk_size = stk_size
        self.autoMap = True if autoMap else False
        self.showRegisters = True if showRegisters else False
        self.useCapstone = True if useCapstone else False
        self.exec_saddr = exec_saddr 
        self.exec_eaddr = exec_eaddr
        self.mapping_saddr = mapping_saddr
        self.mapping_eaddr = mapping_eaddr
        self.segms = segms
        self.map_with_segs = map_with_segs
        self.registers=registers
        self.showMemAccess=showMemAccess
        self.use_seg_perms=use_seg_perms
        self.s_conf = s_conf
        self.amap_conf = amap_conf
        self.memory_init = memory_init
        self.color_graph = color_graph
        self.breakpoints = breakpoints
        self.watchpoints = watchpoints
        self.patches = patches
        self.max_insn = max_insn


    @classmethod
    def generate_default_config(cls,
                                 path: str = None,
                                 arch: str = None,
                                 emulator: str = None,
                                 p_size: int = None,
                                 stk_ba: int = None,
                                 stk_size: int = None,
                                 autoMap: bool = None,
                                 showRegisters: bool = None,
                                 exec_saddr: int =None,
                                 exec_eaddr: int =None,
                                 mapping_saddr: int =None,
                                 mapping_eaddr: int =None,
                                 segms: list =None,
                                 map_with_segs: bool = None,
                                 use_seg_perms: bool =None,
                                 useCapstone: bool = None,
                                 registers: Registers = None,
                                 showMemAccess: bool =None,
                                 s_conf: StubConfiguration = None,
                                 amap_conf: AdditionnalMapping = None,
                                 memory_init: AdditionnalMapping =None,
                                 color_graph: bool =None,
                                 breakpoints: list =None,
                                watchpoints: dict =None,
                                patches: dict = None,
                                max_insn: int = 0x10000):



        """
        !generate_default_config 

        @param arch:                     str             idp name 
        @param emulator                str             emulation solution name 
        @param stk_ba:                 int             for stack base address 
        @param stk_size:             int             for stack size (curved with p_size)    
        @param autoMap:                boolean     if true when a insn hit unmapped page, the page will be mapped by the engine(if available)    
        @param showRegisters:    boolean     if true registers value will be displayed on the console and/or file 
        @param exec_saddr:         int             start address of the execution
        @param exec_eaddr:         int             stop address of the execution
        @param mapping_saddr     int             offset in binary where the mapping starts 
        @param mapping_eaddr     int             offset in binary where the mapping ends
        @param map_with_segs     boolean     allow selecting segm. to map among list (disable two previous options)
        @param use_seg_perms     boolean     use segment permission(s) of the file format (if available)
        @param useCapstone         boolean     use capstone to generate insn disassembly output
        @param registers:            [int]         init values of regsiters
        @param s_conf:
        @param showMemAccess     boolean     when activated display all memory accesses on logger
        @param amap_conf:            [mapping] allow addit. mappings (not belonging to the binary) 
                                                             usefull for arguments mapping etc... 
        @param memory_init         [mapping] allow to store memory initialization
        @param filepath:             str             path of the origianl executable (for stubs)
        @param breakpoint:         list of breakpoints
        @param watchpoints:         dict of {watchpoint_addr: size} #  it does not record fashion access (read/write)
        @param patches:            dict of {addr: asm}

        @return Configuration Object
        """

        if registers == None:
            raise Exception('Registers object must be created when using generate_default_config function')

        if s_conf == None:
            exec_path = search_executable()
            stub_conf = StubConfiguration(nstubs=dict(),
                                            tag_func_tab = True,
                                            activate_stub_mechanism=True,
                                            orig_filepath=exec_path,
                                            custom_stubs_file=None,
                                            auto_null_stub=True if exec_path != "" else False,
                                            tags=dict())
        else:
            stub_conf = s_conf

        if amap_conf == None:
            addmap_conf = AdditionnalMapping.create()
        else:
            addmap_conf = amap_conf

        if memory_init == None:
            meminit = AdditionnalMapping.create()
        else:
            meminit = memory_init


        return Configuration( path=path if path else '',
                              arch=arch,
                              emulator='unicorn',
                              p_size=p_size if p_size else 0x1000,
                              stk_ba=stk_ba if stk_ba else 0x7FFFFFFF,
                              stk_size=stk_size if stk_size else 0x10000,
                              autoMap=autoMap if autoMap else False,
                              showRegisters=showRegisters if showRegisters else True,
                              exec_saddr=exec_saddr if exec_saddr else 0,
                              exec_eaddr=exec_eaddr if exec_eaddr else 0xFFFFFFFF,
                              mapping_saddr=get_min_ea_idb() if not mapping_saddr else mapping_saddr,
                              mapping_eaddr=get_max_ea_idb() if not mapping_eaddr else mapping_eaddr,
                              segms=segms if segms else [],
                              map_with_segs=map_with_segs if map_with_segs else False,
                              use_seg_perms=use_seg_perms if use_seg_perms else False,
                              useCapstone=useCapstone if useCapstone else True,
                              registers=registers,
                              showMemAccess=showMemAccess if showMemAccess else True,
                              s_conf=stub_conf,
                              amap_conf=addmap_conf,
                              memory_init=meminit,
                              color_graph=False,
                              breakpoints=breakpoints if breakpoints else [],
                             watchpoints = watchpoints if watchpoints else {},
                             patches = patches if patches else {},
                             max_insn = max_insn)



    def __str__(self):
        return '\n'.join(['{}: {}'.format(x,self.__dict__[x]) for x in self.__dict__])


    def show_user_mapping(self,displayContent=False):
        for k,v in self.amap_conf.mappings.items():
            logger.console(LogType.INFO,'[%x:%x]'%(k,k+len(v)))
            if displayContent:
                display_mem(v)


    def show_nullstubs(self):

        """ 
        !show_nullstubs 
        """

        for k,v in self.s_conf.nstubs.items():
            logger.console(LogType.INFO,'%s at %x'%(v,k))


    def add_null_stub(self,
                      ea:int) -> None:

        """ 
        !add_null_stub
        """

        self.s_conf.nstubs[ea] = ida_funcs.get_func_name(ea)

    def remove_null_stub(self,
                         ea:int)-> None:

        """ 
        !remove_null_stub
        """

        if ea in self.s_conf.nstubs.keys():
                del self.s_conf.nstubs[ea]
        else:
                logger.console(LogType.WARN,"Could not remove null-stub",
                               "No null-stub registred at this address (%x)"%ea)


    def add_tag(self,
                ea:int,
                stub_name:str) -> None:
        
        """ 
        !add_tag

        @param ea Effective Address of the function
        @param stub_name The name of the tag used to stub the function  


        """

        if ea in self.s_conf.tags.keys():
                logger.console(LogType.WARN,'Tag already registred at this ea (%x). Overwritting the value'%ea)
        self.s_conf.tags[ea] = stub_name

    def remove_tag(self,
                   ea:int)->None:

        """ 
        !remove_tag 

        @param ea Effective Address where the tag was registred

        """


        if ea in self.s_conf.nstubs.keys():
            
                del self.s_conf.nstubs[ea]

        else:
                logger.console(LogType.WARN,"Could not remove tag. No tag registred at this address (%x)"%ea)

    def show_tags(self)-> None:

        """
        !show_tags
        """

        for k,v in self.s_conf.tags.items():
            logger.console(LogType.INFO,'%x : %s'%(k,v))
    
    def save(self,
             path:str)-> None:

        saveconfig(self,path)

    def add_breakpoint(self,
                       ea:int) -> None:

        """
        !add_breakpoint

        @param ea Effective Address for the breakpoint

        """ 
        
        self.breakpoints.append(ea)

    def add_watchpoint(self,
                       base_addr:int,
                       size:int) -> None :

        """ 
        !add_watchpoint

        @param base_addr Effective Address of the data
        @param size Size to consider.
        """

        self.watchpoints[base_addr] = size
        
    def remove_breakpoint(self,
                          ea:int) -> None:

        """ 
        !remove_breakpoint 

        @param ea Effective Address where the breakpoint was registred 
        """


        self.breakpoints.remove(ea)

    def show_breakpoints(self) -> None:

        """ 
        !show_breakpoints 


        """

        for k in self.breakpoints:
            logger.console(LogType.INFO,'%x'%k)

    def add_patch(self,
                    addr: int,
                    asm: str) -> None:

        """
        !add_patch 

        @param addr Effective Address for the patch 
        @param asm Assembly text to be compiled


        """


        self.patches[addr] = asm

    def remove_patch(self,
                     addr: int) -> None:
        """
        !remove_patch 

        @param addr Effective Address where the patch was registred

        """
    
        del self.patches[addr]



class ConfigSerializer(json.JSONEncoder):

    def default(self,
                conf):
       
        """ 
        This class is used for serialization. 

        @param config Configuration Object to be serialized

        """

        if isinstance(conf, Configuration):

            segs = [ seg.start_ea for seg in conf.segms ] 
            funcs = conf.s_conf.nstubs

            f_amap = dict()
            for k,v in conf.amap_conf.mappings.items():
                il = [ b for b in bytearray(v) ]    
                f_amap[k] = il 

            f_meminit = dict()
            for k,v in conf.memory_init.mappings.items():
                il = [ b for b in bytearray(v) ]    
                f_meminit[k] = il 



   
            
            p = dict() 
            for addr,bytecode in conf.patches.items():
                p[addr] = [b for b in bytearray(bytecode)]


            
            return {'path':conf.path, 
                            'arch': conf.arch,
                            'emulator':conf.emulator, 
                            'p_size' : conf.p_size, 
                            'stk_ba': conf.stk_ba, 
                            'stk_size' : conf.stk_size, 
                            'autoMap' : conf.autoMap, 
                            'showRegisters': conf.showRegisters, 
                            'useCapstone': conf.useCapstone, 
                            'exec_saddr' : conf.exec_saddr, 
                            'exec_eaddr' : conf.exec_eaddr, 
                            'mapping_saddr' : conf.mapping_saddr, 
                            'mapping_eaddr' : conf.mapping_eaddr,
                            'segms': segs, 'registers': conf.registers.__dict__, 
                            'map_with_segs' : conf.map_with_segs,
                            'showMemAccess': conf.showMemAccess, 
                            'use_seg_perms': conf.use_seg_perms, 
                            's_conf': {'nstubs' : funcs, 
                                                 'tag_func_tab': conf.s_conf.tag_func_tab,
                                                 'activate_stub_mechanism': conf.s_conf.activate_stub_mechanism, 
                                                 'orig_filepath' : conf.s_conf.orig_filepath, 
                                                 'auto_null_stub': conf.s_conf.auto_null_stub,
                                                 'custom_stubs_file' : conf.s_conf.custom_stubs_file,
                                                 'tags':conf.s_conf.tags}, 
                         'amap_conf': f_amap, 'color_graph': conf.color_graph,
                         'memory_init': f_meminit,
                         'breakpoints':conf.breakpoints,
                         'watchpoints': conf.watchpoints,
                         'patches': p,
                         'max_insn': conf.max_insn}


class ConfigDeserializer(json.JSONDecoder): #PASS ClassType for register parsing ? 
    
        def decode(self,json_txt):
        

            jdict = json.loads(json_txt)
            nstubs = dict()


            for ea,fname in jdict['s_conf']['nstubs'].items(): nstubs[int(ea,10)] = fname
     
                                                    
            amap_dict = dict()
            for k,v in jdict['amap_conf'].items(): 
                amap_dict[int(k,10)] = bytes(v)
       
            meminit_dict = dict()
            for k,v in jdict['memory_init'].items(): 
                meminit_dict[int(k,10)] = bytes(v) 
    
            tags_dict = dict()
            for k,v in jdict['s_conf']['tags'].items():
                tags_dict[int(k,10)] = v 

            watchpoints = dict()
            for k,v in jdict['watchpoints'].items():
                watchpoints[int(k,10)] = v
        
            if jdict['arch'] == 'arm':
                regs=ArmRegisters(**jdict['registers'])
            elif jdict['arch'] == 'mips':
                regs=MipslRegisters(**jdict['registers'])
            elif jdict['arch'] == 'x86':
                regs=x86Registers(**jdict['registers']) 
            elif jdict['arch'] == 'x64':
                regs=x64Registers(**jdict['registers'])
            elif jdict['arch'] == 'aarch64':
                regs=Aarch64Registers(**jdict['registers'])


            patches = dict()
            for addr,intb in jdict['patches'].items():
                patches[int(addr,10)] = bytes(bytearray(intb))
                

            conf = Configuration(path=jdict['path'],
                                 arch=jdict['arch'],
                                 emulator=jdict['emulator'],
                                 p_size=jdict['p_size'],
                                 stk_ba=jdict['stk_ba'],
                                 stk_size=jdict['stk_size'],
                                 autoMap=jdict['autoMap'],
                                 showRegisters=jdict['showRegisters'],
                                 exec_saddr=jdict['exec_saddr'],
                                 exec_eaddr=jdict['exec_eaddr'],
                                 mapping_saddr=jdict['mapping_saddr'],
                                 mapping_eaddr=jdict['mapping_eaddr'],
                                 segms=[ ida_segment.getseg(segea) for segea in jdict['segms'] ],
                                 map_with_segs=jdict['map_with_segs'],
                                 use_seg_perms=jdict['use_seg_perms'],
                                 useCapstone=jdict['useCapstone'],
                                 registers=regs,
                                 showMemAccess=jdict['showMemAccess'],
                                 s_conf=StubConfiguration(nstubs=nstubs,
                                                          tag_func_tab=jdict['s_conf']['tag_func_tab'],
                                                          activate_stub_mechanism=jdict['s_conf']['activate_stub_mechanism'],
                                                           orig_filepath=jdict['s_conf']['orig_filepath'],
                                                           custom_stubs_file=jdict['s_conf']['custom_stubs_file'],
                                                            auto_null_stub=jdict['s_conf']['auto_null_stub'],
                                                            tags=tags_dict),
                                amap_conf=AdditionnalMapping(amap_dict),
                                 memory_init=AdditionnalMapping(meminit_dict),
                                 color_graph=jdict['color_graph'],
                                 breakpoints=jdict['breakpoints'],
                                 watchpoints=watchpoints,
                                 patches=patches,
                                 max_insn=jdict['max_insn'])

            return conf
             
def saveconfig(conf,
               conf_apath:str=''): 

    """ 
    !saveconfig 

    @param conf_apath: Path of the file for Configuration serialization

    """

    if conf_apath == '': 
        conf_apath=conf.path
   
    with open(conf_apath,'w+') as fout: 
        json.dump(conf,fp=fout,cls=ConfigSerializer)
    

def loadconfig(conf_apath:str) -> Configuration : 

    """ 
    !loadconfig 

    @param conf_apath: Path of the Configuration to be deserialized.

    """

    with open(conf_apath, 'r') as fin:

        return json.loads(fin.read(),cls=ConfigDeserializer)



