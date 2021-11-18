from EWS.utils.utils import *
from EWS.utils.registers import *
import json



class AdditionnalMapping():
        
    @staticmethod
    def create():
        return AdditionnalMapping({})

    def __init__(self,mappings):
        self.mappings = mappings

    def __str__(self):
        return '\n'.join(['{}: {}'.format(x,self.__dict__[x]) for x in self.__dict__])

    def __add__(self,addm):
        ret = {**self.mappings, **addm.mappings}
        return AdditionnalMapping(ret)
            


        
class StubConfiguration():

    @staticmethod #should move to classmethod see https://www.geeksforgeeks.org/classmethod-in-python/
    def create():
        cls = StubConfiguration({},False,None,{})
        return cls 

    def __init__(self,nstubs,
                             activate_stub_mechanism,
                             orig_filepath,
                             custom_stubs_file=None,
                             auto_null_stub=False,
                             tags=None):
        """ nstubs                             : null stub dictionnary 
                activate_stub_mechanism: stub sections such as plt/iat ...    
                orig_filepath                : name of the original binary
                custom_stubs_file        : file that specify special behavior for certain function
                autonull stub                : null stubs symbols that are not currently supported
                tags : mapping ea:stub_name 
        """
        
        self.nstubs = nstubs 
        self.activate_stub_mechanism = activate_stub_mechanism
        self.orig_filepath = orig_filepath 
        self.custom_stubs_file = custom_stubs_file 
        self.auto_null_stub = auto_null_stub 
        if tags == None:
            self.tags = dict() 
        else: self.tags = tags

    def __str__(self):
        return '\n'.join(['{}: {}'.format(x,self.__dict__[x]) for x in self.__dict__])


    def __add__(self,sconf):
        nstubs = {**self.nstubs, **sconf.nstubs}
        tags = {**self.tags, **sconf.tags} 
        return StubConfiguration(nstubs,
                                                         sconf.activate_stub_mechanism,
                                                         sconf.orig_filepath,
                                                         sconf.custom_stubs_file,
                                                         sconf.auto_null_stub,
                                                         tags)



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

    """
    
    def __init__(self,
                             path=None,
                             arch=None,
                             emulator=None,
                             p_size=None,
                             stk_ba=None,
                             stk_size=None,
                             autoMap=None,
                             showRegisters=None,
                             exec_saddr=None,
                             exec_eaddr=None,
                             mapping_saddr=None,
                             mapping_eaddr=None,
                             segms=None,
                             map_with_segs=None,
                             use_seg_perms=None,
                             useCapstone=None,
                             registers=None,
                             showMemAccess=None,
                             s_conf=None,
                             amap_conf=None,
                             memory_init=None,
                             color_graph=None,
                             breakpoints=None):

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

    def __str__(self):
        return '\n'.join(['{}: {}'.format(x,self.__dict__[x]) for x in self.__dict__])


    def show_user_mapping(self,displayContent=False):
        for k,v in self.amap_conf.mappings.items():
            logger.console(LogType.INFO,'[%x:%x]'%(k,k+len(v)))
            if displayContent:
                display_mem(v)


    def show_nullstubs(self):
        for k,v in self.s_conf.nstubs.items():
            logger.console(LogType.INFO,'%s at %x'%(v,k))


    def add_null_stub(self,ea):
        self.s_conf.nstubs[ea] = ida_funcs.get_func_name(ea)

    def remove_null_stub(self,ea):
        if ea in self.s_conf.nstubs.keys():
                del self.s_conf.nstubs[ea]
        else:
                logger.console(LogType.WARN,"Could not remove null-stub. No null-stub registred at this address (%x)"%ea)


    def add_tag(self,ea,stub_name):
        if ea in self.s_conf.tags.keys():
                logger.console(LogType.WARN,'Tag already registred at this ea (%x). Overwritting the value'%ea)
        self.s_conf.tags[ea] = stub_name

    def remove_tag(self,ea):
        if ea in self.s_conf.nstubs.keys():
                del self.s_conf.nstubs[ea]
        else:
                logger.console(LogType.WARN,"Could not remove tag. No tag registred at this address (%x)"%ea)

    def show_tags(self):
        for k,v in self.s_conf.tags.items():
            logger.console(LogType.INFO,'%x : %s'%(k,v))
    
    def save(self,path):
        saveconfig(self,path)

    def add_breakpoint(self,ea):
        self.breakpoints.append(ea)
        
    def remove_breakpoint(self,ea):
        self.breakpoints.remove(ea)

    def show_breakpoints(self):
        for k in self.breakpoints:
            logger.console(LogType.INFO,'%x'%k)



class ConfigSerializer(json.JSONEncoder):

    def default(self,conf):
        if isinstance(conf, Configuration):
            segs = [ seg.start_ea for seg in conf.segms ] 
#             funcs = [ conf.s_conf.nstubs[fname].start_ea for fname in conf.s_conf.nstubs.keys() ] 
            funcs = conf.s_conf.nstubs

            f_amap = dict()
            for k,v in conf.amap_conf.mappings.items():
                il = [ b for b in bytearray(v) ]    
                f_amap[k] = il 

            f_meminit = dict()
            for k,v in conf.memory_init.mappings.items():
                il = [ b for b in bytearray(v) ]    
                f_meminit[k] = il 

   
            
            
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
                                                 'activate_stub_mechanism': conf.s_conf.activate_stub_mechanism, 
                                                 'orig_filepath' : conf.s_conf.orig_filepath, 
                                                 'auto_null_stub': conf.s_conf.auto_null_stub,
                                                 'custom_stubs_file' : conf.s_conf.custom_stubs_file,
                                                 'tags':conf.s_conf.tags}, 
                         'amap_conf': f_amap, 'color_graph': conf.color_graph,
                         'memory_init': f_meminit,
                         'breakpoints':conf.breakpoints}


class ConfigDeserializer(json.JSONDecoder): #PASS ClassType for register parsing ? 
    
        def decode(self,json_txt):

         jdict = json.loads(json_txt)
         nstubs = dict()
         try : 
#             for fstart_ea in jdict['s_conf']['nstubs']: nstubs[ida_funcs.get_func_name(fstart_ea)] = ida_funcs.get_func(fstart_ea)
#             nstubs = jdict['s_conf']['nstubs'] 
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

        
            if jdict['arch'] == 'arm':
#                 regs=ArmRegisters( *[ jdict['registers'][rname] for rname in jdict['registers'].keys()    ])
                regs=ArmRegisters(**jdict['registers'])
            elif jdict['arch'] == 'mips':
                regs=MipslRegisters(**jdict['registers'])
#                 regs=MipslRegisters( *[ jdict['registers'][rname] for rname in jdict['registers'].keys()    ])
            elif jdict['arch'] == 'x86':
                regs=x86Registers(**jdict['registers']) 
            elif jdict['arch'] == 'x64':
                regs=x64Registers(**jdict['registers'])
            elif jdict['arch'] == 'aarch64':
                regs=Aarch64Registers(**jdict['registers'])
            else:
                raise Exception('NotImplemented')
                    
                
         
            return Configuration(path=jdict['path'],
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
                                 s_conf=StubConfiguration(nstubs,jdict['s_conf']['activate_stub_mechanism'],
                                                                     jdict['s_conf']['orig_filepath'],
                                                                     jdict['s_conf']['custom_stubs_file'],
                                                                     jdict['s_conf']['auto_null_stub'],
                                                                     tags_dict),
                                 amap_conf=AdditionnalMapping(amap_dict),
                                 memory_init=AdditionnalMapping(meminit_dict),
                                 color_graph=jdict['color_graph'],
                                 breakpoints=jdict['breakpoints'])
         except Exception as e: 
                print('[!] Error deserializing JSON object: %s'%e.__str__()) 
                return None
             
def saveconfig(conf,conf_apath=None): 
    if not conf_apath: 
        conf_apath=conf.path
    out=json.dumps(conf,cls=ConfigSerializer)
    with open(conf_apath,'w+') as fout: 
        fout.write(out)
    

def loadconfig(conf_apath): 

    with open(conf_apath, 'r') as fin:
        return json.loads(fin.read(),cls=ConfigDeserializer)



