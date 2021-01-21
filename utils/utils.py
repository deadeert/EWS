import ida_idaapi
import ida_funcs
import ida_segment
import ida_segregs
import ida_ida
import ida_idp
import ida_ua
import ida_loader
import idc 
import string
import os
import lief
import json
from enum import Enum



def get_seg_list():
  
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
    
  
def get_func_list():

  info = ida_idaapi.get_inf_structure()
  fun_l = [] 
  f = ida_funcs.get_next_func(info.min_ea)
  if f == None:
    print('[!] No function detected')
    exit(1)
  fun_l.append(f)
  while True:
    f = ida_funcs.get_next_func(f.start_ea)
    if f == None:
      break
    fun_l.append(f)
  return fun_l 
    
  

class Registers(object):

  def __init__(self):
    pass
  def __str__(self):
    return '\n'.join(['{}: {}'.format(x,self.__dict__[x]) for x in self.__dict__])



class ArmRegisters(Registers):
 
  def __init__(self,R0,R1,R2,R3,R4,R5,R6,R7,R8,R9,R10,R11,R12,R13,R14,R15):
    self.R0=R0
    self.R1=R1
    self.R2=R2
    self.R3=R3
    self.R4=R4
    self.R5=R5
    self.R6=R6
    self.R7=R7
    self.R8=R8
    self.R9=R9
    self.R10=R10
    self.R11=R11
    self.R12=R12
    self.R13=R13
    self.R14=R14
    self.R15=R15

class arm32CPSR(Registers):
  def __init__(self,N,Z,C,V,I,F):
    self.N = N 
    self.Z = Z
    self.C = C 
    self.V = V 
    self.I = I 
    self.F = F


  @classmethod 
  def create(cls,cpsr):
    return arm32CPSR(N=(cpsr&0x80000000)>>31,
                     Z=(cpsr&0x40000000)>>30,
                     C=(cpsr&0x20000000)>>29,
                     V=(cpsr&0x10000000)>>28,
                     I=(cpsr&0x8000000)>>27,
                     F=(cpsr&0x400000)>>26)

  def __str__(self):
    out = '[N=%d Z=%d C=%d V=%d I=%d F=%d] '%(self.N,self.Z,self.C,self.V,self.I,self.F)
    return out


class Aarch64Registers(Registers):
 
  def __init__(self,X0,X1,X2,X3,X4,X5,X6,X7,X8,X9,
                    X10,X11,X12,X13,X14,X15,X16,X17,X18,X19,
                    X20,X21,X22,X23,X24,X25,X26,X27,X28,FP,LR,SP,PC):
    self.X0=X0
    self.X1=X1
    self.X2=X2
    self.X3=X3
    self.X4=X4
    self.X5=X5
    self.X6=X6
    self.X7=X7
    self.X8=X8
    self.X9=X9
    self.X10=X10
    self.X11=X11
    self.X12=X12
    self.X13=X13
    self.X14=X14
    self.X15=X15
    self.X16=X16
    self.X17=X17
    self.X18=X18
    self.X19=X19
    self.X20=X20
    self.X21=X21
    self.X22=X22
    self.X23=X23
    self.X24=X24
    self.X25=X25
    self.X26=X26
    self.X27=X27
    self.X28=X28
    self.FP=FP
    self.LR=LR
    self.SP=SP
    self.PC=PC

class aarch64CPSR(Registers):
  def __init__(self,N,Z,C,V,I,F):
    self.N = N 
    self.Z = Z
    self.C = C 
    self.V = V 
    self.I = I 
    self.F = F


  @classmethod 
  def create(cls,cpsr):
    return aarch64CPSR(N=(cpsr&0x80000000)>>31,
                     Z=(cpsr&0x40000000)>>30,
                     C=(cpsr&0x20000000)>>29,
                     V=(cpsr&0x10000000)>>28,
                     I=(cpsr&0x8000000)>>27,
                     F=(cpsr&0x400000)>>26)

  def __str__(self):
    out = '[N=%d Z=%d C=%d V=%d I=%d F=%d] '%(self.N,self.Z,self.C,self.V,self.I,self.F)
    return out




class MipslRegisters(Registers): 
  """ Based on https://en.wikibooks.org/wiki/MIPS_Assembly/Register_File
  """
  def __init__(self,at,a0,a1,a2,a3,s0,s1,s2,s3,s4,s5,s6,s7,k0,k1,pc,
                   t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,v0,v1,hi,lo,sp,fp,gp,ra):
    self.at = at
    #arguments
    self.a0 = a0
    self.a1 = a1 
    self.a2 = a2
    self.a3 = a3
    # saved
    self.s0 = s0
    self.s1 = s1 
    self.s2 = s2 
    self.s3 = s3
    self.s4 = s4
    self.s5 = s5 
    self.s6 = s6
    self.s7 = s7
    # temporary
    self.t0 = t0
    self.t1 = t1 
    self.t2 = t2 
    self.t3 = t3
    self.t4 = t4
    self.t5 = t5 
    self.t6 = t6
    self.t7 = t7
    self.t8 = t8
    self.t9 = t9
    # division 
    self.hi = hi
    self.lo = lo 
    # return values
    self.v0 = v0
    self.v1 = v1
    # exec 
    self.gp = gp
    self.fp = fp
    self.sp = sp
    self.ra = ra
    self.pc = pc
    # misc (kernel)
    self.k0 = k0
    self.k1 = k1 
 

    
class x86Registers(Registers):

  def __init__(self,EAX,EBX,ECX,EDX,EDI,ESI,EBP,ESP,EIP):
    self.EAX = EAX
    self.EBX = EBX 
    self.ECX = ECX
    self.EDX = EDX
    self.EDI = EDI
    self.ESI = ESI 
    self.ESP = ESP
    self.EBP = EBP
    self.EIP = EIP


class x86EFLAGS(Registers):
  def __init__(self,CF,PF,AF,ZF,SF,TF,EIF,DF,OF):
    self.CF = CF
    self.PF = PF 
    self.AF = AF
    self.ZF = ZF
    self.SF = SF
    self.TF = TF
    self.EIF = EIF
    self.DF = DF 
    self.OF = OF 

  @classmethod 
  def create(cls,eflags):
    return x86EFLAGS(CF=(eflags)&0x1,
                     PF=(eflags&0x4)>>2,
                     AF=(eflags&0x10)>>4,
                     ZF=(eflags&0x40)>>6,
                     SF=(eflags&0x80)>>7,
                     TF=(eflags&0x100)>>8,
                     EIF=(eflags&0x200)>>9,
                     DF=(eflags&0x400)>>10,
                     OF=(eflags&0x800)>>11)

  def __str__(self):
    out = '[ZF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d EIF=%d DF=%d OF=%d]'%(self.CF,
                                                                      self.PF,
                                                                      self.AF,
                                                                      self.ZF,
                                                                      self.SF,
                                                                      self.TF,
                                                                      self.EIF,
                                                                      self.DF,
                                                                      self.OF)
    return out


class x64Registers(Registers):
  
  def __init__(self,RAX,RBX,RCX,RDX,RDI,RSI,R8,R9,R10,R11,R12,R13,R14,R15,RBP,RSP,RIP):
    self.RAX = RAX
    self.RBX = RBX
    self.RCX = RCX
    self.RDX = RDX
    self.RDI = RDI 
    self.RSI = RSI
    self.R8 = R8
    self.R9 = R9
    self.R10 = R10
    self.R11 = R11
    self.R12 = R12
    self.R13 = R13
    self.R14 = R14
    self.R15 = R15
    self.RBP = RBP 
    self.RSP = RSP 
    self.RIP = RIP 


class x64RFLAGS(Registers):
  def __init__(self,CF,PF,AF,ZF,SF,TF,EIF,DF,OF):
    self.CF = CF
    self.PF = PF 
    self.AF = AF
    self.ZF = ZF
    self.SF = SF
    self.TF = TF
    self.EIF = EIF
    self.DF = DF 
    self.OF = OF 

  @classmethod 
  def create(cls,eflags):
    return x64RFLAGS(CF=(eflags)&0x1,
                     PF=(eflags&0x4)>>2,
                     AF=(eflags&0x10)>>4,
                     ZF=(eflags&0x40)>>6,
                     SF=(eflags&0x80)>>7,
                     TF=(eflags&0x100)>>8,
                     EIF=(eflags&0x200)>>9,
                     DF=(eflags&0x400)>>10,
                     OF=(eflags&0x800)>>11)

  def __str__(self):
    out = '[ZF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d EIF=%d DF=%d OF=%d]'%(self.CF,
                                                                      self.PF,
                                                                      self.AF,
                                                                      self.ZF,
                                                                      self.SF,
                                                                      self.TF,
                                                                      self.EIF,
                                                                      self.DF,
                                                                      self.OF)
    return out


    

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

  @staticmethod
  def create():
    cls = StubConfiguration({},False,None,{})
    return cls 

  def __init__(self,nstubs,
               stub_dynamic_func_tab,
               orig_filepath,
               custom_stubs_file=None,
               auto_null_stub=False,
               tags=None):
    """ nstubs               : null stub dictionnary 
        stub_dynamic_func_tab: stub sections such as plt/iat ...  
        orig_filepath        : name of the original binary
        custom_stubs_file    : file that specify special behavior for certain function
        autonull stub        : null stubs symbols that are not currently supported
        tags : mapping ea:stub_name 
    """
    
    self.nstubs = nstubs 
    self.stub_dynamic_func_tab = stub_dynamic_func_tab
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
                             sconf.stub_dynamic_func_tab,
                             sconf.orig_filepath,
                             sconf.custom_stubs_file,
                             sconf.auto_null_stub,
                             tags)
  

class Configuration():
  """ Configuration as follow
      arch:           str       idp name 
      emulator        str       emulation solution name 
      stk_ba:         int       for stack base address 
      stk_size:       int       for stack size (curved with p_size)  
      autoMap:        boolean   if true when a insn hit unmapped page, the page will be mapped by the engine(if available)  
      showRegisters:  boolean   if true registers value will be displayed on the console and/or file 
      exec_saddr:     int       start address of the execution
      exec_eaddr:     int       stop address of the execution
      mapping_saddr   int       offset in binary where the mapping starts 
      mapping_eaddr   int       offset in binary where the mapping ends
      map_with_segs   boolean   allow selecting segm. to map among list (disable two previous options)
      use_seg_perms   boolean   use segment permission(s) of the file format (if available)
      useCapstone     boolean   use capstone to generate insn disassembly output
      registers:      [int]     init values of regsiters
      s_conf:
      showMemAccess   boolean   when activated display all memory accesses on logger
      amap_conf:      [mapping] allow addit. mappings (not belonging to the binary) 
                                usefull for arguments mapping etc... 
      filepath:       str       path of the origianl executable (for stubs)

  """
  
  def __init__(self,
               path,
               arch,
               emulator,
               p_size,
               stk_ba,
               stk_size,
               autoMap,
               showRegisters,
               exec_saddr,
               exec_eaddr,
               mapping_saddr,
               mapping_eaddr,
               segms,
               map_with_segs,
               use_seg_perms,
               useCapstone,
               registers,
               showMemAccess,
               s_conf,
               amap_conf,
               color_graph,
               breakpoints):
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
      segs = [ ida_segment.get_segm_name(seg) for seg in conf.segms ] 
#       funcs = [ conf.s_conf.nstubs[fname].start_ea for fname in conf.s_conf.nstubs.keys() ] 
      funcs = conf.s_conf.nstubs

      f_amap = dict()
      for k in conf.amap_conf.mappings.keys():
        il = [ b for b in bytearray(conf.amap_conf.mappings[k]) ]  
        f_amap[k] = il 

      
      
      
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
                         'stub_dynamic_func_tab': conf.s_conf.stub_dynamic_func_tab, 
                         'orig_filepath' : conf.s_conf.orig_filepath, 
                         'auto_null_stub': conf.s_conf.auto_null_stub,
                         'custom_stubs_file' : conf.s_conf.custom_stubs_file,
                         'tags':conf.s_conf.tags}, 
             'amap_conf': f_amap, 'color_graph': conf.color_graph,
             'breakpoints':conf.breakpoints}


class ConfigDeserializer(json.JSONDecoder): #PASS ClassType for register parsing ? 
  
    def decode(self,json_txt):

     jdict = json.loads(json_txt)
     nstubs = dict()
     try : 
#       for fstart_ea in jdict['s_conf']['nstubs']: nstubs[ida_funcs.get_func_name(fstart_ea)] = ida_funcs.get_func(fstart_ea)
#       nstubs = jdict['s_conf']['nstubs'] 
      for ea,fname in jdict['s_conf']['nstubs'].items(): nstubs[int(ea,10)] = fname
   
                          
      amap_dict = dict()
      for k in jdict['amap_conf'].keys(): 
        amap_dict[int(k,10)] = bytes(jdict['amap_conf'][k])
  
      tags_dict = dict()
      for k,v in jdict['s_conf']['tags'].items():
        tags_dict[int(k,10)] = v 

    
      if jdict['arch'] == 'arm':
#         regs=ArmRegisters( *[ jdict['registers'][rname] for rname in jdict['registers'].keys()  ])
        regs=ArmRegisters(**jdict['registers'])
      elif jdict['arch'] == 'mips':
        regs=MipslRegisters(**jdict['registers'])
#         regs=MipslRegisters( *[ jdict['registers'][rname] for rname in jdict['registers'].keys()  ])
      elif jdict['arch'] == 'pc':
        regs=x86Registers(**jdict['registers']) 
      elif jdict['arch'] == 'pc64':
        print('pc64')
        regs=x64Registers(**jdict['registers'])
      elif jdict['arch'] == 'aarch64':
        regs=Aarch64Registers(**jdict['registers'])
      else:
        raise NotImplemented
          
        
     
      return Configuration(jdict['path'],
                           jdict['arch'],
                           jdict['emulator'],
                           jdict['p_size'],
                           jdict['stk_ba'],
                           jdict['stk_size'],
                           jdict['autoMap'],
                           jdict['showRegisters'],
                           jdict['exec_saddr'],
                           jdict['exec_eaddr'],
                           jdict['mapping_saddr'],
                           jdict['mapping_eaddr'],
                           [ ida_segment.get_segm_by_name(segname) for segname in jdict['segms'] ],
                           jdict['map_with_segs'],
                           jdict['use_seg_perms'],
                           jdict['useCapstone'],
                           regs,
                           jdict['showMemAccess'],
                           StubConfiguration(nstubs,jdict['s_conf']['stub_dynamic_func_tab'],
                                             jdict['s_conf']['orig_filepath'],
                                             jdict['s_conf']['custom_stubs_file'],
                                             jdict['s_conf']['auto_null_stub'],
                                             tags_dict),
                           AdditionnalMapping(amap_dict),
                           jdict['color_graph'],
                           jdict['breakpoints'])
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
  
def proc_inf(arch,addr):
  
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
  UKN=-1
  READ=0
  WRITE=1 


class LogType(Enum):
  INFO = 0
  WARN = 1
  ERRR = 2

class LoaderType(Enum):
  ELF = 0 
  PE  = 1



class Logger():
  

  def __init__(self,VERBOSE,fpath=None):
    """ int value VERBOSE indicate the verbose of the plugin (0 : none to X: a lot)
    """
    self.VERBOSE = VERBOSE 
    if not fpath:
      from tempfile import NamedTemporaryFile
      fpath = NamedTemporaryFile(delete=False,mode='w+')
      self.console(LogType.WARN,'No log file provided, logs will be written to %s file.'%fpath.name)
    self.fpath = fpath
    
  def console(self,type,*msg):
    if type == LogType.INFO and self.VERBOSE > 1:
      print('[INFO] ',*msg)
    if type == LogType.WARN and self.VERBOSE > 0: 
      print('[WARN] ',*msg)
    if type == LogType.ERRR:  
      print('[ERRR] ',*msg)
  
  def logfile(type,*msg):
   msg = ' '.join(msg)
   if type == LogType.INFO :
      self.fpath.write('[INFO] %s\n'%msg)
   if type == LogType.WARN : 
      self.fpath.write('[WARN] %s\n'%msg)
   if type == LogType.ERRR:  
      self.fpath.write('[ERRR] %s\n'%msg)
  

    
logger = Logger(2)
    
    

class ConfigExcption(Exception):
  def __init__(self,str):
    super().__init__(str)


def get_insn_color(eaddr):
    return idc.get_color(eaddr,idc.CIC_ITEM)

def colorate_graph(color_map):

  for addr in color_map.keys():
    try:  
      idc.set_color(addr,idc.CIC_ITEM,0xAAAAAA)
    except:
      pass

def restore_graph_color(color_map,purge_db=False):
  for addr,color in color_map.items():
    try:
      if color != 0xFFFFFF and color != 0xAAAAAA:       idc.set_color(addr,idc.CIC_ITEM,color)
      else:                                             idc.set_color(addr,idc.CIC_ITEM,0x242424) # TODO: get default color from idc ? 
    except:
      pass

  if purge_db:
    color_map = dict()

      
def display_mem(mem,ba=None,direction=0):
  
  if len(mem) % 8 != 0:
    dist = 8 - (len(mem)%8)
    logger.console(LogType.INFO,'[!] content not aligned. Adding %d extra bytes to output'%(dist))
    fmem = bytes(mem)+b'\x00'*(dist)
  else: fmem = mem
    
  for l in range(0,len(fmem),8):
      out = ''
      if ba: out += '0x%x: '%ba
      out+=' '.join(['%2x'%fmem[l+i] for i in range(0,8)])
      rep=[]
      for i in range(0,8):
        if fmem[l+i] in [ord(x) for x in string.ascii_letters]:
          rep.append(int.to_bytes(fmem[l+i],1,'little').decode('utf-8'))
        else:
          rep.append('.')
      out+='\t\t'
      out+=' '.join(rep)
      if ba: ba += 8
      logger.console(LogType.INFO,out)

def is_thumb(addr):
  return True if ida_segregs.get_sreg(addr,ida_idp.str2reg('T')) == 1 else False


def get_insn_at(ea):
   insn = ida_ua.insn_t()
   ida_ua.decode_insn(insn,ea)
   return insn
    
def build_func_name(ea):
    fn = ida_funcs.get_func_name(ea)
    if fn == None: fn = 'func_%x'%ea
    return fn


def get_min_ea_idb():
    return ida_idaapi.get_inf_structure().min_ea
def get_max_ea_idb():
    return ida_idaapi.get_inf_structure().max_ea






def search_executable():
    """ try to locate binary corresponding to the IDB
        to parse dynamic information (PT_DYNAMIC segment) 
    """

    f_path_l=ida_loader.get_path(ida_loader.PATH_TYPE_CMD).split('.')[:-1]
    ntry=1
    f_path=""
    while ntry<=len(f_path_l):
        candidate='.'.join(f_path_l[0:ntry]) 
        if verify_valid_elf(candidate):
                f_path=candidate 
                break
        else:
            ntry+=1


    if f_path == "":
        logger.console(LogType.WARN,"cannot find suitable executable, please enter manually")


    return f_path


def verify_valid_elf(candidate):
    if os.path.exists(candidate):
            if str(lief.ELF.parse(candidate)) != None:
                    return True
    return False
        

