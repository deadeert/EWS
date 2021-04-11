# from stubs import stubs_conf
# from stubs.stubs_helper import *  
from utils.utils import *
import codecs
import re
from enum import Enum
import os
from os import path 
import tempfile
import struct




byte_l = lambda x: x & 0xFF
byte_2l = lambda x: x & 0xFFFF
byte_h = lambda x: (x >> 16) & 0xFF
byte_2h = lambda x: (x >> 16) & 0xFFFF




# -----------------------------------------------------------------------------
"""                 """
"     STUB OBJECTS    "
"""                 """
# -----------------------------------------------------------------------------
class Stub(object):
  def __init__(self,itnum,arch,helper=None):
    self.idx_it = itnum
    self.helper = helper
    self.arch = arch
  def set_helper(self,helper):
    self.helper = helper
  
winx86_stubs = {} 
winx64_stubs = {} 


class StubsX86():
    itnum_arm = 1
    arch = 'x86'
    def __init__(self,name):
        assert name not in winx86_stubs
        self.itnum = StubsX86.itnum_arm
        StubsX86.itnum_arm+=1
        self.name = name

    def __call__(self,cls):
        obj = cls(self.itnum,StubsX86.arch)
        winx86_stubs[self.name] = obj
        winx86_stubs[self.itnum] = obj
        return cls

class StubsX64(): 
    itnum_arm = 1
    arch = 'x64'
    def __init__(self,name):
        assert name not in winx64_stubs
        self.itnum = StubsX64.itnum_arm
        StubsX64.itnum_arm+=1
        self.name = name

    def __call__(self,cls):
        obj = cls(self.itnum,StubsX64.arch)
        winx64_stubs[self.name] = obj
        winx64_stubs[self.itnum] = obj
        return cls
  


class NullStub(Stub):
    def __init__(self,arch):
        super().__init__(0,arch)
      
    def do_it(self,*args):
        logger.console(LogType.INFO,'[stubs] null stub is called')
        self.helper.set_return(0)
        return True


# -----------------------------------------------------------------------------
"""                   """
"   STUBBED FUNCTIONS   "
"""                   """
# -----------------------------------------------------------------------------

@StubsX86('RegEnumKeyExW')
class RegEnumKeyExW(Stub):
   def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
      
   def do_it(self,*args):
        logger.console(LogType.INFO,'[stubs] RegEnumKeyExW')
        hkey = self.helper.get_arg(0)
        dwIndex = self.helper.get_arg(1)
        lpName = self.helper.get_arg(2)
        lpcchName = self.helper.get_arg(3)
        lpReserved = self.helper.get_arg(4)
        lpClass = self.helper.get_arg(5)
        lpcchClass = self.helper.get_arg(6)
        lpftLastWriteTime = self.helper.get_arg(7) 

        logger.console(LogType.INFO,'args :',hkey,dwIndex,lpName,lpcchName)


        return True

# 
# @StubsX86('printf')
# @StubsX86('_printf')
# @StubsX86('__imp__printf')
# class printf(Stub):
#    def __init__(self,itnum,arch):
#         super().__init__(itnum,arch)
#       
#    def do_it(self,*args):
#         logger.console(LogType.INFO,'[stubs] printf')
#         frmt_addr = self.helper.get_arg(0)
#         frmt = deref_until(self.helper,frmt_addr,b'\0').decode('utf-8')
#         
#         p  = re.compile('%+[l]{0,1}[dpsx]+')
#         reformat = [i for i in p.findall(frmt.strip()) if i != '']
#         if len(reformat) == 0: 
#           logger.console(LogType.INFO,'printf outputs : %s'%frmt)
#           return True
#         frmt_num = 1 
#         out_map = [] 
#         for x in reformat: 
#           if x.strip() == '%s':
#             out_map.append(deref_until(self.helper,self.helper.get_arg(frmt_num),b'\0'))
#           elif x.strip() in [ '%d', '%p', '%x' ]:
#             out_map.append(self.helper.get_arg(frmt_addr))
#           frmt_num+=1   
#         out_map.reverse()
#         out=b''
#         for x in reformat: 
#             if   x == '%s' : out+=out_map.pop()
#             elif x == '%d' : out+=bytes('%d'%out_map.pop(),'utf-8')
#             elif x == '%ld': out+=bytes('%ld'%out_map.pop(),'utf-8')
#             elif x == '%x' : out+=bytes('%x'%out_map.pop(),'utf-8')
#             elif x == '%p' : out+=bytes('%x'%out_map.pop(),'utf-8')
#             elif x != ''   : out+=bytes(x,'utf-8')
#         
# 
#         logger.console(LogType.INFO,'[printf] outputs:',out)
#         return True
# 
# @StubsX86('scanf')
# @StubsX86('_scanf')
# @StubsX86('__imp__scanf')
# class scanf(Stub):
#    def __init__(self,itnum,arch):
#         super().__init__(itnum,arch)
#       
#    def do_it(self,*args):
#         logger.console(LogType.INFO,'[stubs] scanf')
#         frmt_addr = self.helper.get_arg(0)
#         frmt = deref_until(self.helper,frmt_addr,b'\0').decode('utf-8')
#         dst_addr = self.helper.get_arg(1)
#         if frmt == '%s':
#           #TODO pop a windows to get the entry 
# #           self.helper.mem_write(dst_addr,stubs_conf.scanf_string.encode('utf-8'))
#           self.helper.mem_write(dst_addr,'test string'.encode('utf-8'))
#         else:
#           logger.console(LogType.WARN,'format %s not handled'%frmt)
# 
# 
# @StubsX86('strncmp')
# @StubsX86('_strncmp')
# @StubsX86('__imp__strncmp')
# class strncmp(Stub):
# 
#     def __init__(self,itnum,arch):
#         super().__init__(itnum,arch)
#         
# 
#     def do_it(self,*args):
#         """
#         LIBC implementation breaks when first mismatch is found and returns distance between the two current chars.
#         """
#         logger.console(LogType.INFO,'[strncmp] called at 0x%.8X'%(self.helper.get_pc()))
#         s1_addr = self.helper.get_arg(0)
#         s2_addr = self.helper.get_arg(1)
#         cmp_len = self.helper.get_arg(2)
# 
#         s1=deref_size(self.helper,s1_addr,cmp_len,delem=b'\x00')
#         s2=deref_size(self.helper,s2_addr,cmp_len,delem=b'\x00')
#         logger.console(LogType.INFO,'[strncmp] comparing strings\n %s\n vs\n %s\nfor len:%d'%(s1,s2,cmp_len))
#         ret=0
#         mlen = min(len(s1),len(s2))
#         if mlen < cmp_len:
#             cmp_len = mlen
#         if mlen == 0 and len(s1)==0:
#             for e in s2: ret+=e
#         elif mlen == 0 and len(s2)==0:
#             for e in s1: ret+=e
#         else:
#             for x in range(0,cmp_len):
#                 if s1[x] != s2[x]:
#                     ret= s1[x] - s2[x]
#                     break
#         logger.console(LogType.INFO,'[strncmp] returns %d'%ret)
#         self.helper.set_return(ret)
#         return True       
#         
#         
#           

  
