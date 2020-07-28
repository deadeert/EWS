###
#
# TODO 
# - XprintY(): use SAE push/pop functions 
#              to handle more args
#
###

from consts_arm import SVC_INSN_ARM 
from consts_mips import BREAK_INSN_MIPS  
from stubs import stubs_conf
from stubs.stubs_helper import *  
from utils import *
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


def SVC(it):
  return int.to_bytes(SVC_INSN_ARM|it,4,'little')

def BREAK(it,mode):
  return int.to_bytes(it<<6|BREAK_INSN_MIPS,4,mode)

def TRAMPOLINE(it,mode):
  """ bal 0x1008 ; it = 1 """
  return int.to_bytes(0x0C0004<<8|it*3,4,mode) # 3 <=> TRAMPOLINE_SIZE // 4 



# -----------------------------------------------------------------------------
"""                 """
"     STUB OBJECTS    "
"""                 """
# -----------------------------------------------------------------------------
class Stub(object):
  def __init__(self,itnum,arch,helper=None):
    self.idx_it = itnum
    self.helper = helper
    if arch == 'arm':
      self.insn_it = SVC(itnum)
    elif arch == 'mipsl':
#       self.insn_it = BREAK(itnum,'little')
      self.insn_it = TRAMPOLINE(itnum,'little')
    elif arch == 'mipsb':
      self.insn_it = TRAMPOLINE(itnum,'big')
#       self.insn_it = BREAK(itnum,'big')

  def set_helper(self,helper):
    self.helper = helper
  


libc_stubs_arm = dict()
libc_stubs_mipsl = dict()
libc_stubs_mipsb = dict()


class StubsARM():
    itnum_arm = 1
    arch = 'arm'
    def __init__(self,name):
        assert name not in libc_stubs_arm
        self.itnum = StubsARM.itnum_arm
        StubsARM.itnum_arm+=1
        self.name = name

    def __call__(self,cls):
        obj = cls(self.itnum,StubsARM.arch)
        libc_stubs_arm[self.name] = obj
        libc_stubs_arm[self.itnum] = obj
        return cls

class StubsMIPSL():
    itnum_arm = 1
    arch = 'mipsl'
    def __init__(self,name):
        assert name not in libc_stubs_mipsl
        self.itnum = StubsMIPSL.itnum_arm
        StubsMIPSL.itnum_arm+=1
        self.name = name

    def __call__(self,cls):
        obj = cls(self.itnum,StubsMIPSL.arch)
        libc_stubs_mipsl[self.name] = obj
        libc_stubs_mipsl[self.itnum] = obj
        return cls

class StubsMIPSB():
    itnum_arm = 1
    arch = 'mipsb'
    def __init__(self,name):
        assert name not in libc_stubs_mipsb
        self.itnum = StubsMIPSB.itnum_arm
        StubsMIPSB.itnum_arm+=1
        self.name = name

    def __call__(self,cls):
        obj = cls(self.itnum,StubsMIPSB.arch)
        libc_stubs_mipsb[self.name] = obj
        libc_stubs_mipsb[self.itnum] = obj
        return cls



class NullStub(Stub):
    """
    SVC 0 is triggering this code which returns 0
    Inherit from this class to avoid reimplementing this behavior
    """

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
@StubsARM('memset')
@StubsMIPSB('memset')
class memset(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        
    def do_it(self,*args):
        dst = self.helper.get_arg(0)
        data = byte_l (self.helper.get_arg(1)) 
        ln = self.helper.get_arg(2)
        logger.console(LogType.INFO,' memset(%8X, %2X, %X)'%(dst,data,ln))
        self.helper.mem_write(dst,bytes(data*ln))
        return True


# -----------------------------------------------------------------------------
@StubsARM('malloc')
class malloc(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
#         if not fromStub:
          req_size = self.helper.get_arg(0)
          addr = self.helper.malloc(req_size)
          self.helper.set_return(addr)
          logger.console(LogType.INFO,' malloc(%X) = %8X'%(req_size,addr))
          return True
#         else:
#           addr = self.helper.allocator.malloc(size)
#           logger.console(LogType.INFO,' malloc(%X) = %8X (from stub)'%(size,addr))
#           return addr 
# 

# -----------------------------------------------------------------------------
@StubsARM('free')
class free(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        addr = self.helper.get_arg(0)
        self.helper.free(addr)
        logger.console(LogType.INFO,' free(%8X)'%addr)
        return True

# -----------------------------------------------------------------------------
@StubsARM('calloc')
class calloc(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        req_size = self.helper.get_arg(0)
        addr = self.helper.malloc(req_size)
        self.helper.mem_write(addr,b'\x00'*req_size)
        self.helper.set_return(addr)
        logger.console(LogType.INFO,' malloc(%X) = %8X'%(req_size,addr))
        return True

# -----------------------------------------------------------------------------
@StubsARM('__libc_start_main')
class libc_start_main(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        logger.console(LogType.INFO,'[__libc_start_main] called at %.8X'%self.helper.get_pc())
        arg0 = self.helper.get_arg(0)
        logger.console(LogType.INFO,'[__libc_start_main] main => %.8X'%(arg0))
        self.helper.reg_write(14, arg0)
        return True


# -----------------------------------------------------------------------------
@StubsARM('puts')
class puts(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        logger.console(LogType.INFO,'[puts] called at 0x%.8X'%self.helper.get_pc())
        arg0 = self.helper.get_arg(0)
        s = deref_until(self.helper,arg0,b'\0').decode('utf-8')
        self.helper.set_return( 0)
        return True
# -----------------------------------------------------------------------------
@StubsARM('strncpy')
class strncpy(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        logger.console(LogType.INFO,'[strncpy] called at 0x%.8X'%self.helper.get_pc())
        dst=self.helper.get_arg(0)
        src=self.helper.get_arg(1)
        ln=self.helper.get_arg(2)
        data=self.helper.mem_read(src,ln)
        nc = data.find(b'\x00')
        if nc != -1:
            data=data[0:nc]
        self.helper.mem_write(dst,bytes(data))
        logger.console(LogType.INFO,'[strncpy] dst = %.8X src = %.8X ln = %d'%(dst,src,ln),
                  '\n\tCopying string : ',data)
        return True

# -----------------------------------------------------------------------------
@StubsARM('strcpy')
class strcpy(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)

    def do_it(self,*args):
        logger.console(LogType.INFO,'[strcpy] called at 0x%.8X'%self.helper.get_pc())
        dst_addr=self.helper.get_arg(0)
        src_addr=self.helper.get_arg(1)
        src = deref_string(self.helper,src_addr)
        self.helper.mem_write(dst_addr,src)
        return True

# -----------------------------------------------------------------------------
@StubsARM('printf')
@StubsMIPSL('.printf')
class printf(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        format_addr = self.helper.get_arg(0)
        try:
            fmt = deref_until(self.helper,format_addr,b'\0')
        except UnicodeDecodeError as e:
            logger.console(LogType.INFO,'[printf] Cannot decode format :',fmt)
            raise StubExcept('[printf] error decoding format')
        fmt,l = codecs.escape_encode(fmt)
        pc = self.helper.get_pc()
        logger.console(LogType.INFO,'[printf] Call at 0x%.8X with format %s'%(pc,fmt))
        p  = re.compile('%+[l]{0,1}[dpsx]')
        p2  = re.compile('(%+[dpsx])')
        chain_addr = self.helper.get_arg(0)
        chain = deref_string(self.helper,chain_addr)
        reformat = [i for i in p.findall(chain.strip().decode('utf-8')) if i != '']
        deref_list = f(self.helper,reformat)
        deref_list.reverse()
        out=b''
        for x in p2.split(chain.strip().decode('utf-8')):
            if   x == '%s' : out+=deref_list.pop()
            elif x == '%d' : out+=bytes('%d'%deref_list.pop(),'utf-8')
            elif x == '%ld': out+=bytes('%ld'%deref_list.pop(),'utf-8')
            elif x == '%x' : out+=bytes('%x'%deref_list.pop(),'utf-8')
            elif x == '%p' : out+=bytes('%x'%deref_list.pop(),'utf-8')
            elif x != ''   : out+=bytes(x,'utf-8')
        logger.console(LogType.INFO,'[printf] outputs:',out)
        return True

# -----------------------------------------------------------------------------
@StubsMIPSB('memcpy')
@StubsARM('memcpy')
class memcpy(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        logger.console(LogType.INFO,'[memcpy] called at 0x%.8X'%self.helper.get_pc())
        dst=self.helper.get_arg(0)
        src=self.helper.get_arg(1)
        ln=self.helper.get_arg(2)
        data=self.helper.mem_read(src,ln)
        self.helper.mem_write(dst,bytes(data))
        self.helper.set_return(ln)
        return True

# -----------------------------------------------------------------------------
@StubsARM('strlen')
@StubsMIPSL('.strlen')
@StubsMIPSL('strlen')
class strlen(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        str_addr = self.helper.get_arg(0)
        logger.console(LogType.INFO,'[strlen] str_addr: 0x%.8X'%str_addr)
        size=len(deref_until(self.helper,str_addr,b'\0'))
        logger.console(LogType.INFO,'[strlen] returns %d'%size)
        self.helper.set_return(size)
        return True

# -----------------------------------------------------------------------------
@StubsARM('fopen')
class fopen(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        fname_addr = self.helper.get_arg(0)
        mode_addr = self.helper.get_arg(1)
        try:
            #Python does not support file opening with non utf-8 / unicode string.
            filename = deref_until(self.helper,fname_addr,b'\0')
        except SyntaxError:
            raise StubPythonException('[fopen] non utf-8 filename')
        mode = deref_string(self.helper,mode_addr).decode('utf-8')
        logger.console(LogType.INFO,'[fopen] filename: ',filename,' mode:%s'%mode)
        if '+' in mode: mode=mode.split('+')[0]+'b'+mode.split('+')[1]
        else: mode +='b'
        fd = open(filename,mode)
        fd_list[fd.fileno()] = FILE(fd,mode)
        logger.console(LogType.INFO,'[fopen] returning fd %d'%fd.fileno())
        self.helper.set_return(fd.fileno())
        return True
# -----------------------------------------------------------------------------
@StubsARM('fwrite')
class fwrite(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        logger.console(LogType.INFO,'[fwrite] called at 0x%.8X, fd : %d'%(self.helper.get_pc(),
                                                self.helper.get_arg(3)))
        fd = self.helper.get_arg(3)
        buf_addr = self.helper.get_arg(0)
        size = self.helper.get_arg(1)
        nmenb = self.helper.get_arg(2)
        if fd not in fd_list:
            raise StubExcept('[fwrite] file descriptor not in the list')
        data=deref_size(self.helper,buf_addr,nmenb*size)
        try:
            fd_list[fd].write(data)
        except Exception as e:
            raise StubExcept('[fwrite] error writing file: %s'%e.__str__())
        self.helper.set_return(nmemb*size)
        return True

# -----------------------------------------------------------------------------
@StubsARM('fclose')
class fclose(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        logger.console(LogType.INFO,'[fclose] called at 0x%.8X, fd : %d'%(self.helper.get_pc(),
                                                self.helper.get_arg(0)))
        fd = self.helper.get_arg(0)
        if fd not in fd_list:
            raise StubExcept('[fclose] file descriptor not in the list')
        try:
            fd_list[fd].close()
            return True
        except:
            raise StubExcept('[fclose] error closing file with fd %d'%fd)

# -----------------------------------------------------------------------------
@StubsARM('fread')
class fread(Stub):
    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        logger.console(LogType.INFO,'[fread] called at 0x%.8X, fd : %d'%(self.helper.get_pc(),
                                               self.helper.get_arg(3)))
        fd = self.helper.get_arg(3)
        buf_addr = self.helper.get_arg(0)
        size = self.helper.get_arg(1)
        nmenb = self.helper.get_arg(2)
        if fd not in fd_list:
            raise StubExcept('[fread] file descriptor not in the list')
        i = 0
        while(i < (nmenb*size)):
            try:
                self.helper.mem_write(buf_addr+i,fd_list[fd].read(nmenb))
            except Exception as e:
                raise StubExcept('[fread] error reading file: %s'%e.__str__())
            i+=nmenb
        self.helper.set_return(nmenb*size)
        return True

# -----------------------------------------------------------------------------
@StubsARM('fflush')
class fflush(Stub):
    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        logger.console(LogType.INFO,'[fflush] called at 0x%.8X, fd : %d'%(self.helper.get_pc(),
                                                self.helper.get_arg(0)))
        fd = self.helper.get_arg(0)
        if not fd in fd_list:
            raise(Exception('[fflush] file descriptor not in the list'))
        fd_list[fd].fflush()
        self.helper.set_return(0)
        return True

# -----------------------------------------------------------------------------
@StubsARM('fseek')
class fseek(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        logger.console(LogType.INFO,'[fseek] called at 0x%.8X, fd : %d'%(self.helper.get_pc(),
                                               self.helper.get_arg(0)))
        fd = self.helper.get_arg(0)
        offset = self.helper.get_arg(1)
        whence = self.helper.get_arg(2)
        if not fd in fd_list:
            raise(Exception('[fseek] file descriptor not in the list'))
        try:
            fd_list[fd].fseek(offset,whence)
        except Exception as e :
            raise(Exception('[fseek] error fseek'))
        self.helper.set_return(0)
        return True

# -----------------------------------------------------------------------------
@StubsARM('fgetc')
class fgetc(Stub):
    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        logger.console(LogType.INFO,'[fgetc] called at 0x%.8X, fd : %d'%(self.helper.get_pc(),
                                               self.helper.get_arg(0)))
        fd = self.helper.get_arg(0)
        if fd == STDIN:
          self.helper.set_return(stubs_conf.default_stdin[:1].encode('utf-8'))
          return    
        if not fd in fd_list:
            raise(Exception('[fgetc] file descriptor not in the list'))
        self.helper.set_return(fd_list[fd].read(1))
        return True

# -----------------------------------------------------------------------------
@StubsARM('fgets')
@StubsMIPSL('.fgets')
class fgets(Stub):
    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        fd = self.helper.get_arg(2)
        size = self.helper.get_arg(1)
        addr = self.helper.get_arg(0)
        logger.console(LogType.INFO,'[fgets] called at 0x%.8X, fd : %d,dst=0x%.8X,size=%d'%(self.helper.get_pc(),
                                                                      fd,
                                                                      addr,
                                                                      size))
        if not fd in fd_list and not fd == STDIN:
            raise(Exception('[fgets] file descriptor not in the list'))
        # according to man, read size-1 chars maximum to let room for '\0' terminating char
        if fd == STDIN: line = stubs_conf.default_stdin.encode('utf-8')
        else:           line= fd_list[fd].readline()
        if len(line)>size:
            logger.console(LogType.INFO,'[fgets] warning line is longer than the limit size. Rewinding is not implemented, unpredictable behiavor may occur')
            line=line[:size]
        # Can trigger OOB Read
        if line != b'' and line != b'\x0A' and line != b'\x0a\x0d' and line !=b'\x0d\x0a':
            if b'\x0A' in line:
                line=line.split(b'\x0A')[0]
            elif b'\x0D\x0A' in line:
                line=line.split(b'\x0D')[0]
            elif b'\x0A\x0D' in line:
                line=line.split(b'\x0A')[0]
            logger.console(LogType.INFO,'[fgets] returns %s'%line)
            self.helper.mem_write(addr,line)
            self.helper.mem_write(addr+len(line),b'\x00')
        else:
            logger.console(LogType.INFO,'[fgets] returns NULL (no more line)')
            self.helper.set_return(0)    #fgets returns the addr of the buffer (R0 not modified)
        return True

# -----------------------------------------------------------------------------
#CAUTION : Does not handle space between format
@StubsARM('fprintf')
class fprintf(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        logger.console(LogType.INFO,'[fprintf] called at 0x%.8X, fd : %d'%(self.helper.get_pc(),
                                                 self.helper.get_arg(0)))
        fd = self.helper.get_arg(0)
        if not fd in fd_list:
            raise Exception('[fprintf] file descriptor not found')
        chain_addr = self.helper.get_arg(1)
        chain = deref_string(self.helper,chain_addr)
        p  = re.compile('%+[l]{0,1}[dpsx]')
        p2  = re.compile('(%+[l]{0,1}[dpsx])')
        reformat = [i for i in p.findall(chain.strip().decode('utf-8')) if i != '']
        deref_list = g(self.helper,reformat)
        deref_list.reverse()
        out=b''
        for x in p2.split(chain.strip().decode('utf-8')):
            if   x == '%s' : out+=deref_list.pop()
            elif x == '%d' : out+=bytes('%d'%deref_list.pop(),'utf-8')
            elif x == '%ld': out+=bytes('%ld'%deref_list.pop(),'utf-8')
            elif x == '%x' : out+=bytes('%x'%deref_list.pop(),'utf-8')
            elif x == '%p' : out+=bytes('%x'%deref_list.pop(),'utf-8')
            elif x != ''   : out+=bytes(x,'utf-8')
        logger.console(LogType.INFO,'[fprintf] outputs: ',out)
        fd_list[fd].write(bytes(out))
        self.helper.set_return(len(out))
        return True

# -----------------------------------------------------------------------------
@StubsARM('snprintf')
class snprintf(Stub):
    """
    To reflect as maximum as possible C implmentation, we use byte representation of string.
    Hence it is not possible to use Python' string functions self.helper
    """
    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        logger.console(LogType.INFO,'[snprintf]')
        buf_addr = self.helper.get_arg(0)
        size = self.helper.get_arg(1)
        format_addr = self.helper.get_arg(2)
        chain = deref_string(self.helper,format_addr)
        logger.console(LogType.INFO,'[snprintf] dst: 0x%.8X size : %d format : %s'%(buf_addr,size,chain))
        p  = re.compile('%+[l]{0,1}[dpsx]')
        p2  = re.compile('(%+[l]{0,1}[dpsx])')
        reformat = [i for i in p.findall(chain.strip().decode('utf-8')) if i != '']
        deref_list = h(self.helper,reformat)
        deref_list.reverse()
        out=b''
        for x in p2.split(chain.strip().decode('utf-8')):
            if   x == '%s' : out+=deref_list.pop()
            elif x == '%d' : out+=bytes('%d'%deref_list.pop(),'utf-8')
            elif x == '%ld': out+=bytes('%ld'%deref_list.pop(),'utf-8')
            elif x == '%x' : out+=bytes('%x'%deref_list.pop(),'utf-8')
            elif x == '%p' : out+=bytes('%x'%deref_list.pop(),'utf-8')
            elif x != ''   : out+=bytes(x,'utf-8')
        if len(out) > size:
            logger.console(LogType.INFO,'[snprintf] truncating output')
            self.helper.mem_write(buf_addr,bytes(out)[0:size])
            self.helper.mem_write(buf_addr+len(bytes(out)[0:size])-1,b'\x00')
            self.helper.set_return(size)
            logger.console(LogType.INFO,'[snprintf] outputs :',out[0:size])
        else:
            self.helper.mem_write(buf_addr,bytes(out)[0:len(out)])
            self.helper.mem_write(buf_addr+len(bytes(out)[0:len(out)]),b'\x00')
            self.helper.set_return(len(out))
            logger.console(LogType.INFO,'[snprintf] outputs :',out)

        return True

# -----------------------------------------------------------------------------
@StubsARM('strcmp')
class strcmp(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        logger.console(LogType.INFO,'[strcmp] called at 0x%.8X'%(self.helper.get_pc()))
        s1_addr = self.helper.get_arg(0)
        s2_addr = self.helper.get_arg(1)
        ret=0
        s1=deref_until(self.helper,s1_addr,b'\0')
        s2=deref_until(self.helper,s2_addr,b'\0')
        mlen = min(len(s1),len(s2))
        if mlen == 0 and len(s1)==0:
            for e in s2: ret+=e
        elif mlen == 0 and len(s2)==0:
            for e in s1: ret+=e
        else:
            for x in range(0,mlen):
                if s1[x] != s2[x]:
                    ret= s1[x] - s2[x]
                    break
        logger.console(LogType.INFO,'[strcmp] returns %d'%ret)
        self.helper.set_return(ret)
        return True

# -----------------------------------------------------------------------------
@StubsARM('strncmp')
class strncmp(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        """
        LIBC implementation breaks when first mismatch is found and returns distance between the two current chars.
        """
        logger.console(LogType.INFO,'[strncmp] called at 0x%.8X'%(self.helper.get_pc()))
        s1_addr = self.helper.get_arg(0)
        s2_addr = self.helper.get_arg(1)
        cmp_len = self.helper.get_arg(2)

        s1=deref_size(self.helper,s1_addr,cmp_len,delem=b'\x00')
        s2=deref_size(self.helper,s2_addr,cmp_len,delem=b'\x00')
        logger.console(LogType.INFO,'[strncmp] comparing strings\n %s\n vs\n %s\nfor len:%d'%(s1,s2,cmp_len))
        ret=0
        mlen = min(len(s1),len(s2))
        if mlen < cmp_len:
            cmp_len = mlen
        if mlen == 0 and len(s1)==0:
            for e in s2: ret+=e
        elif mlen == 0 and len(s2)==0:
            for e in s1: ret+=e
        else:
            for x in range(0,cmp_len):
                if s1[x] != s2[x]:
                    ret= s1[x] - s2[x]
                    break
        logger.console(LogType.INFO,'[strncmp] returns %d'%ret)
        self.helper.set_return(ret)
        return True

# -----------------------------------------------------------------------------
@StubsARM('strcat')
class strncat(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        dst_addr = self.helper.get_arg(0)
        src_addr = self.helper.get_arg(1)
        beg = deref_until(self.helper,dst_addr,delem=b'\0')
        end = deref_until(self.helper,src_addr,delem=b'\0')
        logger.console(LogType.INFO,'[strcat] happening: ',end,'(0x%.8X) to: '%src_addr,beg,'(0x%.8X) '%dst_addr)
        self.helper.mem_write(dst_addr+len(beg),end)
        self.helper.mem_write(dst_addr+len(beg)+len(end),b'\0')
        self.helper.set_return(dst_addr)
        return True

# -----------------------------------------------------------------------------

@StubsARM('strncat')
class strncat(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        dst_addr = self.helper.get_arg(0)
        src_addr = self.helper.get_arg(1)
        size = self.helper.get_arg(2)
        beg = deref_until(self.helper,dst_addr,delem=b'\0')
        end = deref_size(self.helper,src_addr,size,delem=b'\0')
        logger.console(LogType.INFO,'[strncat] happening: ',end,'(0x%.8X) to: '%src_addr,beg,'(0x%.8X) for size %d.'%(dst_addr,size))
        self.helper.mem_write(dst_addr+len(beg),end)
        self.helper.mem_write(dst_addr+len(beg)+len(end),b'\0')
        logger.console(LogType.INFO,'[strncat] out:',self.helper.mem_read(dst_addr,len(beg)+len(end)+1))
        self.helper.set_return(dst_addr)
        return True

# -----------------------------------------------------------------------------
@StubsARM('scandir')
class scandir(Stub):
    
    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        path_addr = self.helper.get_arg(0)
        dirent_addr = self.helper.get_arg(1)
        search_func_addr = self.helper.get_arg(2) # TODO launch into other exec thread
        search_filter_addr = self.helper.get_arg(3) #TODO launch into other exec thread  
  
#         logger.console(LogType.INFO,'R0 = %x R1 = %x R2 = %x R3 = %x'%(path_addr,dirent_addr,search_func_addr,search_filter_addr))
        path=deref_until(self.helper,path_addr,b'\0')
        logger.console(LogType.INFO,'[scandir] path: ',path)
        entries = [e.name for e in os.path.os.scandir(path.decode('utf-8'))] #Python does not handle non utf-8 dir name
#         dirent_ret = libc_stubs['malloc'].do_it(self.helper,fromStub=True,size=len(entries)*4)
        dirent_ret = self.helper.malloc(len(entries)*4)
        nb_entry = 0
        dirent_struct_len = stubs_conf.dirent_struct_len
        for entry in entries:
            #TODO launch search & filter functions 
#             e_addr = libc_stubs['malloc'].do_it(self.helper,fromStub=True,size=(dirent_struct_len+len(entry)+1))
            e_addr = self.helper.malloc(dirent_struct_len+len(entry)+1)
            self.helper.mem_write(dirent_ret+nb_entry*4,int.to_bytes(e_addr,4,'little',signed=False))
            self.helper.mem_write(e_addr+dirent_struct_len,bytes(entry,'utf-8'))
            self.helper.mem_write(e_addr+dirent_struct_len+len(bytes(entry,'utf-8')),b'\x00')
            nb_entry+=1
        self.helper.mem_write(dirent_addr,int.to_bytes(dirent_ret,4,'little',signed=False))
        logger.console(LogType.INFO,'[scandir] returning %d'%nb_entry)
        self.helper.set_return(nb_entry)
        return True
        


# -----------------------------------------------------------------------------
@StubsARM('getpid')
class getpid(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        logger.console(LogType.INFO,'[getpid]    returning %X'%stubs_conf.pid)
        self.helper.set_return(stubs_conf.pid) #
        return True

# -----------------------------------------------------------------------------
@StubsARM('__errno_location')
class __errno_location(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)
        

    def do_it(self,*args):
        logger.console(LogType.INFO,'[__errno_location] returning : %x'%stubs_conf.errno_location)
        self.helper.set_return(stubs_confs.errno_location)
        return True

# -----------------------------------------------------------------------------
strtok_tokens = []
strtok_acu = 0
@StubsARM('strtok')
class strtok(Stub):
    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)

    def do_it(self,*args):
        """
        strtok uses the string allocation and replaces the delimiter with null char.
        it returns at each call the next location (between two '\0')
        """
        global strtok_tokens
        global strtok_acu
        logger.console(LogType.INFO,'[stubs] strtok called')
        str_addr=self.helper.get_arg(0)
        delem_addr=self.helper.get_arg(1)
        if delem_addr == 0:
            logger.console(LogType.INFO,'[strtok] : null delimiter')
            # useless, just for reader comprehension, if token is not find, str ptr is returned.
            self.helper.set_return(str_addr)
            return
        else:
            delem=deref_size(self.helper,delem_addr,1)
        if str_addr != 0:
            logger.console(LogType.INFO,'[strtok] first call, deleminator is : %s'%delem)
            strtok_acu = 0 # reinit. Warning: not reentrant code
            str=deref_until(self.helper,str_addr,b'\0')
            if str.find(delem) == -1:
                self.helper.set_return(str_addr) # useless, just for reader comprehension, if the token is not find, str ptr is returned.
                return
            else:
                strtok_tokens=str.split(delem)
                strtok_tokens.reverse() # for pop() purpose
        try:
            offset = len(strtok_tokens.pop())
            self.helper.mem_write(str_addr+offset+strtok_acu,b'\x00')
            self.helper.set_return(str_addr+strtok_acu)
            strtok_acu+=offset+str_addr+1 # add one to skip '\0'
        except IndexError:
            self.helper.set_return(0)
        return True



# -----------------------------------------------------------------------------
@StubsARM('index')
class index(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)

    def do_it(self,*args):

        s_addr=self.helper.get_arg(0)
        c=self.helper.get_arg(1)
        s=deref_until(self.helper,s_addr,b'\0') 

        idx = s.find(c)

        if idx < 0: self.helper.set_return(0)
        else:       self.helper.set_return(s_addr+idx)
          
        logger.console(LogType.INFO,'[index] search ',c,' in ',s,
                                    'idx: %d'%idx)
        return True
        
                                          
#         logger.console(LogType.INFO,'[index] search (0x%.2X) %s in %s'%(c,chr(c),s))
#         found = False
#         for i in range(0,len(s)):
#             if s[i] == c:
#                 found=True
#                 break
#         if found:
#             self.helper.set_return(s_addr+i)
#             logger.console(LogType.INFO,'[index] returns : %d'%i)
#         else:
#             self.helper.set_return(0)
#             logger.console(LogType.INFO,'[index] not found! returns 0')


# -----------------------------------------------------------------------------

@StubsARM('strchr')
class strchr(Stub):

  def __init__(self,itnum,arch):
    super().__init__(itnum,arch)
  def do_it(self,*args):
    s_addr = self.helper.get_arg(0)
    c_in = self.helper.get_arg(1)

    haystack = deref_string(s_addr)
    idx = haystack.find(c_in)
    
    if idx < 0: self.helper.set_return(0)
    else:       self.helper.set_return(s_addr+idx)

    logger.console(LogType.INFO,'[strchr] needle: ',c_in,' haystack: ',haystack,
                                 'returns idx: %d'%idx)
    return True
    
    
# -----------------------------------------------------------------------------

@StubsARM('strstr')
class strstr(Stub):

  def __init__(self,itnum,arch):

    super().__init__(itnum,arch)
  def do_it(self,*args):
    haystack_addr = self.helper.get_arg(0)
    needle_addr = self.helper.get_arg(1)

    # according to glibc, it is always unsafely deref until
    # '\0' is found.
    needle = deref_string(self.helper,needle_addr)
    hs = deref_string(self.helper,haystack_addr)
    
    idx = hs.find(needle) 
    if idx < 0:  self.helper.set_return(0)
    else:        self.helper.set_return(haystack_addr+idx)


    logger.console(LogType.INFO,'[strstr] ','needle: ',needle,' haystack: ',
                                 hs,' idx: %d'%idx)
    return True

# -----------------------------------------------------------------------------

@StubsARM('strfry')
class strfry(Stub):

  def __init__(self,itnum,arch):
    super().__init__(itnum,arch)
  def do_it(self,*args):
    s = self.helper.get_arg(0)
    hs = deref_string(self.helper,s).decode('utf-8')

    swap = ''.join([random.choice(hs) for x in range(0,len(hs))])
    self.helper.mem_write(s,swap.encode('utf-8'))
    return True
    
      

@StubsARM('strdup')
@StubsARM('_strdup')
@StubsARM('__strdup')
class strdup(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)

    def do_it(self,*args):
        str_addr=self.helper.get_arg(0)
        logger.console(LogType.INFO,'[strdup] string addr is: %.8X'%str_addr)
        str=deref_until(self.helper,str_addr,b'\x00')
#         cpy_addr = libc_stubs['malloc'].do_it(self.helper,fromStub=True,size=(len(str)+1)) # add one for '\0'
        cpy_addr = self.helper.malloc(len(str)+1)
        if cpy_addr == 0:
          self.helper.set_return(0) 
        self.helper.mem_write(cpy_addr,str)
        self.helper.mem_write(cpy_addr+len(str),b'\x00')
        self.helper.set_return(cpy_addr)
        logger.console(LogType.INFO,'[strdup] returning string:',str)
        return True
       

# -----------------------------------------------------------------------------
@StubsARM('strndup')
@StubsARM('_strndup')
@StubsARM('__strndup')
class strdup(Stub):
    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)

    def do_it(self,*args):
        str_addr=self.helper.get_arg(0)
        size=self.helper.get_arg(1)
        logger.console(LogType.INFO,'[strndup] string addr is: %.8X size : %d'%(str_addr,size))
        str=deref_size(self.helper,str_addr,size,delem=b'\x00')
#         cpy_addr = libc_stubs['malloc'].do_it(self.helper,fromStub=True,size=(len(str)+1)) # add one for '\0'
        cpy_addr = self.helper.malloc(len(str)+1) 
        if cpy_addr == 0: 
          self.helper.set_return(0) 
        self.helper.mem_write(cpy_addr,str)
        self.helper.mem_write(cpy_addr+len(str),b'\x00')
        self.helper.set_return(cpy_addr)
        logger.console(LogType.INFO,'[strdup] returning string:',str)

        return True
# -----------------------------------------------------------------------------
@StubsARM('strtol')
class strtol(Stub):
    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)

    def do_it(self,*args):
        nptr = self.helper.get_arg(0)
        endptr = self.helper.get_arg(1)
        base = self.helper.get_arg(2)
        logger.console(LogType.INFO,'[strtol] nptr = 0x%.8X endptr = 0x%.8X base = %d'%(nptr,endptr,base))
        if base > 36 or base < 2:
            raise Exception('[strtol] invalid base')
        negative=False
        cur_c = 0
        str_num = b''
        c = self.helper.mem_read(nptr,1)
        logger.console(LogType.INFO,'[strtol]',c)
        if c == b'-':
            negative=True
        elif c == b'+': pass
        elif c == b'0': # handle 0x or 0X format. Attention not handling -0x,-0X,+0x+0X
            c = chr(int.from_bytes(self.helper.mem_read(nptr,1),'big'))
            cur_c+=1
            c = chr(int.from_bytes(self.helper.mem_read(nptr,1),'big'))
            if c.lower() == b'x':
                base=16
        else:
            str_num+=c
        while c != b'\0':
            cur_c+=1
            c = self.helper.mem_read(nptr+cur_c,1)
            try:
                if c != b'\0':
                    tot = int((str_num+c).decode('utf-8'),base)
                    str_num+=c
                else:
                     break
            except Exception as e:
                logger.console(LogType.INFO,e.__str__())
                logger.console(LogType.INFO,'[strtol] bad char detected : %d'%ord(c))
                break
        if tot > 0xFFFFFFFF:
            raise Exception('[strtol] str is to long')
            #TODO: see libc implem. Use two registers to return > 4 bytes results ?
        if cur_c == 0:
            self.helper.set_return(0)
            self.helper.mem_write(endptr,0)
        else:
            if negative: tot=-tot
            logger.console(LogType.INFO,'[strtol] returns %d'%tot)
            self.helper.set_return(tot)
            self.helper.mem_write(endptr,int.to_bytes(nptr+cur_c,4,'little',signed=False))
        return True



# -----------------------------------------------------------------------------
@StubsARM('socket')
class socket(Stub):

  def __init__(self,itnum,arch):
        super().__init__(itnum,arch)


  def do_it(self,*args):
    """ ignores all parameters, use only TCP Net """
    sock=NWSock()
    nsock_list[sock.fd] = sock
    self.helper.set_return(sock.fd)
    return True
    

@StubsARM('recv')
class recv(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)


    def do_it(self,*args):
      sock_fd  = self.helper.get_arg(0)
      buf_addr = self.helper.get_arg(1)
      len_t    = self.helper.get_arg(2)
      flags    = self.helper.get_arg(3) 

      logger.console(LogType.INFO,'[recv] sock_fd: %d'%sock_fd,
                                  '       buf_addr: %x'%buf_addr,
                                  '       len: %d'%len_t,
                                  '       flags :%x'%flags)

#       data = nsock_list[sock_fd].recv_broker(len)
      data = NWSock.recv_broker(len_t,sock_fd)
      logger.console(LogType.INFO,'[recv] received:\n',data)
      if len(data): self.helper.mem_write(buf_addr,data)
      self.helper.set_return(len(data))
      return True


@StubsARM('send')
class send(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)


    def do_it(self,*args):
      sock_fd  = self.helper.get_arg(0)
      buf_addr = self.helper.get_arg(1)
      len_t    = self.helper.get_arg(2)
      flags    = self.helper.get_arg(3) 

      
      logger.console(LogType.INFO,'[send] sock_fd: %d'%sock_fd,
                                  '       buf_addr: %x'%buf_addr,
                                  '       len: %d'%len,
                                  '       flags :%x'%flags)
      
      data = self.helper.mem_read(buf_addr,len_t)
#       size = nsock_list[sock_fd].send(data)
      size=NWSock.send(data,sock_fd)
      logger.console(LogType.INFO,'[send] returns: %d\n',size)
      self.helper.set_return(size)
      return True


 






# -----------------------------------------------------------------------------
@StubsARM('dlt_user_log_write_start')
class dlt_user_log_write_start(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)

    def do_it(self,*args):
        logger.console(LogType.INFO,'[dlt_user_log_write_start_arm] called, returning 0')
        self.helper.set_return(0) # returns 0
        return True

@StubsMIPSL('puts')
@StubsMIPSL('.puts')
class dlt_user_log_write_start(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)

    def do_it(self,*args):
        addr = self.helper.get_arg(0)
        out = deref_until(self.helper,addr,b'\0')        
        logger.console(LogType.INFO,'[puts] %s'%out.decode('utf-8'))
        return True



# -----------------------------------------------------------------------------
#TODO : remove specific content
#FOR ATL LIB
#result is expected to be writted back in addr hold by R2
@StubsARM('g_file_get_contents')
class g_file_get_contents(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)

    def do_it(self,*args):
        logger.console(LogType.INFO,'[g_file_get_contents] called, returning 0x34')
        self.helper.mem_write(self.helper.get_arg(2),b'\x34')
        self.helper.set_return(0x34) # returns 0
        return True

@StubsARM('strerror')
class strerror(Stub):

    def __init__(self,itnum,arch):
        super().__init__(itnum,arch)

    def do_it(self,*args):
        r0 = self.helper.get_arg(0)
        logger.console(LogType.INFO,'[strerror] 0x%2X'%r0)
        self.helper.set_return(stubs_conf.errno_location)
        return True

       
#-----------------------------------------------------------------------------

@StubsARM('dlt_user_log_write_string')
class dlt_user_log_write_string_arm(NullStub):
    def __init__(self,itnum,arch):
        super().__init__(arch)

# -----------------------------------------------------------------------------
@StubsARM('dlt_user_log_write_finish')
class dlt_user_log_write_finish_arm(NullStub):
    def __init__(self,itnum,arch):
        super().__init__(arch)

# -----------------------------------------------------------------------------
@StubsARM('dlt_register_context')
class dlt_register_context_arm(NullStub):
    def __init__(self,itnum,arch):
        super().__init__(arch)

# -----------------------------------------------------------------------------
@StubsARM('g_hash_table_new_full')
class g_hash_table_new_full_arm(NullStub):
    def __init__(self,itnum,arch):
        super().__init__(arch)

# -----------------------------------------------------------------------------
@StubsARM('mosquitto_lib_init')
class g_hash_table_new_full_arm(NullStub):
    def __init__(self,itnum,arch):
        super().__init__(arch)


