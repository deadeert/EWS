from consts_arm import SVC_INSN_ARM  
from stubs import stubs_conf
from stubs.stubs_helper import *  
from emu.unicorn.generic import Emucorn
from utils import *
import codecs
import re
from enum import Enum
import os
from os import path 
import tempfile




byte_l = lambda x: x & 0xFF
byte_2l = lambda x: x & 0xFFFF
byte_h = lambda x: (x >> 16) & 0xFF
byte_2h = lambda x: (x >> 16) & 0xFFFF

class Helper(object):

  def __init__(self):
    pass
  def mem_read(self,addr,size):
    """ return value from emulator memory """
    pass
  def mem_write(self,addr,value): 
    """ write value to emulator memory """ 
    pass
  def reg_read(self,reg_id): 
    """ return register value from reg_id (int) """
    pass
  def reg_write(self,reg_id,value):
    """ write value to reg_id register """ 
    #Use EmuXXX.reg_convert static method
    pass


class UnicornHelper(object):

  def __init__(self,uc,allocator):
    self.runner = uc 
    self.allocator = allocator
  def mem_read(self,addr,size):
    return Emucorn.mem_read(self.runner,addr,size)
  def mem_write(self,addr,data):
    Emucorn.mem_write(self.runner,addr,data)
  def reg_read(self,reg_id):
    return Emucorn.reg_read(self.runner,ArmCorn.reg_convert(reg_id))
  def reg_write(self,reg_id,data):
    Emucorn.reg_write(self.runner,ArmCorn.reg_convert(reg_id),data)


libc_stubs = {}


class StubsARM():
    itnum_arm = 1
    def __init__(self,name):
        assert name not in libc_stubs
        self.itnum = StubsARM.itnum_arm
        StubsARM.itnum_arm+=1
        self.name = name

    def __call__(self,cls):
        obj = cls(self.itnum)
        libc_stubs[self.name] = obj
        libc_stubs[self.itnum] = obj
        return cls

class NullStubARM(object):
    """
    SVC 0 is triggering this code which returns 0
    Inherit from this class to avoid reimplementing this behavior
    """

    def __init__(self):
        self.idx_it = 0
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[stubs] null stub is called')
        helper.reg_write(0,0)



@StubsARM('memset')
class memset_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        dst = runner.reg_read(0)
        data = byte_l (runner.reg_read(1)) 
        ln = runner.reg_read(2)
        logger.console(LogType.INFO,' memset(%8X, %2X, %X)'%(dst,data,ln))
        helper.mem_write(dst,bytes(data*ln))

@StubsARM('malloc')
class malloc_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper,fromStub=False,size=None):
        if not fromStub:
          req_size = helper.reg_read(0)
          addr = helper.allocator.malloc(req_size)
          helper.reg_write(0,addr)
          logger.console(LogType.INFO,' malloc(%X) = %8X'%(req_size,addr))
        else:
          addr = helper.allocator.malloc(size)
          logger.console(LogType.INFO,' malloc(%X) = %8X (from stub)'%(size,addr))
          return addr 

          
          


@StubsARM('free')
class free_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        addr = runner.reg_read(0)
        helper.allocator.free(addr)
        logger.console(LogType.INFO,' free(%8X)'%addr)

@StubsARM('calloc')
class calloc_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        req_size = runner.reg_read(0)
        addr = helper.allocator.malloc(req_size)
        helper.mem_write(addr,b'\x00'*req_size)
        helper.reg_write(0,addr)
        logger.console(LogType.INFO,' malloc(%X) = %8X'%(req_size,addr))


@StubsARM('__libc_start_main')
class libc_start_main__arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[__libc_start_main] called at %.8X'%helper.reg_read(15))
        arg0 = helper.reg_read(0)
        logger.console(LogType.INFO,'[__libc_start_main] main => %.8X'%(arg0))
        helper.reg_write(14, arg0)

@StubsARM('puts')
class puts_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[puts] called at 0x%.8X'%helper.reg_read(15))
        arg0 = helper.reg_read(0)
        s = deref_until(helper,arg0,b'\0').decode('utf-8')
        helper.reg_write(0, 0)

# -----------------------------------------------------------------------------
@StubsARM('strncpy')
class strncpy_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[strncpy] called at 0x%.8X'%helper.reg_read(15))
        dst=helper.reg_read(0)
        src=helper.reg_read(1)
        ln=helper.reg_read(2)
        data=helper.mem_read(src,ln)
        nc = data.find(b'\x00')
        if nc != -1:
            data=data[0:nc]
        helper.mem_write(dst,bytes(data))
        logger.console(LogType.INFO,'[strncpy] dst = %.8X src = %.8X ln = %d'%(dst,src,ln),
                  '\n\tCopying string : ',data)

# -----------------------------------------------------------------------------
@StubsARM('strcpy')
class strcpy_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it =  int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[strcpy] called at 0x%.8X'%helper.reg_read(15))
        dst_addr=helper.reg_read(0)
        src_addr=helper.reg_read(1)
        src = deref_string(helper,src_addr)
        helper.mem_write(dst_addr,src)

# -----------------------------------------------------------------------------
@StubsARM('printf')
class printf_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        format_addr = helper.reg_read(0)
        try:
            fmt = deref_until(helper,format_addr,b'\0')
        except UnicodeDecodeError as e:
            logger.console(LogType.INFO,'[printf] Cannot decode format :',fmt)
            raise StubExcept('[printf] error decoding format')
        fmt,l = codecs.escape_encode(fmt)
        pc = helper.reg_read(15)
        logger.console(LogType.INFO,'[printf] Call at 0x%.8X with format %s'%(pc,fmt))
        p  = re.compile('%+[l]{0,1}[dpsx]')
        p2  = re.compile('(%+[dpsx])')
        chain_addr = helper.reg_read(0)
        chain = deref_string(helper,chain_addr)
        reformat = [i for i in p.findall(chain.strip().decode('utf-8')) if i != '']
        deref_list = f(helper,reformat)
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

# -----------------------------------------------------------------------------
@StubsARM('memcpy')
class memcpy_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[memcpy] called at 0x%.8X'%helper.reg_read(15))
        dst=helper.reg_read(0)
        src=helper.reg_read(1)
        ln=helper.reg_read(2)
        data=helper.mem_read(src,ln)
        helper.mem_write(dst,bytes(data))
        helper.reg_write(0,ln)

# -----------------------------------------------------------------------------
@StubsARM('strlen')
class strlen_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        str_addr = helper.reg_read(0)
        logger.console(LogType.INFO,'[strlen] str_addr: 0x%.8X'%str_addr)
        size=len(deref_until(helper,str_addr,b'\0'))
        logger.console(LogType.INFO,'[strlen] returns %d'%size)
        helper.reg_write(0,size)

# -----------------------------------------------------------------------------
@StubsARM('fopen')
class fopen_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        fname_addr = helper.reg_read(0)
        mode_addr = helper.reg_read(1)
        try:
            #Python does not support file opening with non utf-8 / unicode string.
            filename = deref_until(helper,fname_addr,b'\0')
        except SyntaxError:
            raise StubPythonException('[fopen] non utf-8 filename')
        mode = deref_string(helper,mode_addr).decode('utf-8')
        logger.console(LogType.INFO,'[fopen] filename: ',filename,' mode:%s'%mode)
        if '+' in mode: mode=mode.split('+')[0]+'b'+mode.split('+')[1]
        else: mode +='b'
        fd = open(filename,mode)
        fd_list[fd.fileno()] = FILE(fd,mode)
        logger.console(LogType.INFO,'[fopen] returning fd %d'%fd.fileno())
        helper.reg_write(0,fd.fileno())

# -----------------------------------------------------------------------------
@StubsARM('fwrite')
class fwrite_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[fwrite] called at 0x%.8X, fd : %d'%(helper.reg_read(15),
                                                helper.reg_read(3)))
        fd = helper.reg_read(3)
        buf_addr = helper.reg_read(0)
        size = helper.reg_read(1)
        nmenb = helper.reg_read(2)
        if fd not in fd_list:
            raise StubExcept('[fwrite] file descriptor not in the list')
        data=deref_size(helper,buf_addr,nmenb*size)
        try:
            fd_list[fd].write(data)
        except Exception as e:
            raise StubExcept('[fwrite] error writing file: %s'%e.__str__())
        helper.reg_write(0,nmemb*size)

# -----------------------------------------------------------------------------
@StubsARM('fclose')
class fclose_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[fclose] called at 0x%.8X, fd : %d'%(helper.reg_read(15),
                                                helper.reg_read(0)))
        fd = helper.reg_read(0)
        if fd not in fd_list:
            raise StubExcept('[fclose] file descriptor not in the list')
        try:
            fd_list[fd].close()
        except:
            raise StubExcept('[fclose] error closing file with fd %d'%fd)

# -----------------------------------------------------------------------------
@StubsARM('fread')
class fread_arm():
    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[fread] called at 0x%.8X, fd : %d'%(helper.reg_read(15),
                                               helper.reg_read(3)))
        fd = helper.reg_read(3)
        buf_addr = helper.reg_read(0)
        size = helper.reg_read(1)
        nmenb = helper.reg_read(2)
        if fd not in fd_list:
            raise StubExcept('[fread] file descriptor not in the list')
        i = 0
        while(i < (nmenb*size)):
            try:
                helper.mem_write(buf_addr+i,fd_list[fd].read(nmenb))
            except Exception as e:
                raise StubExcept('[fread] error reading file: %s'%e.__str__())
            i+=nmenb
        helper.reg_write(0,nmenb*size)

# -----------------------------------------------------------------------------
@StubsARM('fflush')
class fflush_arm():
    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[fflush] called at 0x%.8X, fd : %d'%(helper.reg_read(15),
                                                helper.reg_read(0)))
        fd = helper.reg_read(0)
        if not fd in fd_list:
            raise(Exception('[fflush] file descriptor not in the list'))
        fd_list[fd].fflush()
        helper.reg_write(0,0)

# -----------------------------------------------------------------------------
@StubsARM('fseek')
class fseek_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[fseek] called at 0x%.8X, fd : %d'%(helper.reg_read(15),
                                               helper.reg_read(0)))
        fd = helper.reg_read(0)
        offset = helper.reg_read(1)
        whence = helper.reg_read(2)
        if not fd in fd_list:
            raise(Exception('[fseek] file descriptor not in the list'))
        try:
            fd_list[fd].fseek(offset,whence)
        except Exception as e :
            raise(Exception('[fseek] error fseek'))
        helper.reg_write(0,0)

# -----------------------------------------------------------------------------
@StubsARM('fgetc')
class fgetc_arm():
    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[fgetc] called at 0x%.8X, fd : %d'%(helper.reg_read(15),
                                               helper.reg_read(0)))
        fd = helper.reg_read(0)
        if not fd in fd_list:
            raise(Exception('[fgetc] file descriptor not in the list'))
        helper.reg_write(0,fd_list[fd].read(1))

# -----------------------------------------------------------------------------
@StubsARM('fgets')
class fgets_arm():
    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        fd = helper.reg_read(2)
        size = helper.reg_read(1)
        addr = helper.reg_read(0)
        logger.console(LogType.INFO,'[fgets] called at 0x%.8X, fd : %d,dst=0x%.8X,size=%d'%(helper.reg_read(15),
                                                                      fd,
                                                                      addr,
                                                                      size))
        if not fd in fd_list:
            raise(Exception('[fgets] file descriptor not in the list'))
        # according to man, read size-1 chars maximum to let room for '\0' terminating char
        line= fd_list[fd].readline()
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
            helper.mem_write(addr,line)
            helper.mem_write(addr+len(line),b'\x00')
        else:
            logger.console(LogType.INFO,'[fgets] returns NULL (no more line)')
            helper.reg_write(0,0)    #fgets returns the addr of the buffer (R0 not modified)

# -----------------------------------------------------------------------------
#CAUTION : Does not handle space between format
@StubsARM('fprintf')
class fprintf_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[fprintf] called at 0x%.8X, fd : %d'%(helper.reg_read(15),
                                                 helper.reg_read(0)))
        fd = helper.reg_read(0)
        if not fd in fd_list:
            raise Exception('[fprintf] file descriptor not found')
        chain_addr = helper.reg_read(1)
        chain = deref_string(helper,chain_addr)
        p  = re.compile('%+[l]{0,1}[dpsx]')
        p2  = re.compile('(%+[l]{0,1}[dpsx])')
        reformat = [i for i in p.findall(chain.strip().decode('utf-8')) if i != '']
        deref_list = g(helper,reformat)
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
        helper.reg_write(0,len(out))

# -----------------------------------------------------------------------------
@StubsARM('snprintf')
class snprintf_arm():
    """
    To reflect as maximum as possible C implmentation, we use byte representation of string.
    Hence it is not possible to use Python' string functions helper
    """
    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[snprintf]')
        buf_addr = helper.reg_read(0)
        size = helper.reg_read(1)
        format_addr = helper.reg_read(2)
        chain = deref_string(helper,format_addr)
        logger.console(LogType.INFO,'[snprintf] dst: 0x%.8X size : %d format : %s'%(buf_addr,size,chain))
        p  = re.compile('%+[l]{0,1}[dpsx]')
        p2  = re.compile('(%+[l]{0,1}[dpsx])')
        reformat = [i for i in p.findall(chain.strip().decode('utf-8')) if i != '']
        deref_list = h(helper,reformat)
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
            helper.mem_write(buf_addr,bytes(out)[0:size])
            helper.mem_write(buf_addr+len(bytes(out)[0:size])-1,b'\x00')
            helper.reg_write(0,size)
            logger.console(LogType.INFO,'[snprintf] outputs :',out[0:size])
        else:
            helper.mem_write(buf_addr,bytes(out)[0:len(out)])
            helper.mem_write(buf_addr+len(bytes(out)[0:len(out)]),b'\x00')
            helper.reg_write(0,len(out))
            logger.console(LogType.INFO,'[snprintf] outputs :',out)

# -----------------------------------------------------------------------------
@StubsARM('strcmp')
class strcmp_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[strcmp] called at 0x%.8X'%(helper.reg_read(15)))
        s1_addr = helper.reg_read(0)
        s2_addr = helper.reg_read(1)
        ret=0
        s1=deref_until(helper,s1_addr,b'\0')
        s2=deref_until(helper,s2_addr,b'\0')
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
        helper.reg_write(0,ret)

# -----------------------------------------------------------------------------
@StubsARM('strncmp')
class strncmp_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        """
        LIBC implementation breaks when first mismatch is found and returns distance between the two current chars.
        """
        logger.console(LogType.INFO,'[strncmp] called at 0x%.8X'%(helper.reg_read(15)))
        s1_addr = helper.reg_read(0)
        s2_addr = helper.reg_read(1)
        cmp_len = helper.reg_read(2)

        s1=deref_size(helper,s1_addr,cmp_len,delem=b'\x00')
        s2=deref_size(helper,s2_addr,cmp_len,delem=b'\x00')
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
        helper.reg_write(0,ret)

# -----------------------------------------------------------------------------
@StubsARM('strcat')
class strncat_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        dst_addr = helper.reg_read(0)
        src_addr = helper.reg_read(1)
        beg = deref_until(helper,dst_addr,delem=b'\0')
        end = deref_until(helper,src_addr,delem=b'\0')
        logger.console(LogType.INFO,'[strcat] happening: ',end,'(0x%.8X) to: '%src_addr,beg,'(0x%.8X) '%dst_addr)
        helper.mem_write(dst_addr+len(beg),end)
        helper.mem_write(dst_addr+len(beg)+len(end),b'\0')
        helper.reg_write(0,dst_addr)

# -----------------------------------------------------------------------------
@StubsARM('strncat')
class strncat_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        dst_addr = helper.reg_read(0)
        src_addr = helper.reg_read(1)
        size = helper.reg_read(2)
        beg = deref_until(helper,dst_addr,delem=b'\0')
        end = deref_size(helper,src_addr,size,delem=b'\0')
        logger.console(LogType.INFO,'[strncat] happening: ',end,'(0x%.8X) to: '%src_addr,beg,'(0x%.8X) for size %d.'%(dst_addr,size))
        helper.mem_write(dst_addr+len(beg),end)
        helper.mem_write(dst_addr+len(beg)+len(end),b'\0')
        logger.console(LogType.INFO,'[strncat] out:',helper.mem_read(dst_addr,len(beg)+len(end)+1))
        helper.reg_write(0,dst_addr)

# -----------------------------------------------------------------------------
@StubsARM('scandir')
class scandir_arm():
    
    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        path_addr = helper.reg_read(0)
        print('%8X'%path_addr)
        dirent_addr = helper.reg_read(1)
        print('%8X'%dirent_addr)
        search_func_addr = helper.reg_read(2) # TODO launch into other exec thread
        search_filter_addr = helper.reg_read(3) #TODO launch into other exec thread  
        path=deref_until(helper,path_addr,b'\0')
        logger.console(LogType.INFO,'[scandir] path: ',path)
        entries = [e.name for e in os.path.os.scandir(path.decode('utf-8'))] #Python does not handle non utf-8 dir name
        dirent_ret = libc_stubs['malloc'].do_it(helper,fromStub=True,size=len(entries)*4)
#         dirent_ret = helper.heap_alloc(len(entries)*4)
        nb_entry = 0
        dirent_struct_len = stubs_conf.dirent_struct_len
        for entry in entries:
            #TODO launch search & filter functions 
            e_addr = libc_stubs['malloc'].do_it(helper,fromStub=True,size=(dirent_struct_len+len(entry)+1))
            helper.mem_write(dirent_ret+nb_entry*4,int.to_bytes(e_addr,4,'little',signed=False))
            helper.mem_write(e_addr+dirent_struct_len,bytes(entry,'utf-8'))
            helper.mem_write(e_addr+dirent_struct_len+len(bytes(entry,'utf-8')),b'\x00')
            nb_entry+=1
        helper.mem_write(dirent_addr,int.to_bytes(dirent_ret,4,'little',signed=False))
        logger.console(LogType.INFO,'[scandir] returning %d'%nb_entry)
        helper.reg_write(0,nb_entry)
        return True
        


# -----------------------------------------------------------------------------
@StubsARM('getpid')
class getpid_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[getpid]    returning %X'%stubs_conf.pid)
        helper.reg_write(0,stubs_conf.pid) #

# -----------------------------------------------------------------------------
@StubsARM('__errno_location')
class __errno_location_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[__errno_location] returning : %x'%stubs_conf.errno_location)
        helper.reg_write(0,stubs_confs.errno_location)

# -----------------------------------------------------------------------------
@StubsARM('index')
class index_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        s_addr=helper.reg_read(0)
        c=helper.reg_read(1)
        s=deref_until(helper,s_addr,b'\0')
        logger.console(LogType.INFO,'[index] search (0x%.2X) %s in %s'%(c,chr(c),s))
        found = False
        for i in range(0,len(s)):
            if s[i] == c:
                found=True
                break
        if found:
            helper.reg_write(0,s_addr+i)
            logger.console(LogType.INFO,'[index] returns : %d'%i)
        else:
            helper.reg_write(0,0)
            logger.console(LogType.INFO,'[index] not found! returns 0')

# -----------------------------------------------------------------------------
strtok_tokens = []
strtok_acu = 0
@StubsARM('strtok')
class strtok_arm():
    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        """
        strtok uses the string allocation and replaces the delimiter with null char.
        it returns at each call the next location (between two '\0')
        """
        global strtok_tokens
        global strtok_acu
        logger.console(LogType.INFO,'[stubs] strtok called')
        str_addr=helper.reg_read(0)
        delem_addr=helper.reg_read(1)
        if delem_addr == 0:
            logger.console(LogType.INFO,'[strtok] : null delimiter')
            # useless, just for reader comprehension, if token is not find, str ptr is returned.
            helper.reg_write(0,str_addr)
            return
        else:
            delem=deref_size(helper,delem_addr,1)
        if str_addr != 0:
            logger.console(LogType.INFO,'[strtok] first call, deleminator is : %s'%delem)
            strtok_acu = 0 # reinit. Warning: not reentrant code
            str=deref_until(helper,str_addr,b'\0')
            if str.find(delem) == -1:
                helper.reg_write(0,str_addr) # useless, just for reader comprehension, if token is not find, str ptr is returned.
                return
            else:
                strtok_tokens=str.split(delem)
                strtok_tokens.reverse() # for pop() purpose
        try:
            offset = len(strtok_tokens.pop())
            helper.mem_write(str_addr+offset+strtok_acu,b'\x00')
            helper.reg_write(0,str_addr+strtok_acu)
            strtok_acu+=offset+str_addr+1 # add one to skip '\0'
        except IndexError:
            helper.reg_write(0,0)

# -----------------------------------------------------------------------------
@StubsARM('strdup')
@StubsARM('_strdup')
@StubsARM('__strdup')
class strdup_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        str_addr=helper.reg_read(0)
        logger.console(LogType.INFO,'[strdup] string addr is: %.8X'%str_addr)
        str=deref_until(helper,str_addr,b'\x00')
#         cpy_addr = allocator.malloc(len(str)+1) # add one for '\0'
        cpy_addr = libc_stubs['malloc'].do_it(helper,fromStub=True,size=(len(str)+1)) # add one for '\0'
        if cpy_addr == 0:
          helper.reg_write(0,0) 
        helper.mem_write(cpy_addr,str)
        helper.mem_write(cpy_addr+len(str),b'\x00')
        helper.reg_write(0,cpy_addr)
        logger.console(LogType.INFO,'[strdup] returning string:',str)
       

# -----------------------------------------------------------------------------
@StubsARM('strndup')
@StubsARM('_strndup')
@StubsARM('__strndup')
class strdup_arm():
    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        str_addr=helper.reg_read(0)
        size=helper.reg_read(1)
        logger.console(LogType.INFO,'[strndup] string addr is: %.8X size : %d'%(str_addr,size))
        str=deref_size(helper,str_addr,size,delem=b'\x00')
        cpy_addr = libc_stubs['malloc'].do_it(helper,fromStub=True,size=(len(str)+1)) # add one for '\0'
        if cpy_addr == 0: 
          helper.reg_write(0,0) 
        helper.mem_write(cpy_addr,str)
        helper.mem_write(cpy_addr+len(str),b'\x00')
        helper.reg_write(0,cpy_addr)
        logger.console(LogType.INFO,'[strdup] returning string:',str)

# -----------------------------------------------------------------------------
@StubsARM('strtol')
class strtol_arm():
    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        nptr = helper.reg_read(0)
        endptr = helper.reg_read(1)
        base = helper.reg_read(2)
        logger.console(LogType.INFO,'[strtol] nptr = 0x%.8X endptr = 0x%.8X base = %d'%(nptr,endptr,base))
        if base > 36 or base < 2:
            raise Exception('[strtol] invalid base')
        negative=False
        cur_c = 0
        str_num = b''
        c = helper.mem_read(nptr,1)
        logger.console(LogType.INFO,'[strtol]',c)
        if c == b'-':
            negative=True
        elif c == b'+': pass
        elif c == b'0': # handle 0x or 0X format. Attention not handling -0x,-0X,+0x+0X
            c = chr(int.from_bytes(helper.mem_read(nptr,1),'big'))
            cur_c+=1
            c = chr(int.from_bytes(helper.mem_read(nptr,1),'big'))
            if c.lower() == b'x':
                base=16
        else:
            str_num+=c
        while c != b'\0':
            cur_c+=1
            c = helper.mem_read(nptr+cur_c,1)
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
            helper.reg_write(0,0)
            helper.mem_write(endptr,0)
        else:
            if negative: tot=-tot
            logger.console(LogType.INFO,'[strtol] returns %d'%tot)
            helper.reg_write(0,tot)
            helper.mem_write(endptr,int.to_bytes(nptr+cur_c,4,'little',signed=False))

# -----------------------------------------------------------------------------
@StubsARM('dlt_user_log_write_start')
class dlt_user_log_write_start_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[dlt_user_log_write_start_arm] called, returning 0')
        helper.reg_write(0,0) # returns 0

# -----------------------------------------------------------------------------
#TODO : remove specific content
#FOR ATL LIB
#result is expected to be writted back in addr hold by R2
@StubsARM('g_file_get_contents')
class g_file_get_contents_arm():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        logger.console(LogType.INFO,'[g_file_get_contents] called, returning 0x34')
        helper.mem_write(helper.reg_read(2),b'\x34')
        helper.reg_write(0,0x34) # returns 0

@StubsARM('strerror')
class strerror():

    def __init__(self,itnum):
        self.idx_it = itnum
        self.insn_it = int.to_bytes(SVC_INSN_ARM|self.idx_it,4,'little')

    def do_it(self,helper):
        r0 = helper.reg_read(0)
        logger.console(LogType.INFO,'[strerror] 0x%2X'%r0)
        helper.reg_write(0,stubs_conf.errno_location)
       
#-----------------------------------------------------------------------------

@StubsARM('dlt_user_log_write_string')
class dlt_user_log_write_string_arm(NullStubARM):
    def __init__(self,itnum):
        super().__init__()

# -----------------------------------------------------------------------------
@StubsARM('dlt_user_log_write_finish')
class dlt_user_log_write_finish_arm(NullStubARM):
    def __init__(self,itnum):
        super().__init__()

# -----------------------------------------------------------------------------
@StubsARM('dlt_register_context')
class dlt_register_context_arm(NullStubARM):
    def __init__(self,itnum):
        super().__init__()

# -----------------------------------------------------------------------------
@StubsARM('g_hash_table_new_full')
class g_hash_table_new_full_arm(NullStubARM):
    def __init__(self,itnum):
        super().__init__()

# -----------------------------------------------------------------------------
@StubsARM('mosquitto_lib_init')
class g_hash_table_new_full_arm(NullStubARM):
    def __init__(self,itnum):
        super().__init__()


