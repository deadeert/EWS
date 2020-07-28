from fuzr.unicorn import *
from fuzr.unicorn.arm_const import *

from fuzr import conf
import socket

from utils import SockMode
#-------------------------------------------------------------
# FILE manipulation helper
#-------------------------------------------------------------
STDIN=0
STDOUT=1
STDERR=2


fd_list = {}

class FILE(object):

    def __init__(self,fd,mode):
        self.fd=fd
        self.mode=mode

    def write(self,data):
        if 'wb' in self.mode:
            self.fd.write(bytes(data))
        else:
            for c in data:
                self.fd.write(chr(c))

    def read(self,size):
        return self.fd.read(size)

    def close(self):
        self.fd.close()

    def fflush(self):
        self.fd.flush()

    def fseek(self,offset,whence):
        self.fd.seek(offset,whence)

    def readline(self):
        return self.fd.readline()

#-------------------------------------------------------------
# Network Socket 
#-------------------------------------------------------------


nsock_list = {} 
sssss = None 
class NWSock(object):
  
  def __init__(self,mode=SockMode.UKN):
    
    self.fd = len(nsock_list) + 1
    self.mode = mode
    


  def bind(self):
    self.mode=SockMode.READ 

  @staticmethod
  def recv_broker(len,fd=0):
    """ mode broker: to get the data, this function connects
                     to localhost:6666
    """ 

    if sssss == None:
      s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
      try:
        s.connect(('localhost',6666))
      except ConnectionRefusedError:
        logger.console(LogType.WARN,'[!] Could not connect to localhost:6666 to receive data\n',
                                    'Make sure that a server is ready to send data (ex: nc -l -p 6666 < data_file)')
        return b''  
    return s.recv(len)

  @staticmethod
  def send(msg,fd=0):
    """ mode broker: to get the data, this function connects
                     to localhost:6666
    """ 

    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
      s.connect(('localhost',6667))
    except ConnectionRefusedError:
      logger.console(LogType.WARN,'[!] Could not connect to localhost:6667.\n',
                                  'Make sure that a server is ready to receive data (ex: nc -l -p 6666 < data_file)')
      return -1  
    return s.send(msg)



    
    




    






#-------------------------------------------------------------
# String deref and manipulation helpers
#-------------------------------------------------------------


def deref_string(helper,addr):
    return deref_until(helper,addr,b'\x00')

def deref_until(helper,addr,delem):
    out=b''
    i=0
    while True:
        c=helper.mem_read(addr+i,1)
        if c == delem or c == b'\0':
            break
        out+=bytes(c)
        i+=1
    return out

def deref_size(helper,addr,size,delem=None):
    out=b''
    i=0
    while i<size:
        c=helper.mem_read(addr+i,1)
        if delem != None and c == delem:
            break
        out+=bytes(c)
        i+=1
    return out

def f(helper,format):
    j=0
    deref_list=[]
    SP=helper.reg_read(13)
    R1=helper.reg_read(1)
    R2=helper.reg_read(2)
    R3=helper.reg_read(3)
    bp_offset=0
    for r in format:
        if r.strip() == '%s':
            if   j==0: deref_list.append( deref_until(helper,R1,b'\0'))
            elif j==1: deref_list.append( deref_until(helper,R2,b'\0'))
            elif j==2: deref_list.append( deref_until(helper,R3,b'\0'))
            else:
                tgt_addr = int.from_bytes(helper.mem_read(SP+bp_offset,4),'little')
                deref_list.append(deref_until(helper,tgt_addr,b'\0'))
                bp_offset+=4
        elif r.strip() == '%d' or r.strip() == '%ld' or r.strip() == '%p' or r.strip() == '%x':
            if   j==0: deref_list.append(R1)
            elif j==1: deref_list.append(R2)
            elif j==2: deref_list.append(R3)
            else:
                dword = int.from_bytes(helper.mem_read(SP+bp_offset,4),'little')
                deref_list.append(dword)
                bp_offset+=4
        else:
            print('Warning format %s not handled'%r.strip())
        j+=1
    return deref_list

def g(helper,format):
    j=1
    deref_list=[]
    SP=helper.reg_read(13)
    R2=helper.reg_read(2)
    R3=helper.reg_read(3)
    bp_offset=0
    for r in format:
        if r.strip() == '%s':
            if j==1: deref_list.append( deref_until(helper,R2,b'\0'))
            if j==2: deref_list.append( deref_until(helper,R3,b'\0'))
            else:
                tgt_addr = int.from_bytes(helper.mem_read(SP+bp_offset,4),'little')
                deref_list.append(deref_until(helper,tgt_addr,b'\0'))
                bp_offset+=4
        elif r.strip() == '%d' or r.strip() == '%ld' or r.strip() == '%p' or r.strip() == '%x':
            if j==1:deref_list.append(R2)
            elif j==2:deref_list.append(R3)
            else:
                dword = int.from_bytes(helper.mem_read(SP+bp_offset,4),'little')
                deref_list.append(dword)
                bp_offset+=4
        j+=1
    return deref_list

def h(helper,format):
    j=2
    deref_list=[]
    SP=helper.reg_read(13)
    R3=helper.reg_read(3)
    bp_offset=0
    for r in format:
        if r.strip() == '%s':
            if j==2: deref_list.append( deref_until(helper,R3,b'\0'))
            else:
                tgt_addr = int.from_bytes(helper.mem_read(SP+bp_offset,4),'little')
                deref_list.append(deref_until(helper,tgt_addr,b'\0'))
                bp_offset+=4
        elif r.strip() == '%d' or r.strip() == '%ld' or r.strip() == '%p' or r.strip() == '%x':
            if j==2:deref_list.append(R3)
            else:
                dword = int.from_bytes(helper.mem_read(SP+bp_offset,4),'little')
                deref_list.append(dword)
                bp_offset+=4
        j+=1
    return deref_list

