#from fuzr.unicorn import *
#from fuzr.unicorn.arm_const import *
#
#from fuzr import conf
import socket

from EWS.utils.utils import *
import struct

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


def deref_format(helper,format,arg_num):
  """ argnum is the number of the first argument to be used 
  """

  deref_list = [] 
  for r in format:
    cur_arg = helper.get_arg(arg_num)
    logger.console(LogType.INFO,'cur arg = %x'%cur_arg)
    if r.strip() == '%s':
      deref_list.append(deref_until(helper,cur_arg,b'\0'))
    elif r.strip() in [ '%d', '%ld', '%x', '%p']: 
      dword = struct.pack('<I',helper.mem_read(helper,cur_arg))
    else :
      logger.console(LogType.WARN,'%s format unsupported')
    arg_num+=1 
  return deref_list


def build_chain(helper,format_l,values):

    out = b''
    for f in format_l:
        print(f)
        if  f == '%s' : out+=values.pop()
        elif f == '%d' : out+=bytes('%d'%values.pop(),'utf-8')
        elif f == '%ld': out+=bytes('%ld'%values.pop(),'utf-8')
        elif f == '%x' : out+=bytes('%x'%values.pop(),'utf-8')
        elif f == '%p' : out+=bytes('%x'%values.pop(),'utf-8')
        elif f != ''   : out+=bytes(f,'utf-8')  # case its encapsulated 
                                                #basic string ( %x basic string %s )

    return out

def write_to_fd(fdnum,fdesc_l,out):

    ln = 0 
    if fdnum > 2 and fdnum in fdesc_l:
          ln = fdesc_l[fdnum].write(bytes(out))
          logger.console(LogType.INFO,'[fprintf] on fd %d outputs: '%fd,out)
          return ln 
    elif fdnum == 2:
          logger.console(LogType.INFO,'[fprintf@strderr] outputs:', out)
    elif fdnum == 1: 
          logger.console(LogType.INFO,'[fprintf@stdout] outputs:', out)
    else:
          logger.console(LogType.INFO,'[fprintf@stdin] outputs:', out)
    return len(out)






