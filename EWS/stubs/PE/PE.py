# from stubs import stubs_conf
# from stubs.stubs_helper import *    
from EWS. utils.utils import *
import codecs
import re
from enum import Enum
import os
from os import path 
import tempfile
import struct
import random
import struct



# -----------------------------------------------------------------------------
"""                                 """
"         STUB OBJECTS        "
"""                                 """
# -----------------------------------------------------------------------------

class Stub(object):
    """
    stub object
    """
    def __init__(self,helper=None):
        """
        constructor of Stub object
        param:
            helper: abstraction of all emulator operations
        """
        self.helper = helper

    def set_helper(self,helper):
        """
        setter of stub object
        param:
            helper: abstraction of all emulator operations
        """
        self.helper = helper

windows_stubs = dict()

class WinStub():
    """
    WinStub:
    decorator to populate windows stub
    """
    def __init__(self,name):
        """
        constructor of WinStub decorator object
        """
        assert name not in windows_stubs
        self.name = name

    def __call__(self,cls):
        """
        populate windows_stubs list with instances of stubs object
        param:
            class object corresponding to the decorated object
        """
        obj = cls()
        windows_stubs[self.name] = obj
        return cls



class NullStub(Stub):

    """
    NullStub is used to hook with minimal artefact the call
    to a method.
    Inherits from this object to stub a symbol.
    """
    def __init__(self,helper=None):
        """
        constructor of NullStub object
        """
        super().__init__(helper)

    def do_it(self,*args):

        """
        code definition of NullStub
        Basically just returns 0 using set_return method.
        Warning, this could create artifact.
        """
        logger.console(LogType.INFO,'[stubs] null stub is called')
        self.helper.set_return(0)
        return True



# -----------------------------------------------------------------------------
"""                                     """
"     STUBBED FUNCTIONS     "
"""                                     """
# -----------------------------------------------------------------------------

@WinStub('RegEnumKeyExW')
class RegEnumKeyExW(Stub):
    def __init__(self):
        super().__init__()



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

@WinStub('malloc')
class malloc(Stub):
    def __init__(self,):
        super().__init__()



    def do_it(self,*args):
        logger.console(LogType.INFO,'[stubs] malloc')
        alloc_size = self.helper.get_arg(0)
        addr = self.helper.malloc(alloc_size)
        self.helper.set_return(addr)
        logger.console(LogType.INFO,'[stubs] malloc returns addr 0x%x'%addr)
        return True

@WinStub('rand')
class rand(Stub):

    def __init__(self,):
        super().__init__()

    def do_it(self,*args):
        logger.console(LogType.INFO,'[stubs] rand')
        r = random.randint(0,0xFFFFFFFF)
        self.helper.set_return(r)
        logger.console(LogType.INFO,'[stubs] rand returns %x'%r)
        return True

