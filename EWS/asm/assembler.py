from keystone import *
from keystone.arm_const import *
from unicorn import *
from unicorn.arm_const import *
from EWS.utils.utils import *


assemblers = dict() # {'arch': [ asm object, ... ]}

class Asm():

    def __init__(self,name,arch):

        self.name = name
        self.arch = arch
        if not arch in assemblers.keys():
            assemblers[arch] = []

    def __call__(self,cls):
        obj = cls(self.name)
        assemblers[self.arch].append(obj)
        return cls



class Assembler():

    def __init__(self,name):
        self.name = name

    def assemble(self,
                 asm: str,
                 addr:int) -> bytes:
        """
        this function take a synthax string and retruns the corresponding
        bytecode
        """
        pass


class KsAssembler(Assembler):

    def __init__(self,
                 name:str,
                 arch:int,
                 mode:int):

        try:
            self.ks = Ks(arch,mode)
        except KsError as e:
            pass

    def assemble(self,
                 asm:str,
                 addr:int):

        return self.ks.asm(asm,
                           addr=addr,
                           as_bytes=True)[0]


@Asm(arch='arm', name='KsArm')
class KsAssemblerArm(KsAssembler):

    def __init__(self,name):
        super().__init__(name,UC_ARCH_ARM,UC_MODE_ARM)

@Asm(arch='armt',name='KsArmThumb')
class KsAssemblerArmThumb(KsAssembler):

    def __init__(self,name):
        super().__init__(name,UC_ARCH_ARM,UC_MODE_THUMB)


@Asm(arch='aarch64',name='KsAarch64')
class KsAssemblerAarch64(KsAssembler):

    def __init__(self,name):
        super().__init__(name,UC_ARCH_ARM64,UC_MODE_ARM)

@Asm(arch='x86',name='Ksx86')
class KsAssemblerx86(KsAssembler):

    def __init__(self,name):
        super().__init__(name,UC_ARCH_X86,UC_MODE_32)

@Asm(arch='x64',name='Ksx64')
class KsAssemblerx64(KsAssembler):

    def __init__(self,name):
        super().__init__(name,UC_ARCH_X86,UC_MODE_64)







