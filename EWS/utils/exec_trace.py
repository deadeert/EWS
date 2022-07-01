from EWS.utils.registers import *
import json



class Exec_Trace(object):

    arch = ''
    addr = dict()

    def __init__(self,arch,addr=None):
        self.arch = arch
        if addr:
            self.addr=addr

    def add_instruction(self,
                        addr:int,
                        assembly:str,
                        regs:Registers,
                        color:int,
                        tainted:bool,
                        count:int):

        # TODO the current key for **addr** dict 
        # is crapy. The data set should be moved. 
        # add a count variable that will be used 
        # to reference all inst and their addresses. 
        # this change should be done in a new branch. 
 
        addr_str = '%x_%d'%(addr,count)

        self.addr[addr_str] = { 'assembly': assembly,
                            'regs': regs,
                            'color': color,
                            'tainted': tainted
                           }

    def get_color_map(self) -> dict:

        """
            returns entries {'addr1':'color1', ...}
        """
        
        color_map = dict()

        for k,v in self.addr.items():
            color_map[k]=v['color']

        return color_map

    def generate_color_map(self,
                           color:int=0x00000000) -> dict:

        """
            return a color map indexed by all executed address.
            used to print the trace on the graph.
        """


        color_map = dict()

        for k in self.addr.keys():
            color_map[k] = color

        return color_map



class Exec_Trace_Serializer(json.JSONEncoder):

    def default(self,exec_trace:Exec_Trace):
        out = dict()
        out['arch'] =  exec_trace.arch,
        out['addr'] = dict()
        for k,v in exec_trace.addr.items():
            out['addr'][k]=dict()

            out['addr'][k] = { 'assembly':v['assembly'], 
                                  'regs': v['regs'].__dict__,
                                  'color':v['color'],
                                 'tainted':v['tainted']
                                   }
        return out

    @staticmethod
    def dump_to_file(exec_trace:Exec_Trace,
                     filepath:str):
        try:
            with open(filepath,'w+') as fout:
                fout.write(json.dumps(exec_trace,cls=Exec_Trace_Serializer))
        except Exception as e:
            print('[!] errror serialization exec_trace object')
            print(e.__str__())






