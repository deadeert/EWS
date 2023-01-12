from EWS.utils.registers import *
import json



class Exec_Trace(object):

    arch = ''
    content = dict()

    def __init__(self,arch,content=None):
        self.arch = arch
        self.count = 0
        if content:
            self.content=content


    def add_instruction(self,
                        addr:int,
                        assembly:str,
                        regs:Registers,
                        color:int,
                        tainted:bool):


        self.content[self.count] = { 'addr': addr,
                                 'assembly': assembly,
                            'regs': regs,
                            'color': color,
                            'tainted': tainted
                           }
        self.count += 1

    def get_color_map(self) -> dict:

        """
            returns entries {'addr1':'color1', ...}
        """
        
        color_map = dict()

        for k,v in self.content.items():
            color_map[k]=v['color']

        return color_map

    def generate_color_map(self,
                           color:int=0x00000000) -> dict:

        """
            return a color map indexed by all executed address.
            used to print the trace on the graph.
        """


        color_map = dict()

        for k in self.content.keys():
            color_map[k] = color

        return color_map



class Exec_Trace_Serializer(json.JSONEncoder):

    def default(self,exec_trace:Exec_Trace):
        out = dict()
        out['arch'] =  exec_trace.arch,
        out['count'] = dict()
        for k,v in exec_trace.content.items():
            out['count'][k]=dict()

            out['count'][k] = { 'addr':v['addr'], 'assembly':v['assembly'], 
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






