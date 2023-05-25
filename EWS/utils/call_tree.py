from enum import Enum
import json

class CTT(Enum):

    CALL=0
    RET=1
    INFO=2



class Call_Tree():


    count = 0
    content = dict()

    def __init__(self):

        pass

    def add_entry(self,
                  trace_id:int,
                  addr:int,
                    depth:int,
                    typ:CTT,
                    target:int=0,
                    info:str=''):

        self.content[self.count] = {}
        self.content[self.count]['trace_id'] = trace_id
        self.content[self.count]['addr'] = addr
        self.content[self.count]['depth'] = depth
        self.content[self.count]['type'] = typ.value
        self.content[self.count]['target'] = target
        self.content[self.count]['info'] = info

        self.count+=1 




        
class Call_Tree_Serializer(json.JSONEncoder):

    def default(self,call_tree:Call_Tree):
        out = dict()
        out['count'] = dict()
        for k,v in call_tree.content.items():
            out['count'][k]=dict()

            out['count'][k] = { 'trace_id':'trace_id',
                               'addr':v['addr'],
                               'depth':v['depth'], 
                               'type': v['type'].value,
                                'target':v['target'],
                                 'info':v['info']}
        return out

    @staticmethod
    def dump_to_file(call_tree:Call_Tree,
                     filepath:str):
        try:
            with open(filepath,'w+') as fout:
                fout.write(json.dumps(call_tree,cls=Call_Tree_Serializer))
        except Exception as e:
            print('[!] errror serialization exec_trace object')
            print(e.__str__())


class Call_Tree_Deserializer(json.JSONDecoder):

    def decode(self,json_txt):

        jdict = json.loads(json_txt)

        trace = jdict['count'] 

        call_tree = Call_Tree()

        for k,v in trace.items():

            i_cnt = int(k,10)

            trace_id = v['trace_id']
            addr = v['addr'] 
            depth = v['depth']
            typ = v['type']
            target = v['target']
            info = v['info']

            call_tree.add_entry(trace_id,
                                addr,
                                depth,
                                CTT(typ),
                                target,
                                info)

        return call_tree



        










