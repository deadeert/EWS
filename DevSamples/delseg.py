import ida_segment


for i in range(0,3):
    print("create")
    ida_segment.add_segm(0,0x9FF00000,0x9FF01000,'Suce','STACK',0)
    
    if ida_segment.getseg(0x9FF00000) != None: 
        ida_segment.del_segm(0x9FF00000,1) 
        print("del")
