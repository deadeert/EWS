import ida_funcs


f=ida_funcs.get_func(0x40A7F0)
print('%x'%f.end_ea)
i=ida_funcs.func_tail_iterator_t(f,0x40A7F0)
print(i)
b=True
while b:
    c=i.chunk()
    print('chunk from %x to %x '%(c.start_ea,c.end_ea))
    b=next(i)
