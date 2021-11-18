
https://hex-rays.com/blog/using-custom-viewers-from-idapython/

The objective is to dock a view with all the assembly and registers value with syntax highlighting. 
and views' synchronisation. 

#Syntax Highlighting

- Modified register in red 
- Address in black
- Instruction in blue and operand green

exemple: 

```asm
0x0: ldr r0, [sp, #-4] ; r0 = xx r1 = yy, r2 = xx, r3 = xx 
                       ; r4 = xxx
                       ; r8 = 
                       ; r12 = 
0x4: blx 0x1235        ; r0 = ...
```

# Coloration of the main graph view 

The main graph view must be colored accordingly the execution. 
**AddPopup** or **AddCommand** could allow to restore original color. 


# Debugging mode 

custom viewer offers feature to insert dynamically lines. (must be confirmed)
All step-in, continue execution must have effect to the the custom view. 

# Synchronisation 

Synchronisation between custom view lines and graph ea can be activated. 
Warning the correspondance of ea and line numbers will depend on the quantity of lines
required to print a single instruction. In prior example, #line = ea*4

UI_Hooks object allows to register callback for specific action. 


```python
    def get_lines_rendering_info(self, out, widget, info):
        self._log("get_lines_rendering_info()")
        """
        take action here
        """

    def screen_ea_changed(self, ea, prev_ea):
        self._log("screen_ea_changed(%x %x)"%(ea,prev_ea))
```



# Define the structure of trace execution. 

json object can be used to represent each executed address: 

```json
{
  "arch": "arm",
  "addr": {
      "0x1234": 
        {"assembly":  "pop {lr}", 
         "regs": {
          "r0":0x0,
          "r1":0x1
         },
        "color": 0xFFEEFFEE,
        "tainted": True
        } 
  } 
}
```

# Add the trace execution structure path to the runtime. 

The json file will be loaded and parsed in the custom view. 

# Integrate it to the emulation engine

**hook_code()** in `generic.py`




