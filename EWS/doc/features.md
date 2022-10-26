# Available Features 

## Configuration 

### Import / Export 



## Debugging

### Execution control 

Like any debugger you can run the following command: 

- **Continue/Run** (`Alt+Shift+C`)
- **Step-in** (`Alt+Shift+I`)
- **Step-over** (`Alt+Shift+O`)

Take into account that Step-Over is not covering 100% of 
the situation, so use it wisely (or do a PR :) ). 


### Breakpoint

Breakpoint can be set using the IDA Pro shortcut (default is `F2`). 
The emulation will stop **before** executing the command.

### Watchpoint

You can use watchpoint to various memory area, there is no limit (one of the few advantages of emulation).
Like common CPU you can activate it either in read and/or write access fashion. 

The shortcut to activate the feature is `Alt+Shift+W`

## Memory

### MemoryExport

You can export some part of the memory. 

### MemoryImport:

You can i###mport memory from **already** mapped area.
To map a new memory area use the feature to add a new mapping (shortcut is `Ctrl+Alt+A`). 

### Memory Display 

There is few features to display memory: 

- Specified address 
- Stack
- Memory Segment (use IDA segment information). 

### Patch Memory 

The emulator uses the binary file to initialize the memory of the emulator. 
As a consequence, any patch done on the IDB won't be considered when the emulator is 
initialized. 

Once the emulator is initialized, you can patch the memory in two seperate way: 

- **Data Patch** (or raw patch): the user provides the bytes in bin hex ascii representation,
each byte being separated by a whitespace. Ex: DE AD BE EF. (`Ctrl+Alt+M`) 
- **Instruction Patch:** the user can directly enter assembly. The engine benefits from a `keystone-engine` 
backend.(`Ctrl+Alt+P`)  

Another feature allows to import a json file with a record of addresses and their corresponding assembly. 


## Stubs Mechanism 

### Implementation Information 
Each supported architecture benefits from a stub mechanism. 
The current design allows to only write a generic stub which will 
be available for each architecture. 

Further improvements could be achieved to also support several calling convention,
but this is not planned. 

To add a stub, the user should reach either `stubs/ELF/ELF.py` or `stubs/PE/PE.py` file 
according to the environment. 

*Note*: Even if the binary is not using a loader, the stub mechanism still available, 
which limited features (it does not automatically patch symbols table). 

The stub receive a `helper` object which primitives that allow to access the arguments. 
This is where the architecture abstraction occurs. 

By default the stub engine will use LIEF to figure out where are the symbols table (either 
the got.plt table or the IAT according to the arch). 

Note: Windows support is very experimental, do not hesitate to PR if you would give an hand. 
I'll not handle Windows related issues, sorry... 

From here; it will either stub the symbols if it is available. Otherwise, the engine will 
put a null-stub (a direct return). 

The stub strategy depends on the architecture, please refer to the stub related functions in `emu/<engine>/<arch.py>` 
file if you are curious.

There is few available features from the stub engine: 

- **null-stub**: you can ask the engine to null-stub a function (even-if it's defined). 
This is useful for example when you know that the function is reading a memory area related to 
a missing peripheral. 
- **tag-function** you can tell the engine that this address correspond to a specific function. 
For example you might find that a function is actually doing allocation. You can tell the engine that
this function is actually `<malloc>/<realloc>`... 

### Allocator 

Yes, there is a dumb allocator available as well...

