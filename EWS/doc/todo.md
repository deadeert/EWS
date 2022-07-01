



# Code introspection:

Analyze the all code and pick-off all the available features.
Add it to the features.md file with the associated documentation. 


# Syntax Refactoring:

Modify the CamelCase fashion to uniformise with the underscore_case. 


# Logging: 

Logging should be done inside a file. 
Logging level can be modified to select which data when and where it is written to. 


# Code Indentation 

It's a totally mess, cannot be released like this. 

# Code Clean, Code Homogenize 

A lot of features must be deprecated/useless -> remove it
A lot of code duplication occured.
Some part of code might be factorized. 

# Configuration: 

## Lock configuration 
Once the plugin has been initied, the configuration cannot be edited /loaded.
the plugin must be reset. 
The plugin configuration object is the one to be modified. it is then used
to instancied to create the emulator. 


## Rework UI: 
- Select Segment (if map with seg allowed)
- Edit Registers 
- Edit Stub Configuration
-

## Stub configuration:

Option: 
- Allow / Disallow stub mechanism
- Stubs symbols (for ELF/PE)
- Auto stub missing symbols (for ELF/PE)
- Tag address for the record. 

Must modify the stub configuration object. 

## Save configuration 
Save the current plugin configuration from the emu: 
- Initial register values (from the conf)
- Watchpoint (add information to the conf when created)
- Null stubs (idem)
- Tags  (idem)
- Additionnal memory sections (idem)
- stdio 




New Features: 

# CustomView see CustomView.md
The objective is to avoid outputing data in console. 

# Remove artefact when plugin closes:
Examples of artefacts :
- Color of executed instruction 

# Add xml configuration for preferences 
Maximum number of executed instructions MAX_EXEC
Follow PC while debugging FOLLOW_PC


# Move plugins in persistent folder 
avoid reinstalling the plugin each time IDA is updated.
move it to ~/.idapro/plugins folder. 

# Integrate Stub in trace_exec 
Just add in assembly output, at the stub address, the stub name
ex: 
  jmp r3 (<stub name>)

# Integrate watchpoint in trace_exec
Just add in assembly output that the instruction concerned a 
watchpoint information.

# Default Configuration enhancment 
Function generate_default_config could return a Configuration object 
based on a default xml file. one per architecture. It will be easier 
for the end user to modify the default conf for each arch. 

# Add listener event on instruction trace
Could be nice to have a UI binding of both registers and graph view 
when the user enters arrow up and down to browse the trace in the 
instructions trace widget.

# STDIN 

Stack stdin values (one poped eachtime function access the stdin fd (0))

# Patching

Introduce a new patching system to patch target instructions. 
The patching mechanism must be abstract in oder to garantee that
any assembler mechanism can be integrated.

Idea add decortator 
@assembly(name=keystone, target_arch=arm)


# Caching
Introduce a cache system to retain information for a dedicated binary:
- watchpoint 
- patches 
- breakpoint 
- additionnal mappings? 

# Save / Restore

Add a feature to save and restore memory (all segments).
Allow to import a give state at a given address.
Define a format:
- register' values.
- mapped memory section (including the ones added / imported by the user)

```json
{
  "addr":[
  "addr1": { "regs" : [], "mems": { "sec_addr1" : "mem1", ...}    

    },
  "addr2": { ... }, "mems": { ... }  
  ]

}
```




# Modify unmapped strategies

Allow user to select among several strategies:
- provide the value each time an unmapped is accessed
- silently map (already supported)
- raise Exception  (already supported)


# Export conf to emulator conf


# Beautiful UI

CoverageTableModel (lighthouse/ui/coverage_table.py)
