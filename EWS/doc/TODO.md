# TODOs

## UI

-Add a console windows to query the emulator. 
-Better UI, anyone ? 

## Standalone Script 

-Make a standalone version of the plugin (running outside IDA),
configuration could be exported from the plugin then imported in 
the script. Evaluate how precious it'll be versus how many time it will take.


## Configuration Lifecycle 

Emulator already instancied: 
 - If the user edit the conf --> extract the conf from the emulator.
 - Need to declare a method for generic.py to query the state of the emulator, 
 for the values that can be modified when the emulator is created: 
   - Registers 
   - Memory Mapping 
   - stub
   - patch data
   - .. 

add a TAG and a PATCH, MAPPING, NSTUB list to generic to keep track these two elements for extract_current_Function 
breakpoint are already included.

This configuration object is then used for configuration edition. 
The emulator is reseted (clean) the view (before doing it ask the user y/n, in case he/she hits the button unintentionnaly. 
Open the edit config view, alert her/him she/he needs to reinstanciate the module.

Emulator not instancied: just edit the current conf object.


!! The config should not be modified at anytime during the execution !! 

## Config Serial / Unserial (not working well)

Now use extract_current_configuration if extracted when the configuration was created.


## libc_start_main for arm / aarch64

