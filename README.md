

<p align="center" >
     <br><br>
<img width="60%" src="EWS/doc/img/Logo_EWS.png"/> <br>
 </p>
 
 # About
 
EWS (*Emulator Wrapper Solution*)  is a IDA PRO plugin that aims to integrate emulation features (such as debugger) 
from various emulators (currently unicorn, but you can add more). 

Writting such plugin was motivated by reversing on x64 machine various embedded binaries from Android native libs to
automotive firmwares. "Click ready" trace generator and basic explorer is a gain of time.  

Key features are: 

1. Support Raw and ELF file. PE is experimental, no support for Mach-O. 
2. Automatically loads binary inside the emulator based on IDB information.  
3. Debugger view with registers' values for each executed instruction. 
4. Debugger capacities such as watchpoints, run / steps the code. 
5. Stub mechanism to emulate imported functions. 

# Getting Started

- [Demonstration](#demo)
- [Features](#features)
- [Installation](#installation)
- [Shortcuts](#shortcuts)
- [Documentation](EWS/doc/features.md) 
- [Extend-me](#extendme) 
- [Contact](#contact)

# Demo  

https://user-images.githubusercontent.com/6783156/212289883-31b8a3b5-0c7d-451d-9569-d661a64a5f25.mp4


# Features

## Debug

This example shows how to recover original strings from encrypted payload using emulator. 

https://user-images.githubusercontent.com/6783156/212301420-5dc397ca-dc65-4408-ad77-82e035386622.mp4

This example demonstrates watchpoint feature. The feature is also available when data is manipulated inside 
a stub.

https://user-images.githubusercontent.com/6783156/212301575-b6e1c417-75cf-4fc7-a825-078fad76ecb0.mp4

IDA Pro breakpoint marker is directly integrated in the plugin.

https://user-images.githubusercontent.com/6783156/212301728-fc99f02a-eef8-40e8-a1dd-4c0601519f60.mp4

Memory can be imported and exported. In this example memory range corresponding to the string is exported. 

https://user-images.githubusercontent.com/6783156/212303397-af887b75-6555-489c-aca0-b502b2644974.mp4

## Stubs Mechanisms   

Some functions from the libc are directly emulated by the stub mechanisms. Stub can be added by using decorator `@LibcStub` 
in files `stubs/ELF/ELF.py`.

https://user-images.githubusercontent.com/6783156/212301041-0a86ba45-4e25-4389-8d49-f190f6a8c4a7.mp4

This example shows how to attribute a tag to a function. `strlen` is applied to the example function. 

https://user-images.githubusercontent.com/6783156/212301210-c9a8b7df-7ebd-4fce-aced-4b7cfced0744.mp4


## Configuration 

Configuration can be edited, stored, loaded. This allows to share with other reversers findings. 

https://user-images.githubusercontent.com/6783156/212310072-520313d1-667a-401b-b26b-cff97838512e.mp4

## More

You can find an exhaustive list of features. 
[Features](EWS/doc/features.md) 


# Shortcuts 

1. Load Context Menu `Ctrl+Alt+E`
2. Reset Plugin `Alt+Shift+R`
3. Generate Configuration from Selection `Ctrl+Alt+S`
4. Generate Configuration for current Function `Ctrl+Alt+F`
5. Edit Configuration `Ctrl+Alt+C`
6. Load Configuration `Shift+Alt+L`
7. Store Configuration `Shift+Alt+D`
8. Run / Continue `Alt+Shift+C`
9. Step-In `Alt+Shift+I`
10. Step-Over `Alt+Shift+O`

# Installation 

## Dependencies

Please install manually the following python packages: 

- hexdump   
- dateutil 
- lief

Please install the following python bindings: 

- unicorn engine (install python bindings `bindings/python/setup.py install`)
- capstone engine (install python bindings `bindings/python/setup.py install`)
- keystone engine (install python bindings `bindings/python/setup.py install`)

If you are lazy, you can directly install them: 

```sh 
pip install -r doc/install/requirements.txt
```

## IDA Plugin

Copy folder `EWS` and `EWSPLugin.py` in your `$IDA_HOME/plugin` (generally corresponding to `$HOME/.idapro`).

## Smoke test

In the default graph view, execute the key combination `CTRL+ALT+E` to get the `ews` menu when you trigger
rigth click. 
You should be ready to go. 
Otherwise, check the console, something mysterious might have happened...


# WIP 

**Code is currently in refactoring, please stay tuned for a stable release**. 

Code refactoring is okay for: 

- x86
- arm32
- aarch64

x64 has not be refactored neither tested, so use it at your own risk.


# Submit an Issue (bug) 

Before submitting an issue, keep in mind that: 

- I'm not actively working on the project, depending the bug you could be faster than me to find the solution :]
- I need to reproduce the bug, so be kind an provide a configuration file and the binary that you was working on when finding out the bug (if possible). Otherwise, it will be a nightmare. 

# Extend Me

- **Offline trace explorer**: Allow to load trace generated outside the plugin. Support is currently planned. 
- ![Avatar2](https://github.com/avatartwo/avatar2): Integrate new emulator Qemu wrapper would help in supporting new architecture.  
- Integrate offline ghidra debugger when it will be available to extend supported architectures.

# Contact 

![@deadeert](https://twitter.com/DeadEert)
