# EWS 

Stands for Emulation Wrapper Solution. 


## Description 

Binds IDA PRO to an emulator solution. 
Currently only unicorn is supported. 
It offers stubs mechanism for Linux and windows environment (experimental). 


Supported architectures are:

- ARM
- AARCH64
- X86
- X64 

Works on IDA PRO 7.6

## Install 

Copy EWS folder and EWSPlugins.py file inside IDA PRO' directory. 

## Features

### Stubs

- Got entries are parsed and either stubbed when a stub is available for this symbol, or is null stubbed (direct return) if not. 
- It is possible to tag a function, it means associate a reversed function to a well known function. 
- It is possible to null stub function, useful when for instance the function has no incidence on what you are analyzing. 

For Windows, an experimental mechanism exist. It should be tested and completed.

### Debugging 

- Basic feature are implemented, start(), step_in(), step_over(), restart(). 
- Memory patching is also available
- Memory inspecting is available, but not for the additionnal mapping and stacks, because I mess up with segments and IDA. I have an issue which I don't understand when allocating and deleting segment. 


### Loading / Running 

- Auto loading using IDB content. 
- Auto configure RAM and associated registers. 
- Can emulate selection or functions
- A run from begining exist for x86 architecture, but should be implemented for the others

### Save / Load Configuration

- Can save current emulation configuration. Useful to share emulation config between several users, or to remind point of interests in the IDB. Honestly, it was developed to ease the testing and the implementing of the feature. 

### Usage 

- Can be used either in graphical mode or in UI. 
- Shortcuts are available to speed up navigation and execution. 

## Disclaimer 

** Please backup your IDB before using this tool !!!**

There is a lot of bugs, and I want now to focus on other topics. 
This might not work the first time, and might require to tweak a little bit the code. 
I developped this code on my freetime, but with not really regularity. Because developping such wrapper between two solutions is quite anoying and very rewarding at the end... I think it's time for me to move to other stuff. 

This project is not maintained anymmore, but it is opensourced because 
it can be a good base to integrate other emulator to IDA PRO, or to emulate/trace/debug program inside IDA PRO.


If people are interrested in the project, want to help correct bugs and stuff, 
you are more than welcomed. I won't spend anytime in the near future, but lets 
see if I find some time later...

## Keywords

IDA PRO (https://hex-rays.com)
unicorn engine (https://github.com/unicorn-engine/)


