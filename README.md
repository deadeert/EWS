


![c](EWS/doc/img/Logo_EWS.png) 

 
 
 
EWS (*Emulator Wrapper Solution*)  is a IDA PRO plugin that aims to integrate emulation features (such as debugger) 
from various emulators (currently unicorn, but you can add more).  

https://user-images.githubusercontent.com/6783156/212289883-31b8a3b5-0c7d-451d-9569-d661a64a5f25.mp4

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
pip install -r requirements.txt
```

## IDA Plugin

Copy folder `EWS` and `EWSPLugin.py` in your `$IDA_HOME/plugin` (generally corresponding to `$HOME/.idapro`).

## Smoke test

In the default graph view, execute the key combination `CTRL+ALT+E` to get the `ews` menu when you trigger
rigth click. 
You should be ready to go. 
Otherwise, check the console, something mysterious might have happened...


# Features & Documentation

[Features](EWS/doc/features.md) 

**stub mechanism**  

You can null stub, use a ready or own defined stub or even "tag" a function. 




# WIP 

**Code is currently in refactoring, please stay tuned for a stable release**. 

Code refactoring is okay for: 

- x86
- arm32
- aarch64

x64 has not be refactored neither tested, so use it at your own risk.


# Submit an Issue (bug) 

Before submitting an issue, keep in mind that: 

- I'm not actively working on the project, according the bug you could be faster than me to find the solution :]
- I need to reproduce the bug, so be kind an provide a configuration file and the binary that you was working on when finding out the bug (if possible). Otherwise, it will be a nightmare. 
