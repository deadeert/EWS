![c](EWS/doc/img/Logo_EWS.png) 

 
 
 
EWS (*Emulator Wrapper Solution*)  is a plugin that aims to integrate emulation features (such as debugger) 
from various emulators (currently unicorn, but you can add more). 

# WIP 

**Code is currently in refactoring, please stay tuned for a stable release**. 

# Help Wanted

**There is loooot of bugs**

Testing such a IDA plugin for each supported architecture is is
quite difficult to achieve alone. 

**Please open issue or make better PR :)**

# An example 

https://user-images.githubusercontent.com/6783156/198288491-7e9b3059-7ab0-4c1f-9e08-7a645a8799e8.mov

![Working Video](EWS/doc/img/EWS_basic_usage.mov) Github failed to import correctly the video. 

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


# Doc

[Features](EWS/doc/features.md)

