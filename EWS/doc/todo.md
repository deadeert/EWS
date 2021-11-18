



Code introspection:

Analyze the all code and pick-off all the available features.
Add it to the features.md file with the associated documentation. 


Syntax Refactoring:

Modify the CamelCase fashion to uniformise with the underscore_case. 


Logging: 

Logging should be done inside a file. 
Logging level can be modified to select which data when and where it is written to. 


Code Indentation 

It's a totally mess, cannot be released like this. 

Code Clean, Code Homogenize 

A lot of features must be deprecated/useless -> remove it
A lot of code duplication occured.
Some part of code might be factorized. 


New Features: 

#CustomView see CustomView.md
The objective is to avoid outputing data in console. 

#Remove artefact when plugin closes:
Examples of artefacts :
- Color of executed instruction 

#Add xml configuration for preferences 
Maximum number of executed instructions MAX_EXEC
Follow PC while debugging FOLLOW_PC


#Move plugins in persistent folder 
avoid reinstalling the plugin each time IDA is updated.
move it to ~/.idapro/plugins folder. 

# Integrate Stub in trace_exec 

# Default Configuration enhancment 
Function generate_default_config could return a Configuration object 
based on a default xml file. one per architecture. It will be easier 
for the end user to modify the default conf for each arch. 
