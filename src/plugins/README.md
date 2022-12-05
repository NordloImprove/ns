```
       _             _           
 _ __ | |_   _  __ _(_)_ __  ___ 
| '_ \| | | | |/ _` | | '_ \/ __|
| |_) | | |_| | (_| | | | | \__ \
| .__/|_|\__,_|\__, |_|_| |_|___/
|_|            |___/             
```

# Go to section
* [Overview](#overview) 
* [1. Requirements](#requirements)
* [1.1 Folder](#folder)
* [1.2 Plugin](#plugin)
* [2. Writing a plugin](#writing-a-plugin)
* [2.1 Example](#example)



# Overview
Plugins can be of two types. input or output. All plugins run against all hosts, but most plugins check for specifik open ports in the beginning och the run funcion, and exits if non are found. Output plugins can take a response from an input plugin, and do something with it (for example sending it to a database or an api).

## Requirements
Plugins have a few requirements.
#### Folder
Before any plugin can be used it has to be put in the right folder.
src/plugins/input is the folder used for input plugins.
src/plugins/output is the folder used for output plugins.

#### Plugin
1. Plugin nees a "run"-funtion that takes a host_address, a host-object (from nmap) and a plugin config.
2. Plugin should never crash the main function. Thus a complete error-control for the run function is needed.
3. Plugin should return two things: output (dictonary) and error (list).
4. Plugins can have a dictionary of defaults that will be used if no specific values are given.

## Writing a plugin
Plugins are initialized first, then run against all targets. There is a PluginBase-class that can be useful to inherit. It helps with defining the requirements for a plugin. A good way of doing a new plugin is to check how the existing plugins are made, and try to adapt that strategy when writing it.

## Example
````
input:
  - ssh:
      port: [22, 6022]
      username: rnd
      scripts:
        - ostype.py
        - localtime.py

````

All settings under a specific "plugin" will be sent to the plugin with a corresponding name. Its up to the designer of the plugin what options should be available to the end user.


