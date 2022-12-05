```
               _       _       
 ___  ___ _ __(_)_ __ | |_ ___ 
/ __|/ __| '__| | '_ \| __/ __|
\__ \ (__| |  | | |_) | |_\__ \
|___/\___|_|  |_| .__/ \__|___/
                |_|            
```

# Go to section
* [Overview](#overview) 
* [1. Requirements](#requirements)
* [1.1 Os](#os)
* [1.2 Script](#script)
* [2. Writing a script](#writing-a-script)
* [2.1 Example](#example)



# Overview
Scripts are what plugins run in order to do something against a target. Scripts is plural, thus several scripts can be executed by each plugin.

## Requirements
Before scripts are run, there is a check being done on the target.
#### OS
Winrm: check for major version of powershell (set by ps_version in config. Defaults to powershell 3)
Ssh: check if python exit (set by python_versions in config. priority matters, e.g if python3 is found, do not check for python2)
#### Script
1. The scripts must output json format.
2. The scripts should have error control to make it never crash.
3. The scripts are merged into one response returned from the plugin.

## Writing a script
The scripts that are run on the target, thus are dependent on what is installed on the host. Potentially everything you can do through a plugin-connection you can do with a script. The script should return output in json-format.
### Example
using ssh as our plugin we are gonna make two plugins. one that shows which operatingsystem is run on the target, and one that lists the local time on the host:

ostype.py

````
import json
import platform

mydict = {}
mydict['os_type'] = platform.system()
print(json.dumps(mydict))

````
output will be something like: **{"os_type": "Darwin"}**

localtime.py

````
import json
from datetime import datetime

mydict = {}
mydict['local_time'] = str(datetime.now())
print(json.dumps(mydict))
````
output will be something like: **{"local_time": "2020-10-07 16:49:18.903237"}**

if config file is something like:

````
input:
  - ssh:
      port: [22]
      username: rnd
      scripts:
        - ostype.py
        - localtime.py

````

ssh plugin will then merge these outputs to: **{"os_type": "Darwin", "local_time": "2020-10-07 16:49:18.903237"}**

**note** If two scripts contains the same level 0 key, the script that runs last will override the previous output.

