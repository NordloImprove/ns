```
                      _                                            _            
 _ __   ___  _ __ __| |___  ___ __ _ _ __         ___ _ __   __ _(_)_ __   ___ 
| '_ \ / _ \| '__/ _` / __|/ __/ _` | '_ \ _____ / _ \ '_ \ / _` | | '_ \ / _ \
| | | | (_) | | | (_| \__ \ (_| (_| | | | |_____|  __/ | | | (_| | | | | |  __/
|_| |_|\___/|_|  \__,_|___/\___\__,_|_| |_|      \___|_| |_|\__, |_|_| |_|\___|
                                                            |___/                         
```
# Section
* [Overview](#overview)
* [Plugins](#plugins)
* [Config](#config)
* [Code](#code)
* [Environment](#environment)
* [Compiling](#compiling)
* [Future](#future)

## Overview
nordscan-engine is a wrapper around nmap. Nmap is a network scanner. Nordscan parses the xml-output from nmap during execution, to find hosts. The engine uses the info supplied by nmap, to execute plugins on a specifik host. The plugin could be using anything that relates to what nmap finds. Currently the plugins are limited to SMTP, WinRM and SSH. Plugins for SSH and WinRM can also run independent scripts and merges that output, before its send to the output plugins. 

## Hosts
There are 3 ways to supply nordscan with hosts. 

- scan an ldap server for hosts.
- hosts in config.
- hosts_file with path in config.

Read nmap documentation on what syntax can be used. If ldap is given, a temporary file will be generated, containing the ldap hosts with a valid dnsentry, and if a hostfile is given, the temporary file will merge that too. All three ways can be used at the same time.

## Plugins
Every plugin that runs should return list with runtime errors, and a response from the host. This is then forwarded to the output plugin queue. To be efficient nordscan uses 2 threadsafe queues. One queue for the input-plugins, and one queue for the output-plugins.

### WinRM
Winrm plugin can use kerberos or ntlm to authenticate. If kerberos is used, reverse lookup needs to be working on the network, as kerberos uses valid dnsnames of hosts for authentication. Kerberos tickets can also be used. Please note that nordscan will not make the ticket, only use valid tickets. How to create or renew kerberos tickets is outside this howto.

### SSH
Ssh plugin works like most ssh-clients do. If you dont use username, the name of the user running the process will be used. If no authentication is given it will try ssh-agent. Else password or key needs to be given.

## Config
Each option that can be used in nordscan or plugins should be documented in the config/config_example.yml.

## Code

Nordscan is written purly in python. There is a certain coding style and a way do to things. If you add code, please make sure it follows the same style and way of doing things. Also make sure that your editor has flake8 support. We are using PEP8 standard for the source-code, except we allow 120 lines instead of the default 80 lines.

## Environment

The program needs a virtual environment. It will lock the version of a specifik library. This is to make sure that the environment in development is run the same way a release will be run. Examples are how to use and upgrade the environment in linux. Its basically the same in windows, and setup.ps1 is also supplied in the bundle.

### Creating

``` ./setup.sh ```

Will make a folder in the directory called .env, and the current environment will be installed. Setup process will install all the files specified in requirements-linux.txt. setup.ps1 will install all the files specified in requirements-windows.txt.

### Using

Please note that the flags are not mutually exclusive (except --help)

To get help on what parameters you can use

```
./nordscan --help
```
Run all input and output plugins but logic in the plugins can determine what to do if the print-flag is used. Its mostly used when developing new plugins or scripts, without sending everything to logstash. There is a global variable that is imported and can be shecked checked in each plugin (config.debug_print).
```
./nordscan --print 
```

Dry run was added mostly for debugging ldap connections. It prints the file of what hosts that was found, and only prints what nmap command to run, but never actually runs it.

```
./nordscan --dry-run 
```

### Upgrading
To make it easy to upgrade all packages in an environment its good to make an alias that looks like this:

```
alias pip-upgrade-venv='pip freeze | cut -d'\''='\'' -f1 | xargs -n1 pip install -U'
```

To upgrade simply enter the environment and run that command:

```
source .env/bin/activate
pip-upgrade-venv
deactivate
```

To save it as the standard way of doing future installs use something like:

```
source .env/bin/activate
pip freeze > linux-requirements.txt
deactivate
```

Note that you should testrun on both linux and windows when you decide to do an upgrade of the environment, and also generate one file for each of these systems (on that platform).

### Adding dependencies
To add a dependency you should use a library that is platform independent (if possible). It will have to be added to requirements.txt as that file is used to to create the requirements for each platform. This file can be used to create new requirement files, and can also contain logic about what packages to install on what platforms (according to the python requirements file syntax).

## Compiling

Nordscan can be compiled using pyinstaller to create a binary for a system (currently only windows is tested). Read the documentation on how this works from pyinstaller, and check the .specs file. If dependencies are added, make sure the compile process still works.

## Future
nordscan-engine is written with the purpose to be a generalised way to wrap around nmap and write plugins based on its output. Currently it only reads data on the hosts, and every host is run against every plugin. The possibility to add other plugins (or scripts) that are run are basically endless. Be creative!


## Tips & Tricks
Testing a script from linux on a remote linux box:

```
cat src/scripts/linux.py | ssh user@host python -
```