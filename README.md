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
* [Components](#components)
* [OS Requirements](#os-requirements)
* [Installation](#installation)
* [Need Help?](#need-help)
* [Tips and Tricks](#tips-and-tricks)

# Overview
nordscan-engine is a wrapper around nmap. Nmap is a network scanner. The idea is to let nmap scan for services on a network, and try to connect to the services if ports are open to investigate them further. After connecting nordscan-engine can run various scripts, and catch the output from each host. That output is sent to the output plugins (for example to logstash).

## Scanning strategy

1. Pingsweep devices on desired network.
2. If host is up, scan ports.
3. Try to connect with desired plugins and run test. If test successful run scripts.
4. If error or result send that to output (currently logstash).

#  Components
## Input plugins
- SSH: [ssh2-python](https://github.com/)
- WinRM: [pypsrp](https://pypi.org/project/pypsrp)

## Output plugins
 - Logstash (possibility to print to terminal instead of sending)

# OS requirements
nordscan-engine runs on any system that can run nmap, and python 3.

## nordscan-engine Host
 - Linux host
 - Python 3.6+
 - nmap installed
 - sudo nmap rights for the user running nordscan (without password prompt)
 - AD joined (if used method for WinRM is kerberos authentication)

## WinRM Guest
 - Windows Operating System
 - Powershell 3 (or later)
 - Port for WinRM open (default port 5985)
 - Kerberos or NTLM enabled (preferably through GPO)
 - AD joined (if used method for WinRM is kerberos ticket authentication)
 - Local admin rights for the user logging in (to be able to login via WinRM)

## SSH Guest
 - GNU / Linux
 - Python 2.7 or 3
 - port for SSH open (default port 22)
 - sudo dmidecode rights for the user logging in (without password prompt)

# Installation
nordscan-engine is released under GPLv2 license. Installation is relativly simple. Just download the latest release archive, and run setup-script (for your platform) in that folder. This will create a ".env"-folder in that directory which contains the runtime environment. After this is done nordscan-engine needs a config file (look in example folder). When the config is set run it with: /<path>/nordscan --config <path_to_config>. There are also examples on how to setup a nordscan-service for systemd, and put it on a schedule.

## Windows Host

### Prerequirements
 - Python 3.6+ installed with the checkbox add Python to PATH from [python.org](https://www.python.org)
 - Nmap for Windows from [Nmap.org](https://nmap.org)

### Installation
1. Download latest version from nordscan-engine Releases.
2. Unzip it. Move it to a desired installation folder.
3. Run setup.ps1 in the folder
4. copy the file examples/config_example.yaml to config.yaml
5. Edit config.yaml to your needs
6. run with nordscan.ps1 --config config.yaml
7. Done

## Linux Host

### Prerequirements

A few packages needs to be in installed on the nordscan-engine host before it can be installed:
```
sudo apt install python3-venv nmap gcc python3-dev libkrb5-dev gss-ntlmssp
```
### Installation
1. Download latest version from nordscan-engine Releases.
2. Unzip it. Move it to a desired installation folder.
3. Run setup.sh in the folder
4. copy the file examples/config_example.yaml to config.yaml
5. Edit config.yaml to your needs
6. run with nordscan --config config.yaml
7. Done

### Running as a Service

There are examples on how to turn nordscan-engine into a service in the directory systemd. Depending on if you want to separate different scans, or run it as a pure service. These filescan be be added and enabled in systemd. The only reason to create separate services is if you have a need to create different config files for different scans (e.g separating servers/clients etc).

```
# create logdir
sudo mkdir /var/log/nordscan && sudo chown $(id -u) /var/log/nordscan
# copy service template to systemd directory
sudo cp /opt/nordscan/examples/nordscan.service /etc/systemd/system/
# start/stop
systemctl start/stop nordscan.service
# status
system status nordscan.service
# enable/disable at boot
systemctl enable/disable nordscan.service
```

## Updating from zip
**Remember to stop any running services before updating version.**

1. Make sure to backup the config.yaml or other files yoy have edited.
2. Replace folder with a newly downloaded one.
3. run setup script again
4. Done


# Need help?
```
<path_to_binary>/nordscan --help
```


# Tips And Tricks
## Output to a textfile (instead of sending)

```
/opt/nordscan/nordscan --config ~/.nordscan/config.yaml --print --no-split > /tmp/nordscan-test.json
```

## Testing if ports are open against a client/network

```
sudo nmap 192.168.0.1/24 -p 22,5985
```

## Dry-run
This function was mainly added for finding hosts through LDAP (Active directory). --dry-run will look for hosts through ldap and print what the nmap command would be. But the nmap command is not executed.

```
/opt/nordscan/nordscan --config ~/.nordscan/config.yaml --dry-run --log-level debug
```







