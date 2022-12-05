#!/usr/bin/env python

import subprocess
import sys
import platform
import json
from os import nice

#set lowest priority
nice(19)


def sanitycheck():
    os_type = platform.system()
    if os_type != 'Linux':
        sys.stderr.write('%s is not supported.\n' % os_type)
        return False

    return True


class LinuxInventory:
    def __init__(self):
        self.logmessage = []
        self.dmi_sections = {
            'BIOS Information': {
                'name': 'bios',
                'filter': [
                    'rom_size',
                    'address',
                    'runtime_size'
                ]
            },
            'System Information': {
                'name': 'system',
                'filter': [
                    'version'
                ]
            },
            'Chassis Information': {
                'name': 'chassis',
                'filter': [
                    'oem_information',
                    'thermal_state',
                    'power_supply_state',
                    'security_status',
                    'number_of_power_cords',
                    'contained_elements',
                    'height'
                ]
            },
            'Memory Device': {
                'name': None,
                'filter': []
            },
            'Base Board Information': {
                'name': 'motherboard',
                'filter': [
                    'chassis_handle',
                    'contained_object_handles',
                    'location_in_chassis'
                ]
            }
        }
        self.dmi = self.dmidecode()

    def dmifilter(self):
        data = {}
        if self.dmi:
            dmi_keys = self.dmi.keys()
            for dmi_k, dmi_v in self.dmi_sections.items():
                if dmi_k in dmi_keys:
                    section = dmi_v['name']
                    if section:
                        data[section] = {
                            k: v for k, v in self.dmi[dmi_k].items() if k not in self.dmi_sections[dmi_k]['filter']}

        return data

    def getinfo(self):
        data = self.dmifilter()
        data['platform'] = self.platform_info()
        data['cpu'] = self.cpu_info()
        data['disk'] = self.disk_info()
        data['network'] = self.network_info()
        data['ram'] = self.ram_info()
        data['users'] = self.user_info()
        data['source'] = self.host_info()
        data['os'] = self.os_info()
        if self.logmessage:
            data['error'] = self.logmessage

        return data

    def platform_info(self):
        data = {}
        data['machine'] = platform.machine()
        data['platform'] = platform.platform()
        data['system'] = platform.system()
        data['release'] = platform.release()
        data['python_version'] = platform.python_version()

        return data

    def cpu_info(self):
        data = {}
        cpu_model = []
        cpu_id = []
        cpu_core = []

        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if 'model name' in line:
                        cpu_model.append((' '.join(line.split()[3:])))
                    if 'physical id' in line:
                        cpu_id.append(' '.join(line.split()[3:]))
                    if 'cpu cores' in line:
                        cpu_core.append(' '.join(line.split()[3:]))
        except OSError as e:
            self.error(type(e).__name__, str(e))
        else:
            if cpu_model:
                data['type'] = cpu_model[0]
                data['cores'] = int(max(cpu_core))
            if cpu_id:
                data['count'] = len(set(cpu_id))

        return data

    def disk_info(self):
        data = []
        output = self.run('df -TPB1')
        if output:
            lines = [s.split() for s in output.splitlines()]
            for line in lines:
                if '/dev/' in line[0]:
                    dev_list = {}
                    i = 0
                    for key in [
                        'filesystem', 'type', 'size', 'used',
                        'available', 'capacity', 'mounted_on'
                    ]:
                        try:
                            dev_list[key] = int(line[i])
                        except Exception:
                            dev_list[key] = line[i]
                        i += 1
                    data.append(dev_list)

        return(data)

    def network_info(self):
        data = []
        output = self.run('ls /sys/class/net/')
        if output:
            for interface in output.split():
                if interface not in ['lo', 'bonding_masters']:
                    output = self.run('/sbin/ip addr show dev %s' % interface)
                    if output:
                        interfaceinfo = [s.split() for s in output.splitlines()]
                        ifinfo = {'name': interface}
                        ipv4 = []
                        ipv6 = []
                        for line in interfaceinfo:
                            if 'link/ether' == line[0]:
                                ifinfo['mac'] = line[1]
                            elif 'inet' == line[0]:
                                ipv4.append(line[1].split('/')[0])
                            elif 'inet6' == line[0]:
                                ipv6.append(line[1].split('/')[0])
                        if ipv4:
                            ifinfo['ipv4'] = ipv4
                        if ipv6:
                            ifinfo['ipv6'] = ipv6
                        data.append(ifinfo)

        return data

    def ram_info(self):
        data = {}
        output = self.run('free -b')
        if output:
            for line in [s.split() for s in output.splitlines()]:
                if 'Mem:' == line[0]:
                    data['available'] = int(line[1])
                    data['used'] = int(line[2])
                    data['free'] = int(line[3])

        if 'Memory Device' in self.dmi.keys():
            count = 0
            for line in self.dmi['Memory Device']:
                if 'size' in line.keys():
                    try:
                        mem_size = int(line['size'].split()[0])
                        mem_unit = line['size'].split()[1]
                        if mem_unit == "MB":
                            count += mem_size * (1024 * 1024)
                        elif mem_unit == "GB":
                            count += mem_size * (1024 * 1024 * 1024)
                    except Exception:
                        pass
            if count:
                data['total'] = count

        return data

    def host_info(self):
        data = {}
        data['name'] = self.run('hostname')
        data['domain'] = self.run('domainname')

        return data

    def user_info(self):
        data = []
        output = self.run('who')
        if output:
            for line in [s.split() for s in output.splitlines()]:
                user = {}
                user['username'] = line[0]
                user['logon_type'] = line[1]
                user['logon_time'] = '{0} {1}'.format(line[2], line[3])
                data.append(user)

        return data

    def os_info(self):
        data = {}
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    kv = line.strip().split('=')
                    if(len(kv) == 2):
                        data[kv[0].lower()] = kv[1].strip('\"')
        except OSError as e:
            self.error(type(e).__name__, str(e))

        data['last_boot'] = self.run('uptime -s')
        data['architecture'] = self.run('uname -m')
        data['kernel'] = self.run('uname -sr')

        output = self.run('last -n1')
        if len(output.splitlines()) > 1:
            data['last_login'] = output.split()[0]

        output = self.run('df -TPB1 /')
        if output:
            system_drive_info = output.splitlines()[1].split()
            data['system_drive'] = system_drive_info[6]
            data['system_drive_size'] = int(system_drive_info[2])

        return data

    def error(self, etype, emessage, command=None):
        data = {}
        data['type'] = etype
        data['message'] = emessage
        if command:
            data['command'] = command
        self.logmessage.append(data)

    def run(self, cmd):
        try:
            proc = subprocess.Popen(
                cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stdout, stderr = proc.communicate()
            output = stdout.decode('utf-8').strip()
            if proc.returncode:
                self.error('CommandError', output)
            else:
                return output
        except Exception as e:
            self.error(type(e).__name__, str(e), cmd)

        return None

    def dmidecode(self):
        data = {}
        output = self.run('sudo -n dmidecode')
        if output:
            section = None
            for line in output.split('\n'):
                if not section:
                    if line in self.dmi_sections.keys():
                        section = line
                        s = {}
                elif line:
                    kv = line.split(': ')
                    if len(kv) == 2:
                        k = kv[0].strip().lower().replace(" ", "_")
                        v = kv[1]
                        s[k] = v
                else:
                    # multiple memory modules
                    if section == 'Memory Device':
                        if section in data.keys():
                            data[section].append(s)
                        else:
                            data[section] = [s]
                    else:
                        data[section] = s

                    section = None

        return data


# check sanity before running any kind of code
if not sanitycheck():
    sys.exit(1)
computer = LinuxInventory()
print(json.dumps(computer.getinfo(), indent=2, sort_keys=True))
