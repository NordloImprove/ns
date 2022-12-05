import subprocess
import xmltodict
import logging
import platform
import sys
import re

from config import config


class Nmap():
    def __init__(self, hosts=None, hosts_file=None, hosts_file_ignore=None, mode=None):
        self.log = logging.getLogger(f'{config.log_name}.{__name__}')
        self.nmaprun = {}
        self.hosts = {}
        self.nmap_defaults = '--stats-every 15 -oX -'.split()
        arguments = []
        if hosts:
            for host in re.split('[,\\s]+', hosts):
                arguments.append(host)
        if hosts_file:
            arguments.append('-iL')
            arguments.append(config.resolve(hosts_file))
        if hosts_file_ignore:
            arguments.append('--excludefile')
            arguments.append(config.resolve(hosts_file_ignore))
        if mode == 'ipv6':
            arguments.append('-6')
        self.nmap_arguments = arguments
        system = platform.system()

        if system == 'Windows':
            nmap = 'nmap'
        else:
            nmap = 'sudo -n nmap'
        self.nmap_command = nmap.split()

    def scan(self, ports, dry_run=False):
        ports_tcp = ','.join([str(x) for x in ports['tcp']])
        ports_udp = ','.join([str(x) for x in ports['udp']])
        if ports_tcp and ports_udp:
            self.nmap_arguments += f'-sU -sT -pT:{ports_tcp},U:{ports_udp}'.split()
        elif ports_tcp:
            self.nmap_arguments += f'-sT -pT:{ports_tcp}'.split()
        elif ports_udp:
            self.nmap_arguments += f'-sU -pU:{ports_udp}'.split()
        cmd = self.nmap_command + self.nmap_arguments + self.nmap_defaults
        xml_content = []
        if config.args.dry_run:
            self.log.info(' '.join(cmd))
            self.log.info('Skipping nmap scan')
            return
        try:
            for line in self.run(cmd):
                if line.startswith('<'):
                    if line.startswith('<taskprogress'):
                        mydict = xmltodict.parse(line, attr_prefix='')['taskprogress']
                        task = mydict['task']
                        percent = mydict['percent']
                        self.log.info(f'Task: {task}, Percent: {percent}')
                    else:
                        xml_content.append(line)
                else:
                    self.log.warning(line.strip())
            scan_info = xmltodict.parse(
                ''.join(xml_content), attr_prefix='', force_list={'host', 'hostname', 'address', 'port'})

            for key, data_entry in scan_info['nmaprun'].items():
                if key == 'host':
                    for data in data_entry:
                        host = NmapHost(data)
                        self.hosts[host.ip()] = host
                else:
                    self.nmaprun[key] = scan_info['nmaprun'][key]

        except FileNotFoundError:
            self.log.error('Can not execute Nmap. Is it installed?')
        except Exception as e:
            self.log.error(e)

    def run(self, cmd):
        self.log.debug('Running command: {}'.format(' '.join(cmd)))
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        for line in process.stdout:
            yield line.decode()
        process.stdout.close()
        return_code = process.wait()

        if return_code:
            sys.exit(return_code)

    def report(self):
        data = {}
        data['args'] = self.nmaprun['args']
        data['hosts'] = self.nmaprun['runstats']['hosts']
        data['runtime'] = float(self.nmaprun['runstats']['finished']['elapsed'])
        data['version'] = self.nmaprun['version']
        data['xmloutputversion'] = self.nmaprun['xmloutputversion']
        data['type'] = 'nmap'
        return data


class NmapHost():
    def __init__(self, data):
        self.data = data

    def hostname(self):
        try:
            return self.data['hostnames']['hostname'][0]
        except TypeError:
            pass
        return None

    def ip(self):
        try:
            for entry in self.data['address']:
                if entry['addrtype'] in ['ipv4', 'ipv6']:
                    return entry['addr']
                    break
        except TypeError:
            pass
        return None

    def addr_info(self, addrtype='ipv4,ipv6'):
        try:
            for entry in self.data['address']:
                if entry['addrtype'] in addrtype.split(','):
                    return entry
        except KeyError:
            pass
        return None

    def status(self):
        try:
            return self.data['status']['state']
        except TypeError:
            pass
        return None

    def has_port(self, port, state=[]):
        if not isinstance(state, list):
            state = [state]
        try:
            if self.data['ports']:
                for x in self.data['ports']['port']:
                    if x['portid'] == str(port):
                        if not state or x["state"]["state"] in state:
                            return True
        except KeyError:
            pass
        return False

    def metadata(self):
        data = {}
        data['ip'] = self.ip()
        data['hostname'] = self.hostname()
        data['mac'] = self.addr_info('mac')
        return dict(data)
