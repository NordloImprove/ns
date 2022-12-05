#!/usr/bin/env python
import subprocess
import sys
import json
import platform
import os
from datetime import datetime
from optparse import OptionParser
import base64
#import re
import fnmatch

#set lowest priority
os.nice(19)


def sanitycheck():
    os_type = platform.system()
    if os_type != 'Linux':
        sys.stderr.write('%s is not supported.\n' % os_type)
        return False
    return True


class LinuxSoftwareInventory:
    def __init__(self, args):
        self.logmessage = []
        self.args = args

    def getinfo(self):
        data = {}
        data['software'] = self.software()
        if self.logmessage:
            data['error'] = self.logmessage

        return data

    def software(self):
        data = []
        if self.run('dpkg --version', log=False):
            data = self.dpkg_software()
        elif self.run('rpm --version', log=False):
            data = self.rpm_software()

        return data

    def filter_output(self, _data, filter_list, keep=False):
        data = []
        for item in _data:
            _filter = keep
            for k, v in filter_list.items():
                try:
                    if [i for i in v if fnmatch.fnmatch(item[k], i)]:
                        _filter = not keep
                except KeyError:
                    pass
            if _filter:
                data.append(item)
        return data

    def format_output(self, output):
        data = []
        section = {}
        lines = output.splitlines()

        #output should end with empty line
        if lines[-1]:
            lines.append('')

        for line in lines:
            if not line:
                data.append(section)
                section = {}
            else:
                k, v = line.split(':', 1)
                if k == 'install_date':
                    v = datetime.utcfromtimestamp(int(v)).strftime('%Y-%m-%d %H:%M:%S')
                section[k.lower()] = v

        if isinstance(self.args, dict):
            if 'filter' in self.args.keys() and self.args['filter']:
                data = self.filter_output(data, self.args['filter'], keep=False)
            if 'ignore' in self.args.keys() and self.args['ignore']:
                data = self.filter_output(data, self.args['ignore'], keep=True)
        else:
            self.error('ArgumentError', 'Arguments is not a dictonary')

        return data

    def rpm_software(self):
        data = []
        pformat = {
            "name": "%{name}",
            "version": "%{version}-%{release}.%{arch}",
            "section": "%{group}",
            "vendor": "%{vendor}",
            "maintainer": "%{packager}",
            "install_date": "%{installtime}",
        }
        pformat_string = "\n".join(['%s:%s' % (k, v) for k, v in pformat.items()])
        output = self.run('rpm -qa --queryformat=%s\n\n' % pformat_string)
        if output:
            data = self.format_output(output)
        return data

    def dpkg_software(self):
        data = []
        pformat = {
            "name": "${package}",
            "version": "${version}.${architecture}",
            "section": "${section}",
            "maintainer": "${maintainer}",
        }
        pformat_string = "\n".join(['%s:%s' % (k, v) for k, v in pformat.items()])
        output = self.run('dpkg-query --showformat=%s\n\n -W' % pformat_string)
        if output:
            data = self.format_output(output)
            data = self.dpkg_install_dates(data)

        return data

    def dpkg_install_dates(self, data):
        path = '/var/lib/dpkg/info'
        files = {}
        for f in os.listdir(path):
            if f.endswith('.list'):
                k = os.path.splitext(f)[0].split(':')[0]
                files[k] = f
        for entry in data:
            try:
                file = files[entry['name']]
                v = os.path.getmtime(os.path.join(path, file))
                entry['install_date'] = datetime.utcfromtimestamp(int(v)).strftime('%Y-%m-%d %H:%M:%S')
            except Exception as e:
                self.error(type(e).__name__, str(e))

        return data

    def error(self, etype, emessage, command=None):
        data = {}
        data['type'] = etype
        data['message'] = emessage
        if command:
            data['command'] = command
        self.logmessage.append(data)

    def run(self, cmd, log=True):
        try:
            proc = subprocess.Popen(
                cmd.split(' '), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stdout, stderr = proc.communicate()
            output = stdout.decode('utf-8')
            if proc.returncode:
                if log:
                    self.error('ExecError', output, cmd)
            else:
                return output
        except Exception as e:
            if log:
                self.error(type(e).__name__, str(e), cmd)

        return None


# check sanity before running any kind of code
if not sanitycheck():
    sys.exit(1)

parser = OptionParser()
(opts, args) = parser.parse_args()
try:
    decoded_args = eval(base64.b64decode(args[0]))
except IndexError:
    decoded_args = {}

computer = LinuxSoftwareInventory(decoded_args)
print(json.dumps(computer.getinfo(), indent=2, sort_keys=True))
