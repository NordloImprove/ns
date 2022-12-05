import json

from pathlib import Path

from config import config
from plugins import InputPluginBase
import getpass

import socket
from ssh2.session import Session
from ssh2.exceptions import FileError, AuthenticationError, AgentConnectionError

import base64


def channel_messages(channel):
    error = ''
    size, data = channel.read_stderr()
    while size > 0:
        error += data.decode()
        size, data = channel.read_stderr()
    output = ''
    size, data = channel.read()
    while size > 0:
        output += data.decode()
        size, data = channel.read()

    return output, error


class Plugin(InputPluginBase):
    plugin_name = 'ssh'
    plugin_type = 'input'
    defaults = {
        'ports': [22],
        'protocol': 'tcp'
    }

    def __init__(
            self, host_addr, host, scripts, username='', ports=defaults['ports'],
            ssh_key='', ssh_key_password='', password='',
            python_versions=['python3', 'python2.7']):
        super(self.__class__, self).__init__()

        self.host_addr = host_addr
        self.host = host
        self._ports = ports
        if username:
            self._username = username
        else:
            self._username = getpass.getuser()
        self._password = password
        self._ssh_key = config.resolve(ssh_key)
        self._ssh_key_password = ssh_key_password

        self._scripts = scripts
        self._python_versions = python_versions

        self._error = []
        self._output = {}

        self._session = None
        self._socket = None
        self._port = None

    def connect(self, port):
        self._port = port
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((self.host_addr, port))
        self._session = Session()
        self._session.handshake(self._socket)

    def disconnect(self):
        if self._session:
            self._session.disconnect()
        if self._socket:
            self._socket.close()
        self._port = None

    def encode(self, obj):
        string = json.dumps(obj)
        return base64.b64encode(string)

    def run_scripts(self, python):
        for script in self._scripts:
            if isinstance(script, str):
                script_name = script
                script_path = Path(config.path['scripts']).joinpath(script_name)
                cmd = f'{python}'
            else:
                if 'name' in script.keys():
                    script_name = script['name']
                    script_path = Path(config.path['scripts']).joinpath(script_name)
                    cmd = f'{python}'
                    if 'arguments' in script.keys():
                        script_args = script['arguments']
                        encoded_args = base64.b64encode(str(script_args).encode('utf-8'))
                        cmd += f' - {encoded_args.decode()}'

            with script_path.open() as f:
                file = f.read()
                channel = self._session.open_session()
                channel.execute(cmd)
                channel.write(file)
                channel.send_eof()
                output, error = channel_messages(channel)
                channel.close()
                if not channel.get_exit_status():
                    try:
                        if output:
                            self.output(json.loads(output))
                    except json.JSONDecodeError as e:
                        etype = type(e).__name__
                        self.error(etype, 'Script returned invalid json object', script_name)
                else:
                    self.error('ScriptError', error, script_name)

    def check_python(self):
        for python in self._python_versions:
            channel = self._session.open_session()
            channel.execute(f'{python} --version')
            channel.send_eof()
            output, error = channel_messages(channel)
            channel.close()
            if not channel.get_exit_status():
                return python
        self.error('CheckError', f'No valid python version found: {self._python_versions}')

    def check_connection(self, port):
        self.connect(port)

        try:
            if self._ssh_key:
                ssh_key = str(Path(self._ssh_key).expanduser())
                self.log.debug(f'{self.host_addr}:{port} Using ssh key')
                self._session.userauth_publickey_fromfile(
                    self._username, ssh_key, passphrase=self._ssh_key_password)
            elif self._password:
                self.log.debug(f'{self.host_addr}:{port} Using ssh password')
                self._session.userauth_password(self._username, self._password)
            else:
                self.log.debug(f'{self.host_addr}:{port} Using ssh agent')
                self._session.agent_auth(self._username)
        except FileError:
            self.error('AuthenticationError', f'File not found: {self._ssh_key}')
        except AgentConnectionError:
            self.error('AuthenticationError', 'Could not connect to ssh agent')
        except AuthenticationError:
            self.error('AuthenticationError', f'Authentication failed for user {self._username}')

        if self._session.userauth_authenticated():
            self.log.debug(f'{self.host_addr}:{port} Authentication OK')
            return True

    def run(self):
        for port in self._ports:
            if self.host.has_port(port, 'open'):
                try:
                    if self.check_connection(port):
                        python = self.check_python()
                        if python:
                            self.run_scripts(python)
                            #break if we came here, it means great success
                            break

                except Exception as e:
                    etype = type(e).__name__
                    emessage = str(e)
                    self.error(etype, emessage)
                finally:
                    self.disconnect()
            else:
                self.log.debug(f'{self.host_addr}:{port} Port not open')

        if self._output:
            try:
                emessage = self._output["error"]
                if emessage:
                    self.log.info(f'ScriptWarning: {emessage}')
            except KeyError:
                pass
            self.log.debug(f'{self.host_addr}:{port} Output OK')

        return self._output, self._error
