import json
from pathlib import Path
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan
from pypsrp.shell import Process, SignalCode, WinRS

from config import config
from plugins import InputPluginBase

#import sys


class Plugin(InputPluginBase):
    plugin_name = 'winrm'
    plugin_type = 'input'
    defaults = {
        'ports': [5985],
        'protocol': 'tcp'
    }

    def __init__(
            self, host_addr, host, scripts, username=None, ports=defaults['ports'], password=None, ssl_cert='',
            ssl_key='', cert_validation=False, ps_version=3, auth="negotiate"):
        super(self.__class__, self).__init__()

        self.host_addr = host_addr
        self.host = host

        try:
            self._host = self.host.data['hostnames']['hostname'][0]['name']
        except TypeError:
            self._host = self.host_addr

        self._ports = ports
        self._username = username
        self._scripts = scripts
        self._ps_version = ps_version

        self._auth = auth
        self._password = password
        self._ssl_cert = config.resolve(ssl_cert)
        self._ssl_key = config.resolve(ssl_key)
        self._cert_validation = cert_validation

        self._output = {}
        self._error = []

        self._port = None

    def use_ssl(self, port):
        if port == 5985:
            return False
        return True

    def run_scripts(self, port):
        session = self.connect(port)
        with RunspacePool(session) as pool:
            for script in self._scripts:
                if isinstance(script, str):
                    script_name = script
                    script_path = Path(config.path['scripts']).joinpath(script_name)
                else:
                    script_name = script['name']
                    script_path = Path(config.path['scripts']).joinpath(script_name)

                ps = PowerShell(pool)
                with script_path.open() as f:
                    file = f.read()
                    ps.add_script(file)
                    ps.invoke()
                    if ps.output:
                        try:
                            self.output(json.loads(ps.output[0]))
                        except json.JSONDecodeError as e:
                            etype = type(e).__name__
                            self.error(etype, 'Script returned invalid json object', script_name)
                    if ps.had_errors:
                        script_error = "\n".join([str(s) for s in ps.streams.error])
                        self.error('ScriptError', script_error, script_name)

    def disconnect(self):
        self._port = None

    def connect(self, port):
        self._port = port
        return WSMan(
            server=self._host, port=port, username=self._username, password=self._password,
            auth=self._auth, ssl=self.use_ssl(port), cert_validation=self._cert_validation,
            certificate_key_pem=self._ssl_key, certificate_pem=self._ssl_cert)

    def check_connection(self, port):
        session = self.connect(port)
        self.log.debug(f'{self._host}:{port} Using {self._auth} authentication')
        with session, WinRS(session) as shell:
            ps = Process(shell, "powershell.exe -Command Write-Host $PSVersionTable.PSVersion.Major")
            ps.invoke()
            ps.signal(SignalCode.CTRL_C)
            if ps.rc == 0:
                ps_version = ps.stdout.decode().strip()
                try:
                    if int(ps_version) >= int(self._ps_version):
                        self.log.debug(f'{self._host}:{port} Check ok: PS version {ps_version}')
                        return True
                except ValueError:
                    pass
        self.log.debug(f'{self._host}:{port} Check failed.')

    def run(self):
        for port in self._ports:
            if self.host.has_port(port, 'open'):
                try:
                    if self.check_connection(port):
                        self.run_scripts(port)
                        break
                except Exception as e:
                    etype = type(e).__name__
                    emessage = str(e)
                    self.error(etype, emessage)
                finally:
                    self.disconnect()
            else:
                self.log.debug(f'{self._host}:{port} Port not open')

        if self._output:
            try:
                emessage = self._output["error"]
                if emessage:
                    self.log.info(f'ScriptWarning: {emessage}')
            except KeyError:
                pass
            self.log.debug(f'{self._host}:{port} Output OK')

        return self._output, self._error
