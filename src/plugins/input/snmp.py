import re
from plugins import InputPluginBase
from pysnmp import hlapi


def cast(x):
    try:
        return int(x)
    except ValueError:
        pass
    try:
        return float(x)
    except ValueError:
        pass
    return x


class Plugin(InputPluginBase):
    plugin_name = 'snmp'
    plugin_type = 'input'
    defaults = {
        'ports': [161],
        'protocol': 'udp'
    }

    def __init__(
            self, host_addr, host, community, items, ports=defaults['ports']):
        super(self.__class__, self).__init__()

        self.host_addr = host_addr
        self.host = host

        self._community = community
        self._items = items
        self._ports = ports

        self._port = None

        self._error = []
        self._output = {}

    def get(self, port):
        oids = []
        for k in self._items.keys():
            x, y, z = re.split('::|\\.', k)
            obj = hlapi.ObjectType(hlapi.ObjectIdentity(x, y, z))
            oids.append(obj)
        output = hlapi.getCmd(
            hlapi.SnmpEngine(),
            hlapi.CommunityData(self._community),
            hlapi.UdpTransportTarget((self.host_addr, port)),
            hlapi.ContextData(),
            *tuple(oids))
        result = {}
        for error_indication, error_status, error_index, var_binds in output:
            if error_indication:
                self.error(type(error_indication).__name__, str(error_indication))
            for k, v in var_binds:
                if v:
                    t_key = self._items[k.prettyPrint()]
                    if t_key:
                        result[t_key] = cast(str(v))
                    else:
                        result[k.prettyPrint()] = cast(str(v))

        return result

    def run(self):
        for port in self._ports:
            self._port = port
            if self.host.has_port(port, ['open', 'open|filtered']):
                try:
                    result = self.get(port)
                    if result:
                        self._output = {'snmp': result}
                    break
                except Exception as e:
                    etype = type(e).__name__
                    emessage = str(e)
                    self.error(etype, emessage)
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
