import logging
from config import config


class PluginBase:
    plugin_name = None
    plugin_type = None

    def __init__(self):
        name = f'{config.log_name}.{self.plugin_type}.{self.plugin_name}'
        self.log = logging.getLogger(name)


class InputPluginBase(PluginBase):
    def __init__(self):
        super().__init__()

    def run(self):
        return None, NotImplementedError

    def output(self, output):
        for k, v in output.items():
            try:
                if k in self._output.keys():
                    self._output[k].extend(v)
                else:
                    self._output[k] = v
            except AttributeError:
                self.error('AttributeError', f'Existing output key: {k} is not a list. Can not merge script output')

    def error(self, etype, emessage, script=None):
        self.log.error(f'{self.host_addr}:{self._port} {etype}: {emessage}')
        data = {}
        data['type'] = etype
        data['message'] = emessage
        data['plugin'] = self.plugin_name
        if script:
            data['script'] = script
        self._error.append(data)


class OutputPluginBase(PluginBase):
    def __init__(self):
        super().__init__()

    def run(self):
        return None, NotImplementedError
