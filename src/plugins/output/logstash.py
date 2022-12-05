import requests
import json
from plugins import OutputPluginBase
from nordscan import pprint
from time import sleep
from functools import reduce
import fnmatch
from config import config


def get_recursive_key(k, mydict):
    return reduce(lambda c, k: c.get(k, {}), k.split('.'), mydict)


class Plugin(OutputPluginBase):
    plugin_name = 'logstash'
    plugin_type = 'output'
    defaults = {
        'types': {
            'default': 'computer',
            'type': []
        }
    }

    def __init__(
            self, output, error, address, metadata, hostdata={}, types={},
            splitdata=None, retry_timer=30, ssl_cert='', ssl_key='', ssl_ca=''):
        super().__init__()

        self._address = address

        self._ssl_cert = config.resolve(ssl_cert)
        self._ssl_key = config.resolve(ssl_key)
        self._ssl_ca = config.resolve(ssl_ca)

        self._output = output
        self._error = error
        self._metadata = dict(hostdata, **metadata)
        self._retry_timer = retry_timer
        self._types = {**Plugin.defaults['types'], **types}

        if splitdata:
            self._splitdata = splitdata
        else:
            self._splitdata = {'source': None, 'system': {'uuid': None}}

    def send_request(self, data):
        try:
            if self._ssl_cert:
                response = requests.post(
                    url=self._address, data=json.dumps(data, sort_keys=True),
                    cert=(self._ssl_cert, self._ssl_key),
                    verify=self._ssl_ca,
                    headers={'content-type': 'application/json'})
            else:
                response = requests.post(
                    url=self._address, data=json.dumps(data, sort_keys=True),
                    headers={'content-type': 'application/json'})

            if response.status_code == 200:
                self.log.debug(f'Response from {self._address}: {response.status_code} {response.content.decode()}')
                return True
            else:
                self.log.debug(
                    f'Failed response from {self._address}: {response.status_code} {response.content.decode()}')
                return False

        except requests.exceptions.ConnectionError as e:
            etype = type(e).__name__
            self.log.error(f'{etype}: {e}')
            return False
        except Exception as e:
            etype = type(e).__name__
            self.log.error(f'{etype}: {e}')
            return True
        return False

    def split(self, data):
        result = []

        all_keys = data.keys()
        list_keys = [k for k, v in data.items() if isinstance(v, list)]
        split_keys = [k for k in self._splitdata.keys()]
        data_keys = all_keys - (list_keys + split_keys)

        for key in list_keys:
            list_entry = data.pop(key, None)
            for e in list_entry:
                entry = {key: e}
                entry['type'] = key

                for k, v in self._splitdata.items():
                    if k in all_keys:
                        if not v:
                            entry[k] = data[k]
                        else:
                            entry[k] = {}
                            for _k in v.keys():
                                try:
                                    entry[k][_k] = data[k][_k]
                                except KeyError:
                                    pass
                entry["metadata"] = self.metadata()
                result.append(entry)

        if data_keys:
            data["metadata"] = self.metadata()
            if 'type' not in data_keys:
                for _type in self._types['type']:
                    _match = True
                    for k, v in _type['filter'].items():
                        try:
                            value = reduce(lambda c, k: c.get(k, {}), k.split('.'), data)
                            if value:
                                if not fnmatch.fnmatch(value, v):
                                    _match = False
                            else:
                                _match = False
                        except KeyError:
                            pass
                    if _match:
                        data['type'] = _type['name']
                        break

            if 'type' not in data.keys():
                data['type'] = self._types['default']
            result.append(data)
        return result

    def error(self):
        result = []
        for e in self._error:
            entry = {
                "error": e,
                "type": "error",
            }
            entry["metadata"] = self.metadata()
            result.append(entry)
        return result

    def metadata(self):
        return self._metadata

    def output(self):
        data = self._output.copy()

        if config.args.debug_split:
            result = self.split(data)
        else:
            data["metadata"] = self.metadata()
            result = [data]
        return result

    def run(self):
        data = []

        if self._error:
            data.extend(self.error())
        if self._output:
            data.extend(self.output())

        if config.args.debug_print:
            pprint(data)
        elif self._retry_timer > 0:
            while True:
                if self.send_request(data):
                    break
                self.log.info(f'Retry in {self._retry_timer}')
                sleep(self._retry_timer)
        else:
            self.send_request(data)
