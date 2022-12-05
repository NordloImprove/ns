#!/usr/bin/env python
import sys
import argparse
import logging
import json
from config import config
from datetime import datetime
from pathlib import Path
import yaml
import importlib
import pkgutil
import pathlib

from http.server import HTTPServer, SimpleHTTPRequestHandler
from io import BytesIO
import ssl


def get_plugins(conf, plugin_type):
    plugin_base = f'plugins.{plugin_type}'
    plugin_module = importlib.import_module(f'{plugin_base}')
    plugin_conf = {f'{plugin_base}.{k}': v for k,
                   v in conf[plugin_type].items()}

    plugin_list = {
        name: {
            "module": importlib.import_module(name),
            "conf": plugin_conf[name]
        }
        for finder, name, ispkg in iter_namespace(plugin_module)
        if name in plugin_conf
    }
    log.debug(f'Plugin {plugin_type}: {", ".join(plugin_list.keys())}')
    return plugin_list


def iter_namespace(ns_pkg):
    return pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")


def get_config():
    try:
        yaml_conf = Path(config.args.config)
        if yaml_conf.exists():
            log.debug(f'Config: {yaml_conf}')
            with yaml_conf.open() as f:
                cfg = yaml.load(f, Loader=yaml.FullLoader)
                return cfg
        else:
            log.error('Cannot find config file')
            #sys.exit(1)
    except ImportError as e:
        log.error('Could not load config')
        log.error(e)
    except Exception as e:
        log.error(e)
        sys.exit(1)

    return {}


class HTTPRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        conf = get_config()
        self._plugins_output = get_plugins(conf, 'output')
        base_dir = pathlib.Path(__file__).parent.resolve()
        super().__init__(*args, directory=f'{base_dir}/scripts', **kwargs)

    def do_POST(self):
        output = {}
        error = []

        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        content_length = int(self.headers['Content-Length'])

        try:
            body = self.rfile.read(content_length)
            host_addr = self.client_address[0]
            output = json.loads(body)

        except Exception as e:
            error.append(str(e))
            self.send_response(400)
            self.end_headers()
            response = BytesIO()
            response.write(b'Error')
            self.wfile.write(response.getvalue())
        else:
            self.send_response(200)
            self.end_headers()
            response = BytesIO()
            response.write(b'Ok')
            self.wfile.write(response.getvalue())

        hostdata = {}
        hostdata['timestamp'] = timestamp
        hostdata['ip'] = host_addr

        try:
            for (plugin_name, plugin) in self._plugins_output.items():
                obj = plugin['module'].Plugin(
                    output=output, error=error, hostdata=hostdata, **plugin['conf'])
                obj.run()
        except Exception as e:
            log.error(f'{plugin_name} failed. {e}')


def main():
    conf = get_config()
    httpd_conf = conf.get('httpd') or {}
    host_addr = httpd_conf.get('address') or ''
    host_port = httpd_conf.get('port') or 8080

    try:
        log.info(f'Starting webserver at {host_addr}:{host_port}')
        httpd = HTTPServer(
            (host_addr, host_port), HTTPRequestHandler)
        if 'ssl_cert' in httpd_conf.keys():
            httpd.socket = ssl.wrap_socket(
                httpd.socket, keyfile=httpd_conf['ssl_key'], certfile=httpd_conf['ssl_cert'], server_side=True)
        httpd.serve_forever()
    except KeyboardInterrupt:
        log.info('Exiting')
        sys.exit(1)


if __name__ == '__main__':
    my_parser = argparse.ArgumentParser(description='HTTP-server')
    my_parser.add_argument('--config', dest='config', type=str,
                           default='config.yaml', help='path to config')
    my_parser.add_argument('--print', dest='debug_print', action='store_true', default=False,
                           help="print to stdout instead of sending")
    my_parser.add_argument('--no-split', dest='debug_split', action='store_false', default=True,
                           help="do not split data")
    my_parser.add_argument('--log-level', dest='log_level', type=str,
                           default=None, help='select log_level')
    my_parser.add_argument('--log-file', dest='log_file', type=str,
                           default=None, help='path for log file')
    my_parser.add_argument('--version', dest='version', action='store_true', default=False,
                           help="show version")

    args = my_parser.parse_args()

    #initial setup for config object
    config.setup(args)

    log = logging.getLogger(f'{config.log_name}')
    main()
