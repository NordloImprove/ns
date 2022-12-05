#!/usr/bin/env python
import sys
import argparse
import yaml
import threading
import queue
import importlib
import pkgutil
import json
from pathlib import Path
from datetime import datetime
import logging
import pycron
import time
import platform
import tempfile
import os
from modules import ldap
from modules import nmap

from config import config


def merge(data, newdata):
    for k, v in newdata.items():
        if k in data.keys():
            try:
                data[k].extend(v)
            except AttributeError:
                # maybe also send to plugin output?
                log.error('AttributeError', f'Existing output key: {k} is not a list. Can not merge plugin output')
        else:
            data[k] = v
    return data


def pprint(data, indent=2):
    print(json.dumps(data, indent=indent, sort_keys=True))


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
            sys.exit(1)
    except ImportError as e:
        log.error('Could not load config')
        log.error(e)
    except Exception as e:
        log.error(e)
        sys.exit(1)

    return None


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


class NordScan():
    def __init__(self):
        self.conf = get_config()
        self.plugins_input = get_plugins(self.conf, 'input')
        self.plugins_output = get_plugins(self.conf, 'output')

        self.scanstamp = None

        self.input_queue = queue.Queue()
        self.output_queue = queue.Queue()

        self._lock = threading.Lock()

        self._temp_host_file = None

        input_threads = self.conf['nordscan']['threads']['input']
        log.debug(f'Setting up {input_threads} input thread(s)')
        for i in range(input_threads):
            threading.Thread(target=self.input_thread, args=[i], daemon=True).start()

        output_threads = self.conf['nordscan']['threads']['output']
        log.debug(f'Setting up {output_threads} output thread(s)')
        for i in range(output_threads):
            threading.Thread(target=self.output_thread, args=[i], daemon=True).start()

    def set_scanstamp(self):
        self.scanstamp = datetime.now().strftime('%Y%m%d-%H%M%S')

    def get_plugin_ports(self):
        nmap_ports = {'tcp': [], 'udp': []}
        for plugin in self.plugins_input.values():
            if hasattr(plugin['module'].Plugin, 'defaults'):
                defaults = plugin['module'].Plugin.defaults
            else:
                defaults = {}
            conf = {**defaults, **plugin['conf']}
            if 'ports' in conf.keys():
                ports = conf['ports']
                if 'protocol' in conf.keys():
                    protocol = conf['protocol']
                    nmap_ports[protocol].extend(ports)
                else:
                    nmap_ports['tcp'].extend(ports)
        return nmap_ports

    def platform_info(self):
        data = {}
        data['machine'] = platform.machine()
        data['platform'] = platform.platform()
        data['system'] = platform.system()
        data['release'] = platform.release()
        data['python_version'] = platform.python_version()
        return data

    def stats_reset(self):
        self._stats_total = 0
        self._stats_output = 0
        self._stats_error = 0
        self._stats_start_time = datetime.now()
        self.scanstamp = self._stats_start_time.strftime('%Y%m%d-%H%M%S')

        self._stats_plugin = {}
        for plugin in self.plugins_input.values():
            name = plugin['module'].Plugin.plugin_name
            self._stats_plugin[name] = {
                'output': 0,
                'error': 0
            }

    def stats_count(self, error, output):
        with self._lock:
            self._stats_total += 1
            if error:
                self._stats_error += 1
            if output:
                self._stats_output += 1

    def stats_plugin_count(self, error, output, plugin_name):
        with self._lock:
            plugin_stats = self._stats_plugin[plugin_name]
            if error:
                plugin_stats['error'] += 1
            if output:
                plugin_stats['output'] += 1

    def report(self):
        data = {
            'hosts': {
                'error': self._stats_error,
                'output': self._stats_output,
                'total': self._stats_total,
                **self._stats_plugin,
            },
            'type': f'{config.log_name}',
            'version': version(),
            'runtime': round((datetime.now() - self._stats_start_time).total_seconds(), 2),
            'platform': self.platform_info(),
        }

        return data

    def input_thread(self, i):
        while True:
            log.debug(f'Input Thread {i}: Looking for the next queue object')

            error = []
            output = {}

            host_addr, host = self.input_queue.get()
            try:
                for plugin in self.plugins_input.values():
                    p = plugin['module'].Plugin(host_addr=host_addr, host=host, **plugin['conf'])
                    p_output, p_error = p.run()
                    error.extend(p_error)
                    output = merge(output, p_output)
                    self.stats_plugin_count(p_error, p_output, p.plugin_name)
                self.send(output=output, error=error, hostdata=host.metadata())
            except Exception as e:
                log.error(f'Input Plugin loading failed: {e}')
            finally:
                self.input_queue.task_done()
                self.stats_count(error, output)

    def output_thread(self, i):
        while True:
            log.debug(f'Output Thread {i}: Looking for the next queue object')
            try:
                plugin_name, output, error, hostdata = self.output_queue.get()
                plugin = self.plugins_output[plugin_name]
                obj = plugin['module'].Plugin(
                    output=output, error=error, hostdata=hostdata, **plugin['conf'])
                obj.run()
            except Exception as e:
                log.error(f'{plugin_name} failed. {e}')
            finally:
                self.output_queue.task_done()

    def daemon(self):
        schedule = self.conf['schedule']
        log.info(f'Using schedule: {schedule}')
        while True:
            if pycron.is_now(schedule):
                log.info('Scheduled scan: starting')
                self.run()
                log.info('Scheduled scan: done')
            time.sleep(60)

    def send(self, output, error=[], hostdata={}):
        hostdata['time'] = self.scanstamp
        hostdata['timestamp'] = datetime.utcnow().isoformat()

        for plugin_name in self.plugins_output.keys():
            self.output_queue.put((plugin_name, output, error, hostdata))

    def get_ldap_hosts(self, ldap_conf):
        try:
            channel = ldap.Ldap(**ldap_conf)
            if channel.connect():
                ldap_hosts = channel.get_computers()
                channel.disconnect()
                return ldap_hosts
        except KeyError as e:
            log.error(f'Ldap error: Cant find method {e}')
        except Exception as e:
            log.error(f'Ldap error: {e}')
        return []

    def make_tmpfile(self, ldap_conf, nmap_conf):
        tmpfile = tempfile.NamedTemporaryFile(prefix=f'{config.log_name}-', delete=False)
        log.debug(f'Using temporary host_file: {tmpfile.name}')

        for host in self.get_ldap_hosts(ldap_conf):
            tmpfile.write(f'{host}\n'.encode())

        if nmap_conf and nmap_conf.get('hosts_file'):
            with open(config.resolve(nmap_conf.get('hosts_file'))) as hosts_file:
                for line in hosts_file:
                    tmpfile.write(line.encode())

        tmpfile.seek(0)

        if config.args.debug_print:
            log.info(f'Printing {tmpfile.name}:')
            print(f'{tmpfile.read().decode()}')

        tmpfile.close()
        return tmpfile

    def run(self):
        log.info('*** Starting run ***')

        self.stats_reset()

        ldap_conf = self.conf.get('ldap')
        nmap_conf = self.conf.get('nmap')

        if ldap_conf:
            tmpfile = self.make_tmpfile(ldap_conf, nmap_conf)
            if nmap_conf:
                nm = nmap.Nmap(**{**nmap_conf, 'hosts_file': tmpfile.name})
            else:
                nm = nmap.Nmap(hosts_file=tmpfile.name)
            nm.scan(self.get_plugin_ports())
            log.debug(f'Removing tempfile {tmpfile.name}')
            os.unlink(tmpfile.name)
        else:
            nm = nmap.Nmap(**nmap_conf)
            nm.scan(self.get_plugin_ports())

        if not nm.hosts:
            log.warning('No hosts found! (maybe take a look at the config)')
            sys.exit(1)

        #nmap report
        self.send(output=nm.report())

        log.info(f'Hosts to check: {len(nm.hosts)}')

        for host_addr, host in nm.hosts.items():
            if host.status() == 'up':
                self.input_queue.put((host_addr, host))

        log.debug('*** Input threads waiting ***')
        self.input_queue.join()
        log.debug('*** Input threads done ***')

        #nordscan report
        output = self.report()
        self.send(output)

        log.debug('*** Output threads waiting ***')
        self.output_queue.join()
        log.debug('*** Out output threads done ***')

        for k, v in self._stats_plugin.items():
            log.info('{}: {}'.format(k, ', '.join([f'{k}: {v}' for k, v in v.items()])))
        log.info('output: {}, error: {}, total: {}'.format(self._stats_output, self._stats_error, self._stats_total))

        log.info('*** Finished run ***')


def main():
    try:
        nordscan = NordScan()
        if 'schedule' in nordscan.conf.keys():
            nordscan.daemon()
        else:
            nordscan.run()
    except KeyboardInterrupt:
        log.info('Exiting')
        sys.exit(0)


def version():
    return '1.3.4'


if __name__ == '__main__':

    my_parser = argparse.ArgumentParser(description='Scans networks and hosts')
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
    my_parser.add_argument('--dry-run', dest='dry_run', action='store_true', default=False,
                           help="never do nmap scan")

    args = my_parser.parse_args()

    #initial setup for config object
    config.setup(args)

    if config.args.version:
        print(version())
        sys.exit()

    log = logging.getLogger(f'{config.log_name}')
    main()
