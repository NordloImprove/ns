import os
import sys
import errno

import logging
from pathlib import Path


class BaseConfig():
    def setup(self, args):
        self.base_dir = Path(__file__).parent.resolve()
        self.path = {
            'scripts': Path.joinpath(self.base_dir, 'scripts')
        }
        self.log_name = 'nordscan'
        self.args = args
        self.conf_dir = Path(args.config).parent.resolve()

        self.logging()

    def logging(self):
        log_levels = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR
        }

        formatter = logging.Formatter('%(asctime)s %(levelname)s [%(name)s] %(message)s')
        log = logging.getLogger(self.log_name)

        try:
            if self.args.log_level:
                log_level = log_levels[self.args.log_level.upper()]
            elif os.getenv('LOG_LEVEL'):
                log_level = log_levels[os.getenv('LOG_LEVEL').upper()]
            else:
                log_level = 'INFO'
        except KeyError:
            print(f'Not a valid log level: {(", ").join(log_levels.keys())}')
            sys.exit(1)

        log.setLevel(log_level)

        if self.args.log_file:
            log_file = self.args.log_file
        elif os.getenv('LOG_FILE'):
            log_file = os.getenv('LOG_FILE')
        else:
            log_file = None

        if log_file:
            handler = logging.FileHandler(Path(log_file).expanduser())
            handler.setFormatter(formatter)
            log.addHandler(handler)
        else:
            handler = logging.StreamHandler()
            handler.setFormatter(formatter)
            log.addHandler(handler)

    def resolve(self, filename):
        if filename:
            path = Path(filename).expanduser()
            if path.is_absolute():
                filepath = path
            else:
                filepath = Path(self.conf_dir).joinpath(filename)

            if filepath.is_file():
                return str(filepath)
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(filepath))
        return filename


#Object that can be imported where needed
config = BaseConfig()
