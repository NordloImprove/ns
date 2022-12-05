import ldap3
import ssl
import json
import logging

from config import config


class Ldap():
    timeout = 5

    def __new__(cls, method, *args, **kwargs):
        subclass_map = {subclass.method: subclass for subclass in cls.__subclasses__()}
        subclass = subclass_map[method]
        instance = super(Ldap, subclass).__new__(subclass)
        return instance

    def __init__(self, search_base, search_filter):
        self._search_base = search_base
        self._search_filter = search_filter or '(objectclass=computer)'

    def connect(self):
        self.log.debug('Binding')
        if self.connection.bind():
            return True
        else:
            self.log.debug('Bind failed')
            self.log.error(self.connection.result.get('message'))
        return False

    def disconnect(self):
        self.log.debug('Unbinding')
        return self.connection.unbind()

    def get_computers(self):
        self.log.debug(f'Searching with base {self._search_base} and filter {self._search_filter}')
        self.connection.search(
            search_base=self._search_base, search_filter=self._search_filter, attributes=['dNSHostName'])
        response = json.loads(self.connection.response_to_json())

        if self.log.getEffectiveLevel() == logging.DEBUG:
            self.log.debug('Listing entries')
            for e in response['entries']:
                self.log.debug(e)

        self.log.info(f'Found {len(response["entries"])} hosts')
        result = [r['attributes']['dNSHostName'] for r in response['entries'] if r['attributes']['dNSHostName']]
        return result


class Kerberos(Ldap):
    method = 'kerberos'

    def __init__(
            self, host, search_base, method, search_filter=None, port=636):
        name = f'{config.log_name}.{__name__}.{self.method}'
        self.log = logging.getLogger(name)
        self.log.debug('Using TLS')
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        server = ldap3.Server(host=host, port=port, use_ssl=True, tls=tls, connect_timeout=Ldap.timeout)
        self.log.debug(f'Connecting to {host}')
        self.connection = ldap3.Connection(
            server, authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS)
        super().__init__(search_base, search_filter)


class Digest_md5(Ldap):
    method = 'digest-md5'

    def __init__(self, host, user, password, search_base, method, search_filter=None, port=389):
        name = f'{config.log_name}.{__name__}.{self.method}'
        self.log = logging.getLogger(name)
        server = ldap3.Server(host=host, port=port, use_ssl=False, connect_timeout=Ldap.timeout)
        self.log.debug(f'Connecting to {host}')
        self.connection = ldap3.Connection(
            server, authentication=ldap3.SASL, sasl_mechanism=ldap3.DIGEST_MD5,
            sasl_credentials=(None, user, password, None, 'sign'))
        super().__init__(search_base, search_filter)
