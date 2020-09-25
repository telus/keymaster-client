"""Defines the ConfigSource abstract base class, and classes that implement it."""
import abc
import logging

from urllib.parse import urlparse
from typing import List

import requests

from keymaster_client.wireguard import WireguardInterface, get_public_key

LOGGER = logging.getLogger('keymaster_client')


def _validate_url(url: str):
    parsed_url = urlparse(url)
    if parsed_url.scheme == '' or parsed_url.netloc == '' or parsed_url.path != '':
        msg = f'{url} is not a valid URL. Must be of the form <scheme>://<hostname>[:<port>]'
        raise ValueError(msg)


class ConfigSource(abc.ABC):
    """Represents a source of configuration. This can be a server, a local
    file that is monitored, or anything else that your imagination can come
    up with."""

    @abc.abstractmethod
    def get_config(self) -> List[WireguardInterface]:
        """Gets the config from the ConfigSource, parses it into a list of
        `WireguardInterface`s, and returns that list."""

    @abc.abstractmethod
    def patch_public_key(self, interface: WireguardInterface):
        """Writes a the public key that corresponds to the private key of a WireguardInterface
        to the ConfigSource so that nodes that treat this interface as a Peer can include
        it in their [Peer] config."""


class uDPUAPI(ConfigSource): # pylint: disable=invalid-name
    """Interfaces with the uDPU API."""

    def __init__(self, url: str, network_name: str):
        _validate_url(url)
        self.url = url
        self.network_name = network_name

    @staticmethod
    def _parse_from_upstream(config: dict) -> dict:
        """Takes the config that the API returns, which is in the form:
        ```
        {
            "interface": { interface configuration }
            "peers": [
                { interface configuration },
                { interface configuration },
                ...
                { interface configuration }
            ]
        }
        ```
        and puts it into a format that can be consumed by WireguardInterface.from_dict.
        For more details please see the udpu-api documentation."""
        # peers
        peers = []
        for peer in config['peers']:
            if peer.get('public_key') is not None:
                output_peer = {
                    'public_key': peer['public_key'],
                    'allowed_ips': peer['allowed_ips'],
                    'endpoint': peer.get('endpoint'),
                    'persistent_keepalive': peer.get('persistent_keepalive')
                }
                peers.append(output_peer)

        # interface
        output_config = {
            'name': config['interface']['name'],
            'addresses': config['interface']['addresses'],
            'listen_port': config['interface'].get('listen_port'),
            'peers': peers,
            'auxiliary_data': {
                'id': config['interface']['_id'],
                'old_public_key': config['interface']['public_key'],
            }
        }

        return output_config

    def get_config(self) -> List[WireguardInterface]:
        """Fetches the config from the uDPU API and returns it as a single
        WireguardInterface in a list."""
        url = f'{self.url}/v1/wireguard/config/server/{self.network_name}'
        response = requests.get(url)
        response.raise_for_status()
        raw_config = response.json()
        parsed_config = self._parse_from_upstream(raw_config)
        interface = WireguardInterface.from_dict(parsed_config)
        return [interface]

    def patch_public_key(self, interface: WireguardInterface):
        """Makes a PATCH request to keymaster-server that updates the public key of
        the interface with the ID in the interface's auxiliary data. The new value of
        the public key is that of the counterpart to the private key of `interface`."""
        # get interface_id and public key
        interface_id = interface.auxiliary_data['id']
        public_key = get_public_key(interface.private_key)

        # patch public key
        url = f'{self.url}/v1/interfaces/server/{interface_id}'
        payload = {'public_key': public_key}
        response = requests.patch(url, json=payload)
        response.raise_for_status()


class KeymasterServer(ConfigSource):
    """Uses keymaster-server as the source of configuration."""

    def __init__(self, url: str, token: str):
        _validate_url(url)
        self.url = url
        self.token = token

    def get_config(self) -> List[WireguardInterface]:
        url = f'{self.url}/api/configs/'
        headers = {'Authorization': f'Token {self.token}'}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        raw_config = response.json()
        interfaces = []
        for raw_interface in raw_config:
            identifier = raw_interface.pop('id')
            public_key = raw_interface.pop('public_key')
            interface = WireguardInterface.from_dict(raw_interface)
            interface.auxiliary_data['id'] = identifier
            interface.auxiliary_data['old_public_key'] = public_key
            interfaces.append(interface)
        return interfaces

    def patch_public_key(self, interface: WireguardInterface):
        interface_id = interface.auxiliary_data['id']
        public_key = get_public_key(interface.private_key)
        url = f'{self.url}/api/interfaces/{interface_id}/'
        headers = {'Authorization': f'Token {self.token}'}
        payload = {'public_key': public_key}
        response = requests.patch(url, headers=headers, json=payload)
        response.raise_for_status()
