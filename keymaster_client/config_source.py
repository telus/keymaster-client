"""Defines the ConfigSource abstract base class, and classes that implement it."""
import abc
import logging

from urllib.parse import urlparse
from typing import List, Dict

import requests

from keymaster_client import wireguard as wg

LOGGER = logging.getLogger('keymaster_client')


class ConfigSource(abc.ABC):
    """Represents a source of configuration. This can be a server, a local
    file that is monitored, or anything else that your imagination can come
    up with."""

    @abc.abstractmethod
    def get_config(self, private_key_mapping: Dict[str, str]) -> List[wg.WireguardInterface]:
        """Gets the config from the ConfigSource, parses it into `WireguardInterface`s,
        and returns it as a list of `WireguardInterface`s. `private_key_mapping` is a dict
        with interface names as keys and the private keys for those interfaces as values.
        If an interface is received from the ConfigSource and there is no private key for
        it in `private_key_mapping`, one will be created."""

    @abc.abstractmethod
    def patch_public_key(self, interface_name: str, public_key: str):
        """Writes a public key to the ConfigSource so that nodes that treat
        this one as a Peer can include it in their [Peer] config."""


class uDPUAPI(ConfigSource):
    """Interfaces with the uDPU API."""

    def __init__(self, url: str, network_name: str):
        self.url = url
        self.network_name = network_name
        self.interface_mapping = {}
        # validation
        parsed_url = urlparse(self.url)
        if parsed_url.scheme == '' or parsed_url.netloc == '' or parsed_url.path != '':
            msg = f'{self.url} is not a valid URL.' + \
                'Must be of the form <scheme>://<hostname>[:<port>]'
            raise ValueError(msg)

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
            'peers': peers
        }

        return output_config

    def get_config(self, private_key_mapping: Dict[str, str]) -> List[wg.WireguardInterface]:
        """Fetches the config from the uDPU API and returns it as a single
        WireguardInterface in a list."""
        url = f'{self.url}/v1/wireguard/config/server/{self.network_name}'
        response = requests.get(url)
        response.raise_for_status()
        raw_config = response.json()
        self.interface_mapping = {
            raw_config['interface']['name']: raw_config['interface']['_id']
        }
        parsed_config = self._parse_from_upstream(raw_config)
        interface = wg.WireguardInterface.from_dict(parsed_config)
        return [interface]

    def patch_public_key(self, interface_name: str, public_key: str):
        """Makes a PATCH request to keymaster-server that updates the interface
        by the name of `interface_name` with the public key `public_key`.
        For uDPUAPI, `get_config` must be called before `patch_public_key`, since
        `get_config` populates `self.interface_mapping` so that we can get `interface_id`
        from `interface_name`."""
        # get interface_id
        try:
            interface_id = self.interface_mapping[interface_name]
        except KeyError:
            LOGGER.error(f'interface {interface_name} is not in interface mapping')
            return

        # patch public key
        url = f'{self.url}/v1/interfaces/server/{interface_id}'
        payload = {
            'public_key': public_key
        }
        response = requests.patch(url, json=payload)
        response.raise_for_status()


class KeymasterAPI(ConfigSource):
    pass
