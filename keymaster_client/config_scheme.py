"""Defines the ConfigScheme abstract base class, and classes that implement it."""
import abc
import subprocess
import json
import os

from typing import List

import keymaster_client.wireguard as wg


class ConfigScheme(abc.ABC):
    """Defines a common interface used by different config schemes to take
    the classes defined in keymaster_client.wireguard, and use a scheme-specific
    procedure to either implement them as config on the system or to read the
    system and return a representative instance."""

    @abc.abstractmethod
    def interface_exists(self, interface_name: str) -> bool:
        """Tests whether the interface with name `interface_name` exists."""

    @abc.abstractmethod
    def read(self, interface_name: str) -> wg.WireguardInterface:
        """Reads the interface by the name of `interface_name` from the system,
        and returns it as a WireguardInterface."""

    @abc.abstractmethod
    def write(self, interface: wg.WireguardInterface):
        """Writes a WireguardInterface to the system."""


class wgConfigScheme(ConfigScheme): # pylint: disable=invalid-name
    """In this scheme config is persisted to the system in three places:

    - via the `wg` command
    - via the `ip` command
    - inside the directory pointed to by `config_dir`

    It is necessary to persist config in `config_dir` because the `wg` command
    does not show you the interface private key on calls to `wg show` and the like.
    """

    def __init__(self, config_dir: str):
        self.config_dir = config_dir
        # validation
        required_tools = ['wg', 'ip']
        for tool in required_tools:
            subprocess.run(['which', tool], capture_output=True, check=True)

    def interface_exists(self, interface_name: str) -> bool:
        """Tests whether an interface with a specific name exists."""
        result = subprocess.run(['ip', 'link', 'show', interface_name],
                                capture_output=True, check=False)
        return result.returncode == 0

    def read(self, interface_name: str) -> wg.WireguardInterface:
        # get addresses
        addresses = self._get_address_list(interface_name)

        # get WireguardInterface
        config_path = os.path.join(self.config_dir, f'{interface_name}.conf')
        with open(config_path, 'r') as infile:
            interface = wg.WireguardInterface.from_wireguard_config_file(
                interface_name, addresses, infile)

        return interface

    def write(self, interface: wg.WireguardInterface):
        # create interface if not already there
        if not self.interface_exists(interface.name):
            subprocess.run(['ip', 'link', 'add', interface.name, 'type', 'wireguard'],
                           capture_output=True, check=True)

        # sync addresses
        current_addresses = self._get_address_list(interface.name)
        for addr in interface.addresses:
            if not addr in current_addresses:
                subprocess.run(['ip', 'address', 'add', addr, 'dev', interface.name],
                               capture_output=True, check=True)
        for addr in current_addresses:
            if not addr in interface.addresses:
                subprocess.run(['ip', 'address', 'del', addr, 'dev', interface.name],
                               capture_output=True, check=True)

        # ensure interface is set to up
        subprocess.run(['ip', 'link', 'set', interface.name, 'up'],
                       capture_output=True, check=True)

        # persist configuration
        config_path = os.path.join(self.config_dir, f'{interface.name}.conf')
        with open(config_path, 'w') as outfile:
            interface.write_to_wireguard_config_file(outfile)

        # load config into wireguard with `wg`
        subprocess.run(['wg', 'setconf', interface.name, config_path],
                       capture_output=True, check=True)

    @staticmethod
    def _get_address_list(interface_name: str) -> List[str]:
        """Gets a list of configured IP addresses (both IPv4 and IPv6) that are configured
        for a particular interfce."""
        result = subprocess.run(['ip', '-br', '-j', 'address'], capture_output=True, check=True)
        raw_ifaces = json.loads(result.stdout.decode())
        addresses = []
        for iface in raw_ifaces:
            if iface['ifname'] == interface_name:
                for addr in iface['addr_info']:
                    addresses.append(f"{addr['local']}/{addr['prefixlen']}")
        return addresses


#class uciConfigScheme(ConfigScheme):
#
#    def __init__(self)
#        # validation
#        required_tools = ['wg', 'uci']
#        for tool in required_tools:
#            subprocess.run(['which', tool], capture_output=True, check=True)
#
#    def read(self, interface_name: str) -> wg.WireguardInterface:
#        raise NotImplementedError
#
#    def write(self, interface: wg.WireguardInterface):
#        raise NotImplementedError
