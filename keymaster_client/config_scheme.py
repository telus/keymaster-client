"""Defines the ConfigScheme abstract base class, and classes that implement it."""
import abc
import subprocess
import json
import os

from typing import List, Union
from subprocess import run

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


class UCIConfigScheme(ConfigScheme):
    """`UCIConfigScheme` uses the OpenWrt project's `uci` (universal configuration
    interface) tool to configure wireguard interfaces. For more information see
    the OpenWrt documentation on wireguard configuration."""

    def __init__(self):
        # validation
        required_tools = ['wg', 'uci']
        for tool in required_tools:
            run(['which', tool], capture_output=True, check=True)

    def interface_exists(self, interface_name: str) -> bool:
        """Tests whether the interface with name `interface_name` exists."""
        result = run(['uci', 'get', f'network.{interface_name}'], capture_output=True, check=False)
        return result.returncode == 0

    @staticmethod
    def _uci_get(node_name: str, required: bool = False) -> Union[str, List[str], None]:
        """Reads the value of the uci node passed in `node_name`.
        If `required=True`, a nonexistent node will raise `subprocess.CalledProcessError`.
        If `required=False`, a nonexistent node will return None.
        If the `allowed_ips` or `addresses` wireguard node are requested, parses these
        values into a list before returning them."""
        result = run(['uci', 'get', node_name], capture_output=True, check=required)
        if result.returncode != 0:
            return None
        if 'addresses' in node_name:
            return result.stdout.decode().strip().split(' ')
        if 'allowed_ips' in node_name:
            return result.stdout.decode().strip().replace('\n', '').split(' ')
        return result.stdout.decode().strip()

    def read(self, interface_name: str) -> wg.WireguardInterface:
        """Takes the name of a wireguard interface, pulls the necessary info from UCI,
        and returns a WireguardInterface from that info."""
        # check if network interface exists in UCI
        if not self.interface_exists(interface_name):
            raise RuntimeError(f'interface {interface_name} is not present')

        # build dict from uci outputs
        base_node = f'network.{interface_name}'
        peer_names = self._get_uci_peer_names(interface_name)
        output_dict = {
            'name': interface_name,
            'peers': [self._read_peer(peer) for peer in peer_names],
            'addresses': self._uci_get(f'{base_node}.addresses', required=True),
            'private_key': self._uci_get(f'{base_node}.private_key', required=True)
        }
        if listen_port_raw := self._uci_get(f'{base_node}.listen_port', required=False):
            output_dict['listen_port'] = int(listen_port_raw)
        if fw_mark_raw := self._uci_get(f'{base_node}.fwmark', required=False):
            output_dict['fw_mark'] = int(fw_mark_raw)

        # return WireguardInterface object
        return wg.WireguardInterface(**output_dict)

    def _read_peer(self, node_name: str) -> wg.WireguardPeer:
        """Takes the name of a wireguard peer node, pulls all related info from UCI,
        and builds a WireguardPeer from that info."""
        # check if peer node exists in UCI
        if not self.interface_exists(node_name):
            raise RuntimeError(f'node {node_name} is not present')

        # build dict from uci outputs
        base_node = f'network.{node_name}'
        output_dict = {
            'public_key': self._uci_get(f'{base_node}.public_key', required=True),
            'allowed_ips': self._uci_get(f'{base_node}.allowed_ips', required=True)
        }
        endpoint_host_raw = self._uci_get(f'{base_node}.endpoint_host', required=False)
        endpoint_port_raw = self._uci_get(f'{base_node}.endpoint_port', required=False)
        if endpoint_host_raw and endpoint_port_raw:
            output_dict['endpoint'] = f'{endpoint_host_raw}:{endpoint_port_raw}'
        if pk_raw := self._uci_get(f'{base_node}.persistent_keepalive', required=False):
            output_dict['persistent_keepalive'] = int(pk_raw)
        if preshared_key := self._uci_get(f'{base_node}.preshared_key', required=False):
            output_dict['preshared_key'] = preshared_key

        return wg.WireguardPeer(**output_dict)

    @staticmethod
    def _uci_set(node_name: str, value: Union[str, List[str]]):
        """Sets the node given by `node_name` to the value passed in `value` by using `uci set`.
        If `value` is of type `list`, then the `uci add_list` command is used for each element
        of `value`."""
        if isinstance(value, str):
            run(['uci', 'set', f'{node_name}={value}'], capture_output=True, check=True)
        elif isinstance(value, list):
            for element in value:
                run(['uci', 'add_list', f'{node_name}={element}'], capture_output=True, check=True)
        else:
            raise TypeError(f'value is of type {type(value)} but must be a list or str')

    def write(self, interface: wg.WireguardInterface):
        """Writes this WireguardInterface to UCI and commits the changes."""
        # delete old interface
        result = run(['uci', 'get', f'network.{interface.name}'], capture_output=True, check=False)
        if result.returncode == 0:
            run(['uci', '-q', 'delete', f'network.{interface.name}'],
                capture_output=True, check=True)

        # build new interface
        self._uci_set(f'network.{interface.name}', 'interface')
        self._uci_set(f'network.{interface.name}.proto', 'wireguard')
        self._uci_set(f'network.{interface.name}.private_key', interface.private_key)
        self._uci_set(f'network.{interface.name}.addresses', interface.addresses)
        if interface.listen_port is not None:
            self._uci_set('network.{interface.name}.listen_port', interface.listen_port)
        if interface.fw_mark is not None:
            self._uci_set('network.{interface.name}.fwmark', interface.fw_mark)

        # clear all peers
        peer_names = self._get_uci_peer_names(interface.name)
        for peer_name in peer_names:
            run(['uci', '-q', 'delete', f'network.{peer_name}'], capture_output=True, check=True)

        # write all peers
        for i, peer in enumerate(interface.peers):
            self._write_peer(peer, interface.name, i)

        # commit changes
        run(['uci', 'commit', 'network'], capture_output=True, check=True)

    def _write_peer(self, peer: wg.WireguardPeer, interface_name: str, peer_number: int):
        """Writes a WireguardPeer to UCI. Peer record in UCI does not need to be
        deleted here; `uciConfigScheme.write` takes care of that since it
        is in a better position to do so."""
        node_name = f'{interface_name}_peer{peer_number}'
        self._uci_set(f'network.{node_name}', f'wireguard_{interface_name}')
        self._uci_set(f'network.{node_name}.public_key', peer.public_key)
        self._uci_set(f'network.{node_name}.allowed_ips', peer.allowed_ips)
        if peer.endpoint is not None:
            host, port = peer.endpoint.split(':')
            self._uci_set(f'network.{node_name}.endpoint_host', host)
            self._uci_set(f'network.{node_name}.endpoint_port', port)
        if peer.preshared_key is not None:
            self._uci_set(f'network.{node_name}.preshared_key', peer.preshared_key)
        if peer.persistent_keepalive is not None:
            self._uci_set(f'network.{node_name}.persistent_keepalive', peer.persistent_keepalive)

    @staticmethod
    def _get_uci_peer_names(interface_name: str) -> List[str]:
        """Under UCI, peers are like interfaces but rather than being of the form
        `network.{interface_name}=interface`, they are of the form
        `network.{peer_name}=wireguard_{interface_name}. This function gets all
        `peer_name`s for a specific `interface_name`."""
        result = run(['uci', 'show', 'network'], capture_output=True, check=True)
        lines = result.stdout.decode().strip().split('\n')
        peer_names = []
        for line in lines:
            print(line)
            sep_index = line.index('=')
            key = line[:sep_index]
            value = line[sep_index+1:]
            if value == f'wireguard_{interface_name}':
                peer_names.append(key.split('.')[1])
        return peer_names
