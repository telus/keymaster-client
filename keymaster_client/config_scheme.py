"""Defines the ConfigScheme abstract base class, and classes that implement it."""
import abc
import subprocess
import json
import os

from typing import List
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


class uciConfigScheme(ConfigScheme):

    def __init__(self):
        # validation
        required_tools = ['wg', 'uci']
        for tool in required_tools:
            run(['which', tool], capture_output=True, check=True)

    def interface_exists(self, interface_name: str) -> bool:
        """Tests whether the interface with name `interface_name` exists."""
        result = run(['uci', 'get', f'network.{interface_name}'], capture_output=True, check=False)
        return result.returncode == 0

    def read(self, interface_name: str) -> wg.WireguardInterface:
        """Takes the name of a wireguard interface, pulls the necessary info from UCI,
        and returns a WireguardInterface from that info."""
        # check if network interface exists in UCI
        if not self.interface_exists(interface_name):
            raise RuntimeError(f'interface {interface_name} is not present')

        # build dict from uci outputs
        output_dict = {}

        output_dict['name'] = interface_name

        result = run(['uci', 'get', f'network.{interface_name}.addresses'], capture_output=True,
                     check=True)
        output_dict['addresses'] = result.stdout.decode().strip().split(' ')

        result = run(['uci', 'get', f'network.{interface_name}.private_key'], capture_output=True,
                     check=True)
        output_dict['private_key'] = result.stdout.decode().strip()

        result = run(['uci', 'get', f'network.{interface_name}.listen_port'], capture_output=True,
                     check=False)
        if result.returncode == 0:
            output_dict['listen_port'] = int(result.stdout.decode().strip())

        result = run(['uci', 'get', f'network.{interface_name}.fwmark'], capture_output=True,
                     check=False)
        if result.returncode == 0:
            output_dict['fw_mark'] = int(result.stdout.decode().strip())

        peer_names = self._get_uci_peer_names(interface_name)

        output_dict['peers'] = [self._read_peer(peer) for peer in peer_names]

        return wg.WireguardInterface(**output_dict)

    def _read_peer(self, node_name: str) -> wg.WireguardPeer:
        """Takes the name of a wireguard peer node, pulls all related info from UCI,
        and builds a WireguardPeer from that info."""
        # check if peer node exists in UCI
        if not self.interface_exists(node_name):
            raise RuntimeError(f'node {node_name} is not present')

        # build dict from uci outputs
        output_dict = {}
        result = run(['uci', 'get', f'network.{node_name}.public_key'], capture_output=True,
                     check=True)
        output_dict['public_key'] = result.stdout.decode().strip()

        result = run(['uci', 'get', f'network.{node_name}.allowed_ips'], capture_output=True,
                     check=True)
        output_dict['allowed_ips'] = result.stdout.decode().replace('\n', '').split(' ')

        result = run(['uci', 'get', f'network.{node_name}.endpoint_host'], capture_output=True,
                     check=False)
        if result.returncode == 0:
            endpoint_host = result.stdout.decode().strip()
        result = run(['uci', 'get', f'network.{node_name}.endpoint_port'], capture_output=True,
                     check=False)
        if result.returncode == 0:
            endpoint_port = result.stdout.decode().strip()
        output_dict['endpoint'] = f'{endpoint_host}:{endpoint_port}'

        result = run(['uci', 'get', f'network.{node_name}.persistent_keepalive'],
                     capture_output=True, check=False)
        if result.returncode == 0:
            output_dict['persistent_keepalive'] = int(result.stdout.decode().strip())

        result = run(['uci', 'get', f'network.{node_name}.preshared_key'], capture_output=True,
                     check=False)
        if result.returncode == 0:
            output_dict['preshared_key'] = result.stdout.decode().strip()

        return wg.WireguardPeer(**output_dict)

    def write(self, interface: wg.WireguardInterface):
        """Writes this WireguardInterface to UCI and commits the changes."""
        # delete old interface
        result = run(['uci', 'get', f'network.{interface.name}'], capture_output=True, check=False)
        if result.returncode == 0:
            run(['uci', '-q', 'delete', f'network.{interface.name}'],
                capture_output=True, check=True)

        # build new interface
        run(['uci', 'set', f'network.{interface.name}=interface'], capture_output=True, check=True)
        run(['uci', 'set', f'network.{interface.name}.proto=wireguard'],
            capture_output=True, check=True)
        run(['uci', 'set', f'network.{interface.name}.private_key={interface.private_key}'],
            capture_output=True, check=True)

        for address in interface.addresses:
            run(['uci', 'add_list', f'network.{interface.name}.addresses={address}'],
                capture_output=True, check=True)

        if interface.listen_port is not None:
            run(['uci', 'add_list', f'network.{interface.name}.listen_port={interface.listen_port}'],
                capture_output=True, check=True)

        if interface.fw_mark is not None:
            run(['uci', 'add_list', f'network.{interface.name}.fwmark={interface.fw_mark}'],
                capture_output=True, check=True)

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

        run(['uci', 'set', f'network.{node_name}=wireguard_{interface_name}'],
            capture_output=True, check=True)

        run(['uci', 'set', f'network.{node_name}.public_key={peer.public_key}'],
            capture_output=True, check=True)

        for allowed_ip in peer.allowed_ips:
            run(['uci', 'add_list', f'network.{node_name}.allowed_ips={allowed_ip}'],
                capture_output=True, check=True)

        if peer.endpoint is not None:
            host, port = peer.endpoint.split(':')
            run(['uci', 'set', f'network.{node_name}.endpoint_host={host}'],
                capture_output=True, check=True)
            run(['uci', 'set', f'network.{node_name}.endpoint_port={port}'],
                capture_output=True, check=True)

        if peer.preshared_key is not None:
            run(['uci', 'set', f'network.{node_name}.preshared_key={peer.preshared_key}'],
                capture_output=True, check=True)

        if peer.persistent_keepalive is not None:
            run(['uci', 'set',
                 f'network.{node_name}.persistent_keepalive={peer.persistent_keepalive}'],
                capture_output=True, check=True)

    def _get_uci_peer_names(self, interface_name: str) -> List[str]:
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
