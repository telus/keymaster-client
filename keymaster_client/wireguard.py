"""Contains WireguardInterface and WireguardPeer, which are used to
validate wireguard configuration and then convert it into other formats."""
from __future__ import annotations
from subprocess import run
from copy import deepcopy

from typing import List, IO, Iterable
from dataclasses import dataclass, field
from ipaddress import ip_interface, ip_network


UCI_PRESENT = run(['which', 'uci'], capture_output=True, check=False).returncode == 0


def uci_interface_present(interface: str, check: bool = False):
    """Checks whether `interface` is present as a node in the UCI network config."""
    result = run(['uci', 'get', f'network.{interface}'], capture_output=True, check=check)
    return result.returncode == 0


def generate_private_key():
    """Uses the local installation of `wg` to generate a private key."""
    result = run(['wg', 'genkey'], capture_output=True, check=True)
    return result.stdout.decode().strip()


def get_public_key(private_key: str):
    """Generates a public key from the passed-in private key using the local
    `wg` installation."""
    result = run(['wg', 'pubkey'], capture_output=True, check=True,
                 input=private_key)
    return result.stdout.decode().strip()


def _get_uci_peer_names(interface: str) -> List[str]:
    """Under UCI, peers are like interfaces but rather than being of the form
    `network.{interface_name}=interface`, they are of the form
    `network.{peer_name}=wireguard_{interface_name}. This function gets all
    `peer_name`s for a specific `interface_name`."""
    result = run(['uci', 'show', 'network'], capture_output=True, check=True)
    lines = result.stdout.decode().strip().split('\n')
    peer_names = []
    for line in lines:
        sep_index = line.index('=')
        key = line[:sep_index]
        value = line[sep_index+1:]
        if value == f'wireguard_{interface}':
            peer_names.append(key.split('.')[1])
    return peer_names


def _separate_peers(lines: List[str]) -> Iterable[List[str]]:
    """Takes a list of lines which contains configuration for
    any number of Peers in wireguard configuration file format.
    Each yield returns a list of lines that contain the configuration
    (still in wireguard configuration file format) for a single Peer."""
    if len(lines) == 0:
        return
    output_peer = []
    for line in lines:
        stripped_line = line.replace(' ', '').replace('\t', '')
        if stripped_line == '':
            continue
        if stripped_line == '[Peer]':
            if len(output_peer) > 0:
                yield output_peer
            output_peer = []
        else:
            output_peer.append(line)
    yield output_peer


@dataclass
class WireguardPeer:
    """Represents a single Peer in a wireguard configuration. Can
    be instantiated directly, from a uci config using `from_uci`,
    or from a list of strings that correspond to a single peer in
    wireguard configuration file format.

    For an understanding of what each field of this object does,
    please refer to the wireguard documentation."""
    public_key: str
    allowed_ips: List[str]
    endpoint: str = None
    persistent_keepalive: int = None
    preshared_key: str = None

    def __post_init__(self):
        """Runs after __init__, which is created using the `dataclass` decorator.
        Here, its sole purpose is data validation."""
        # pylint: disable=too-many-branches
        if not isinstance(self.public_key, str):
            raise TypeError('public_key must be a string')

        if not isinstance(self.allowed_ips, list):
            raise TypeError('allowed_ips must be a list')
        if len(self.allowed_ips) < 1:
            raise ValueError('allowed_ips is not allowed to be empty')
        for ip_str in self.allowed_ips:
            ip_network(ip_str)
            _, _ = ip_str.split('/')

        if self.endpoint is not None:
            if not isinstance(self.endpoint, str):
                raise TypeError('endpoint must be a string')
            hostname, port = self.endpoint.split(':')
            if not hostname:
                raise ValueError(f'{self.endpoint} does not contain a valid hostname')
            try:
                port = int(port)
            except ValueError:
                raise ValueError(f'"{port}" is not a valid port')
            if port < 0 or port > 65535:
                raise ValueError(f'"{port}" is not a valid port')

        if self.persistent_keepalive is not None:
            if not isinstance(self.persistent_keepalive, int):
                raise TypeError('persistent_keepalive must be an integer')
            if self.persistent_keepalive < 0 or self.persistent_keepalive > 65535:
                raise ValueError('persistent_keepalive must be between 0 and 65535 inclusive')

        if self.preshared_key is not None:
            if not isinstance(self.preshared_key, str):
                raise TypeError('preshared_key must be a string')

    @classmethod
    def from_wireguard_config(cls, lines: List[str]) -> WireguardPeer:
        """Input is a list of strings, where the list makes up the configuration for a single Peer.
        The list should be in wireguard configuration file format. Returns a WireguardPeer."""
        output_dict = {}

        for line in lines:
            stripped_line = line.replace(' ', '').replace('\t', '')
            if stripped_line == '[Peer]':
                continue
            sep_index = stripped_line.index('=')
            key = stripped_line[:sep_index]
            value = stripped_line[sep_index+1:]
            if key == 'PublicKey':
                output_dict['public_key'] = value
            elif key == 'AllowedIPs':
                output_dict['allowed_ips'] = value.split(',')
            elif key == 'Endpoint':
                output_dict['endpoint'] = value
            elif key == 'PersistentKeepalive':
                output_dict['persistent_keepalive'] = int(value)
            elif key == 'PresharedKey':
                output_dict['preshared_key'] = value

        return cls(**output_dict)

    @classmethod
    def from_uci(cls, node_name: str) -> WireguardPeer:
        """Takes the name of a wireguard peer node, pulls all related info from UCI,
        and builds a WireguardPeer from that info."""
        if not UCI_PRESENT:
            raise RuntimeError('The system does not have uci')

        # check if network interface exists in UCI
        uci_interface_present(node_name, check=True)

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

        return cls(**output_dict)

    def to_wireguard_config_lines(self) -> List[str]:
        """Turns the WireguardPeer object into a list of lines that make up the
        configuration for a single Peer. These lines are in wireguard configuration
        file format."""
        output_string_list = [
            '[Peer]',
            f'PublicKey = {self.public_key}',
            f"AllowedIPs = {', '.join(self.allowed_ips)}"
        ]
        if self.endpoint is not None:
            output_string_list.append(f'Endpoint = {self.endpoint}')
        if self.persistent_keepalive is not None:
            output_string_list.append(f'PersistentKeepalive = {self.persistent_keepalive}')
        if self.preshared_key is not None:
            output_string_list.append(f'PresharedKey = {self.preshared_key}')

        return output_string_list

    def write_to_uci(self, interface, peer_number):
        """Writes the WireguardPeer to UCI. Peer record in UCI does not need to be
        deleted here; WireguardInterface.write_to_uci takes care of that since it
        is in a better position to do so."""
        if not UCI_PRESENT:
            raise RuntimeError('The system does not have uci')
        node_name = f'{interface}_peer{peer_number}'

        run(['uci', 'set', f'network.{node_name}=wireguard_{interface}'],
            capture_output=True, check=True)

        run(['uci', 'set', f'network.{node_name}.public_key={self.public_key}'],
            capture_output=True, check=True)

        for allowed_ip in self.allowed_ips:
            run(['uci', 'add_list', f'network.{node_name}.allowed_ips={allowed_ip}'],
                capture_output=True, check=True)

        if self.endpoint is not None:
            host, port = self.endpoint.split(':')
            run(['uci', 'set', f'network.{node_name}.endpoint_host={host}'],
                capture_output=True, check=True)
            run(['uci', 'set', f'network.{node_name}.endpoint_port={port}'],
                capture_output=True, check=True)

        if self.preshared_key is not None:
            run(['uci', 'set', f'network.{node_name}.preshared_key={self.preshared_key}'],
                capture_output=True, check=True)

        if self.persistent_keepalive is not None:
            run(['uci', 'set',
                 f'network.{node_name}.persistent_keepalive={self.persistent_keepalive}'],
                capture_output=True, check=True)


@dataclass
class WireguardInterface:
    """Represents a wireguard Interface, along with any Peers that it may
    be able to route traffic to. Should not be instantiated directly unless
    you have a list of `WireguardPeer`s ready to pass to it. Can be instantiated
    from a dict with `from_dict`, from a uci config using `from_uci`,
    or from a file-like object that contains wireguard configuration in the wireguard
    configuration file format.

    `name`: the name of the wireguard interface

    `addresses`: a list of addresses, plus the prefix length

    For the other fields, please refer to the wireguard documentation."""
    name: str
    addresses: List[str]
    private_key: str
    listen_port: int = None
    fw_mark: int = None
    peers: List[WireguardPeer] = field(default_factory=list)

    def __post_init__(self):
        """Runs after __init__, which is created using the `dataclass` decorator.
        Here, its sole purpose is data validation."""
        if not isinstance(self.name, str):
            raise TypeError('interface name must be a string')

        if not isinstance(self.addresses, list):
            raise TypeError('addresses must be a list')
        if len(self.addresses) < 1:
            raise ValueError('At least one interface address is required')
        for ip_str in self.addresses:
            ip_interface(ip_str)
            _, _ = ip_str.split('/')

        if not isinstance(self.private_key, str):
            raise TypeError(f'private_key must be a string but is of type {type(self.private_key)}')

        if self.listen_port is not None:
            if not isinstance(self.listen_port, int):
                raise TypeError('listen_port must be an integer')
            if self.listen_port < 0 or self.listen_port > 65535:
                raise ValueError('listen_port must be between 0 and 65535 inclusive')

        if self.fw_mark is not None:
            if not isinstance(self.fw_mark, int):
                raise TypeError('fw_mark must be an integer')

        if not isinstance(self.peers, list):
            raise TypeError('peers must be a list')

    @classmethod
    def from_wireguard_config_file(cls, name: str, addresses: List[str],
                                   infile: IO) -> WireguardInterface:
        """Builds a WireguardInterface object by reading from a file-like object that it
        expects to be in wireguard configuration file format. The user of this method
        must pass in `name` and `addresses` because they do not exist in the wireguard
        configuration file format. If this information must be stored, it is the
        responsibility of the user of this method to figure that out."""

        # parse the file into lines
        raw_lines = infile.read().strip().split('\n')
        lines = [line.strip() for line in raw_lines]

        # split the Interface and the Peers into two separate lists
        parsing_state = None
        interface_lines = []
        peer_lines = []
        for line in lines:
            stripped_line = line.strip().replace(' ', '').replace('\t', '')
            if stripped_line == '':
                continue
            if stripped_line == '[Peer]':
                parsing_state = 'peer'
            elif stripped_line == '[Interface]':
                parsing_state = 'interface'

            if parsing_state == 'peer':
                peer_lines.append(stripped_line)
            elif parsing_state == 'interface':
                interface_lines.append(stripped_line)

        # parse interface lines into interface dict
        interface_dict = {
            'peers': [WireguardPeer.from_wireguard_config(x) for x in _separate_peers(peer_lines)],
            'name': name,
            'addresses': addresses
        }
        for line in interface_lines:
            stripped_line = line.replace(' ', '').replace('\t', '')
            if stripped_line == '[Interface]':
                continue
            sep_index = stripped_line.index('=')
            key = stripped_line[:sep_index]
            value = stripped_line[sep_index+1:]
            if key == 'PrivateKey':
                interface_dict['private_key'] = value
            elif key == 'ListenPort':
                interface_dict['listen_port'] = int(value)
            elif key == 'FwMark':
                interface_dict['fw_mark'] = int(value)

        return cls(**interface_dict)

    @classmethod
    def from_uci(cls, interface: str) -> WireguardInterface:
        """Takes the name of a wireguard interface, pulls the necessary info from UCI,
        and returns a WireguardInterface from that info."""
        if not UCI_PRESENT:
            raise RuntimeError('The system does not have uci')

        # check if network interface exists in UCI
        uci_interface_present(interface, check=True)

        # build dict from uci outputs
        output_dict = {}

        output_dict['name'] = interface

        result = run(['uci', 'get', f'network.{interface}.addresses'], capture_output=True,
                     check=True)
        output_dict['addresses'] = result.stdout.decode().strip().split(' ')

        result = run(['uci', 'get', f'network.{interface}.private_key'], capture_output=True,
                     check=True)
        output_dict['private_key'] = result.stdout.decode().strip()

        result = run(['uci', 'get', f'network.{interface}.listen_port'], capture_output=True,
                     check=False)
        if result.returncode == 0:
            output_dict['listen_port'] = int(result.stdout.decode().strip())

        result = run(['uci', 'get', f'network.{interface}.fwmark'], capture_output=True,
                     check=False)
        if result.returncode == 0:
            output_dict['fw_mark'] = int(result.stdout.decode().strip())

        peer_names = _get_uci_peer_names(interface)

        output_dict['peers'] = [WireguardPeer.from_uci(peer) for peer in peer_names]

        return cls(**output_dict)

    @classmethod
    def from_dict(cls, input_dict: dict) -> WireguardInterface:
        """Takes a dict that contains info we can build a WireguardInterface out of.
        We use this method instead of calling `WireguardInterface(**my_dict)`
        because the `peers` key of the dictionary must be parsed into
        `WireguardPeer`s first."""
        interface_dict = deepcopy(input_dict)
        interface_dict['peers'] = [WireguardPeer(**x) for x in interface_dict['peers']]
        return cls(**interface_dict)

    def write_to_wireguard_config_file(self, outfile: IO):
        """Takes a writeable file-like object and writes a representation of this
        WireguardInterface to it, in wireguard configuration file format."""
        output_string_list = [
            '[Interface]',
            f'PrivateKey = {self.private_key}'
        ]

        if self.listen_port is not None:
            output_string_list.append(f'ListenPort = {self.listen_port}')

        if self.fw_mark is not None:
            output_string_list.append(f'FwMark = {self.fw_mark}')

        for peer in self.peers:
            output_string_list.append('')
            for line in peer.to_wireguard_config_lines():
                output_string_list.append(line)

        output_string_list.append('')

        outfile.write('\n'.join(output_string_list))

    def write_to_uci(self):
        """Writes this WireguardInterface to UCI and commits the changes."""
        if not UCI_PRESENT:
            raise RuntimeError('The system does not have uci')

        # delete old interface
        result = run(['uci', 'get', f'network.{self.name}'], capture_output=True, check=False)
        if result.returncode == 0:
            run(['uci', '-q', 'delete', f'network.{self.name}'],
                capture_output=True, check=True)

        # build new interface
        run(['uci', 'set', f'network.{self.name}=interface'], capture_output=True, check=True)
        run(['uci', 'set', f'network.{self.name}.proto=wireguard'],
            capture_output=True, check=True)
        run(['uci', 'set', f'network.{self.name}.private_key={self.private_key}'],
            capture_output=True, check=True)

        for address in self.addresses:
            run(['uci', 'add_list', f'network.{self.name}.addresses={address}'],
                capture_output=True, check=True)

        if self.listen_port is not None:
            run(['uci', 'add_list', f'network.{self.name}.listen_port={self.listen_port}'],
                capture_output=True, check=True)

        if self.fw_mark is not None:
            run(['uci', 'add_list', f'network.{self.name}.fwmark={self.fw_mark}'],
                capture_output=True, check=True)

        # clear all peers
        peer_names = _get_uci_peer_names(self.name)
        for peer_name in peer_names:
            run(['uci', '-q', 'delete', f'network.{peer_name}'], capture_output=True, check=True)

        # write all peers
        for i, peer in enumerate(self.peers):
            peer.write_to_uci(self.name, i)

        # commit changes
        run(['uci', 'commit', 'network'], capture_output=True, check=True)
