# -*- coding: utf-8 -*-

"""Tests for wireguard in keymaster_client package."""

import pytest

from copy import deepcopy
from subprocess import CompletedProcess
from io import StringIO

from keymaster_client.wireguard import (
    WireguardPeer,
    WireguardInterface,
    _get_uci_peer_names,
    _separate_peers,
)


BASE_PEER = {
    'public_key': 'asdfasdfasdf',
    'allowed_ips': ['192.168.1.0/24']
}

BASE_INTERFACE = {
    'name': 'wg0',
    'addresses': ['223.224.225.226/24'],
    'private_key': 'asdfasdfasdfasdf',
    'peers': [BASE_PEER]
}


def test_get_uci_peer_names(mocker):
    interface = 'wg0'
    fake_stdout_line_list = [
        "network.eth2=interface",
        "network.eth2.ifname='eth2'",
        "network.eth2.proto='static'",
        "network.eth2.ipaddr='10.10.10.1'",
        "network.eth2.netmask='255.255.255.0'",
        "network.lan=interface",
        "network.lan.type='bridge'",
        "network.lan.ifname='eth1 eth0'",
        "network.lan.proto='dhcp'",
        f"network.{interface}=interface",
        f"network.{interface}.proto='wireguard'",
        f"network.{interface}.private_key='eEka88hW5MRI99ggd+zOP65na1W+gWC/fGXEieHcf3Q='",
        f"network.{interface}.addresses='192.168.127.3/24'",
        f"network.{interface}_peer0=wireguard_{interface}",
        f"network.{interface}_peer0.public_key='HrE/V7ueXdybmHvkuYoBX22qcUPgxFt17KaN0uZ2nRQ='",
        f"network.{interface}_peer0.allowed_ips='192.168.127.0/24'",
        f"network.{interface}_peer0.endpoint_host='15.223.4.126'",
        f"network.{interface}_peer0.endpoint_port='51820'",
        f"network.{interface}_peer0.persistent_keepalive='25'",
        ""
    ]
    repl_proc = CompletedProcess(
        args=['uci', 'show', 'network'],
        returncode=0,
        stdout='\n'.join(fake_stdout_line_list).encode()
    )
    mocker.patch('keymaster_client.wireguard.run', return_value=repl_proc)
    peer_names = _get_uci_peer_names(interface)
    assert peer_names[0] == f'{interface}_peer0'
    assert len(peer_names) == 1


def test_separate_peers(mocker):
    peer_lines_to_separate = [
        '[Peer]',
        'PublicKey = asdfasdfasdfasdf',
        'Endpoint = 192.168.1.2',
        'PersistentKeepalive = 25',
        'PresharedKey = asdfasdfasdf',
        '',
        '[Peer]',
        'PublicKey = asdfasdfasdfasdf',
        'Endpoint = 192.168.1.2',
        'PersistentKeepalive = 25',
        'PresharedKey = asdfasdfasdf',
        '',
    ]
    separated_peers = list(_separate_peers(peer_lines_to_separate))
    assert separated_peers[0][0] == 'PublicKey = asdfasdfasdfasdf'
    assert separated_peers[0][1] == 'Endpoint = 192.168.1.2'
    assert separated_peers[0][2] == 'PersistentKeepalive = 25'
    assert separated_peers[0][3] == 'PresharedKey = asdfasdfasdf'
    assert separated_peers[1][0] == 'PublicKey = asdfasdfasdfasdf'
    assert separated_peers[1][1] == 'Endpoint = 192.168.1.2'
    assert separated_peers[1][2] == 'PersistentKeepalive = 25'
    assert separated_peers[1][3] == 'PresharedKey = asdfasdfasdf'


class TestWireguardPeer:

    def run_uci_side_effect(self, *args, **kwargs):
        interface = 'asdf'

        if args[0] == ['uci', 'get', f'network.{interface}']:
            return CompletedProcess(
                args=args[0],
                returncode=0
            )

        elif args[0] == ['uci', 'get', f'network.{interface}.public_key']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='publickey'.encode()
            )

        elif args[0] == ['uci', 'get', f'network.{interface}.allowed_ips']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='192.168.1.0/24 192.168.2.0/24'.encode()
            )

        elif args[0] == ['uci', 'get', f'network.{interface}.endpoint_host']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='192.168.1.2'.encode()
            )

        elif args[0] == ['uci', 'get', f'network.{interface}.endpoint_port']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='4444'.encode()
            )

        elif args[0] == ['uci', 'get', f'network.{interface}.persistent_keepalive']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='25'.encode()
            )

        elif args[0] == ['uci', 'get', f'network.{interface}.preshared_key']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='presharedkey'.encode()
            )

    def test_comparison(self):
        a = WireguardPeer(**BASE_PEER)
        b = WireguardPeer(**BASE_PEER)
        assert a == b

        b.public_key = 'qwerqwer'
        assert a != b

    def test_no_uci(self, mocker):
        mocker.patch('keymaster_client.wireguard.UCI_PRESENT', False)
        with pytest.raises(RuntimeError):
            p = deepcopy(BASE_PEER)
            a = WireguardPeer(**p)
            a.write_to_uci('wg0', 0)
        with pytest.raises(RuntimeError):
            p = deepcopy(BASE_PEER)
            a = WireguardPeer(**p)
            a.from_uci('wg0')

    def test_from_uci(self, mocker):
        mocker.patch('keymaster_client.wireguard.UCI_PRESENT', True)
        mocker.patch('keymaster_client.wireguard.run', side_effect=self.run_uci_side_effect)
        p = WireguardPeer.from_uci('asdf')
        assert p.public_key == 'publickey'
        assert p.allowed_ips == ['192.168.1.0/24', '192.168.2.0/24']
        assert p.endpoint == '192.168.1.2:4444'
        assert p.persistent_keepalive == 25
        assert p.preshared_key == 'presharedkey'

    def test_from_wireguard_config(self):
        pub_key = 'asdfasdfasdf'
        allowed_ips = ['192.168.1.0/24', '192.168.127.0/24']
        endpoint = 'hello.com:234'
        pers_keepalive = 24
        preshared_key = 'asdfasdfasdfasdfasd'
        input_lines = [
            '[Peer]',
            f'PublicKey = {pub_key}',
            f'AllowedIPs = {", ".join(allowed_ips)}',
            f'Endpoint = {endpoint}',
            f'PersistentKeepalive = {pers_keepalive}',
            f'PresharedKey = {preshared_key}',
        ]
        p = WireguardPeer.from_wireguard_config(input_lines)
        assert pub_key == p.public_key
        for i, ip in enumerate(allowed_ips):
            assert ip == p.allowed_ips[i]
        assert endpoint == p.endpoint
        assert pers_keepalive == p.persistent_keepalive
        assert preshared_key == p.preshared_key

    def test_validation(self):
        # PublicKey
        with pytest.raises(TypeError):
            p = deepcopy(BASE_PEER)
            p['public_key'] = 42
            WireguardPeer(**p)

        # AllowedIPs
        with pytest.raises(ValueError):
            p = deepcopy(BASE_PEER)
            p['allowed_ips'] = ['192.373.0.4/24']
            WireguardPeer(**p)
        with pytest.raises(ValueError):
            p = deepcopy(BASE_PEER)
            p['allowed_ips'] = ['192.173.0.4/24']
            WireguardPeer(**p)
        with pytest.raises(ValueError):
            p = deepcopy(BASE_PEER)
            p['allowed_ips'] = []
            WireguardPeer(**p)
        with pytest.raises(ValueError):
            p = deepcopy(BASE_PEER)
            p['allowed_ips'] = ['192.73.0.4']
            WireguardPeer(**p)
        with pytest.raises(ValueError):
            p = deepcopy(BASE_PEER)
            p['allowed_ips'] = ['192.73.0.4/33']
            WireguardPeer(**p)
        with pytest.raises(TypeError):
            p = deepcopy(BASE_PEER)
            p['allowed_ips'] = 'allowedips'
            WireguardPeer(**p)

        # Endpoint
        with pytest.raises(TypeError):
            p = deepcopy(BASE_PEER)
            p['endpoint'] = 42
            WireguardPeer(**p)
        with pytest.raises(ValueError):
            p = deepcopy(BASE_PEER)
            p['endpoint'] = 'asdf'
            WireguardPeer(**p)
        with pytest.raises(ValueError):
            p = deepcopy(BASE_PEER)
            p['endpoint'] = 'google.com:asdf'
            WireguardPeer(**p)
        with pytest.raises(ValueError):
            p = deepcopy(BASE_PEER)
            p['endpoint'] = '172.34.89.92:84323'
            WireguardPeer(**p)
        with pytest.raises(ValueError):
            p = deepcopy(BASE_PEER)
            p['endpoint'] = '172.34.89.92:8432:anotha-one'
            WireguardPeer(**p)

        # PersistentKeepalive
        with pytest.raises(ValueError):
            p = deepcopy(BASE_PEER)
            p['persistent_keepalive'] = -3
            WireguardPeer(**p)
        with pytest.raises(ValueError):
            p = deepcopy(BASE_PEER)
            p['persistent_keepalive'] = 100000
            WireguardPeer(**p)
        with pytest.raises(TypeError):
            p = deepcopy(BASE_PEER)
            p['persistent_keepalive'] = 'asdf'
            WireguardPeer(**p)

        # PresharedKey
        with pytest.raises(TypeError):
            p = deepcopy(BASE_PEER)
            p['preshared_key'] = 42
            WireguardPeer(**p)


class TestWireguardInterface:

    def run_uci_side_effect(self, *args, **kwargs):
        interface = 'asdf'

        if args[0] == ['uci', 'get', f'network.{interface}']:
            return CompletedProcess(
                args=args[0],
                returncode=0
            )

        elif args[0] == ['uci', 'get', f'network.{interface}.addresses']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='192.168.1.2/24 192.168.2.2/24'.encode()
            )

        elif args[0] == ['uci', 'get', f'network.{interface}.private_key']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='privatekey'.encode()
            )

        elif args[0] == ['uci', 'get', f'network.{interface}.listen_port']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='4444'.encode()
            )

        elif args[0] == ['uci', 'get', f'network.{interface}.fwmark']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='32'.encode()
            )

    def test_comparison(self):
        a = WireguardInterface.from_dict(BASE_INTERFACE)
        b = WireguardInterface.from_dict(BASE_INTERFACE)
        assert a == b

        b.private_key = 'qwerqwer'
        assert a != b

        b = WireguardInterface.from_dict(BASE_INTERFACE)
        b.peers[0].public_key = 'qwerqwerqwer'
        assert a != b

    def test_no_uci(self, mocker):
        mocker.patch('keymaster_client.wireguard.UCI_PRESENT', False)
        with pytest.raises(RuntimeError):
            i = deepcopy(BASE_INTERFACE)
            a = WireguardInterface(**i)
            a.write_to_uci()
        with pytest.raises(RuntimeError):
            i = deepcopy(BASE_INTERFACE)
            a = WireguardInterface(**i)
            a.from_uci('wg0')

    def test_from_uci(self, mocker):
        mocker.patch('keymaster_client.wireguard.UCI_PRESENT', True)
        mocker.patch('keymaster_client.wireguard.run', side_effect=self.run_uci_side_effect)
        mocker.patch('keymaster_client.wireguard._get_uci_peer_names', return_value=[])
        interface = WireguardInterface.from_uci('asdf')
        assert interface.name == 'asdf'
        assert interface.addresses == ['192.168.1.2/24', '192.168.2.2/24']
        assert interface.private_key == 'privatekey'
        assert interface.listen_port == 4444
        assert interface.fw_mark == 32

    def test_from_wireguard_config_file(self):
        name = 'wg0'
        addresses = ['192.168.1.3/24', '192.168.127.3/24']
        priv_key = 'asdfaewdfwerwer'
        listen_port = 24
        fwmark = 32
        input_lines = [
            '[Interface]',
            f'PrivateKey = {priv_key}',
            f'ListenPort = {listen_port}',
            f'FwMark = {fwmark}',
            '',
            '[Peer]',
            'PublicKey = asdafsdfasdf',
            'AllowedIPs = 192.168.1.0/24, 192.168.127.0/24',
            'Endpoint = hello.com:234',
            'PersistentKeepalive = 24',
            'PresharedKey = asdfasdfasdfasdf',
            '',
            '[Peer]',
            'PublicKey = asdafsdfasdf',
            'AllowedIPs = 192.168.1.0/24, 192.168.127.0/24',
            'Endpoint = hello.com:234',
            'PersistentKeepalive = 24',
            'PresharedKey = asdfasdfasdfasdf',
        ]
        fake_file = StringIO('\n'.join(input_lines))
        interface = WireguardInterface.from_wireguard_config_file(name, addresses, fake_file)
        assert priv_key == interface.private_key
        for i, addr in enumerate(addresses):
            assert addr == interface.addresses[i]
        assert listen_port == interface.listen_port
        assert fwmark == interface.fw_mark

        # test with \r\n newlines
        fake_file = StringIO('\r\n'.join(input_lines))
        interface = WireguardInterface.from_wireguard_config_file(name, addresses, fake_file)
        assert priv_key == interface.private_key
        for i, addr in enumerate(addresses):
            assert addr == interface.addresses[i]
        assert listen_port == interface.listen_port
        assert fwmark == interface.fw_mark

        # test with random tabs
        input_lines = [
            '\t[Interface]',
            f'\tPrivateKey = {priv_key}',
            f'ListenPort = {listen_port}',
            f'\tFwMark = {fwmark}',
            '',
        ]
        fake_file = StringIO('\n'.join(input_lines))
        interface = WireguardInterface.from_wireguard_config_file(name, addresses, fake_file)
        assert priv_key == interface.private_key
        for i, addr in enumerate(addresses):
            assert addr == interface.addresses[i]
        assert listen_port == interface.listen_port
        assert fwmark == interface.fw_mark

        # test without spaces between keys and values and at end
        input_lines = [
            '[Interface]  ',
            f'  PrivateKey= {priv_key}',
            f'ListenPort ={listen_port}  ',
            f' FwMark={fwmark}       ',
            '',
        ]
        fake_file = StringIO('\n'.join(input_lines))
        interface = WireguardInterface.from_wireguard_config_file(name, addresses, fake_file)
        assert priv_key == interface.private_key
        for i, addr in enumerate(addresses):
            assert addr == interface.addresses[i]
        assert listen_port == interface.listen_port
        assert fwmark == interface.fw_mark

    def test_write_then_read_then_compare(self, tmp_path):
        name = 'wg0'
        addresses = ['192.168.1.3/24', '192.168.127.3/24']
        f = tmp_path / f'{name}.conf'
        a = WireguardInterface(
            name=name,
            addresses=addresses,
            private_key='privatekey',
            listen_port=51820,
            peers=[
                WireguardPeer(
                    public_key='publickey',
                    endpoint='203.183.182.2:51820',
                    allowed_ips=['192.168.1.0/24', '192.168.2.0/24'],
                    persistent_keepalive=30
                ),
                WireguardPeer(
                    public_key='publickey',
                    endpoint='203.183.182.2:51820',
                    allowed_ips=['192.168.1.0/24', '192.168.2.0/24'],
                    persistent_keepalive=30
                ),
            ]
        )
        with open(f, 'w') as outfile:
            a.write_to_wireguard_config_file(outfile)

        with open(f, 'r') as infile:
            b = WireguardInterface.from_wireguard_config_file(name, addresses, infile)

        assert a == b

    def test_validation(self):
        # name
        with pytest.raises(TypeError):
            i = deepcopy(BASE_INTERFACE)
            i['name'] = 42
            WireguardInterface.from_dict(i)

        # addresses
        with pytest.raises(TypeError):
            i = deepcopy(BASE_INTERFACE)
            i['addresses'] = '192.168.1.2/24'
            WireguardInterface.from_dict(i)
        with pytest.raises(ValueError):
            i = deepcopy(BASE_INTERFACE)
            i['addresses'] = ['asdf']
            WireguardInterface.from_dict(i)
        with pytest.raises(ValueError):
            i = deepcopy(BASE_INTERFACE)
            i['addresses'] = ['192.268.1.2/24']
            WireguardInterface.from_dict(i)
        with pytest.raises(ValueError):
            i = deepcopy(BASE_INTERFACE)
            i['addresses'] = ['192.168.1.2']
            WireguardInterface.from_dict(i)
        with pytest.raises(ValueError):
            i = deepcopy(BASE_INTERFACE)
            i['addresses'] = ['::8g:1/120']
            WireguardInterface.from_dict(i)
        with pytest.raises(ValueError):
            i = deepcopy(BASE_INTERFACE)
            i['addresses'] = []
            WireguardInterface.from_dict(i)

        # PrivateKey
        with pytest.raises(TypeError):
            i = deepcopy(BASE_INTERFACE)
            i['private_key'] = 42
            WireguardInterface.from_dict(i)

        # ListenPort
        with pytest.raises(TypeError):
            i = deepcopy(BASE_INTERFACE)
            i['listen_port'] = 'asdf'
            WireguardInterface.from_dict(i)

        # FwMark
        with pytest.raises(TypeError):
            i = deepcopy(BASE_INTERFACE)
            i['fw_mark'] = 'asdf'
            WireguardInterface.from_dict(i)

        # peers
        with pytest.raises(TypeError):
            i = deepcopy(BASE_INTERFACE)
            i['peers'] = 'asdf'
            WireguardInterface.from_dict(i)
