# -*- coding: utf-8 -*-

"""Tests for wireguard in keymaster_client package."""

import pytest

from copy import deepcopy
from subprocess import CompletedProcess
from io import StringIO

from keymaster_client.wireguard import (
    WireguardPeer,
    WireguardInterface,
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

    def test_comparison(self):
        a = WireguardPeer(**BASE_PEER)
        b = WireguardPeer(**BASE_PEER)
        assert a == b

        b.public_key = 'qwerqwer'
        assert a != b

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

    def test_comparison(self):
        a = WireguardInterface.from_dict(BASE_INTERFACE)
        b = WireguardInterface.from_dict(BASE_INTERFACE)
        assert a == b

        b.private_key = 'qwerqwer'
        assert a != b

        b = WireguardInterface.from_dict(BASE_INTERFACE)
        b.peers[0].public_key = 'qwerqwerqwer'
        assert a != b

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
            interface = WireguardInterface.from_dict(i)
            interface.validate()

        # addresses
        with pytest.raises(TypeError):
            i = deepcopy(BASE_INTERFACE)
            i['addresses'] = '192.168.1.2/24'
            interface = WireguardInterface.from_dict(i)
            interface.validate()
        with pytest.raises(ValueError):
            i = deepcopy(BASE_INTERFACE)
            i['addresses'] = ['asdf']
            interface = WireguardInterface.from_dict(i)
            interface.validate()
        with pytest.raises(ValueError):
            i = deepcopy(BASE_INTERFACE)
            i['addresses'] = ['192.268.1.2/24']
            interface = WireguardInterface.from_dict(i)
            interface.validate()
        with pytest.raises(ValueError):
            i = deepcopy(BASE_INTERFACE)
            i['addresses'] = ['192.168.1.2']
            interface = WireguardInterface.from_dict(i)
            interface.validate()
        with pytest.raises(ValueError):
            i = deepcopy(BASE_INTERFACE)
            i['addresses'] = ['::8g:1/120']
            interface = WireguardInterface.from_dict(i)
            interface.validate()
        with pytest.raises(ValueError):
            i = deepcopy(BASE_INTERFACE)
            i['addresses'] = []
            interface = WireguardInterface.from_dict(i)
            interface.validate()

        # PrivateKey
        with pytest.raises(TypeError):
            i = deepcopy(BASE_INTERFACE)
            i['private_key'] = 42
            interface = WireguardInterface.from_dict(i)
            interface.validate()

        # ListenPort
        with pytest.raises(TypeError):
            i = deepcopy(BASE_INTERFACE)
            i['listen_port'] = 'asdf'
            interface = WireguardInterface.from_dict(i)
            interface.validate()

        # FwMark
        with pytest.raises(TypeError):
            i = deepcopy(BASE_INTERFACE)
            i['fw_mark'] = 'asdf'
            interface = WireguardInterface.from_dict(i)
            interface.validate()

        # peers
        with pytest.raises(TypeError):
            i = deepcopy(BASE_INTERFACE)
            i['peers'] = 'asdf'
            interface = WireguardInterface.from_dict(i)
            interface.validate()
