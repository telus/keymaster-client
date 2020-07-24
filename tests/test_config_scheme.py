# -*- coding: utf-8 -*-
"""Tests for wireguard in keymaster_client package."""

from subprocess import CompletedProcess

from keymaster_client.config_scheme import UCIConfigScheme


def test_uci_config_scheme_read_peer(mocker):
    interface = 'asdf'
    def mock_run(*args, **kwargs):
        if args[0] == ['which', 'uci']:
            return CompletedProcess(
                args=['which', 'uci'],
                returncode=0,
                stdout=b'/sbin/uci\n'
            )
        elif args[0] == ['which', 'wg']:
            return CompletedProcess(
                args=['which', 'uci'],
                returncode=0,
                stdout=b'/usr/bin/wg\n'
            )
        elif args[0] == ['uci', 'get', f'network.{interface}']:
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
    mocker.patch('keymaster_client.config_scheme.run', mock_run)
    cs = UCIConfigScheme()
    p = cs._read_peer(interface)
    assert p.public_key == 'publickey'
    assert p.allowed_ips == ['192.168.1.0/24', '192.168.2.0/24']
    assert p.endpoint == '192.168.1.2:4444'
    assert p.persistent_keepalive == 25
    assert p.preshared_key == 'presharedkey'


def test_get_uci_peer_names(mocker):
    interface = 'wg0'

    def mock_run(*args, **kwargs):
        if args[0] == ['which', 'uci']:
            return CompletedProcess(
                args=['which', 'uci'],
                returncode=0,
                stdout=b'/sbin/uci\n'
            )
        elif args[0] == ['which', 'wg']:
            return CompletedProcess(
                args=['which', 'uci'],
                returncode=0,
                stdout=b'/usr/bin/wg\n'
            )
        elif args[0] == ['uci', 'show', 'network']:
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
            return CompletedProcess(
                args=['uci', 'show', 'network'],
                returncode=0,
                stdout='\n'.join(fake_stdout_line_list).encode()
            )

    mocker.patch('keymaster_client.config_scheme.run', mock_run)
    cs = UCIConfigScheme()
    peer_names = cs._get_uci_peer_names(interface)
    assert peer_names[0] == f'{interface}_peer0'
    assert len(peer_names) == 1


def test_from_uci(mocker):
    interface_name = 'asdf'

    def mock_run(*args, **kwargs):
        if args[0] == ['uci', 'get', f'network.{interface_name}']:
            return CompletedProcess(
                args=args[0],
                returncode=0
            )
        elif args[0] == ['uci', 'get', f'network.{interface_name}.addresses']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='192.168.1.2/24 192.168.2.2/24'.encode()
            )
        elif args[0] == ['uci', 'get', f'network.{interface_name}.private_key']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='privatekey'.encode()
            )
        elif args[0] == ['uci', 'get', f'network.{interface_name}.listen_port']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='4444'.encode()
            )
        elif args[0] == ['uci', 'get', f'network.{interface_name}.fwmark']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='32'.encode()
            )

    mocker.patch('keymaster_client.config_scheme.run', mock_run)
    mocker.patch('keymaster_client.config_scheme.UCIConfigScheme._get_uci_peer_names', return_value=[])
    cs = UCIConfigScheme()
    interface = cs.read(interface_name)
    assert interface.name == interface_name
    assert interface.addresses == ['192.168.1.2/24', '192.168.2.2/24']
    assert interface.private_key == 'privatekey'
    assert interface.listen_port == 4444
    assert interface.fw_mark == 32
