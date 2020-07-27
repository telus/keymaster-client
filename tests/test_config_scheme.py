# -*- coding: utf-8 -*-
"""Tests for wireguard in keymaster_client package."""

from subprocess import CompletedProcess

from keymaster_client.config_scheme import UCIConfigScheme


def make_mock_run_peer(interface_name, endpoint_host=None, endpoint_port=None,
                       persistent_keepalive=None, preshared_key=None):
    def mock_run_peer(*args, **kwargs):
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
        elif args[0] == ['uci', 'get', f'network.{interface_name}']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='interface'.encode()
            )
        elif args[0] == ['uci', 'get', f'network.{interface_name}.public_key']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='publickey'.encode()
            )
        elif args[0] == ['uci', 'get', f'network.{interface_name}.allowed_ips']:
            return CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='192.168.1.0/24 192.168.2.0/24'.encode()
            )
        elif args[0] == ['uci', 'get', f'network.{interface_name}.endpoint_host']:
            if endpoint_host:
                return CompletedProcess(args=args[0], returncode=0, stdout=f'{endpoint_host}'.encode())
            else:
                return CompletedProcess(args=args[0], returncode=1, stdout=f''.encode())
        elif args[0] == ['uci', 'get', f'network.{interface_name}.endpoint_port']:
            if endpoint_port:
                return CompletedProcess(args=args[0], returncode=0, stdout=f'{endpoint_port}'.encode())
            else:
                return CompletedProcess(args=args[0], returncode=1, stdout=f''.encode())
        elif args[0] == ['uci', 'get', f'network.{interface_name}.persistent_keepalive']:
            if persistent_keepalive:
                return CompletedProcess(args=args[0], returncode=0, stdout=f'{persistent_keepalive}'.encode())
            else:
                return CompletedProcess(args=args[0], returncode=1, stdout=f''.encode())
        elif args[0] == ['uci', 'get', f'network.{interface_name}.preshared_key']:
            if preshared_key:
                return CompletedProcess(args=args[0], returncode=0, stdout=f'{preshared_key}'.encode())
            else:
                return CompletedProcess(args=args[0], returncode=1, stdout=f''.encode())
    return mock_run_peer


def test_uci_config_scheme_read_peer(mocker):
    interface_name = 'asdf'
    endpoint_host = '192.168.1.2'
    endpoint_port = 4444
    persistent_keepalive = 25
    preshared_key = 'presharedkey'
    mock_run_peer = make_mock_run_peer(interface_name, endpoint_host=endpoint_host,
                                       endpoint_port=endpoint_port,
                                       persistent_keepalive=persistent_keepalive,
                                       preshared_key=preshared_key)
    mocker.patch('keymaster_client.config_scheme.run', mock_run_peer)
    cs = UCIConfigScheme()
    p = cs._read_peer(interface_name)
    assert p.public_key == 'publickey'
    assert p.allowed_ips == ['192.168.1.0/24', '192.168.2.0/24']
    assert p.endpoint == f'{endpoint_host}:{endpoint_port}'
    assert p.persistent_keepalive == persistent_keepalive
    assert p.preshared_key == preshared_key


def test_uci_config_scheme_read_peer_required_only(mocker):
    interface_name = 'asdf'
    mock_run_peer = make_mock_run_peer(interface_name)
    mocker.patch('keymaster_client.config_scheme.run', mock_run_peer)
    cs = UCIConfigScheme()
    p = cs._read_peer(interface_name)
    assert p.public_key == 'publickey'
    assert p.allowed_ips == ['192.168.1.0/24', '192.168.2.0/24']


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


def make_mock_run(interface_name, listen_port=None, fwmark=None):
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
            if listen_port:
                return CompletedProcess(args=args[0], returncode=0, stdout=f'{listen_port}'.encode())
            else:
                return CompletedProcess(args=args[0], returncode=1, stdout=''.encode())
        elif args[0] == ['uci', 'get', f'network.{interface_name}.fwmark']:
            if fwmark:
                return CompletedProcess(args=args[0], returncode=0, stdout=f'{fwmark}'.encode())
            else:
                return CompletedProcess(args=args[0], returncode=1, stdout=''.encode())
    return mock_run


def test_from_uci(mocker):
    interface_name = 'asdf'
    listen_port = 4444
    fwmark = 32
    mock_run = make_mock_run(interface_name, listen_port=listen_port, fwmark=fwmark)
    mocker.patch('keymaster_client.config_scheme.run', mock_run)
    mocker.patch('keymaster_client.config_scheme.UCIConfigScheme._get_uci_peer_names', return_value=[])
    cs = UCIConfigScheme()
    interface = cs.read(interface_name)
    assert interface.name == interface_name
    assert interface.addresses == ['192.168.1.2/24', '192.168.2.2/24']
    assert interface.private_key == 'privatekey'
    assert interface.listen_port == listen_port
    assert interface.fw_mark == fwmark


def test_from_uci_required_only(mocker):
    interface_name = 'asdf'
    mock_run = make_mock_run(interface_name)
    mocker.patch('keymaster_client.config_scheme.run', mock_run)
    mocker.patch('keymaster_client.config_scheme.UCIConfigScheme._get_uci_peer_names', return_value=[])
    cs = UCIConfigScheme()
    interface = cs.read(interface_name)
    assert interface.name == interface_name
    assert interface.addresses == ['192.168.1.2/24', '192.168.2.2/24']
    assert interface.private_key == 'privatekey'
