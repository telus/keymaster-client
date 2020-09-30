from copy import deepcopy
from unittest.mock import Mock

import pytest

import keymaster_client.wireguard as wg
from keymaster_client.keymaster_client import sync_interfaces


TEST_INTERFACE = wg.WireguardInterface.from_dict({
    'name': 'wg0',
    'addresses': ['192.168.1.2/24'],
    'private_key': 'asdfasdfasdf',
    'peers': [
        {
            'public_key': 'pubkey1',
            'allowed_ips': ['10.0.0.0/24'],
        }
    ]
})
TEST_INTERFACE.auxiliary_data = {
    'old_public_key': 'pubkey',
}

TEST_DATA = {
    'interface': {
        '_id': 'qwerasdfzxcv',
        'is_server': True,
        'network': 'default',
        'name': 'wg0',
        'addresses': ['192.168.1.1/24'],
        'listen_port': 51820,
        'public_key': 'pubkey1',
        'allowed_ips': ['192.168.1.0/24'],
        'endpoint': '204.205.206.207:51820',
        'persistent_keepalive': 30
    },
    'peers': [
        {
            '_id': '123475892fkd',
            'is_server': False,
            'network': 'default',
            'name': 'wg0',
            'addresses': ['192.168.1.2/24'],
            'listen_port': 51820,
            'public_key': 'pubkey2',
            'allowed_ips': ['192.168.1.2/32'],
            'endpoint': '204.205.206.208:51820',
            'persistent_keepalive': None
        },
        {
            '_id': 'sdjfhwek3',
            'is_server': False,
            'network': 'default',
            'name': 'wg0',
            'addresses': ['192.168.1.3/24'],
            'listen_port': 51820,
            'public_key': 'pubkey3',
            'allowed_ips': ['192.168.1.3/32'],
            'endpoint': '204.205.206.209:51820',
            'persistent_keepalive': None
        }
    ]
}


@pytest.fixture()
def make_config_source():
    def _make_config_source(returned_config=[TEST_INTERFACE]):
        config_source = Mock()
        config_source.patch_public_key = Mock()
        config_source.get_config = Mock(return_value=returned_config)
        return config_source
    return _make_config_source


@pytest.fixture()
def make_config_scheme():
    def _make_config_scheme(read_returns=TEST_INTERFACE, names_return=['wg0']):
        config_scheme = Mock()
        config_scheme.interface_names = Mock(return_value=names_return)
        config_scheme.read = Mock(return_value=read_returns)
        config_scheme.write = Mock()
        return config_scheme
    return _make_config_scheme


def test_same_public_key_no_patch(mocker, make_config_source, make_config_scheme):
    """Tests that same public key results in NO call to `config_source.patch_public_key`."""
    config_source = make_config_source()
    config_scheme = make_config_scheme(read_returns=TEST_INTERFACE)
    mocker.patch('keymaster_client.keymaster_client.wg.get_public_key', return_value='pubkey')
    sync_interfaces(config_source, config_scheme)
    config_source.patch_public_key.assert_not_called()


def test_diff_public_key_patch(mocker, make_config_source, make_config_scheme):
    """Test that different public keys results in call to `config_source.patch_public_key`."""
    config_source = make_config_source()
    config_scheme = make_config_scheme(read_returns=TEST_INTERFACE)
    mocker.patch('keymaster_client.keymaster_client.wg.get_public_key', return_value='new pubkey')
    sync_interfaces(config_source, config_scheme)
    config_source.patch_public_key.assert_called()


def test_different_api_interface_and_current_interface(mocker, make_config_source, make_config_scheme):
    """Test that different api_interface and current_interface results in call to config_scheme.write."""
    new_interface = deepcopy(TEST_INTERFACE)
    new_interface.addresses = ['192.168.1.3/24']
    config_source = make_config_source(returned_config=[new_interface])
    config_scheme = make_config_scheme(read_returns=TEST_INTERFACE)
    mocker.patch('keymaster_client.keymaster_client.wg.get_public_key', return_value='pubkey')
    sync_interfaces(config_source, config_scheme)
    config_scheme.write.assert_called()


def test_sync_interfaces_tolerant_of_no_public_key(mocker, make_config_source, make_config_scheme):
    """Test that sync_interfaces is tolerant of no public_key in wg_config."""
    new_interface = deepcopy(TEST_INTERFACE)
    new_interface.auxiliary_data = {}
    config_source = make_config_source(returned_config=[new_interface])
    config_scheme = make_config_scheme(read_returns=TEST_INTERFACE)
    mocker.patch('keymaster_client.keymaster_client.wg.get_public_key', return_value='pubkey1')
    sync_interfaces(config_source, config_scheme)


def test_diff_private_key_overwritten(mocker, make_config_source, make_config_scheme):
    """Test that a stored private key is overwritten by a different user-specified private key."""
    config_source = make_config_source()
    config_scheme = make_config_scheme(read_returns=deepcopy(TEST_INTERFACE))
    mocker.patch('keymaster_client.keymaster_client.wg.get_public_key', return_value='pubkey1')
    sync_interfaces(config_source, config_scheme, private_key='qwerasdf')
    config_scheme.write.assert_called()


def test_with_no_previous_interface(mocker, make_config_source, make_config_scheme):
    """Test the basics when configuring a previously-absent interface."""
    config_source = make_config_source()
    config_scheme = make_config_scheme(read_returns=None, names_return=[])
    mocker.patch('keymaster_client.keymaster_client.wg.get_public_key', return_value='pubkey1')
    mocker.patch('keymaster_client.keymaster_client.wg.generate_private_key', return_value='private key')
    sync_interfaces(config_source, config_scheme)
    config_scheme.write.assert_called()
    config_source.patch_public_key.assert_called()


def test_private_key_not_generated_if_specified(mocker, make_config_source, make_config_scheme):
    """Test logic for case where user specifies private key."""
    config_source = make_config_source()
    config_scheme = make_config_scheme(read_returns=None, names_return=[])
    mocker.patch('keymaster_client.keymaster_client.wg.get_public_key', return_value='pubkey1')
    gpk_mock = mocker.Mock(return_value='private_key')
    mocker.patch('keymaster_client.keymaster_client.wg.generate_private_key', gpk_mock)
    sync_interfaces(config_source, config_scheme, private_key='qwerasdf')
    gpk_mock.assert_not_called()


def test_private_key_generated_if_not_specified(mocker, make_config_source, make_config_scheme):
    """Ensure that private key is generated if not specified by user."""
    config_source = make_config_source()
    config_scheme = make_config_scheme(read_returns=None, names_return=[])
    mocker.patch('keymaster_client.keymaster_client.wg.get_public_key', return_value='pubkey1')
    gpk_mock = mocker.Mock(return_value='private_key')
    mocker.patch('keymaster_client.keymaster_client.wg.generate_private_key', gpk_mock)
    sync_interfaces(config_source, config_scheme)
    gpk_mock.assert_called()
