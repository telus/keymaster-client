from copy import deepcopy
from unittest.mock import Mock

import pytest

import keymaster_client.wireguard as wg
from keymaster_client.keymaster_client import configure_wireguard_interface
from keymaster_client.keymaster_api import KeymasterAPI


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
def make_config_scheme():
    def _make_config_scheme(interface_exists=True, read_return=TEST_INTERFACE):
        cs_mock = Mock()
        cs_mock.interface_exists = Mock(return_value=interface_exists)
        cs_mock.read = Mock(return_value=read_return)
        cs_mock.write = Mock()
        return cs_mock
    return _make_config_scheme


def test_same_public_key_no_patch(mocker, make_config_scheme):
    """Tests that same public key results in NO call to `KeymasterAPI.patch_server_public_key`."""
    cs_mock = make_config_scheme(interface_exists=True)
    ka_mock = mocker.Mock()
    ka_mock.patch_server_public_key = mocker.Mock()
    mocker.patch('keymaster_client.keymaster_client.wg.get_public_key', return_value='pubkey1')
    configure_wireguard_interface(ka_mock, cs_mock, deepcopy(TEST_DATA))
    ka_mock.patch_server_public_key.assert_not_called()


def test_diff_public_key_patch(mocker, make_config_scheme):
    """Test that different public keys results in call to `KeymasterAPI.patch_server_public_key`."""
    cs_mock = make_config_scheme(interface_exists=True)
    ka_mock = mocker.Mock()
    ka_mock.patch_server_public_key = mocker.Mock()
    mocker.patch('keymaster_client.keymaster_client.wg.get_public_key', return_value='chjvxcvkxcjv')
    configure_wireguard_interface(ka_mock, cs_mock, deepcopy(TEST_DATA))
    ka_mock.patch_server_public_key.assert_called()


def test_different_api_interface_and_current_interface(mocker, make_config_scheme):
    """Test that different api_interface and current_interface results in call to config_scheme.write."""
    cs_mock = make_config_scheme(interface_exists=True)
    ka_mock = mocker.Mock()
    ka_mock.patch_server_public_key = mocker.Mock()
    mocker.patch('keymaster_client.keymaster_client.wg.get_public_key', return_value='pubkey1')
    modded_test_data = deepcopy(TEST_DATA)
    modded_test_data['interface']['addresses'] = ['192.168.1.2/24']
    configure_wireguard_interface(ka_mock, cs_mock, modded_test_data)
    cs_mock.write.assert_called()


def test_configure_wireguard_interface_tolerant_of_no_public_key(mocker, make_config_scheme):
    """Test that configure_wireguard_interface is tolerant of no public_key in wg_config."""
    cs_mock = make_config_scheme(interface_exists=True)
    ka_mock = mocker.Mock()
    ka_mock.patch_server_public_key = mocker.Mock()
    mocker.patch('keymaster_client.keymaster_client.wg.get_public_key', return_value='pubkey1')
    modded_test_data = deepcopy(TEST_DATA)
    del modded_test_data['interface']['public_key']
    configure_wireguard_interface(ka_mock, cs_mock, modded_test_data)


def test_diff_private_key_overwritten(mocker, make_config_scheme):
    """Test that a stored private key is overwritten by a different user-specified private key."""
    cs_mock = make_config_scheme(interface_exists=True)
    ka_mock = mocker.Mock()
    ka_mock.patch_server_public_key = mocker.Mock()
    mocker.patch('keymaster_client.keymaster_client.wg.get_public_key', return_value='pubkey1')
    configure_wireguard_interface(ka_mock, cs_mock, deepcopy(TEST_DATA), private_key='qwerasdf')
    cs_mock.write.assert_called()


def test_with_no_previous_interface(mocker, make_config_scheme):
    """Test the basics when configuring a previously-absent interface."""
    cs_mock = make_config_scheme(interface_exists=False)
    ka_mock = mocker.Mock()
    ka_mock.patch_server_public_key = mocker.Mock()
    mocker.patch('keymaster_client.keymaster_client.wg.get_public_key', return_value='pubkey1')
    mocker.patch('keymaster_client.keymaster_client.wg.generate_private_key', return_value='private key')
    configure_wireguard_interface(ka_mock, cs_mock, deepcopy(TEST_DATA))
    cs_mock.write.assert_called()
    ka_mock.patch_server_public_key.assert_called()


def test_private_key_not_generated_if_specified(mocker, make_config_scheme):
    """Test logic for case where user specifies private key."""
    cs_mock = make_config_scheme(interface_exists=False)
    ka_mock = mocker.Mock()
    ka_mock.patch_server_public_key = mocker.Mock()
    mocker.patch('keymaster_client.keymaster_client.wg.get_public_key', return_value='pubkey1')
    gpk_mock = mocker.Mock(return_value='private_key')
    mocker.patch('keymaster_client.keymaster_client.wg.generate_private_key', gpk_mock)
    configure_wireguard_interface(ka_mock, cs_mock, deepcopy(TEST_DATA), private_key='qwerasdf')
    gpk_mock.assert_not_called()


def test_private_key_generated_if_not_specified(mocker, make_config_scheme):
    """Ensure that private key is generated if not specified by user."""
    cs_mock = make_config_scheme(interface_exists=False)
    ka_mock = mocker.Mock()
    ka_mock.patch_server_public_key = mocker.Mock()
    mocker.patch('keymaster_client.keymaster_client.wg.get_public_key', return_value='pubkey1')
    gpk_mock = mocker.Mock(return_value='private_key')
    mocker.patch('keymaster_client.keymaster_client.wg.generate_private_key', gpk_mock)
    configure_wireguard_interface(ka_mock, cs_mock, deepcopy(TEST_DATA))
    gpk_mock.assert_called()
