import pytest

from keymaster_client.config_source import KeymasterServer


def test_keymaster_server_validation(mocker):
    with pytest.raises(ValueError):
        KeymasterAPI('example.com')
