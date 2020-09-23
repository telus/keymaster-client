import pytest

from keymaster_client.config_source import KeymasterAPI


def test_keymaster_api_validation(mocker):
    with pytest.raises(ValueError):
        KeymasterAPI('example.com')
