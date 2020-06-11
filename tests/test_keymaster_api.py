import pytest

from keymaster_client.keymaster_api import KeymasterAPI


def test_keymaster_api_validation(mocker):
    with pytest.raises(ValueError):
        KeymasterAPI('example.com')
