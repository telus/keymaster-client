"""
.. include:: ../README.md
"""

__author__ = 'Adam Pickering'
__email__ = 'adamkpickering@gmail.com'
__version__ = '1.0.2'

from keymaster_client.config_scheme import wgConfigScheme, UCIConfigScheme
from keymaster_client.wireguard import (
    WireguardInterface,
    get_public_key,
    generate_private_key
)
