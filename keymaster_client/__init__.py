"""
.. include:: ../README.md
"""

__author__ = 'Adam Pickering'
__email__ = 'adamkpickering@gmail.com'
__version__ = '0.0.0'

from keymaster_client.config_scheme import wgConfigScheme, uciConfigScheme
from keymaster_client.wireguard import (
    WireguardInterface,
    get_public_key,
    generate_private_key
)
