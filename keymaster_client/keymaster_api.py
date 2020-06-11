"""Contains code for interfacing with keymaster-server."""
from urllib.parse import urlparse

import requests

class KeymasterAPI:
    """The object that is used to interface with keymaster-server."""

    def __init__(self, url: str):
        self.url = url
        # validation
        parsed_url = urlparse(self.url)
        if parsed_url.scheme == '' or parsed_url.netloc == '' or parsed_url.path != '':
            msg = f'{self.url} is not a valid URL.' + \
                'Must be of the form <scheme>://<hostname>[:<port>]'
            raise ValueError(msg)

    def get_config(self, network_name: str) -> dict:
        """Returns the raw configuration for the **server** in the star network
        with the name `network_name`. This configuration is in the form:
        ```
        {
            "interface": { interface configuration }
            "peers": [
                { interface configuration },
                { interface configuration },
                ...
                { interface configuration }
            ]
        }
        ```
        For more details please see the keymaster-server."""
        url = f'{self.url}/v1/wireguard/config/server/{network_name}'
        response = requests.get(url)
        response.raise_for_status()
        return response.json()

    def patch_server_public_key(self, interface_id: str, public_key: str):
        """Makes a PATCH request to keymaster-server that updates the interface
        with the id `interface_id` with the public key `public_key`."""
        url = f'{self.url}/v1/interfaces/server/{interface_id}'
        payload = {
            'public_key': public_key
        }
        response = requests.patch(url, json=payload)
        response.raise_for_status()
