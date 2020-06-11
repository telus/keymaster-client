"""Contains the core logic of keymaster-client."""
import time
import logging

import keymaster_client.wireguard as wg
from keymaster_client.keymaster_api import KeymasterAPI
from keymaster_client.config_scheme import ConfigScheme


LOGGER = logging.getLogger('keymaster_client')


def parse_from_upstream(config: dict) -> dict:
    """Takes the config that keymaster-server returns and puts
    it into a format that can be consumed by WireguardInterface.from_dict."""
    # peers
    peers = []
    for peer in config['peers']:
        if peer.get('public_key') is not None:
            output_peer = {
                'public_key': peer['public_key'],
                'allowed_ips': peer['allowed_ips'],
                'endpoint': peer.get('endpoint'),
                'persistent_keepalive': peer.get('persistent_keepalive')
            }
            peers.append(output_peer)

    # interface
    output_config = {
        'name': config['interface']['name'],
        'addresses': config['interface']['addresses'],
        'listen_port': config['interface'].get('listen_port'),
        'peers': peers
    }

    return output_config


def configure_wireguard_interface(server: KeymasterAPI, config_scheme: ConfigScheme,
                                  wg_config: dict, private_key: str = None):
    """An idempotent function that compares the current configured interface
    (if previously configured) to the one represented by `wg_config`, which
    is meant to be received from keymaster-server. Always leaves the interface
    in the state described by `wg_config`, with one exception: when `private_key`
    is defined. In this case, `private_key` takes precedence over any other
    private key present. This is so that keymaster-client can be made to
    have the same configuration on multiple servers.

    An addition purpose of `configure_wireguard_interface` is to notify
    keymaster-server of any changes to the public key for the interface
    it configures."""
    api_interface_id = wg_config['interface']['_id']
    interface_name = wg_config['interface']['name']
    api_public_key = wg_config['interface'].get('public_key')

    if config_scheme.interface_exists(interface_name):

        current_interface = config_scheme.read(interface_name)

        formatted_api_config = parse_from_upstream(wg_config)
        if private_key is not None:
            formatted_api_config['private_key'] = private_key
        else:
            formatted_api_config['private_key'] = current_interface.private_key
        api_interface = wg.WireguardInterface.from_dict(formatted_api_config)

        if current_interface != api_interface:
            config_scheme.write(api_interface)

        current_public_key = wg.get_public_key(api_interface.private_key)
        if api_public_key != current_public_key:
            server.patch_server_public_key(api_interface_id, current_public_key)

    else:
        formatted_api_config = parse_from_upstream(wg_config)
        if private_key is not None:
            formatted_api_config['private_key'] = private_key
        else:
            formatted_api_config['private_key'] = wg.generate_private_key()
        new_interface = wg.WireguardInterface.from_dict(formatted_api_config)

        config_scheme.write(new_interface)
        LOGGER.debug(f'interface {interface_name}: interface configured')
        new_public_key = wg.get_public_key(new_interface.private_key)
        server.patch_server_public_key(api_interface_id, new_public_key)
        LOGGER.debug(f'interface {interface_name}: public key uploaded')


def main(server: KeymasterAPI, config_scheme: ConfigScheme, daemon_config: dict):
    """The main loop of the keymaster-client daemon."""
    while True:
        try:
            wg_config = server.get_config(daemon_config['network_name'])
            configure_wireguard_interface(server, config_scheme, wg_config,
                                          private_key=daemon_config.get('private_key'))
        except Exception as exc: # pylint: disable=broad-except
            LOGGER.error(f'caught exception: {exc}')
        LOGGER.debug(f"Waiting {daemon_config['sync_period']} seconds until next sync")
        time.sleep(daemon_config['sync_period'])
