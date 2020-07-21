"""Contains the core logic of keymaster-client."""
import time
import logging

import keymaster_client.wireguard as wg
from keymaster_client.config_source import uDPUAPI
from keymaster_client.config_scheme import ConfigScheme


LOGGER = logging.getLogger('keymaster_client')


def configure_wireguard_interface(config_source: uDPUAPI, config_scheme: ConfigScheme,
                                  desired_interface: wg.WireguardInterface, private_key: str = None):
    """An idempotent function that compares the current configured interface
    (if previously configured) to the one represented by `desired_interface`.
    Always leaves the interface in the state described by `desired_interface`,
    with one exception: when `private_key` is defined. In this case, `private_key`
    takes precedence over any other private key present. This is so that
    a number of hosts running keymaster-client can be made to have the same
    configuration (for redundant wireguard configs).

    An addition purpose of `configure_wireguard_interface` is to notify
    keymaster-server of any changes to the public key for the interface
    it configures."""
    interface_name = wg_config['interface']['name']
    desired_public_key = wg_config['interface'].get('public_key')

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
            config_source.patch_public_key(desired_interface.name, current_public_key)

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
        config_source.patch_public_key(api_interface_id, new_public_key)
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
