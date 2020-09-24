"""Contains the core logic of keymaster-client."""
import time
import logging

import keymaster_client.wireguard as wg
from keymaster_client.config_source import ConfigSource
from keymaster_client.config_scheme import ConfigScheme


LOGGER = logging.getLogger('keymaster_client')


def sync_interfaces(config_source: ConfigSource, config_scheme: ConfigScheme,
                    private_key: str = None):
    """Gets the list of interfaces that should be configured from the ConfigSource,
    gets the list of interfaces that are currently configured from the ConfigScheme,
    and compares/reconciles them. Also takes care of updating the public_key
    for each interface in the ConfigSource."""
    # get list of currently-configured interfaces from config scheme
    current_iface_names = config_scheme.interface_names()
    current_ifaces = [config_scheme.read(name) for name in current_iface_names]
    for current_iface in current_ifaces:
        current_iface.validate()
    LOGGER.debug(f'current interfaces: {current_ifaces}')

    # get list of desired interfaces and their names from config source
    desired_ifaces = config_source.get_config()
    desired_iface_names = [iface.name for iface in desired_ifaces]
    LOGGER.debug(f'desired interfaces: {desired_ifaces}')

    # delete any interfaces whose name is not in desired interfaces
    for name in current_iface_names:
        if not name in desired_iface_names:
            config_scheme.delete(name)
            LOGGER.debug(f'deleted iface {name}')

    # reconcile any differences in remaining interfaces
    for desired_iface in desired_ifaces:
        current_iface_filtered = [x for x in current_ifaces if x.name == desired_iface.name]
        length = len(current_iface_filtered)
        assert length in (0, 1)

        if length == 0: # interface does not yet exist
            LOGGER.debug(f'interface {desired_iface}: creating interface')
            desired_iface.private_key = private_key if private_key else wg.generate_private_key()
            desired_iface.validate()
            LOGGER.debug(f'interface {desired_iface}: interface valid')
            config_scheme.write(desired_iface)
            LOGGER.debug(f'interface {desired_iface}: interface configured')
            config_source.patch_public_key(desired_iface)
            LOGGER.debug(f'interface {desired_iface}: public key uploaded')

        elif length == 1: # interface exists
            LOGGER.debug(f'interface {desired_iface}: updating interface')
            current_iface = current_iface_filtered[0]
            desired_iface.private_key = private_key if private_key else current_iface.private_key
            desired_iface.validate()
            LOGGER.debug(f'interface {desired_iface}: interface valid')
            if current_iface != desired_iface:
                config_scheme.write(desired_iface)
            LOGGER.debug(f'interface {desired_iface}: interface configured')
            api_public_key = desired_iface.auxiliary_data['old_public_key']
            desired_public_key = wg.get_public_key(desired_iface.private_key)
            if api_public_key != desired_public_key:
                config_source.patch_public_key(desired_iface)
            LOGGER.debug(f'interface {desired_iface}: public key consistent')

def main(config_source: ConfigSource, config_scheme: ConfigScheme, daemon_config: dict):
    """The main loop of the keymaster-client daemon."""
    while True:
        try:
            sync_interfaces(config_source, config_scheme,
                            private_key=daemon_config.get('private_key'))
        except Exception as exc: # pylint: disable=broad-except
            LOGGER.error(f'caught exception: {exc}')
        LOGGER.debug(f"Waiting {daemon_config['sync_period']} seconds until next sync")
        time.sleep(daemon_config['sync_period'])
