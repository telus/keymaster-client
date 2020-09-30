# -*- coding: utf-8 -*-
"""Console script for udpu_client."""
import logging
import sys

from typing import List

import click
import yaml

import keymaster_client.keymaster_client as kc
from keymaster_client.config_source import uDPUAPI, KeymasterServer
from keymaster_client.config_scheme import wgConfigScheme, UCIConfigScheme


LOGGER = logging.getLogger('keymaster_client')


@click.command()
@click.option('-f', '--path-to-config', default='/etc/keymaster_client.yaml', type=click.STRING,
              help='Path to config directory')
@click.option('-l', '--log-level', default='INFO', type=click.STRING,
              help='Acceptable values: WARN[ING], INFO, DEBUG, or ERROR. Defaults to INFO.')
def main(path_to_config: str, log_level: str):
    """Configure keymaster-client using data from keymaster-server."""
    initialize_logging(getattr(logging, log_level.upper()))
    daemon_config = get_daemon_config(path_to_config)

    if daemon_config.get('uDPUAPI'):
        url = daemon_config['uDPUAPI']['url']
        network_name = daemon_config['uDPUAPI']['networkName']
        config_source = uDPUAPI(url, network_name)
    elif daemon_config.get('keymasterServer'):
        url = daemon_config['keymasterServer']['url']
        token = daemon_config['keymasterServer']['token']
        config_source = KeymasterServer(url, token)

    if daemon_config.get('wg'):
        config_dir = daemon_config['wg']['configDir']
        config_scheme = wgConfigScheme(config_dir)
    elif daemon_config.get('uci'):
        config_scheme = UCIConfigScheme()

    kc.main(config_source, config_scheme, daemon_config)


def get_daemon_config(config_path: str) -> dict:
    """Gets config from the config file. Config file format:
    ```
    ---
    uDPUAPI:
      url: ...
      networkName: ...
    keymasterServer:
      url: ...
      token: ...
    wg:
      configDir: ...
    uci:
    privateKey: ...
    syncPeriod: ...
    ```
    There may be only one of uDPUAPI and keymasterServer, and only one of wg and uci.
    """
    try:
        with open(config_path, 'r') as infile:
            config = yaml.safe_load(infile)
    except FileNotFoundError as exc:
        msg = f'No config file found at {config_path}. Config is required.'
        raise FileNotFoundError(msg) from exc

    # check for config scheme and config source
    config_source = _ensure_exactly_one(config, ['uDPUAPI', 'keymasterServer'], 'ConfigSource')
    config_scheme = _ensure_exactly_one(config, ['wg', 'uci'], 'ConfigScheme')

    # check contents of config source
    if config_source == 'uDPUAPI':
        if not config['uDPUAPI'].get('url'):
            raise AttributeError('uDPUAPI.url is required.')
        config['uDPUAPI']['networkName'] = config['uDPUAPI'].get('networkName', 'default')
    elif config_source == 'keymasterServer':
        for key in ['url', 'token']:
            if not key in config['keymasterServer'].keys():
                raise AttributeError(f'keymasterServer.{key} is required.')

    # check contents of config scheme
    if config_scheme == 'wg':
        if not isinstance(config['wg'], dict):
            config['wg'] = {}
        config['wg']['configDir'] = config['wg'].get('configDir', '/var/lib/keymaster_client/')
    elif config_scheme == 'uci':
        config['uci'] = True

    # set defaults for keys that aren't required
    config['syncPeriod'] = config.get('syncPeriod', 60)

    LOGGER.debug(f'Parsed config: {config}')

    return config


def initialize_logging(level):
    """Initializes logging."""
    stream_handler = logging.StreamHandler(stream=sys.stdout)
    stream_handler.setLevel(level)
    fmt_string = '%(asctime)s %(levelname)s %(filename)s:%(funcName)s: %(message)s'
    formatter = logging.Formatter(fmt_string, datefmt='%Y/%m/%d %H:%M:%S')
    stream_handler.setFormatter(formatter)
    LOGGER.addHandler(stream_handler)
    LOGGER.setLevel(level)
    LOGGER.debug(f"Initialized logging with level: {logging.getLevelName(level)}")


def _ensure_exactly_one(config: dict, key_list: List[str], type_name: str) -> str:
    """When passed a `config` as read in by pyyaml, verifies that exactly one of
    the keys passed in `key_list` is present. More or less than one raises an
    AttributeError. `type_name` is the name of the type configured by the keys
    passed in `key_list`."""
    present_key = None
    for key in key_list:
        if key in config.keys():
            if present_key:
                raise AttributeError(f'You cannot configure more than one {type_name}')
            present_key = key
    if not present_key:
        raise AttributeError(f'You must configure at least one {type_name}')
    return present_key
