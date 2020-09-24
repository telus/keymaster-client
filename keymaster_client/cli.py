# -*- coding: utf-8 -*-
"""Console script for udpu_client."""

import logging
import os
import sys

from typing import List

import click
import yaml

import keymaster_client.keymaster_client as kc
from keymaster_client.config_source import uDPUAPI, KeymasterServer
from keymaster_client.config_scheme import wgConfigScheme, UCIConfigScheme


LOGGER = logging.getLogger('keymaster_client')


@click.command()
@click.option('-f', '--config-dir', default='/etc/keymaster_client/', type=click.STRING,
              help='Path to config directory')
@click.option('-l', '--log-level', default='INFO', type=click.STRING,
              help='Acceptable values: WARN[ING], INFO, DEBUG, or ERROR. Defaults to INFO.')
def main(config_dir: str, log_level: str):
    """Configure keymaster-client using data from keymaster-server."""
    daemon_config = get_daemon_config(config_dir)
    initialize_logging(getattr(logging, log_level.upper()))

    if daemon_config.get('uDPUAPI'):
        url = daemon_config['uDPUAPI']['url']
        network_name = daemon_config['uDPUAPI']['networkName']
        config_source = uDPUAPI(url, network_name)
    elif daemon_config.get('keymasterServer'):
        url = daemon_config['keymasterServer']['url']
        token = daemon_config['keymasterServer']['token']
        config_source = KeymasterServer(url, token)

    if daemon_config.get('wg'):
        wg_config_dir = daemon_config['wg']['configDir']
        config_scheme = wgConfigScheme(wg_config_dir)
    elif daemon_config.get('uci'):
        config_scheme = UCIConfigScheme()

    kc.main(config_source, config_scheme, daemon_config)


def get_daemon_config(config_dir: str) -> dict:
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
      configPath: ...
    uci:
    privateKey: ...
    syncPeriod: ...
    ```
    There may be only one of uDPUAPI and keymasterServer, and only one of wg and uci.
    """
    # read config
    config_path = os.path.join(config_dir, 'config.yaml')
    try:
        with open(config_path, 'r') as infile:
            config = yaml.safe_load(infile)
    except FileNotFoundError as exc:
        msg = f'No config file found at {config_path}. Config is required.'
        raise FileNotFoundError(msg) from exc

    # check for config scheme and config source
    _ensure_exactly_one(config, ['uDPUAPI', 'keymasterServer'], 'ConfigScheme')
    _ensure_exactly_one(config, ['wg', 'uci'], 'ConfigSource')

    # check contents of uDPUAPI
    if config.get('uDPUAPI'):
        if not config['uDPUAPI'].get('url'):
            raise AttributeError('uDPUAPI.url is required.')
        config['uDPUAPI'] = config['uDPUAPI'].get('network_name', 'default')

    # check contents of keymasterServer
    if config.get('keymasterServer'):
        for key in ['url', 'token']:
            if not config['keymasterServer'].get(key):
                raise AttributeError(f'keymasterServer.{key} is required.')

    # check contents of wg
    if config.get('wg'):
        config['wg'] = config['wg'].get('configDir', config_dir)

    # set defaults for keys that aren't required
    config['syncPeriod'] = config.get('syncPeriod', 60)

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


def _ensure_exactly_one(config: dict, key_list: List[str], type_name: str):
    """When passed a `config` as read in by pyyaml, verifies that exactly one of
    the keys passed in `key_list` is present. More or less than one raises an
    AttributeError. `type_name` is the name of the type configured by the keys
    passed in `key_list`."""
    key_present = False
    for key in key_list:
        if config.get(key):
            if key_present:
                raise AttributeError(f'You cannot configure more than one {type_name}')
            key_present = True
    if not key_present:
        raise AttributeError('You must configure at least one {type_name}')
