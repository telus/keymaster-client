# -*- coding: utf-8 -*-
"""Console script for udpu_client."""

import json
import logging
import os
import sys

import click

import keymaster_client.keymaster_client as kc
from keymaster_client.keymaster_api import KeymasterAPI
from keymaster_client.config_scheme import wgConfigScheme


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
    server = KeymasterAPI(daemon_config['server_url'])
    config_scheme = wgConfigScheme(config_dir)
    kc.main(server, config_scheme, daemon_config)


def get_daemon_config(config_dir: str) -> dict:
    """Gets config from the config file. Config file format:
    ```
    {
        "server_url": "...",
        "private_key": "...",   # for case where we need same private key on multiple servers
        "network_name": "...",
        "sync_period": 60,
        "config_scheme": "wg"   # currently, "wg" is the only option
    }
    ```
    """
    config_path = os.path.join(config_dir, 'config.json')
    try:
        with open(config_path, 'r') as infile:
            config = json.load(infile)
    except FileNotFoundError:
        raise FileNotFoundError(f'No config file found at {config_path}. Config is required.')

    # check for required keys
    required_keys = [
        'server_url'
    ]
    for key in required_keys:
        if not key in config:
            raise AttributeError(f'key {key} is not present in config but is required')

    # set defaults for keys that aren't required
    if not config.get('sync_period'):
        config['sync_period'] = 60
    if not config.get('network_name'):
        config['network_name'] = 'default'
    if not config.get('config_scheme'):
        config['config_scheme'] = 'wg'

    # validation
    if config['config_scheme'] != 'wg':
        raise ValueError(f"{config['config_scheme']} is not a valid config scheme")

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
