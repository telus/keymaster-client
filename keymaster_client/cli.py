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
            "sync_frequency": 60,
            "config_scheme": "wg"   # currently, "wg" is the only option
        }
    ```
    """
    config_path = os.path.join(config_dir, 'config.json')
    with open(config_path, 'r') as infile:
        config = json.load(infile)

    # check for required keys
    required_keys = [
        'server_url'
    ]
    for key in required_keys:
        config[key]

    # set defaults for keys that aren't required
    if config.get('sync_frequency') is None:
        config['sync_frequency'] = 60
    if config.get('network_name') is None:
        config['network_name'] = 'default'
    if config.get('config_scheme') is None:
        config['config_scheme'] = 'wg'

    # validation
    if not config['config_scheme'] == 'wg':
        raise ValueError(f"{config['config_scheme']} is not a valid config scheme")

    return config


def initialize_logging(level):
    """Initalizes the root logger."""
    stream_handler = logging.StreamHandler(stream=sys.stdout)
    stream_handler.setLevel(level)
    fmt_string = '%(asctime)s %(levelname)s %(filename)s:%(funcName)s: %(message)s'
    formatter = logging.Formatter(fmt_string, datefmt='%Y/%m/%d %H:%M:%S')
    stream_handler.setFormatter(formatter)
    LOGGER.addHandler(stream_handler)
    LOGGER.setLevel(level)
    LOGGER.debug(f"Initialized logging with level: {logging.getLevelName(level)}")
