# keymaster-client

keymaster-client is the client portion of the keymaster wireguard
key distribution solution. This readme is limited to configuration of
the keymaster-client daemon; for an overview and general information
please see [the keymaster-server repo](https://github.com/telus/keymaster-server).


## Installation & Usage

To install keymaster-client:

```
pip install keymaster-client
```

To run keymaster-client, first create a configuration (see below) and then run:

```
keymaster_client
```


## Configuration

By default, keymaster-client looks for configuration at the path
/etc/keymaster_client.yaml. You can change this by passing the desired
path in the `-f` or `--path-to-config` flags.

### Example Configuration

```
---
keymasterServer:
  url: https://example.com:5300
  token: a-fake-token
wg:
  configDir: /var/different/directory/
syncPeriod: 30
```

### Configuration Reference

**`keymasterServer`**

If present, indicates that the `keymasterServer` ConfigSource is to be used.
Cannot be used at the same time as the uDPUAPI ConfigSource.

--------------------------------------------------------------------------------

**`keymasterServer.url`**

Required if `keymasterServer` is specified. The complete URL of the
keymaster-server deployment.

--------------------------------------------------------------------------------

**`keymasterServer.token`**

Required if `keymasterServer` is specified. The token to use in requests to
the keymaster-server deployment. This token can be obtained from the
keymaster-server web UI.

--------------------------------------------------------------------------------

**`uDPUAPI`**

A ConfigSource for a proprietary system. Cannot be used at the same time as
the keymasterServer ConfigSource.

--------------------------------------------------------------------------------

**`uDPUAPI.url`**

Required if `uDPUAPI` is specified. The complete URL of the uDPU API deployment.

--------------------------------------------------------------------------------

**`uDPUAPI.networkName`**

Required if `uDPUAPI` is specified. The network name to request config for on the
uDPU API.

--------------------------------------------------------------------------------

**`uci`**

A ConfigScheme that uses OpenWrt's UCI (Universal Configuration Interface) to
configure wireguard interfaces. Has no options. Cannot be used at the same time
as the `wg` ConfigScheme. For more information on UCI please see
[the OpenWrt wiki](https://openwrt.org/docs/guide-user/base-system/uci).

--------------------------------------------------------------------------------

**`wg`**

A ConfigScheme that uses the `ip` and `wg` commands to configure wireguard
interfaces on the host running keymaster-client. Cannot be used at the same
time as the `wg` ConfigScheme.

--------------------------------------------------------------------------------

**`wg.configDir`**

Optional. Default: /var/lib/keymaster_client/

The directory in which configuration is stored after syncing with the
ConfigSource.

--------------------------------------------------------------------------------

**`privateKey`**

Optional.

Allows you to specify the private key that this deployment of keymaster-client
will configure **all** interfaces with. This value takes precedence over any
values that otherwise would be generated by keymaster-client. This setting
is useful if you have multiple non-endpoint interfaces behind a load balancer that
you want to appear as a single highly-available interface to any endpoint
interfaces connecting to them. 

--------------------------------------------------------------------------------

**`syncPeriod`**

Optional. Default: 60

Lets you specify the interval, in seconds, at which keymaster-client requests
configuration from the ConfigSource.


## Extending

keymaster-client provides two interfaces that make it easy to modify:

A **`ConfigScheme`** specifies how wireguard configurations are written to,
and read from, the Node.

A **`ConfigSource`** tells keymaster-client how to get configuration of
wireguard interfaces. This can take the form of a local file, a remote server,
or anything else you can imagine.

For more information, please see the code.
