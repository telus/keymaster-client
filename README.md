# keymaster-client

Configures wireguard using information from keymaster-server


## Objects

`keymaster-client` uses a number of object types to keep the code clean
and extensible:

A **WireguardInterface** contains all of the configuration for a single
wireguard interface. This is the central object in `keymaster-client`.

A **ConfigScheme** is a way of making the interface described by a
`WireguardInterface` a reality on the local system.

A **ConfigSource** is a place that `keymaster-client` periodically
polls for configuration to be applied to the local system.
