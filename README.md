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


## Branch Explanation

The idea here was to abstract away the source of config - the keymaster
server, a config file, some other custom server, whatever. For several
reasons, though, this is hard (impossible?) to do cleanly. I may be missing
something, but I can't figure it out. Given that it is always better to
have no abstraction rather than a crappy abstraction, I'm leaving this
for now.
