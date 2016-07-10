# DHCP option injector

Have you ever wanted to intercept DHCP requests and squeeze in a few extra DHCP
options, unbeknownst to the sender? Probably not. However, should the need ever
come, **dhcpoptinj** will (hopefully) help you.

## Why

There can be many a reason to mangle DHCP requests, although chances are you
ought to look for a much better method for solving your problem. Perhaps you do
not have access to the DHCP server/clients, perhaps the DHCP software is
difficult to configure, or perhaps you only want to experiment sending exotic
or malformed options? There is a small chance that dhcoptinj might actually be
of some use.

## How

dhcpoptinj waits for packets to arrive in a netfilter queue. It will ensure
that a packet is in fact a BOOTP/DHCP packet, and if so proceed to inject
options. It will recalculate the IPv4 header checksum, disable the UDP
checksum (for a simpler implementation) and then give the packet back to
netfilter.

You need an iptables rule in order to intercept packets and send them to
dhcpoptinj. Let us say you have two interfaces bridged together, *eth0* and
*eth1*. Let us say you want to intercept all BOOTP requests coming from *eth0*
and inject the [relay agent information
option](https://tools.ietf.org/html/rfc3046) (82/0x52). Let us make up a silly
payload: An [agent circuit ID
sub-option](https://tools.ietf.org/html/rfc3046#section-3.1) with the value
"Fjas".

Add a rule to the iptables mangle table:`sudo iptables -t mangle -A PREROUTING
-m physdev --physdev-in eth0 -p udp --dport 67 -j NFQUEUE --queue-num 42`.

Then run dhcpoptinj (let us run it in the foreground with extra debug output):
`sudo dhcpoptinj -d -f -q 42 -o'52 01 04 46 6A 61 73'`. Note that dhcpoptinj
must be run by a user with the CAP\_NET\_ADMIN capability. You do not need to,
and you really should not run dhcpoptinj as root. Instead, you can for instance
grant the CAP\_NET\_ADMIN capability to the binary (using *setcap*) and limit
execution rights to only a specific user or group. This is a method used for
running wireshark as non-root, so you will find several guides helping you
accomplish this.

Now send a DHCP packet to the *eth0* interface and watch it (using a tool like
[wireshark](https://www.wireshark.org/)) having been modified when it reaches
the bridged interface. It should have the injected option at the end of the
option list.

Note the format of the argument to the *-o* option: It should be a hexadecimal
string starting with the DHCP option code followed by the option payload. The
option length (the byte that normally follows the option code) is automatically
calculated and must not be specified. The hex string can be delimited by
non-hexadecimal characters for readability. All options must have a payload,
except for the special [pad
option](https://tools.ietf.org/html/rfc2132#section-2) (code 0).

The layout of the nonsensical option used in this example (first the [DHCP
option layout](https://tools.ietf.org/html/rfc2132#section-2), then the
specific [relay agent information option sub-option
layout](https://tools.ietf.org/html/rfc3046#section-2.0)) is as follows:

| Code | Length |            Data            |
|------|--------|----------------------------|
|  52  | (auto) | 01 04 46 6A 61 73 ("Fjas") |

| Sub-opt. | Length |         Data         |
|----------|--------|----------------------|
|    01    |   4    | 46 6A 61 73 ("Fjas") |

Note that dhcpoptinj does not care about what you write in the option payloads,
neither does it check whether your option code exists. It does however forbid
you to use the option code 255 (the terminating end option). dhcpoptinj inserts
this option as the last option automatically.

## Installing

dhcoptinj is quite a simple program and should be unproblematic to build.

### Prerequisites

You need [cmake](http://www.cmake.org/) and
[libnetfilter\_queue](http://www.netfilter.org/projects/libnetfilter_queue/)
(and a C compiler that supports C99). Hopefully, you are using a Debian-like
system, in which case you can run the following to install them: `sudo apt-get
install cmake libnetfilter-queue-dev`.

### Build

1. Download or clone the source: `git clone git://github.com/misje/dhcpoptinj`
1. Enter the directory: `cd dhcpoptinj`
1. Create a build directory and enter it (optional, but recommended): `mkdir
	build && cd build`
1. Run cmake: `cmake ..` (or `cmake -DCMAKE_BUILD_TYPE=Debug ..` if you want a
	debug build)
1. Run make: `make -j4`
1. Install (optional, but you will benefit from having dhcpoptinj in your
	PATH): `sudo make install`

### Demolish

1. Run `sudo make uninstall` from your build directory

The build directory with all its contents can be safely removed. If you did not
use a build directory, you can get rid of all the cmake rubbish by running `git
clean -dfx`. Note, however, that this removes **everything** in the project
directory that is not under source control.

## Help

This readme should have got you started. There is no man page for dhcpoptinj,
but the help (`dhcpoptinj -h`) should cover everything the utility has to
offer.

For bugs and suggestions please create an issue.

### Limitations

dhcpoptinj is simple and will hopefully stay that way. Nonetheless, the
following are missing features that hopefully will be added some day:

1. Remove options instead of having to replace them
2. Filter incoming packets by their DHCP message type (code 53) before mangling
	them

### Troubleshooting

1. *Failed to bind queue handler to AF_INET: Operation not permitted*

	Most likely you do not have CAP\_NET\_ADMIN capability or there is another
	process (perhaps another dhcpoptinj instance?) bound to the same netfilter
	queue number.

### Known issues

I am not experienced in the netfilter library. There may be (although I cannot
promise) bugs.

1. *Syscall param socketcall.sendto(msg) points to uninitialised byte(s)*
	valgrind error

	This issue is not fully investigated yet.

1. Memory leak on non-normal exit.

	This is not considered a leak. However, there should be no memory leak on a
	normal exit (catching SIGTERM, SIGINT or SIGHUP).

## Useful information

When creating iptables rules to use with dhcpoptinj, the following options can
be useful:

-	`--queue-bypass`

	Do not drop packets, but let them pass through if dhcpoptinj is not running
	(or not listening on the correct queue number).

## Contributing

I really do not expect anyone to need or use this utility, thus I do not expect
anyone to contribute. However, by all means fork the project and leave pull
requests!

## License

I have chosen to use GPL for this project. If that does not suit you, contact
me, and we can agree on a different license.
