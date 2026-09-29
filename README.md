# Net::QUIC

Net::QUIC is a QUIC transport library for Perl built on ngtcp2.

This repository is in early development.

## Design boundary

Net::QUIC owns QUIC and TLS protocol state.

It does not own an event loop. It does not require Linux::Event, IO::Async, EV,
or another particular networking framework.

The recommended integration shape is:

```text
Net::QUIC::Driver
    |
    +-- Net::QUIC::Endpoint
            |
            +-- Net::QUIC::Connection
                    |
                    +-- Net::QUIC::Stream
```

The integration layer still owns:

- the UDP socket
- readable and writable readiness
- receiving and sending UDP datagrams
- one replaceable one-shot timeout
- the surrounding event loop

The Driver owns the repetitive QUIC servicing rules. An adapter does not drain
Endpoint output itself and does not calculate when Endpoint timers must be
rearmed.

The adapter supplies two callbacks:

```perl
send => sub {
    my ($datagram) = @_;

    # Send one complete UDP datagram.
    # Return false only after accepting it when output is backpressured.
},

set_timeout => sub {
    my ($seconds) = @_;

    # Replace the current one-shot QUIC timeout.
    # undef means cancel it.
},
```

The adapter reports four simple events:

```perl
$driver->start;                         # UDP transport is ready
$driver->receive($bytes, $local, $peer); # one UDP packet arrived
$driver->timeout;                       # requested QUIC timeout fired
$driver->writable;                      # UDP output recovered
```

The ordinary adapter has no QUIC output-drain loop.

Conceptually:

```perl
sub udp_transport_ready {
    $driver->start;
}

sub udp_packet_received {
    my ($bytes, $local, $peer) = @_;
    $driver->receive($bytes, $local, $peer);
}

sub quic_timeout_fired {
    $driver->timeout;
}

sub udp_output_drained {
    $driver->writable;
}
```

Linux::Event can map those calls to Datagram readiness, Datagram receive/drain,
and one Kernel::Timer. IO::Async can map them to its datagram and timer
facilities. EV can map them to its I/O and timer watchers. Net::QUIC does not
need framework-specific code.

Application operations such as Stream `send`, `finish`, `reset`, receive
flow-control consumption, and Connection `close` automatically notify the
Driver when the Connection was obtained through it. Application code therefore
does not need to remember a separate "service QUIC" step after ordinary QUIC
operations.

### Low-level Endpoint boundary

`Net::QUIC::Endpoint` remains available for tests and unusual integrations that
want direct control.

Its low-level operations are:

```perl
$endpoint->receive_datagram($bytes, $local, $peer);

while (my $datagram = $endpoint->next_datagram) {
    ...
}

my $seconds = $endpoint->timeout_after;
$endpoint->handle_timeout;
```

Those primitives remain the implementation foundation below Driver. Ordinary
adapter authors should normally use `Net::QUIC::Driver` instead.

## Client integration

```perl
use Net::QUIC::Driver;

my $driver = Net::QUIC::Driver->client(
    local       => $packed_local_address,
    peer        => $packed_peer_address,
    alpn        => 'my-protocol',
    server_name => 'example.com',

    send        => sub { ... },
    set_timeout => sub { ... },
);

my $connection = $driver->connection;

# Call this once the UDP transport is ready.
$driver->start;
```

The local and peer values are packed IPv4 or IPv6 socket addresses. The
framework normally obtains them from the UDP socket it already owns.

Client certificate verification is enabled by default. Net::QUIC uses Picotls'
OpenSSL verifier to validate the certificate chain and to verify the DNS name
or IP address in `server_name`. OpenSSL's default trust locations are used.

For a private or test CA, add a PEM file with `ca_file`:

```perl
my $driver = Net::QUIC::Driver->client(
    local       => $packed_local_address,
    peer        => $packed_peer_address,
    alpn        => 'my-protocol',
    server_name => 'internal.example',
    ca_file     => '/path/to/private-ca.pem',
    send        => sub { ... },
    set_timeout => sub { ... },
);
```

There is no insecure skip-verification option.

The Driver uses an Endpoint internally to build real QUIC packets and maintain
ngtcp2's expiry deadlines. The connection reports handshake readiness and can
open bidirectional and unidirectional QUIC streams.

## Transport defaults

Client and server constructors accept an optional `transport` hash:

```perl
transport => {
    handshake_timeout => 10,
    idle_timeout      => 30,
    connection_window => 1024 * 1024,
    stream_window     => 256 * 1024,
    max_bidi_streams  => 100,
    max_uni_streams   => 100,
}
```

Those values are the defaults.

Timeouts are in seconds. The receive windows are in bytes. Stream and
connection receive credit is returned as application data is consumed, so the
window values are starting flow-control credit rather than lifetime transfer
limits.

`max_bidi_streams` and `max_uni_streams` control the initial number of
peer-initiated concurrent streams. Stream credit is replenished as streams
close.

Active connection migration is deliberately advertised as disabled for now.
Migration will become configurable only when Net::QUIC implements and tests
the required path-change behavior.

Lower-level ACK timing, congestion control, PMTU, packet-size shaping, and
connection-ID behavior remain internal policy rather than public knobs.

## Streams

A connection opens a local stream:

```perl
my $stream = $connection->open_bidi_stream;

$stream->send("hello");
$stream->finish;
```

`finish` closes only the local send side cleanly. The peer can still send data
back on a bidirectional stream.

Streams opened by the peer are pulled from the connection:

```perl
while (my $stream = $connection->next_stream) {
    while (defined(my $bytes = $stream->next_data)) {
        handle_bytes($bytes);
    }
}
```

QUIC streams carry ordered bytes, not messages. One `send` call is not
guaranteed to become one `next_data` result. Applications that need messages
must add their own framing.

With a Driver integration, `send`, `finish`, `reset`, received-data
consumption, and Connection `close` automatically wake the Driver when they
change QUIC output state. No extra adapter or application call is required.

Closed stream state remains available while the application still holds its
`Net::QUIC::Stream` object. This keeps final status and unread buffered data
usable after QUIC closes the stream. Once the stream is closed and neither a
Stream object nor the pending incoming-stream queue needs it, Net::QUIC
reclaims the native per-stream state.

Large `send` calls are copied into fixed-size internal transmit chunks.
Acknowledged chunks are released independently, so a long-lived or
flow-controlled stream does not have to retain the entire original application
send allocation until its final byte is acknowledged.

The first multi-connection server Endpoint and stateless server front door are
implemented. Client certificate and hostname verification are enabled by
default.

## Server integration

A server Driver uses the same adapter contract while routing more than one QUIC
connection:

```perl
my $driver = Net::QUIC::Driver->server(
    alpn             => 'my-protocol',
    certificate_file => 'server-cert.pem',
    private_key_file => 'server-key.pem',
    validate_address => 1,

    send        => sub { ... },
    set_timeout => sub { ... },
);

$driver->start;
$driver->receive($bytes, $local, $peer);

while (my $connection = $driver->next_connection) {
    # A new peer has created a Connection.
    # Check $connection->ready when handshake completion matters.
}
```

Driver handles Endpoint output draining and timeout replacement exactly as it
does for a client. The server Endpoint underneath chooses the right Connection
from the QUIC destination connection ID and exposes one aggregate timeout for
all Connections.

Unsupported QUIC versions are answered with a stateless Version Negotiation
packet. Setting `validate_address => 1` enables stateless Retry before a new
Connection is allocated. Retry tokens are authenticated, tied to the client's
socket address, and accepted for 10 seconds. Address validation is optional and
is off by default, avoiding the extra Retry round trip unless the application
chooses it.

The server side now retires finished Connections automatically after QUIC's
closing or draining period and removes all CID routes that belonged to them.

The server certificate and private key are loaded once when the Endpoint is
constructed. Accepted Connections create their own Picotls sessions from that
shared TLS context, so the credential files are not reopened for each client
and do not need to remain readable after Endpoint construction.

After Connection state is gone, a sufficiently large short-header packet for
an unknown destination connection ID can receive a Stateless Reset. Reset
tokens are derived from an Endpoint-private secret and the server-issued
connection ID, so the Endpoint can answer without recreating Connection state.
Unknown long-header packets and packets too small for a safe reset are dropped.

## Native dependency

Net::QUIC uses Alien::ngtcp2 0.03 or newer.

Net::QUIC has one QUIC TLS path: Picotls. Alien::ngtcp2 supplies the tested
ngtcp2 and Picotls build. Picotls handles TLS 1.3 and uses the host OpenSSL
installation underneath for cryptography and certificate support.

Normal Net::QUIC users do not choose a TLS backend.

## Development

    perl Makefile.PL
    make
    make test

## License

Net::QUIC is MIT licensed.
