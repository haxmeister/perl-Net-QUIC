# Net::QUIC

Net::QUIC is a QUIC transport library for Perl built on ngtcp2.

This repository is in early development.

## Design boundary

Net::QUIC owns QUIC and TLS protocol state.

It does not own an event loop. It does not require Linux::Event, IO::Async, or
another particular networking framework.

The object split is:

```text
Net::QUIC::Endpoint
    |
    +-- Net::QUIC::Connection
            |
            +-- Net::QUIC::Stream
```

The endpoint is the event-loop and UDP boundary. A connection represents one
QUIC connection and is where application-facing connection and stream behavior
belongs.

An integration layer owns:

- the UDP socket
- readable and writable readiness
- receiving and sending UDP datagrams
- one timer

Net::QUIC gives that integration four endpoint operations:

```perl
$endpoint->receive_datagram($bytes, $local, $peer);
my $datagram = $endpoint->next_datagram;
my $seconds  = $endpoint->timeout_after;
$endpoint->handle_timeout;
```

That is the event-loop contract.

A framework adapter follows the same cycle regardless of the framework:

```perl
sub udp_readable {
    my ($bytes, $local, $peer) = receive_udp_packet();

    $endpoint->receive_datagram($bytes, $local, $peer);
    pump_quic();
}

sub pump_quic {
    while (my $datagram = $endpoint->next_datagram) {
        send_udp_packet($datagram->data, $datagram->peer);
    }

    arm_timer($endpoint->timeout_after);
}

sub quic_timer_fired {
    $endpoint->handle_timeout;
    pump_quic();
}
```

An IO::Async adapter replaces `receive_udp_packet`, `send_udp_packet`, and
`arm_timer` with IO::Async operations. A Linux::Event adapter replaces them
with Linux::Event operations. The Net::QUIC calls stay the same.

## Client endpoint

```perl
use Net::QUIC::Endpoint;

my $endpoint = Net::QUIC::Endpoint->client(
    local       => $packed_local_address,
    peer        => $packed_peer_address,
    alpn        => 'my-protocol',
    server_name => 'example.com',
);

my $connection = $endpoint->connection;
```

The local and peer values are packed IPv4 or IPv6 socket addresses. The
framework normally obtains them from the UDP socket it already owns.

The endpoint builds real QUIC packets and maintains ngtcp2's expiry timer. The
connection reports handshake readiness and can open bidirectional and
unidirectional QUIC streams.

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

After `send`, `finish`, or `reset`, the surrounding integration uses the
same endpoint cycle as before: drain `next_datagram` and rearm the endpoint
timer.

The first multi-connection server Endpoint is implemented, but the server
front door is still under development. Production client certificate
verification is also not implemented yet.

## Server endpoint

A server uses the same UDP and timer boundary while routing more than one QUIC
connection:

```perl
my $endpoint = Net::QUIC::Endpoint->server(
    alpn             => 'my-protocol',
    certificate_file => 'server-cert.pem',
    private_key_file => 'server-key.pem',
);

$endpoint->receive_datagram($bytes, $local, $peer);

while (my $connection = $endpoint->next_connection) {
    # A new peer has created a Connection.
    # Check $connection->ready when handshake completion matters.
}
```

The integration still drains `next_datagram`, schedules
`timeout_after`, and calls `handle_timeout` exactly as it does for a client
endpoint. The server Endpoint chooses the right Connection from the QUIC
destination connection ID and uses one aggregate timer for all Connections.

The server side is still early development. Retry/address validation, version
negotiation responses, automatic connection retirement, and shared server TLS
credential state are not implemented yet.

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
