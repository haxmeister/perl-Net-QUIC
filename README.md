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

Client certificate verification is enabled by default. Net::QUIC uses Picotls'
OpenSSL verifier to validate the certificate chain and to verify the DNS name
or IP address in `server_name`. OpenSSL's default trust locations are used.

For a private or test CA, add a PEM file with `ca_file`:

```perl
my $endpoint = Net::QUIC::Endpoint->client(
    local       => $packed_local_address,
    peer        => $packed_peer_address,
    alpn        => 'my-protocol',
    server_name => 'internal.example',
    ca_file     => '/path/to/private-ca.pem',
);
```

There is no insecure skip-verification option.

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

The first multi-connection server Endpoint and stateless server front door are
implemented. Client certificate and hostname verification are enabled by
default.

## Server endpoint

A server uses the same UDP and timer boundary while routing more than one QUIC
connection:

```perl
my $endpoint = Net::QUIC::Endpoint->server(
    alpn             => 'my-protocol',
    certificate_file => 'server-cert.pem',
    private_key_file => 'server-key.pem',
    validate_address => 1,
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
