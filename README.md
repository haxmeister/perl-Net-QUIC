# Net::QUIC

Net::QUIC is a QUIC transport library for Perl built on ngtcp2.

This repository is in early development.

## Design boundary

Net::QUIC owns QUIC and TLS protocol state.

It does not own an event loop. It does not require Linux::Event, IO::Async, or
another particular networking framework.

An integration layer owns:

- the UDP socket
- readable and writable readiness
- receiving and sending UDP datagrams
- one timer

Net::QUIC gives that integration four operations:

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

The first transport-facing API is a client endpoint:

```perl
use Net::QUIC::Endpoint;

my $endpoint = Net::QUIC::Endpoint->client(
    local       => $packed_local_address,
    peer        => $packed_peer_address,
    alpn        => 'my-protocol',
    server_name => 'example.com',
);
```

The local and peer values are packed IPv4 or IPv6 socket addresses. The
framework normally obtains them from the UDP socket it already owns.

The endpoint can already build a real QUIC Initial packet and maintain ngtcp2's
expiry timer. Stream handling, server endpoints, and the final certificate
verification API come next.

## Native dependency

Net::QUIC uses Alien::ngtcp2 0.02 or newer.

Alien::ngtcp2 supplies:

- libngtcp2
- one compatible ngtcp2 TLS helper

The TLS helper is selected to fit the host system. Normal Net::QUIC users
should not need to choose OpenSSL, GnuTLS, Picotls, or another backend.

## Development

    perl Makefile.PL
    make
    make test

## License

Net::QUIC is MIT licensed.
