package Net::QUIC::Endpoint;

use strict;
use warnings;

use Carp qw(croak);
use Net::QUIC ();
use Net::QUIC::Datagram ();

our $VERSION = $Net::QUIC::VERSION;

sub client {
    my ($class, %args) = @_;

    for my $name (qw(local peer alpn)) {
        croak "missing required $name argument"
            if !defined $args{$name};
    }

    my $server_name = defined $args{server_name}
        ? $args{server_name}
        : '';

    return $class->_client_new(
        $args{local},
        $args{peer},
        $args{alpn},
        $server_name,
    );
}

1;

__END__

=head1 NAME

Net::QUIC::Endpoint - event-loop boundary for QUIC

=head1 SYNOPSIS

    use Net::QUIC::Endpoint;

    my $endpoint = Net::QUIC::Endpoint->client(
        local       => $packed_local_address,
        peer        => $packed_peer_address,
        alpn        => 'my-protocol',
        server_name => 'example.com',
    );

    while (my $datagram = $endpoint->next_datagram) {
        $udp->send($datagram->data, $datagram->peer);
    }

    my $after = $endpoint->timeout_after;

=head1 DESCRIPTION

Net::QUIC::Endpoint is the small boundary between QUIC and an event loop.

An event-loop integration owns the UDP socket and its timer. The endpoint owns
the QUIC protocol state.

For a client integration, the basic cycle is:

    UDP readable
        -> receive_datagram
        -> send each next_datagram
        -> arm a timer for timeout_after

    timer fires
        -> handle_timeout
        -> send each next_datagram
        -> arm the timer again

The C<local> and C<peer> addresses are packed socket addresses such as those
returned by Perl's L<Socket> functions or by the networking framework in use.
They must be IPv4 or IPv6 addresses.

This is an early development API. It currently establishes the native client
endpoint and transport boundary. Stream handling and the final TLS verification
API are still under development.

=head1 METHODS

=head2 client

    my $endpoint = Net::QUIC::Endpoint->client(
        local       => $local,
        peer        => $peer,
        alpn        => 'chat/1',
        server_name => 'example.com',
    );

Creates client-side QUIC state. C<local>, C<peer>, and C<alpn> are required.
C<server_name> is used for TLS SNI when supplied.

The UDP socket must already have a real local address before creating the
endpoint. An integration will normally create or connect its UDP socket first,
then obtain the socket's local and peer addresses and create the endpoint.

=head2 receive_datagram

    $endpoint->receive_datagram($bytes, $local, $peer);

Feeds one received UDP datagram into QUIC.

=head2 next_datagram

    while (my $datagram = $endpoint->next_datagram) {
        ...
    }

Returns the next UDP datagram QUIC wants sent, or undef if none is ready.

=head2 timeout_after

    my $seconds = $endpoint->timeout_after;

Returns the number of seconds until QUIC next needs timer service. It may
return zero when the timeout is already due, or undef when no timeout is
currently needed.

=head2 handle_timeout

    $endpoint->handle_timeout;

Tells QUIC that its event-loop timer fired. After this call, drain
C<next_datagram> again and arrange the new C<timeout_after> value.

=head2 ready

    if ($endpoint->ready) {
        ...
    }

Returns true after the QUIC cryptographic handshake has completed.

=cut
