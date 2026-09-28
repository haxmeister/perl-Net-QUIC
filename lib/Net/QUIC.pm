package Net::QUIC;

use strict;
use warnings;

use XSLoader ();

our $VERSION = '0.001_002';

XSLoader::load(__PACKAGE__, $VERSION);

1;

__END__

=head1 NAME

Net::QUIC - QUIC transport for Perl

=head1 SYNOPSIS

    use Net::QUIC;

    say Net::QUIC::ngtcp2_version();
    say Net::QUIC::crypto_backend();

=head1 DESCRIPTION

Net::QUIC is a Perl QUIC transport library built on ngtcp2.

The library is intentionally event-loop neutral. Net::QUIC owns QUIC and TLS
protocol state. The application or integration layer owns UDP sockets,
readiness notification, and scheduling.

The first transport-facing API is L<Net::QUIC::Endpoint>. An event-loop
integration feeds received UDP datagrams into an endpoint, sends the datagrams
it produces, and schedules the timeout it requests.

Net::QUIC uses Picotls for QUIC TLS. Alien::ngtcp2 supplies the tested
ngtcp2 and Picotls build. Picotls uses the host OpenSSL installation underneath
for cryptography and certificate support. Applications do not choose a TLS
backend.

=head1 FUNCTIONS

=head2 ngtcp2_version

    my $version = Net::QUIC::ngtcp2_version();

Returns the version string reported by the linked ngtcp2 library.

=head2 ngtcp2_version_num

    my $version_num = Net::QUIC::ngtcp2_version_num();

Returns ngtcp2's numeric version value.

=head2 crypto_backend

    my $backend = Net::QUIC::crypto_backend();

Returns C<picotls>. This diagnostic exists so a build can report its native
QUIC TLS implementation. Application code should not need to branch on it.

=head1 EVENT LOOP BOUNDARY

Net::QUIC does not choose an event loop.

The integration contract is deliberately small:

    UDP packet arrives
        -> $endpoint->receive_datagram(...)

    Net::QUIC has packets to send
        -> $endpoint->next_datagram

    Net::QUIC needs a timer
        -> $endpoint->timeout_after

    Timer fires
        -> $endpoint->handle_timeout

See L<Net::QUIC::Endpoint> for the complete cycle.

=head1 STATUS

The native client endpoint, event-loop boundary, first public stream API, and
first multi-connection server Endpoint are implemented. Bidirectional and
unidirectional streams can send and receive ordered bytes, finish cleanly, and
reset.

The server front door now handles Version Negotiation and optional stateless
Retry/address validation before Connection allocation. QUIC clients verify
server certificate chains and host names by default using Picotls and OpenSSL.
Shared server TLS credential state, stateless reset policy for unknown
connection IDs, and automatic connection retirement are not implemented yet.

=head1 SEE ALSO

L<Net::QUIC::Endpoint>

L<Net::QUIC::Connection>

L<Net::QUIC::Stream>

L<Alien::ngtcp2>

L<https://github.com/ngtcp2/ngtcp2>

=head1 AUTHOR

Joshua S. Day

=head1 COPYRIGHT AND LICENSE

This software is Copyright (c) 2026 by Joshua S. Day.

This is free software, licensed under:

    The MIT (X11) License

=cut
