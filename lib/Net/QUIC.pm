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

L<Net::QUIC::Driver> is the recommended event-loop integration API. An
adapter reports UDP receive, timeout, and writable events to the Driver. The
Driver sends complete UDP datagrams through an adapter callback and asks the
adapter to replace one QUIC timeout.

L<Net::QUIC::Endpoint> remains the low-level engine boundary for unusual
integrations and tests.

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

The recommended adapter contract is deliberately small:

    UDP transport becomes ready
        -> $driver->start

    UDP packet arrives
        -> $driver->receive(...)

    Requested QUIC timeout fires
        -> $driver->timeout

    UDP output recovers from backpressure
        -> $driver->writable

The adapter supplies C<send> and C<set_timeout> callbacks. Driver owns Endpoint
output draining, backpressure pause/resume state, and QUIC timeout updates.

Application calls that change QUIC output state are also serviced
automatically when Connections are obtained through the Driver.

See L<Net::QUIC::Driver> for the ordinary adapter API and
L<Net::QUIC::Endpoint> for the lower-level primitives.

=head1 STATUS

The native client endpoint, event-loop boundary, first public stream API, and
first multi-connection server Endpoint are implemented. Bidirectional and
unidirectional streams can send and receive ordered bytes, finish cleanly, and
reset.

The server front door now handles Version Negotiation and optional stateless
Retry/address validation before Connection allocation. QUIC clients verify
server certificate chains and host names by default using Picotls and OpenSSL.
Finished server Connections are retired automatically after QUIC's closing or
draining period, together with all of their CID routes. Server TLS credentials
are loaded once per Endpoint and shared by accepted Connection sessions.
The server also handles lost or retired server-issued connection IDs
statelessly. A sufficiently large unknown short-header packet can receive a
Stateless Reset without recreating Connection state; unknown long-header and
undersized packets are dropped.

=head1 SEE ALSO

L<Net::QUIC::Driver>

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
