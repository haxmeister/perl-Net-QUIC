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

Normal applications should not need to choose a TLS backend. Alien::ngtcp2
selects one that fits the host system when Net::QUIC is built.

=head1 FUNCTIONS

=head2 ngtcp2_version

    my $version = Net::QUIC::ngtcp2_version();

Returns the version string reported by the linked ngtcp2 library.

=head2 ngtcp2_version_num

    my $version_num = Net::QUIC::ngtcp2_version_num();

Returns ngtcp2's numeric version value.

=head2 crypto_backend

    my $backend = Net::QUIC::crypto_backend();

Returns the TLS backend selected when Net::QUIC was built. This is diagnostic
information. Application code should not need to change behavior based on it.

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

The native client endpoint and event-loop boundary are under active
development. Stream handling, server endpoints, and the final certificate
verification API are not stable yet.

=head1 SEE ALSO

L<Net::QUIC::Endpoint>

L<Alien::ngtcp2>

L<https://github.com/ngtcp2/ngtcp2>

=head1 AUTHOR

Joshua S. Day

=head1 COPYRIGHT AND LICENSE

This software is Copyright (c) 2026 by Joshua S. Day.

This is free software, licensed under:

    The MIT (X11) License

=cut
