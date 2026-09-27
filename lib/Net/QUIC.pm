package Net::QUIC;

use strict;
use warnings;

use XSLoader ();

our $VERSION = '0.001_001';

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

This is an early development version. The first implementation step proves the
native binding and TLS helper selected by Alien::ngtcp2. The connection and
stream API is still being designed.

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

A Linux::Event, IO::Async, or other integration will eventually feed incoming
UDP packets and time information into Net::QUIC, send the packets Net::QUIC
produces, and arrange the next requested timeout.

Keeping that boundary small lets one QUIC implementation work with different
Perl networking systems.

=head1 STATUS

The native binding is under active development. The public connection and
stream API is not stable yet.

=head1 SEE ALSO

L<Alien::ngtcp2>

L<https://github.com/ngtcp2/ngtcp2>

=head1 AUTHOR

Joshua S. Day

=head1 COPYRIGHT AND LICENSE

This software is Copyright (c) 2026 by Joshua S. Day.

This is free software, licensed under:

    The MIT (X11) License

=cut
