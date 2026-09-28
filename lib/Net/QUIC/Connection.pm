package Net::QUIC::Connection;

use strict;
use warnings;

use Net::QUIC ();

our $VERSION = $Net::QUIC::VERSION;

1;

__END__

=head1 NAME

Net::QUIC::Connection - one QUIC connection

=head1 DESCRIPTION

Net::QUIC::Connection represents one QUIC connection.

Application-facing connection and stream behavior belongs here. UDP socket and
timer integration belongs to L<Net::QUIC::Endpoint>.

The connection objects are currently created by
L<Net::QUIC::Endpoint/client>. Direct construction is private while the API is
still being built.

=head1 METHODS

=head2 ready

    if ($connection->ready) {
        ...
    }

Returns true after the QUIC cryptographic handshake has completed.

=cut
