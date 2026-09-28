package Net::QUIC::Datagram;

use strict;
use warnings;

use Net::QUIC ();

our $VERSION = $Net::QUIC::VERSION;

sub data  { $_[0]->[0] }
sub local { $_[0]->[1] }
sub peer  { $_[0]->[2] }

1;

__END__

=head1 NAME

Net::QUIC::Datagram - UDP datagram produced by Net::QUIC

=head1 DESCRIPTION

A Net::QUIC::Datagram is returned by
L<Net::QUIC::Endpoint/next_datagram>. It contains the UDP payload and the
network path chosen by QUIC.

=head1 METHODS

=head2 data

Returns the UDP payload bytes.

=head2 local

Returns the packed local socket address for the datagram.

=head2 peer

Returns the packed peer socket address for the datagram.

=cut
