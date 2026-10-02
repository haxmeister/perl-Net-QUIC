package Net::QUIC::Datagram;

use strict;
use warnings;

use Net::QUIC ();

our $VERSION = '0.02';

sub _new {
    my ($class, $data, $local, $peer, $ecn) = @_;
    $ecn = 0 if !defined $ecn;
    return bless [$data, $local, $peer, $ecn], $class;
}

sub data  { $_[0]->[0] }
sub local { $_[0]->[1] }
sub peer  { $_[0]->[2] }
sub ecn   { $_[0]->[3] }

1;

__END__

=head1 NAME

Net::QUIC::Datagram - UDP datagram produced by Net::QUIC

=head1 DESCRIPTION

A Net::QUIC::Datagram contains one complete UDP payload, the network path
chosen by QUIC, and the ECN codepoint that should be placed in the IP header.

L<Net::QUIC::Driver> passes these objects to its C<send> callback.

Low-level L<Net::QUIC::Endpoint> users receive them from C<next_datagram>.

=head1 METHODS

=head2 data

Returns the UDP payload bytes.

=head2 local

Returns the packed concrete local source address for the datagram.

An adapter using a socket bound to one concrete address normally gets this
source address automatically from the socket.

An adapter using a wildcard-bound socket must preserve this source address when
transmitting the packet, using the platform's source-address selection
mechanism.

=head2 peer

Returns the packed peer socket address for the datagram.

=head2 ecn

Returns the two-bit ECN codepoint that the UDP adapter should place in the IP
header for this datagram:

    0   Not-ECT
    1   ECT(1)
    2   ECT(0)
    3   CE

The value is the wire codepoint, not a QUIC-specific enumeration.

When ECN is supported by the adapter, the outgoing packet must use this value
so ngtcp2 can validate ECN behavior for the network path.

=cut
