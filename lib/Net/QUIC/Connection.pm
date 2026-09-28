package Net::QUIC::Connection;

use strict;
use warnings;

use Net::QUIC ();
use Net::QUIC::Stream ();

our $VERSION = $Net::QUIC::VERSION;

sub open_bidi_stream {
    my ($self) = @_;
    my $id = $self->_open_stream(1);
    return Net::QUIC::Stream->_new($self, $id, 1, 1);
}

sub open_uni_stream {
    my ($self) = @_;
    my $id = $self->_open_stream(0);
    return Net::QUIC::Stream->_new($self, $id, 1, 0);
}

sub next_stream {
    my ($self) = @_;
    my $id = $self->_next_stream_id;

    return if !defined $id;

    my $info = $self->_stream_info($id);
    return Net::QUIC::Stream->_new($self, $id, $info->[0], $info->[1]);
}

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

=head2 open_bidi_stream

    my $stream = $connection->open_bidi_stream;

Opens a bidirectional stream and returns a L<Net::QUIC::Stream>.

=head2 open_uni_stream

    my $stream = $connection->open_uni_stream;

Opens a local unidirectional stream. This side can send on the stream, but it
does not receive application data on it.

=head2 next_stream

    while (my $stream = $connection->next_stream) {
        ...
    }

Returns the next stream opened by the peer, or undef when there is no new
incoming stream waiting.

=head2 ready

    if ($connection->ready) {
        ...
    }

Returns true after the QUIC cryptographic handshake has completed.

=cut
