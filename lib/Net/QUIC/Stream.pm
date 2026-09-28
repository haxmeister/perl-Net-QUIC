package Net::QUIC::Stream;

use strict;
use warnings;

use Carp qw(croak);
use Net::QUIC ();

our $VERSION = $Net::QUIC::VERSION;

sub _new {
    my ($class, $connection, $id, $local_initiated, $bidirectional) = @_;

    return bless {
        connection      => $connection,
        id              => $id,
        local_initiated => $local_initiated ? 1 : 0,
        bidirectional   => $bidirectional ? 1 : 0,
    }, $class;
}

sub id {
    my ($self) = @_;
    return $self->{id};
}

sub local_initiated {
    my ($self) = @_;
    return $self->{local_initiated};
}

sub bidirectional {
    my ($self) = @_;
    return $self->{bidirectional};
}

sub can_send {
    my ($self) = @_;
    return $self->{bidirectional} || $self->{local_initiated};
}

sub can_receive {
    my ($self) = @_;
    return $self->{bidirectional} || !$self->{local_initiated};
}

sub send {
    my ($self, $bytes) = @_;

    croak "send requires bytes" if !defined $bytes;
    croak "cannot send on this unidirectional QUIC stream"
        if !$self->can_send;

    $self->{connection}->_stream_send($self->{id}, $bytes);
    return;
}

sub finish {
    my ($self) = @_;

    croak "cannot finish the send side of this QUIC stream"
        if !$self->can_send;

    $self->{connection}->_stream_finish($self->{id});
    return;
}

sub next_data {
    my ($self) = @_;

    croak "cannot receive on this unidirectional QUIC stream"
        if !$self->can_receive;

    my $event = $self->{connection}->_stream_take_data($self->{id});
    return if !defined $event;

    return $event->[0];
}

sub remote_finished {
    my ($self) = @_;
    return $self->{connection}->_stream_remote_finished($self->{id});
}

sub closed {
    my ($self) = @_;
    return $self->{connection}->_stream_closed($self->{id});
}

sub remote_reset_code {
    my ($self) = @_;
    return $self->{connection}->_stream_remote_reset_code($self->{id});
}

sub reset {
    my ($self, $app_error_code) = @_;

    $app_error_code = 0 if !defined $app_error_code;
    croak "application error code must be a non-negative integer"
        if $app_error_code !~ /\A\d+\z/;

    $self->{connection}->_stream_reset($self->{id}, $app_error_code);
    return;
}

1;

__END__

=head1 NAME

Net::QUIC::Stream - one QUIC byte stream

=head1 DESCRIPTION

Net::QUIC::Stream represents one QUIC byte stream.

QUIC stream data is an ordered sequence of bytes, not a sequence of messages.
A C<send> call does not define a message boundary, and received bytes may be
returned by C<next_data> in different-sized chunks. Applications that need
messages must add their own framing.

A stream does not own a socket. Data queued with C<send> becomes UDP datagrams
when the surrounding L<Net::QUIC::Endpoint> is drained with C<next_datagram>.

Stream objects keep their L<Net::QUIC::Connection> alive.

=head1 METHODS

=head2 id

Returns the QUIC stream ID.

=head2 local_initiated

Returns true when this endpoint opened the stream.

=head2 bidirectional

Returns true for a bidirectional stream and false for a unidirectional stream.

=head2 can_send

Returns true when this endpoint is allowed to send application bytes on the
stream.

=head2 can_receive

Returns true when this endpoint is allowed to receive application bytes on the
stream.

=head2 send

    $stream->send($bytes);

Queues bytes for reliable ordered delivery.

The bytes are copied into Net::QUIC-owned memory and kept unchanged until
ngtcp2 reports that they are acknowledged or the stream closes.

=head2 finish

    $stream->finish;

Closes the local send side cleanly after all bytes already queued with C<send>.
This sends QUIC FIN. It does not discard queued data.

=head2 next_data

    while (defined(my $bytes = $stream->next_data)) {
        ...
    }

Returns the next received chunk, or undef when no received data is waiting.

An empty string is a valid return value when the peer sends a FIN with no final
data, so test the result with C<defined>.

Reading a chunk gives its receive flow-control credit back to QUIC.

=head2 remote_finished

Returns true after a clean FIN has been received from the peer.

=head2 reset

    $stream->reset($application_error_code);

Aborts the stream with a QUIC application error code. The code defaults to
zero when omitted.

=head2 remote_reset_code

Returns the application error code when the peer reset the stream, or undef if
no peer reset has been received.

=head2 closed

Returns true after ngtcp2 reports that the stream is fully closed.

=cut
