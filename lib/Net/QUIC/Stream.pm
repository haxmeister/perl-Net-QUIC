package Net::QUIC::Stream;

use strict;
use warnings;

use Carp qw(croak);
use Net::QUIC ();

our $VERSION = '0.01';

sub _new {
    my ($class, $connection, $id, $local_initiated, $bidirectional) = @_;

    $connection->_stream_retain($id);

    return bless {
        connection      => $connection,
        id              => $id,
        local_initiated => $local_initiated ? 1 : 0,
        bidirectional   => $bidirectional ? 1 : 0,
        retained        => 1,
    }, $class;
}

sub DESTROY {
    my ($self) = @_;

    return if !$self->{retained};

    $self->{retained} = 0;
    my $connection = $self->{connection};
    return if !defined $connection;

    eval { $connection->_stream_release($self->{id}) };
    return;
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
    $self->{connection}->_notify_output;
    return;
}

sub finish {
    my ($self) = @_;

    croak "cannot finish the send side of this QUIC stream"
        if !$self->can_send;

    $self->{connection}->_stream_finish($self->{id});
    $self->{connection}->_notify_output;
    return;
}

sub next_data {
    my ($self) = @_;

    croak "cannot receive on this unidirectional QUIC stream"
        if !$self->can_receive;

    my $event = $self->{connection}->_stream_take_data($self->{id});
    return if !defined $event;

    $self->{connection}->_notify_output;
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

sub local_reset_code {
    my ($self) = @_;
    return $self->{connection}->_stream_local_reset_code($self->{id});
}

sub remote_stop_sending_code {
    my ($self) = @_;
    return $self->{connection}->_stream_remote_stop_sending_code($self->{id});
}

sub local_stop_sending_code {
    my ($self) = @_;
    return $self->{connection}->_stream_local_stop_sending_code($self->{id});
}

sub reset {
    my ($self, $app_error_code) = @_;

    croak "cannot reset the send side of this QUIC stream"
        if !$self->can_send;

    $app_error_code = 0 if !defined $app_error_code;
    croak "application error code must be a non-negative integer"
        if $app_error_code !~ /\A\d+\z/;

    $self->{connection}->_stream_reset($self->{id}, $app_error_code);
    $self->{connection}->_notify_output;
    return;
}

sub stop_sending {
    my ($self, $app_error_code) = @_;

    croak "cannot stop the receive side of this QUIC stream"
        if !$self->can_receive;

    $app_error_code = 0 if !defined $app_error_code;
    croak "application error code must be a non-negative integer"
        if $app_error_code !~ /\A\d+\z/;

    $self->{connection}->_stream_stop_sending($self->{id}, $app_error_code);
    $self->{connection}->_notify_output;
    return;
}

1;

__END__

=head1 NAME

Net::QUIC::Stream - one QUIC byte stream

=head1 SYNOPSIS

Send bytes:

    $stream->send("hello");
    $stream->finish;

Read bytes:

    while (defined(my $bytes = $stream->next_data)) {
        handle_bytes($bytes);
    }

Check for a clean peer FIN:

    if ($stream->remote_finished) {
        ...
    }

Abort the local send side:

    $stream->reset($application_error_code);

Stop the peer from sending more data:

    $stream->stop_sending($application_error_code);

=head1 DESCRIPTION

Net::QUIC::Stream represents one QUIC byte stream.

A QUIC stream is an ordered sequence of bytes.

It is not a sequence of application messages.

One call to:

    $stream->send($message);

does not guarantee one matching C<next_data> result on the peer.

Applications that need message boundaries should add their own framing above
the QUIC stream.

A Stream does not own a socket. UDP and timer integration normally stays in
L<Net::QUIC::Driver>.

=head1 STREAM DIRECTION

A bidirectional stream allows both endpoints to send.

A unidirectional stream allows only its creator to send application bytes.

Use:

    $stream->can_send

and:

    $stream->can_receive

when code needs to handle either kind.

=head1 METHODS

=head2 id

    my $id = $stream->id;

Returns the QUIC stream ID.

=head2 local_initiated

    if ($stream->local_initiated) {
        ...
    }

Returns true when this endpoint opened the stream.

=head2 bidirectional

    if ($stream->bidirectional) {
        ...
    }

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

The bytes are copied into Net::QUIC-owned memory.

Large sends are stored internally in fixed-size pieces so fully acknowledged
earlier bytes can be released without keeping the entire original send
allocation alive.

When this Stream belongs to a Connection obtained through Driver, C<send>
automatically notifies Driver that QUIC may have new output.

No extra integration call is required.

=head2 finish

    $stream->finish;

Closes the local send side cleanly after all bytes already queued with
C<send>.

This sends QUIC FIN.

It does not discard queued data.

On a bidirectional stream, the peer may continue sending bytes back after this
endpoint calls C<finish>.

=head2 next_data

    while (defined(my $bytes = $stream->next_data)) {
        ...
    }

Returns the next received chunk, or undef when no received data is currently
waiting.

Always test with C<defined>.

Reading data returns its receive flow-control credit to QUIC. With a Driver
integration, any protocol output made possible by that credit is serviced
automatically.

=head2 remote_finished

Returns true after a clean FIN has been received from the peer.

This means the peer has finished its send side.

=head2 reset

    $stream->reset;

or:

    $stream->reset($application_error_code);

Aborts the local stream send side with a QUIC RESET_STREAM frame and an
application error code.

Queued transmit data that has not already completed is discarded.

The receive side is independent. On a bidirectional stream, calling C<reset>
does not prevent the peer from continuing to send data back.

The code defaults to zero.

=head2 stop_sending

    $stream->stop_sending;

or:

    $stream->stop_sending($application_error_code);

Stops the local receive side abruptly and asks the peer to stop transmitting
with a QUIC STOP_SENDING frame.

Unread buffered receive data is discarded. On a bidirectional stream, the
local send side remains independent and can continue sending unless the peer
also asks it to stop.

The code defaults to zero.

=head2 remote_reset_code

    my $code = $stream->remote_reset_code;

Returns the application error code when the peer reset the stream, or undef if
no peer reset has been received.

=head2 local_reset_code

    my $code = $stream->local_reset_code;

Returns the application error code passed to C<reset> on this endpoint, or
undef if this endpoint has not reset the stream.

Keeping local and remote reset codes separate makes the reset direction
unambiguous.

=head2 remote_stop_sending_code

    my $code = $stream->remote_stop_sending_code;

Returns the application error code when the peer sent STOP_SENDING for this
endpoint's send side, or undef if no such request has been received.

Receiving STOP_SENDING closes this endpoint's send side. QUIC sends a
RESET_STREAM with the same application error code when the send side still
requires an abort; no RESET_STREAM is needed after a completed send has already
been fully acknowledged.

=head2 local_stop_sending_code

    my $code = $stream->local_stop_sending_code;

Returns the application error code passed to C<stop_sending> on this endpoint,
or undef if this endpoint has not stopped its receive side.

=head2 closed

Returns true after ngtcp2 reports that the stream is fully closed.

=head1 OBJECT LIFETIME

A Stream object keeps its L<Net::QUIC::Connection> alive.

Closed native stream state remains available while a Stream object still needs
it. This keeps final status and unread buffered receive data usable after QUIC
closes the stream.

Once the native stream is closed and no public Stream object or pending
incoming-stream queue entry needs it, Net::QUIC reclaims that state.

Dropping a Stream object before native close does not discard already queued
transmit data. Net::QUIC keeps the native stream state until QUIC can finish or
close it.

=head1 SEE ALSO

L<Net::QUIC>

L<Net::QUIC::Connection>

L<Net::QUIC::Driver>

=cut
