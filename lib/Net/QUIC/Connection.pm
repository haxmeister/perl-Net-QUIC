package Net::QUIC::Connection;

use strict;
use warnings;

use Hash::Util::FieldHash qw(fieldhash);

use Net::QUIC ();
use Net::QUIC::Stream ();

our $VERSION = $Net::QUIC::VERSION;

fieldhash my %OUTPUT_CALLBACK;

sub _set_output_callback {
    my ($self, $callback) = @_;

    if (defined $callback) {
        die "output callback must be a coderef"
            if ref($callback) ne 'CODE';
        $OUTPUT_CALLBACK{$self} = $callback;
    } else {
        delete $OUTPUT_CALLBACK{$self};
    }

    return;
}

sub _notify_output {
    my ($self) = @_;
    my $callback = $OUTPUT_CALLBACK{$self};
    $callback->() if $callback;
    return;
}

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

sub close {
    my ($self, $application_error_code) = @_;

    $application_error_code = 0
        if !defined $application_error_code;

    die "application error code must be a non-negative integer"
        if $application_error_code !~ /\A\d+\z/;

    $self->_close($application_error_code);
    $self->_notify_output;
    return;
}

sub closed {
    my ($self) = @_;
    return $self->_retired;
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

=head2 close

    $connection->close;
    $connection->close($application_error_code);

Starts a normal QUIC application-level connection close.

The application error code defaults to zero. Calling C<close> again while the
connection is already closing is harmless.

C<close> does not immediately destroy the Connection object. QUIC keeps a
closing or draining connection around for a short period so late packets are
handled correctly. The surrounding L<Net::QUIC::Endpoint> continues to report
the timer needed for that period.

=head2 closed

    if ($connection->closed) {
        ...
    }

Returns true after the connection has completely finished its QUIC closing or
draining period and no longer needs network or timer service.

=head2 ready

    if ($connection->ready) {
        ...
    }

Returns true after the QUIC cryptographic handshake has completed.

=cut
