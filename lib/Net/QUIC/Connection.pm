package Net::QUIC::Connection;

use strict;
use warnings;

use Hash::Util::FieldHash qw(fieldhash);

use Net::QUIC ();
use Net::QUIC::Stream ();

our $VERSION = $Net::QUIC::VERSION;

fieldhash my %OUTPUT_CALLBACK;
fieldhash my %STREAM_AVAILABLE_CALLBACK;

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

sub on_stream_available {
    my ($self, $callback) = @_;

    if (defined $callback) {
        die "stream availability callback must be a coderef"
            if ref($callback) ne 'CODE';
        $STREAM_AVAILABLE_CALLBACK{$self} = $callback;
    } else {
        delete $STREAM_AVAILABLE_CALLBACK{$self};
    }

    $self->_dispatch_stream_availability;
    return $self;
}

sub _dispatch_stream_availability {
    my ($self) = @_;

    my $callback = $STREAM_AVAILABLE_CALLBACK{$self};
    return if !$callback;

    my $events = $self->_take_stream_available;
    $callback->($self, 'bidi') if $events & 0x01;
    $callback->($self, 'uni')  if $events & 0x02;
    return;
}

sub open_bidi_stream {
    my ($self) = @_;
    my $id = $self->_open_stream(1);
    return if !defined $id;
    return Net::QUIC::Stream->_new($self, $id, 1, 1);
}

sub open_uni_stream {
    my ($self) = @_;
    my $id = $self->_open_stream(0);
    return if !defined $id;
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

sub close_info {
    my ($self) = @_;
    return $self->_close_info;
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

Application-facing connection and stream behavior belongs here. Ordinary UDP
socket and timer integration is driven through L<Net::QUIC::Driver>.
L<Net::QUIC::Endpoint> remains the lower-level transport boundary.

The connection objects are currently created by
L<Net::QUIC::Endpoint/client>. Direct construction is private while the API is
still being built.

=head1 METHODS

=head2 open_bidi_stream

    my $stream = $connection->open_bidi_stream;

Opens a bidirectional stream and returns a L<Net::QUIC::Stream>.

Returns undef when the peer's current bidirectional stream limit has been
reached. This is normal QUIC flow control and does not mean the Connection has
failed. Other failures still throw an exception.

=head2 open_uni_stream

    my $stream = $connection->open_uni_stream;

Opens a local unidirectional stream. This side can send on the stream, but it
does not receive application data on it.

Returns undef when the peer's current unidirectional stream limit has been
reached. Other failures still throw an exception.

=head2 on_stream_available

    $connection->on_stream_available(sub {
        my ($connection, $type) = @_;

        if ($type eq 'bidi') {
            my $stream = $connection->open_bidi_stream;
            ...
        }
    });

Registers a callback for stream-limit recovery.

The callback is useful after C<open_bidi_stream> or C<open_uni_stream> returns
undef. It runs when the peer later raises that stream limit, and C<$type> is
either C<bidi> or C<uni>.

The callback runs outside ngtcp2's internal callback stack, so opening a stream
from it is safe.

Pass undef to remove the callback.

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
handled correctly. When the Connection belongs to a L<Net::QUIC::Driver>, the
Driver automatically services the close packet and updates the required QUIC
timeout.

=head2 close_info

    my $info = $connection->close_info;

Returns undef while no connection close or failure has been recorded.

Once a connection is closing or has failed, returns a small hash reference.
The common fields are:

    type       application, transport, tls, certificate,
               handshake, idle, or drop

    initiator  local or peer

    code       the application, QUIC transport, or TLS alert code

C<frame_type> is included when a peer transport close identifies the QUIC frame
that caused the error. C<native_error> is included for failures detected by
ngtcp2 locally.

A normal application close uses C<type =E<gt> 'application'> and code zero.
This means local and peer normal closes can be distinguished without treating
either one as an exception.

TLS certificate verification failures use C<type =E<gt> 'certificate'>.
Other TLS failures use C<type =E<gt> 'tls'>. Handshake timeout uses
C<type =E<gt> 'handshake'>.

Local API misuse, invalid configuration, allocation failure, and internal
implementation failures still throw exceptions instead of becoming
C<close_info>. Those are local program/system failures rather than remote
connection outcomes.

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
