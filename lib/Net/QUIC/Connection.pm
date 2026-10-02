package Net::QUIC::Connection;

use strict;
use warnings;

use Hash::Util::FieldHash qw(fieldhash);

use Net::QUIC ();
use Net::QUIC::Stream ();

our $VERSION = '0.01';

fieldhash my %OUTPUT_CALLBACK;
fieldhash my %STREAM_AVAILABLE_CALLBACK;

my $EARLY_DATA_MAGIC = "NQED";
my $EARLY_DATA_VERSION = 1;
my $EARLY_DATA_HEADER_LEN = 13;

sub _encode_early_data_state {
    my ($class, $ticket, $transport) = @_;

    die "missing TLS session ticket for early-data state"
        if !defined($ticket) || $ticket eq '';
    die "missing QUIC transport parameters for early-data state"
        if !defined($transport) || $transport eq '';

    return pack(
        'a4CNN',
        $EARLY_DATA_MAGIC,
        $EARLY_DATA_VERSION,
        length($ticket),
        length($transport),
    ) . $ticket . $transport;
}

sub _decode_early_data_state {
    my ($class, $state) = @_;

    die "early_data must be an opaque state returned by early_data_state"
        if !defined($state)
        || ref($state)
        || length($state) < $EARLY_DATA_HEADER_LEN;

    my ($magic, $version, $ticket_len, $transport_len) =
        unpack('a4CNN', substr($state, 0, $EARLY_DATA_HEADER_LEN));

    die "invalid Net::QUIC early-data state"
        if $magic ne $EARLY_DATA_MAGIC
        || $version != $EARLY_DATA_VERSION
        || $ticket_len == 0
        || $transport_len == 0
        || $ticket_len > length($state) - $EARLY_DATA_HEADER_LEN
        || $transport_len
            != length($state) - $EARLY_DATA_HEADER_LEN - $ticket_len;

    my $ticket = substr($state, $EARLY_DATA_HEADER_LEN, $ticket_len);
    my $transport = substr(
        $state,
        $EARLY_DATA_HEADER_LEN + $ticket_len,
        $transport_len,
    );

    return ($ticket, $transport);
}

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

sub migrate {
    my ($self, $local) = @_;

    die "missing migration local address"
        if !defined $local;

    $self->_migrate($local);
    $self->_notify_output;
    return;
}

sub path {
    my ($self) = @_;

    my $path = $self->_path;
    return if !defined $path;

    return {
        local => $path->[0],
        peer  => $path->[1],
    };
}

sub path_validation {
    my ($self) = @_;

    my $state = $self->_path_validation;
    return { status => 'none' } if !defined $state;

    my @status = qw(none validating succeeded failed aborted);
    my $status = $status[$state->[0]];

    die "invalid native path validation status"
        if !defined $status;

    return {
        status            => $status,
        local             => $state->[2],
        peer              => $state->[3],
        preferred_address => ($state->[1] & 0x01) ? 1 : 0,
        new_token         => ($state->[1] & 0x02) ? 1 : 0,
    };
}

sub path_validation_status {
    my ($self) = @_;
    return $self->path_validation->{status};
}

sub early_data_state {
    my ($self) = @_;

    my $ticket = $self->session_ticket;
    return if !defined $ticket;

    my $transport = $self->_early_data_transport_params;
    return if !defined $transport;

    return __PACKAGE__->_encode_early_data_state($ticket, $transport);
}

sub early_data_status {
    my ($self) = @_;
    my @status = qw(none pending accepted rejected);
    my $value = $self->_early_data_status;

    die "invalid native early-data status"
        if !defined($status[$value]);

    return $status[$value];
}

sub closed {
    my ($self) = @_;
    return $self->_retired;
}

1;

__END__

=head1 NAME

Net::QUIC::Connection - one QUIC connection

=head1 SYNOPSIS

A client Connection normally comes from L<Net::QUIC::Driver>:

    my $connection = $driver->connection;

Wait for the QUIC/TLS handshake:

    return if !$connection->ready;

Open a bidirectional stream:

    my $stream = $connection->open_bidi_stream;

    if ($stream) {
        $stream->send("hello");
        $stream->finish;
    }

Accept streams opened by the peer:

    while (my $stream = $connection->next_stream) {
        ...
    }

Close the Connection normally:

    $connection->close;

=head1 DESCRIPTION

Net::QUIC::Connection represents one QUIC connection.

Application protocol code normally works with Connection and
L<Net::QUIC::Stream>. UDP socket and timer integration normally stays in
L<Net::QUIC::Driver>.

A client Driver owns one Connection. A server Driver can expose many
Connections through C<next_connection>.

Connection objects are created by Driver or L<Net::QUIC::Endpoint>. Direct
native construction is private.

=head1 HANDSHAKE READINESS

=head2 ready

    if ($connection->ready) {
        ...
    }

Returns true after the QUIC cryptographic handshake has completed.

A server Connection may be returned before this becomes true.

Application work that requires an established connection should wait for
C<ready>, unless the client deliberately opened a replay-safe 0-RTT stream
using saved early-data state.

=head2 early_data_state

    my $state = $connection->early_data_state;

Returns an opaque byte string containing the TLS session ticket and the QUIC
transport parameters needed for a later 0-RTT attempt.

Returns undef until the client has completed a handshake and received a session
ticket.

Pass the returned value as C<early_data> on a later client Driver or Endpoint:

    my $driver = Net::QUIC::Driver->client(
        ...
        early_data => $state,
    );

The state is opaque. Applications should store it without parsing or modifying
it.

=head2 early_data_status

    my $status = $connection->early_data_status;

Returns one of:

    none
    pending
    accepted
    rejected

C<none> means this connection did not attempt 0-RTT.

C<pending> means 0-RTT was requested and the peer has not yet accepted or
rejected it.

C<accepted> means the server accepted the early data.

C<rejected> means the server rejected it or the saved state could not be used.
ngtcp2 discards the early stream state in this case. Stream objects opened for
that rejected attempt are no longer valid; the application should wait for the
handshake to become ready, open new streams, and resend only if that is
appropriate.

0-RTT data can be replayed by the network. Only operations that are safe to
repeat should be sent before the handshake is ready.

=head2 resumed

    if ($connection->resumed) {
        ...
    }

Returns true when the completed TLS 1.3 handshake resumed a previous session
using a saved session ticket.

A normal first connection returns false.

An unusable or expired ticket does not make the connection fail. TLS can fall
back to a full certificate handshake, in which case C<resumed> is false.

=head2 session_ticket

    my $ticket = $connection->session_ticket;

Returns the newest opaque TLS session ticket received by a client Connection,
or undef when no ticket has been received yet.

The application may store this byte string and pass it as C<session_ticket> on
a later client Endpoint or Driver connection to the same server identity and
ALPN.

The ticket is opaque. Applications should not parse or modify it.

Net::QUIC does not enable 0-RTT merely because a session ticket is supplied.
This method currently provides handshake resumption only.

=head2 address_token

    my $token = $connection->address_token;

Returns the newest opaque QUIC address-validation token received through a
NEW_TOKEN frame, or undef if none has been received.

A server Endpoint with C<validate_address =E<gt> 1> automatically issues a
NEW_TOKEN after address validation and handshake completion. Save the returned
byte string and pass it as C<address_token> on a later client Endpoint or
Driver connection.

A valid token lets the server validate the client's source address without
requiring another Retry round trip. The token is independent of TLS session
tickets and can be cached alongside them.

Address tokens are opaque. Applications should not parse or modify them.

=head1 NETWORK PATHS

=head2 path

    my $path = $connection->path;

Returns the current active QUIC network path:

    {
        local => $packed_local_address,
        peer  => $packed_peer_address,
    }

The addresses use the same packed IPv4/IPv6 representation used by Driver,
Endpoint, and Datagram.

=head2 migrate

    $connection->migrate($new_packed_local_address);

Starts validated client migration to a new local network path.

The remote server address remains unchanged. Net::QUIC first validates the new
path with PATH_CHALLENGE/PATH_RESPONSE and switches to it only after validation
succeeds.

The event-loop adapter remains responsible for actually sending datagrams with
the source address in C<Datagram-E<gt>local> and for reporting the concrete
local destination address of received packets. No new Driver callback is
required.

C<migrate> is client-only. It requires a completed and confirmed handshake, an
unused peer connection ID, and a local address different from the current path.

=head2 path_validation_status

    my $status = $connection->path_validation_status;

Returns one of:

    none
    validating
    succeeded
    failed
    aborted

=head2 path_validation

    my $validation = $connection->path_validation;

Returns the detailed current or most recent path-validation state:

    {
        status            => 'validating',
        local             => $packed_local_address,
        peer              => $packed_peer_address,
        preferred_address => 0,
        new_token         => 0,
    }

Before any path validation has been observed it returns:

    { status => 'none' }

The same state is available on server Connections when a peer causes path
validation. C<preferred_address> and C<new_token> expose the corresponding
ngtcp2 path-validation flags for preferred-address and NEW_TOKEN path work.

=head1 OPENING STREAMS

=head2 open_bidi_stream

    my $stream = $connection->open_bidi_stream;

Opens a local bidirectional stream and returns a L<Net::QUIC::Stream>.

Both endpoints can send application bytes on a bidirectional stream.

Returns undef when the peer's current bidirectional stream limit has been
reached.

That is normal QUIC flow control. It does not mean the Connection failed.

Other failures still throw an exception.

=head2 open_uni_stream

    my $stream = $connection->open_uni_stream;

Opens a local unidirectional stream.

This endpoint can send application bytes on the stream but cannot receive
application bytes from it.

Returns undef when the peer's current unidirectional stream limit has been
reached.

Other failures still throw an exception.

=head2 on_stream_available

    $connection->on_stream_available(sub {
        my ($connection, $type) = @_;

        return if $type ne 'bidi';

        my $stream = $connection->open_bidi_stream;
        return if !defined $stream;

        ...
    });

Registers a callback for stream-limit recovery.

Use it when C<open_bidi_stream> or C<open_uni_stream> returned undef and the
application wants to continue when the peer later grants more stream credit.

C<$type> is:

    bidi

or:

    uni

The callback runs outside ngtcp2's internal callback stack, so opening a stream
from it is safe.

Pass undef to remove the callback:

    $connection->on_stream_available(undef);

=head1 PEER-CREATED STREAMS

=head2 next_stream

    while (my $stream = $connection->next_stream) {
        ...
    }

Returns the next stream opened by the peer, or undef when no new incoming
stream is waiting.

The returned object is a L<Net::QUIC::Stream>.

=head1 CLOSING

=head2 close

    $connection->close;

or:

    $connection->close($application_error_code);

Starts a normal QUIC application-level Connection close.

The application error code defaults to zero.

Calling C<close> again while the Connection is already closing is harmless.

C<close> does not immediately destroy the object. QUIC has a closing/draining
period during which late packets still need network and timer service.

When the Connection belongs to a Driver, Driver automatically services the
close packet and timeout changes.

=head2 closed

    if ($connection->closed) {
        ...
    }

Returns true after the Connection has completely finished its QUIC closing or
draining period and no longer needs network or timer service.

C<close_info> can become available before C<closed> becomes true.

=head1 CLOSE AND ERROR INFORMATION

=head2 close_info

    my $info = $connection->close_info;

Returns undef while no Connection close or failure has been recorded.

Once a close or failure is known, returns a small hash reference.

The common fields are:

    type
    initiator
    code

C<type> is one of:

    application
    transport
    tls
    certificate
    handshake
    idle
    drop

C<initiator> is:

    local

or:

    peer

C<code> is the application error code, QUIC transport error code, or TLS alert
code as appropriate.

For example, a normal peer application close can be:

    {
        type      => 'application',
        initiator => 'peer',
        code      => 0,
    }

C<frame_type> is included when a peer transport close identifies the QUIC frame
that caused the error.

C<native_error> is included for failures detected locally by ngtcp2.

TLS certificate verification failures use:

    type => 'certificate'

Other TLS failures use:

    type => 'tls'

Handshake timeout uses:

    type => 'handshake'

Local API misuse, invalid configuration, allocation failure, and internal
implementation failures still throw Perl exceptions. Those are local
programming or system failures rather than ordinary remote Connection
outcomes.

=head1 DRIVER NOTIFICATION

Connections obtained through L<Net::QUIC::Driver> are privately connected back
to that Driver.

State-changing application calls such as stream send/finish/reset,
stop_sending, data consumption, and Connection close can therefore cause QUIC
output and timer
changes to be serviced automatically.

Application code does not need to call a separate pump or service method.

=head1 SEE ALSO

L<Net::QUIC>

L<Net::QUIC::Driver>

L<Net::QUIC::Stream>

L<Net::QUIC::Endpoint>

=cut
