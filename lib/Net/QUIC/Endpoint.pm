package Net::QUIC::Endpoint;

use strict;
use warnings;

use Carp qw(croak);
use Net::QUIC ();
use Net::QUIC::Connection ();
use Net::QUIC::Datagram ();

our $VERSION = $Net::QUIC::VERSION;

sub client {
    my ($class, %args) = @_;

    for my $name (qw(local peer alpn)) {
        croak "missing required $name argument"
            if !defined $args{$name};
    }

    my $server_name = defined $args{server_name}
        ? $args{server_name}
        : '';

    my $connection = Net::QUIC::Connection->_client_new(
        $args{local},
        $args{peer},
        $args{alpn},
        $server_name,
    );

    return bless {
        mode       => 'client',
        connection => $connection,
    }, $class;
}

sub server {
    my ($class, %args) = @_;

    for my $name (qw(alpn certificate_file private_key_file)) {
        croak "missing required $name argument"
            if !defined $args{$name};
    }

    return bless {
        mode                => 'server',
        alpn                => $args{alpn},
        certificate_file    => $args{certificate_file},
        private_key_file    => $args{private_key_file},
        cid_length          => $class->_server_cid_length,
        routes              => {},
        connections         => [],
        pending_connections => [],
        tx_cursor           => 0,
    }, $class;
}

sub _sync_server_routes {
    my ($self, $connection) = @_;

    while (my $event = $connection->_take_cid_event) {
        my ($add, $cid) = @$event;

        if ($add) {
            $self->{routes}{$cid} = $connection;
        } else {
            delete $self->{routes}{$cid};
        }
    }

    return;
}

sub _server_receive_datagram {
    my ($self, $bytes, $local, $peer) = @_;

    my $dcid = $self->_packet_dcid($bytes, $self->{cid_length});
    return if !defined $dcid;

    my $connection = $self->{routes}{$dcid};

    if (!$connection) {
        my $initial_dcid = $self->_initial_dcid($bytes);
        return if !defined $initial_dcid;

        $connection = Net::QUIC::Connection->_server_new(
            $bytes,
            $local,
            $peer,
            $self->{alpn},
            $self->{certificate_file},
            $self->{private_key_file},
        );

        $self->{routes}{$initial_dcid} = $connection;
        push @{$self->{connections}}, $connection;
        push @{$self->{pending_connections}}, $connection;
        $self->_sync_server_routes($connection);
    }

    $connection->_receive_datagram($bytes, $local, $peer);
    $self->_sync_server_routes($connection);
    return;
}

sub _server_next_datagram {
    my ($self) = @_;
    my $connections = $self->{connections};
    my $count = @$connections;

    return if !$count;

    for (1 .. $count) {
        my $index = $self->{tx_cursor} % $count;
        $self->{tx_cursor} = ($index + 1) % $count;

        my $connection = $connections->[$index];
        my $datagram = $connection->_next_datagram;
        $self->_sync_server_routes($connection);

        return $datagram if defined $datagram;
    }

    return;
}

sub _server_timeout_after {
    my ($self) = @_;
    my $minimum;

    for my $connection (@{$self->{connections}}) {
        my $after = $connection->_timeout_after;
        next if !defined $after;

        $minimum = $after
            if !defined($minimum) || $after < $minimum;
    }

    return $minimum;
}

sub _server_handle_timeout {
    my ($self) = @_;

    for my $connection (@{$self->{connections}}) {
        my $after = $connection->_timeout_after;
        next if !defined($after) || $after > 0;

        $connection->_handle_timeout;
        $self->_sync_server_routes($connection);
    }

    return;
}

sub connection {
    my ($self) = @_;

    croak "server endpoint manages multiple connections; use next_connection"
        if $self->{mode} eq 'server';

    return $self->{connection};
}

sub next_connection {
    my ($self) = @_;

    croak "next_connection is only available on a server endpoint"
        if $self->{mode} ne 'server';

    return shift @{$self->{pending_connections}};
}

sub receive_datagram {
    my ($self, @args) = @_;

    return $self->_server_receive_datagram(@args)
        if $self->{mode} eq 'server';

    return $self->{connection}->_receive_datagram(@args);
}

sub next_datagram {
    my ($self) = @_;

    return $self->_server_next_datagram
        if $self->{mode} eq 'server';

    return $self->{connection}->_next_datagram;
}

sub timeout_after {
    my ($self) = @_;

    return $self->_server_timeout_after
        if $self->{mode} eq 'server';

    return $self->{connection}->_timeout_after;
}

sub handle_timeout {
    my ($self) = @_;

    return $self->_server_handle_timeout
        if $self->{mode} eq 'server';

    return $self->{connection}->_handle_timeout;
}

1;

__END__

=head1 NAME

Net::QUIC::Endpoint - event-loop boundary for QUIC

=head1 SYNOPSIS

    use Net::QUIC::Endpoint;

    my $endpoint = Net::QUIC::Endpoint->client(
        local       => $packed_local_address,
        peer        => $packed_peer_address,
        alpn        => 'my-protocol',
        server_name => 'example.com',
    );

    my $connection = $endpoint->connection;

    while (my $datagram = $endpoint->next_datagram) {
        $udp->send($datagram->data, $datagram->peer);
    }

    my $after = $endpoint->timeout_after;

=head1 DESCRIPTION

Net::QUIC::Endpoint is the small boundary between QUIC and an event loop.

An event-loop integration owns the UDP socket and its timer. The endpoint owns
the transport-facing side of QUIC and gives the integration datagrams to send
and a timeout to schedule.

A QUIC connection is represented separately by L<Net::QUIC::Connection>.
For a client endpoint there is currently one connection. A future server
endpoint can use the same event-loop boundary while managing several
connections behind one UDP socket.

For a client integration, the basic cycle is:

    UDP readable
        -> receive_datagram
        -> send each next_datagram
        -> arm a timer for timeout_after

    timer fires
        -> handle_timeout
        -> send each next_datagram
        -> arm the timer again

The C<local> and C<peer> addresses are packed socket addresses such as those
returned by Perl's L<Socket> functions or by the networking framework in use.
They must be IPv4 or IPv6 addresses.

=head1 METHODS

=head2 client

Creates a client endpoint and its first L<Net::QUIC::Connection>.

C<local>, C<peer>, and C<alpn> are required. C<server_name> is used for TLS
SNI when supplied.

=head2 connection

    my $connection = $endpoint->connection;

Returns the client connection owned by this endpoint.

=head2 receive_datagram

    $endpoint->receive_datagram($bytes, $local, $peer);

Feeds one received UDP datagram into QUIC.

=head2 next_datagram

    while (my $datagram = $endpoint->next_datagram) {
        ...
    }

Returns the next UDP datagram QUIC wants sent, or undef if none is ready.

=head2 timeout_after

    my $seconds = $endpoint->timeout_after;

Returns the number of seconds until QUIC next needs timer service. It may
return zero when the timeout is already due, or undef when no timeout is
currently needed.

=head2 handle_timeout

    $endpoint->handle_timeout;

Tells QUIC that its event-loop timer fired. After this call, drain
C<next_datagram> again and arrange the new C<timeout_after> value.

=cut
