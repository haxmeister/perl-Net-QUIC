use strict;
use warnings;

use FindBin ();
use Socket qw(inet_aton pack_sockaddr_in);
use Test2::V0;
use Time::HiRes qw(sleep);

use Net::QUIC::Endpoint;

my $cert_file = "$FindBin::Bin/data/server-cert.pem";
my $key_file = "$FindBin::Bin/data/server-key.pem";
my $alpn = 'net-quic-datagram-test';

sub make_pair {
    my (%args) = @_;

    my $client_local = pack_sockaddr_in(
        $args{client_port},
        inet_aton('127.0.0.1'),
    );
    my $server_local = pack_sockaddr_in(
        $args{server_port},
        inet_aton('127.0.0.1'),
    );

    my $server = Net::QUIC::Endpoint->server(
        alpn             => $alpn,
        certificate_file => $cert_file,
        private_key_file => $key_file,
        transport        => {
            max_datagram_frame_size => $args{server_datagram_size} // 65535,
        },
        (defined($args{version})
            ? (preferred_version => $args{version})
            : ()),
    );

    my $client = Net::QUIC::Endpoint->client(
        local       => $client_local,
        peer        => $server_local,
        alpn        => $alpn,
        server_name => 'localhost',
        ca_file     => $cert_file,
        transport   => {
            max_datagram_frame_size => $args{client_datagram_size} // 65535,
        },
        (defined($args{version}) ? (version => $args{version}) : ()),
    );

    return ($client, $server);
}

sub pump {
    my ($client, $server, $accepted_ref) = @_;
    my $progress = 0;

    while (my $datagram = $server->next_datagram) {
        ++$progress;
        $client->receive_datagram(
            $datagram->data,
            $datagram->peer,
            $datagram->local,
            $datagram->ecn,
        );
    }

    while (my $datagram = $client->next_datagram) {
        ++$progress;
        $server->receive_datagram(
            $datagram->data,
            $datagram->peer,
            $datagram->local,
            $datagram->ecn,
        );
    }

    $$accepted_ref ||= $server->next_connection if $accepted_ref;

    my @wait;
    for my $endpoint ($client, $server) {
        my $after = $endpoint->timeout_after;

        if (defined($after) && $after <= 0) {
            ++$progress;
            $endpoint->handle_timeout;
        } elsif (defined($after)) {
            push @wait, $after;
        }
    }

    if (!$progress && @wait) {
        @wait = sort { $a <=> $b } @wait;
        my $nap = $wait[0] > 0.01 ? 0.01 : $wait[0] + 0.001;
        sleep($nap);
        ++$progress;
    }

    return $progress;
}

sub handshake {
    my ($client, $server) = @_;
    my $accepted;

    for (1 .. 1000) {
        pump($client, $server, \$accepted);
        last if $accepted
            && $client->connection->ready
            && $accepted->ready;
    }

    ok($accepted, 'server accepts connection');
    ok($client->connection->ready, 'client handshake completes');
    ok($accepted->ready, 'server handshake completes');

    return $accepted;
}

subtest 'bidirectional RFC 9221 datagrams' => sub {
    my ($client, $server) = make_pair(
        client_port => 40600,
        server_port => 4600,
    );
    my $server_connection = handshake($client, $server);
    my $client_connection = $client->connection;

    is(
        $client_connection->local_max_datagram_frame_size,
        65535,
        'client advertises configured DATAGRAM receive size',
    );
    is(
        $client_connection->peer_max_datagram_frame_size,
        65535,
        'client sees server DATAGRAM receive size',
    );
    ok($client_connection->can_send_datagram, 'client can send DATAGRAM');
    ok($client_connection->can_receive_datagram, 'client can receive DATAGRAM');
    ok($server_connection->can_send_datagram, 'server can send DATAGRAM');
    ok($server_connection->can_receive_datagram, 'server can receive DATAGRAM');

    ok(
        $client_connection->send_datagram('client-one'),
        'first client DATAGRAM is accepted',
    );
    ok(
        !$client_connection->send_datagram('client-two'),
        'second client DATAGRAM is backpressured while one is pending',
    );

    pump($client, $server);

    my ($server_bytes, $server_early) =
        $server_connection->next_received_datagram;
    is($server_bytes, 'client-one', 'server receives client DATAGRAM');
    is($server_early, 0, 'normal DATAGRAM is not marked as 0-RTT');
    ok(
        !defined($server_connection->next_received_datagram),
        'backpressured DATAGRAM was not silently queued',
    );

    ok(
        $server_connection->send_datagram('server-one'),
        'server DATAGRAM is accepted',
    );
    pump($client, $server);

    is(
        scalar($client_connection->next_received_datagram),
        'server-one',
        'client receives server DATAGRAM',
    );
};

subtest 'datagram callback dispatch' => sub {
    my ($client, $server) = make_pair(
        client_port => 40601,
        server_port => 4601,
    );
    my $server_connection = handshake($client, $server);
    my @received;

    $server_connection->on_datagram(sub {
        my ($connection, $bytes, $early) = @_;
        push @received, [$bytes, $early];
    });

    ok(
        $client->connection->send_datagram('callback-data'),
        'DATAGRAM for callback is accepted',
    );
    pump($client, $server);

    is(
        \@received,
        [['callback-data', 0]],
        'received DATAGRAM is dispatched after packet processing',
    );
    ok(
        !defined($server_connection->next_received_datagram),
        'callback drains the received DATAGRAM queue',
    );
};

subtest 'one-way negotiation and limits' => sub {
    my ($client, $server) = make_pair(
        client_port          => 40602,
        server_port          => 4602,
        client_datagram_size => 0,
        server_datagram_size => 64,
    );
    my $server_connection = handshake($client, $server);
    my $client_connection = $client->connection;

    ok(
        $client_connection->can_send_datagram,
        'client can send because server advertised DATAGRAM support',
    );
    ok(
        !$server_connection->can_send_datagram,
        'server cannot send because client did not advertise support',
    );

    like(
        dies { $server_connection->send_datagram('x') },
        qr/peer does not support QUIC DATAGRAM/,
        'send is rejected when peer did not advertise DATAGRAM support',
    );

    like(
        dies { $client_connection->send_datagram('x' x 100) },
        qr/exceeds peer max_datagram_frame_size/,
        'oversize DATAGRAM is rejected before queueing',
    );

    ok(
        $client_connection->send_datagram('small'),
        'client can send within server limit',
    );
    pump($client, $server);
    is(
        scalar($server_connection->next_received_datagram),
        'small',
        'one-way DATAGRAM delivery succeeds',
    );
};

subtest 'QUIC v2 datagram transport' => sub {
    my ($client, $server) = make_pair(
        client_port => 40603,
        server_port => 4603,
        version     => 2,
    );
    my $server_connection = handshake($client, $server);
    my $client_connection = $client->connection;

    is($client_connection->version, 2, 'client negotiated QUIC v2');
    is($server_connection->version, 2, 'server negotiated QUIC v2');

    ok(
        $client_connection->send_datagram('v2-datagram'),
        'QUIC v2 DATAGRAM is accepted',
    );
    pump($client, $server);
    is(
        scalar($server_connection->next_received_datagram),
        'v2-datagram',
        'QUIC v2 DATAGRAM is delivered',
    );
};

like(
    dies {
        Net::QUIC::Endpoint->server(
            alpn             => $alpn,
            certificate_file => $cert_file,
            private_key_file => $key_file,
            transport        => {
                max_datagram_frame_size => 65536,
            },
        );
    },
    qr/max_datagram_frame_size cannot exceed 65535/,
    'impossible DATAGRAM frame size is rejected',
);

done_testing;
