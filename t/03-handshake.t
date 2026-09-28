use strict;
use warnings;

use FindBin ();
use Socket qw(inet_aton pack_sockaddr_in);
use Test2::V0;

use Net::QUIC::Connection;
use Net::QUIC::Endpoint;

my $client_local = pack_sockaddr_in(40000, inet_aton('127.0.0.1'));
my $server_local = pack_sockaddr_in(4433, inet_aton('127.0.0.1'));
my $alpn = 'net-quic-test';
my $cert_file = "$FindBin::Bin/data/server-cert.pem";
my $key_file = "$FindBin::Bin/data/server-key.pem";

ok(-f $cert_file, 'test server certificate exists');
ok(-f $key_file, 'test server private key exists');

my $client = Net::QUIC::Endpoint->client(
    local       => $client_local,
    peer        => $server_local,
    alpn        => $alpn,
    server_name => 'localhost',
);

my $initial = $client->next_datagram;
ok(defined($initial), 'client produces an Initial for the server proof');

my $server = Net::QUIC::Connection->_server_new(
    $initial->data,
    $server_local,
    $client_local,
    $alpn,
    $cert_file,
    $key_file,
);

isa_ok($server, ['Net::QUIC::Connection'], 'private server connection is created');
ok(!$client->connection->ready, 'client is not ready before packet exchange');
ok(!$server->ready, 'server is not ready before receiving the Initial');

$server->_receive_datagram(
    $initial->data,
    $server_local,
    $client_local,
);

for (1 .. 100) {
    last if $client->connection->ready && $server->ready;

    my $progress = 0;

    while (my $datagram = $server->_next_datagram) {
        ++$progress;
        $client->receive_datagram(
            $datagram->data,
            $client_local,
            $server_local,
        );
    }

    while (my $datagram = $client->next_datagram) {
        ++$progress;
        $server->_receive_datagram(
            $datagram->data,
            $server_local,
            $client_local,
        );
    }

    my $client_after = $client->timeout_after;
    if (defined($client_after) && $client_after <= 0) {
        ++$progress;
        $client->handle_timeout;
    }

    my $server_after = $server->_timeout_after;
    if (defined($server_after) && $server_after <= 0) {
        ++$progress;
        $server->_handle_timeout;
    }

    last if !$progress;
}

ok($client->connection->ready, 'client completes the in-memory QUIC/TLS handshake');
ok($server->ready, 'server completes the in-memory QUIC/TLS handshake');

done_testing;
