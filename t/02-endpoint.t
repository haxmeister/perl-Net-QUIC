use strict;
use warnings;

use Socket qw(inet_aton pack_sockaddr_in);
use Test2::V0;

use Net::QUIC::Datagram;
use Net::QUIC::Endpoint;

my $local = pack_sockaddr_in(40000, inet_aton('127.0.0.1'));
my $peer  = pack_sockaddr_in(4433, inet_aton('127.0.0.1'));

if ($^O eq 'MSWin32') {
    warn "NETQUIC-WIN before arg probe\n";
    my $probe = Net::QUIC::Endpoint->_arg_probe(
        $local,
        $peer,
        'net-quic-test',
        'localhost',
    );
    warn "NETQUIC-WIN arg probe=$probe\n";
}

warn "NETQUIC-WIN before client\n" if $^O eq 'MSWin32';
my $endpoint = Net::QUIC::Endpoint->client(
    local       => $local,
    peer        => $peer,
    alpn        => 'net-quic-test',
    server_name => 'localhost',
);

warn "NETQUIC-WIN after client\n" if $^O eq 'MSWin32';
isa_ok($endpoint, ['Net::QUIC::Endpoint'], 'client endpoint is created');
ok(!$endpoint->ready, 'new client is not ready before the handshake');

warn "NETQUIC-WIN before next_datagram\n" if $^O eq 'MSWin32';
my $datagram = $endpoint->next_datagram;
warn "NETQUIC-WIN after next_datagram\n" if $^O eq 'MSWin32';
isa_ok($datagram, ['Net::QUIC::Datagram'], 'client produces an initial datagram');

ok(length($datagram->data) >= 1200, 'initial QUIC datagram is at least 1200 bytes');
is($datagram->local, $local, 'outbound datagram keeps the local address');
is($datagram->peer, $peer, 'outbound datagram keeps the peer address');

my $after = $endpoint->timeout_after;
ok(defined($after), 'client reports a timer after initial transmission');
ok($after >= 0, 'timer delay is non-negative');

like(
    dies { Net::QUIC::Endpoint->client(local => $local, peer => $peer) },
    qr/missing required alpn argument/,
    'client constructor explains a missing required argument',
);

warn "NETQUIC-WIN before endpoint destroy\n" if $^O eq 'MSWin32';
undef $endpoint;
warn "NETQUIC-WIN after endpoint destroy\n" if $^O eq 'MSWin32';

done_testing;
