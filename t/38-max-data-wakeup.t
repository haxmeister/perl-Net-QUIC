use strict;
use warnings;
use FindBin ();
use Socket qw(inet_aton pack_sockaddr_in);
use Test2::V0;
use Net::QUIC::Endpoint;

# This tests connection-wide QUIC send credit, with no HTTP dependency.
my $saddr = pack_sockaddr_in(4492, inet_aton('127.0.0.1'));
my $caddr = pack_sockaddr_in(4092, inet_aton('127.0.0.1'));
my $server = Net::QUIC::Endpoint->server(
    alpn => 'credit-test',
    certificate_file => "$FindBin::Bin/data/server-cert.pem",
    private_key_file => "$FindBin::Bin/data/server-key.pem",
    transport => { connection_window => 2048, stream_window => 8192 },
);
my $client = Net::QUIC::Endpoint->client(
    local => $caddr, peer => $saddr, alpn => 'credit-test',
    server_name => 'localhost',
    ca_file => "$FindBin::Bin/data/server-cert.pem",
);
sub pump {
    while (my $d = $server->next_datagram) {
        $client->receive_datagram($d->data, $caddr, $saddr);
    }
    while (my $d = $client->next_datagram) {
        $server->receive_datagram($d->data, $saddr, $caddr);
    }
}
my $rxconn;
for (1 .. 1000) {
    pump();
    $rxconn ||= $server->next_connection;
    last if $rxconn && $rxconn->ready && $client->connection->ready;
}
ok($rxconn && $rxconn->ready, 'QUIC handshake');
my $txconn = $client->connection;
$txconn->send_buffer_limit(4096);
my $a = $txconn->open_bidi_stream;
my $b = $txconn->open_bidi_stream;
my $calls = 0;
$txconn->on_stream_activity(sub { ++$calls });
is($a->send_some('A' x 2048, limit_to_credit => 1), 2048,
    'first Stream fills connection credit');
is($b->send_some('B' x 1024, limit_to_credit => 1), 0,
    'independent Stream is connection-credit blocked');
my (%rx, $got);
for (1 .. 1000) {
    pump();
    while (my $s = $rxconn->next_stream) { $rx{$s->id} = $s; }
    if (my $s = $rx{$a->id}) {
        while (my $chunk = $s->next_data_chunk) { $got .= $chunk->[0]; }
    }
    last if defined($got) && length($got) == 2048
        && $txconn->send_buffered_bytes == 0;
}
is($got, 'A' x 2048, 'explicit Reader holds original payload');
is($txconn->send_buffered_bytes, 0, 'no transmit bytes awaiting ACK');
while (defined($txconn->next_active_stream_id)) {}
my $before = $calls;
$rx{$a->id}->consume(1024);
my $woke;
for (1 .. 1000) {
    pump();
    while (defined(my $id = $txconn->next_active_stream_id)) {
        $woke++ if $id == $b->id;
    }
    last if $woke;
}
ok($woke, 'MAX_DATA wakes connection-credit-blocked sibling');
ok($calls > $before, 'existing stream activity callback fires');
is($b->send_some('B' x 1024, limit_to_credit => 1), 1024,
    'sibling can use returned connection credit');
my $second = '';
for (1 .. 1000) {
    pump();
    while (my $s = $rxconn->next_stream) { $rx{$s->id} = $s; }
    if (my $s = $rx{$b->id}) {
        while (my $chunk = $s->next_data_chunk) { $second .= $chunk->[0]; }
    }
    last if length($second) == 1024;
}
is($second, 'B' x 1024, 'sibling delivers exact bytes');
done_testing;
