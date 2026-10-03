use strict;
use warnings;

use FindBin ();
use Socket qw(inet_aton pack_sockaddr_in);
use Time::HiRes qw(time);

use lib "$FindBin::Bin/../../blib/lib";
use lib "$FindBin::Bin/../../blib/arch";

use Net::QUIC::Endpoint;

my $cert_file = "$FindBin::Bin/../../t/data/server-cert.pem";
my $key_file = "$FindBin::Bin/../../t/data/server-key.pem";
my $alpn = 'net-quic-protocol-engine-benchmark';

my $lookup_iterations = $ENV{NET_QUIC_BENCH_LOOKUPS} || 100_000;
my $tx_iterations = $ENV{NET_QUIC_BENCH_TX_ITERS} || 20_000;
my $tx_chunk_size = $ENV{NET_QUIC_BENCH_TX_CHUNK} || 1024;
my $rx_bytes = $ENV{NET_QUIC_BENCH_RX_BYTES} || (8 * 1024 * 1024);

sub rate {
    my ($count, $seconds) = @_;
    return $seconds > 0 ? $count / $seconds : 0;
}

sub fmt_rate {
    my ($value) = @_;
    return sprintf('%.0f', $value);
}

sub establish_pair {
    my (%args) = @_;

    my $server_port = $args{server_port};
    my $client_port = $args{client_port};
    my $max_streams = $args{max_streams} || 100;
    my $connection_window = $args{connection_window} || (32 * 1024 * 1024);
    my $stream_window = $args{stream_window} || (32 * 1024 * 1024);

    my $server_local =
        pack_sockaddr_in($server_port, inet_aton('127.0.0.1'));
    my $client_local =
        pack_sockaddr_in($client_port, inet_aton('127.0.0.1'));

    my $server = Net::QUIC::Endpoint->server(
        alpn             => $alpn,
        certificate_file => $cert_file,
        private_key_file => $key_file,
        transport        => {
            connection_window => $connection_window,
            stream_window     => $stream_window,
            max_bidi_streams  => $max_streams,
            max_uni_streams   => $max_streams,
        },
    );

    my $client = Net::QUIC::Endpoint->client(
        local       => $client_local,
        peer        => $server_local,
        alpn        => $alpn,
        server_name => 'localhost',
        ca_file     => $cert_file,
        transport   => {
            connection_window => $connection_window,
            stream_window     => $stream_window,
            max_bidi_streams  => $max_streams,
            max_uni_streams   => $max_streams,
        },
    );

    my $accepted;

    my $pump = sub {
        my $progress = 0;

        while (my $datagram = $server->next_datagram) {
            ++$progress;
            $client->receive_datagram(
                $datagram->data,
                $client_local,
                $server_local,
            );
        }

        while (my $datagram = $client->next_datagram) {
            ++$progress;
            $server->receive_datagram(
                $datagram->data,
                $server_local,
                $client_local,
            );
        }

        my $server_after = $server->timeout_after;
        if (defined($server_after) && $server_after <= 0) {
            ++$progress;
            $server->handle_timeout;
        }

        my $client_after = $client->timeout_after;
        if (defined($client_after) && $client_after <= 0) {
            ++$progress;
            $client->handle_timeout;
        }

        if (!$progress) {
            my @wait = sort { $a <=> $b }
                grep { defined($_) && $_ > 0 }
                ($server_after, $client_after);

            if (@wait) {
                my $nap = $wait[0] > 0.001 ? 0.001 : $wait[0] + 0.0001;
                select undef, undef, undef, $nap;
                ++$progress;
            }
        }

        return $progress;
    };

    for (1 .. 2000) {
        $pump->();
        $accepted ||= $server->next_connection;

        last if $accepted
            && $client->connection->ready
            && $accepted->ready;
    }

    die "benchmark QUIC handshake did not complete\n"
        if !$accepted
        || !$client->connection->ready
        || !$accepted->ready;

    return ($client, $server, $accepted, $pump);
}

sub benchmark_lookup {
    my ($count, $server_port, $client_port) = @_;

    my ($client) = establish_pair(
        server_port => $server_port,
        client_port => $client_port,
        max_streams => $count + 10,
    );

    my @streams;
    for (1 .. $count) {
        push @streams, $client->connection->open_bidi_stream;
    }

    my @targets = (
        ['first',  $streams[0]],
        ['middle', $streams[int($count / 2)]],
        ['last',   $streams[-1]],
    );

    for my $target (@targets) {
        my ($position, $stream) = @$target;

        for (1 .. 1000) {
            $stream->acked_offset;
        }

        my $start = time;
        for (1 .. $lookup_iterations) {
            $stream->acked_offset;
        }
        my $elapsed = time - $start;

        print join(
            ' ',
            'LOOKUP',
            "streams=$count",
            "position=$position",
            "iterations=$lookup_iterations",
            'seconds=' . sprintf('%.6f', $elapsed),
            'lookups_per_sec=' . fmt_rate(
                rate($lookup_iterations, $elapsed)
            ),
        ), "\n";
    }
}

sub benchmark_tx {
    my ($server_port, $client_port) = @_;

    my ($client) = establish_pair(
        server_port => $server_port,
        client_port => $client_port,
    );

    my $connection = $client->connection;
    my $bytes = 'x' x $tx_chunk_size;

    my $ordinary = $connection->open_bidi_stream;

    my $start = time;
    for (1 .. $tx_iterations) {
        $ordinary->send($bytes);
    }
    my $ordinary_elapsed = time - $start;

    print join(
        ' ',
        'TX',
        'mode=send',
        "iterations=$tx_iterations",
        "chunk_bytes=$tx_chunk_size",
        'seconds=' . sprintf('%.6f', $ordinary_elapsed),
        'calls_per_sec=' . fmt_rate(
            rate($tx_iterations, $ordinary_elapsed)
        ),
        'mb_per_sec=' . sprintf(
            '%.2f',
            rate($tx_iterations * $tx_chunk_size, $ordinary_elapsed)
                / (1024 * 1024),
        ),
    ), "\n";

    $ordinary->reset(1);

    my $limit = $tx_iterations * $tx_chunk_size + $tx_chunk_size;
    $connection->send_buffer_limit($limit);

    my $bounded = $connection->open_bidi_stream;

    $start = time;
    my $accepted = 0;
    for (1 .. $tx_iterations) {
        $accepted += $bounded->send_some($bytes);
    }
    my $bounded_elapsed = time - $start;

    die "send_some benchmark did not accept all bytes\n"
        if $accepted != $tx_iterations * $tx_chunk_size;

    print join(
        ' ',
        'TX',
        'mode=send_some',
        "iterations=$tx_iterations",
        "chunk_bytes=$tx_chunk_size",
        'seconds=' . sprintf('%.6f', $bounded_elapsed),
        'calls_per_sec=' . fmt_rate(
            rate($tx_iterations, $bounded_elapsed)
        ),
        'mb_per_sec=' . sprintf(
            '%.2f',
            rate($accepted, $bounded_elapsed) / (1024 * 1024),
        ),
        'relative_to_send=' . sprintf(
            '%.3f',
            $ordinary_elapsed / $bounded_elapsed,
        ),
    ), "\n";
}

sub prepare_rx {
    my (%args) = @_;

    my ($client, $server, $accepted, $pump) = establish_pair(%args);

    my $sender = $client->connection->open_bidi_stream;
    $sender->send('r' x $rx_bytes);
    $sender->finish;

    my $receiver;

    for (1 .. 20000) {
        $pump->();
        $receiver ||= $accepted->next_stream;

        last if $receiver
            && $receiver->remote_finished;
    }

    die "RX benchmark did not receive complete Stream\n"
        if !$receiver || !$receiver->remote_finished;

    return ($receiver, $client, $server, $accepted);
}

sub benchmark_rx {
    my ($server_port, $client_port) = @_;

    my ($ordinary) = prepare_rx(
        server_port       => $server_port,
        client_port       => $client_port,
        connection_window => $rx_bytes * 2,
        stream_window     => $rx_bytes * 2,
    );

    my $ordinary_bytes = 0;
    my $ordinary_chunks = 0;
    my $start = time;

    while (defined(my $chunk = $ordinary->next_data)) {
        $ordinary_bytes += length($chunk);
        ++$ordinary_chunks;
    }

    my $ordinary_elapsed = time - $start;

    die "ordinary RX byte count mismatch\n"
        if $ordinary_bytes != $rx_bytes;

    print join(
        ' ',
        'RX',
        'mode=next_data',
        "bytes=$ordinary_bytes",
        "chunks=$ordinary_chunks",
        'seconds=' . sprintf('%.6f', $ordinary_elapsed),
        'chunks_per_sec=' . fmt_rate(
            rate($ordinary_chunks, $ordinary_elapsed)
        ),
        'mb_per_sec=' . sprintf(
            '%.2f',
            rate($ordinary_bytes, $ordinary_elapsed) / (1024 * 1024),
        ),
    ), "\n";

    my ($explicit) = prepare_rx(
        server_port       => $server_port + 1,
        client_port       => $client_port + 1,
        connection_window => $rx_bytes * 2,
        stream_window     => $rx_bytes * 2,
    );

    my $explicit_bytes = 0;
    my $explicit_chunks = 0;
    $start = time;

    while (my $event = $explicit->next_data_chunk) {
        my $len = length($event->[0]);
        $explicit_bytes += $len;
        ++$explicit_chunks;
        $explicit->consume($len);
    }

    my $explicit_elapsed = time - $start;

    die "explicit RX byte count mismatch\n"
        if $explicit_bytes != $rx_bytes;

    print join(
        ' ',
        'RX',
        'mode=next_data_chunk_consume',
        "bytes=$explicit_bytes",
        "chunks=$explicit_chunks",
        'seconds=' . sprintf('%.6f', $explicit_elapsed),
        'chunks_per_sec=' . fmt_rate(
            rate($explicit_chunks, $explicit_elapsed)
        ),
        'mb_per_sec=' . sprintf(
            '%.2f',
            rate($explicit_bytes, $explicit_elapsed) / (1024 * 1024),
        ),
        'relative_to_next_data=' . sprintf(
            '%.3f',
            $ordinary_elapsed / $explicit_elapsed,
        ),
    ), "\n";
}

print "Net::QUIC protocol-engine benchmark\n";
print "perl=$] pid=$$\n";
print "lookup_iterations=$lookup_iterations\n";
print "tx_iterations=$tx_iterations tx_chunk_size=$tx_chunk_size\n";
print "rx_bytes=$rx_bytes\n";

benchmark_lookup(100, 4510, 4110);
benchmark_lookup(1000, 4511, 4111);
benchmark_lookup(5000, 4512, 4112);
benchmark_tx(4513, 4113);
benchmark_rx(4514, 4114);
