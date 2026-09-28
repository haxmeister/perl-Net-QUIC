use strict;
use warnings;

use FindBin ();
use Socket qw(inet_aton pack_sockaddr_in);
use Test2::V0;
use Time::HiRes qw(sleep);

use Net::QUIC::Endpoint;

my $server_local = pack_sockaddr_in(4438, inet_aton('127.0.0.1'));
my $client_local = pack_sockaddr_in(40007, inet_aton('127.0.0.1'));
my $alpn = 'net-quic-certificate-verification-test';
my $cert_file = "$FindBin::Bin/data/server-cert.pem";
my $key_file = "$FindBin::Bin/data/server-key.pem";

like(
    dies {
        Net::QUIC::Endpoint->client(
            local => $client_local,
            peer  => $server_local,
            alpn  => $alpn,
        );
    },
    qr/missing required server_name argument/,
    'verified client requires a server name',
);

like(
    dies {
        Net::QUIC::Endpoint->client(
            local       => $client_local,
            peer        => $server_local,
            alpn        => $alpn,
            server_name => 'localhost',
            ca_file     => "$FindBin::Bin/data/does-not-exist.pem",
        );
    },
    qr/unable to load client CA file/,
    'bad CA file is rejected during client construction',
);

sub run_handshake {
    my (%args) = @_;

    my $server = Net::QUIC::Endpoint->server(
        alpn             => $alpn,
        certificate_file => $cert_file,
        private_key_file => $key_file,
    );

    my %client_args = (
        local       => $client_local,
        peer        => $server_local,
        alpn        => $alpn,
        server_name => $args{server_name},
    );
    $client_args{ca_file} = $args{ca_file}
        if defined $args{ca_file};

    my $client = Net::QUIC::Endpoint->client(%client_args);
    my $server_connection;
    my $error;

    for (1 .. 300) {
        while (my $datagram = $client->next_datagram) {
            my $ok = eval {
                $server->receive_datagram(
                    $datagram->data,
                    $server_local,
                    $client_local,
                );
                1;
            };
            if (!$ok) {
                $error = $@;
                last;
            }
        }
        last if defined $error;

        $server_connection ||= $server->next_connection;

        while (my $datagram = $server->next_datagram) {
            my $ok = eval {
                $client->receive_datagram(
                    $datagram->data,
                    $client_local,
                    $server_local,
                );
                1;
            };
            if (!$ok) {
                $error = $@;
                last;
            }
        }
        last if defined $error;

        return ($client, $server_connection, undef)
            if $server_connection
            && $client->connection->ready
            && $server_connection->ready;

        my $server_after = $server->timeout_after;
        my $client_after = $client->timeout_after;

        if (defined($server_after) && $server_after <= 0) {
            $server->handle_timeout;
            next;
        }
        if (defined($client_after) && $client_after <= 0) {
            $client->handle_timeout;
            next;
        }

        my @wait = sort { $a <=> $b }
            grep { defined($_) && $_ > 0 }
            ($server_after, $client_after);

        if (@wait) {
            my $nap = $wait[0] > 0.01 ? 0.01 : $wait[0] + 0.001;
            sleep($nap);
        }
    }

    return ($client, $server_connection, $error);
}

my ($trusted_client, $trusted_server, $trusted_error) = run_handshake(
    server_name => 'localhost',
    ca_file     => $cert_file,
);

ok(!defined($trusted_error), 'trusted localhost certificate is accepted');
ok($trusted_client->connection->ready, 'verified client handshake completes');
ok($trusted_server && $trusted_server->ready, 'server completes verified handshake');

my ($untrusted_client, undef, $untrusted_error) = run_handshake(
    server_name => 'localhost',
);

ok(defined($untrusted_error), 'self-signed certificate is rejected without trust anchor');
ok(!$untrusted_client->connection->ready, 'untrusted client never becomes ready');

my ($wrong_name_client, undef, $wrong_name_error) = run_handshake(
    server_name => 'not-localhost.example',
    ca_file     => $cert_file,
);

ok(defined($wrong_name_error), 'certificate with wrong host name is rejected');
ok(!$wrong_name_client->connection->ready, 'wrong-name client never becomes ready');

done_testing;
