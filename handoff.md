# Net::QUIC handoff

## Current branch

feature/handshake-proof

Baseline before the Picotls-only cleanup:

e4218ca85faf2e6e5fdffcaa7516b7db3c362efa

## Purpose

Net::QUIC is the public Perl QUIC transport distribution built on ngtcp2.

The native dependency is supplied by Alien::ngtcp2 0.03 or newer.

Net::QUIC is intentionally event-loop neutral.

## Fixed event-loop boundary

Net::QUIC owns:

- QUIC connection state
- TLS state and handshake integration
- packet parsing and packet generation
- connection IDs
- QUIC expiry calculations
- future stream state

The integration layer owns:

- the UDP socket
- readable and writable readiness
- receiving and sending UDP datagrams
- one timer
- the surrounding event loop

The public object split is now:

    Net::QUIC::Endpoint
        |
        +-- Net::QUIC::Connection

Endpoint is the UDP/event-loop boundary. Connection is one QUIC connection and
is where application-facing connection and stream behavior belongs.

The integration contract is now concrete:

    $endpoint->receive_datagram($bytes, $local, $peer);

    while (my $datagram = $endpoint->next_datagram) {
        # send $datagram->data to $datagram->peer
    }

    my $seconds = $endpoint->timeout_after;

    $endpoint->handle_timeout;

After receive_datagram or handle_timeout, the adapter drains next_datagram and
then rearms its timer from timeout_after.

This is the intended boundary for Linux::Event, IO::Async, EV, AnyEvent, and
other event systems.

## Current public/native slice

Development version:

0.001_002

The branch now contains:

- Net::QUIC::Endpoint
- Net::QUIC::Connection
- Net::QUIC::Datagram
- a native client QUIC connection using ngtcp2
- a private test-only native server QUIC connection
- one Picotls TLS implementation below the Perl API
- a real in-memory client/server QUIC/TLS handshake proof
- receive_datagram
- next_datagram
- timeout_after
- handle_timeout
- ready
- real QUIC Initial packet generation
- packed IPv4/IPv6 local and peer path handling

A client endpoint is created with:

    my $endpoint = Net::QUIC::Endpoint->client(
        local       => $packed_local_address,
        peer        => $packed_peer_address,
        alpn        => 'my-protocol',
        server_name => 'example.com',
    );

    my $connection = $endpoint->connection;

The UDP socket is still owned by the event-loop integration.

## CI baseline

GitHub Actions run 36404934969 passed all 15 jobs on handshake-proof
source commit 11211aedb5228f9c109960e35c01ee66e4d18a57:

- Linux Perl 5.20
- Linux Perl 5.22
- Linux Perl 5.24
- Linux Perl 5.26
- Linux Perl 5.28
- Linux Perl 5.30
- Linux Perl 5.32
- Linux Perl 5.34
- Linux Perl 5.36
- Linux Perl 5.38
- Linux Perl 5.40
- Linux Perl 5.42
- Linux Perl 5.44
- macOS Perl 5.44
- Windows Perl 5.44

The endpoint test creates a real native client and requires ngtcp2 to produce a
real QUIC Initial datagram of at least 1200 bytes.

The handshake test creates a real client and a private test-only server, loads a
test certificate and private key, exchanges QUIC datagrams entirely in memory,
and requires both sides to complete the QUIC/TLS handshake. On Windows the
final run reports t/03-handshake.t as successful and finishes teardown normally.

## Windows portability findings

Several Windows runtime-boundary issues were found and fixed.

First, the MinGW compiler used by the Windows Perl build defines WIN32. The
native monotonic-clock selection now recognizes WIN32 as well as _WIN32.

Second, raw C allocation from the XS DLL is unsafe for Net::QUIC-owned memory on
the threaded Windows Perl configuration because Perl uses its own runtime
allocation boundary. Net::QUIC-owned memory therefore uses Perl allocation:

- Newx / Newxz
- Safefree

This includes the Connection object, copied strings, and Picotls extension
storage.

Picotls itself allocates its loaded certificate buffers with the C runtime.
Those buffers must not be released with Safefree. Net::QUIC keeps a small
system-free helper defined before the Perl headers and uses it only for memory
owned by Picotls.

Windows Perl also uses PERL_IMPLICIT_SYS and redirects stdio calls. The private
server key loader originally used fopen after perl.h; the key file existed but
that redirected fopen could not open it for the OpenSSL PEM reader. Net::QUIC
now keeps system fopen/fclose helpers defined before the Perl headers and uses
those handles for the server private key.

Keep the ownership boundary explicit: Perl allocators for Net::QUIC-owned
memory, and the real C runtime for memory or FILE handles that belong to the
native Picotls/OpenSSL side.

## TLS provider rule

Net::QUIC has one TLS implementation: Picotls.

Alien::ngtcp2 0.03 supplies the tested ngtcp2/Picotls pair. Picotls handles
TLS 1.3 and uses the host OpenSSL installation underneath for cryptography and
X.509 certificate support.

Normal users do not choose a TLS backend. Net::QUIC::crypto_backend remains as
a diagnostic and reports picotls.

Do not restore separate OpenSSL, GnuTLS, BoringSSL, or wolfSSL QUIC TLS paths
unless the project direction is explicitly changed.

## Native dependency detail

Alien::ngtcp2 0.03 supplies libngtcp2, libngtcp2_crypto_picotls, the pinned
Picotls build, and the flags needed to use them.

Alien::ngtcp2 can return absolute static archive filenames in crypto_libs.
ExtUtils::MakeMaker filters bare archive filenames out of LIBS, so Net::QUIC
translates those filenames to equivalent -L and -l flags before passing them
to MakeMaker.

CI now installs Alien::ngtcp2 0.03 from CPAN. The broad Linux Perl matrix
from 5.20 through 5.44 remains intact, along with macOS and Windows coverage.

## Next useful work

The event-loop boundary is implemented and tested.

The Picotls-only client path and the private in-memory client/server handshake
proof are green across the full 15-job CI matrix.

The private _server_new constructor is only a development proof. Do not turn it
into the public server API directly.

Next:

1. Add the stream callbacks and state needed for incoming and outgoing QUIC
   streams.
2. Design the public server Endpoint around CID routing and multiple Connection
   objects, keeping the private proof constructor private.
3. Write a small Linux::Event adapter as the first framework integration
   example after the raw contract is stable.
4. Keep HTTP/3 out of this transport layer for now.

Certificate verification is still future work. The current client proof does
not configure production server-certificate verification, so the self-signed
test certificate is only evidence that the QUIC/TLS handshake machinery works.

## Repository hygiene

handoff.md is a development file and must not be included in a CPAN
distribution.
