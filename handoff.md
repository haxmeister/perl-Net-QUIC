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
- one Picotls TLS implementation below the Perl API
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

GitHub Actions run 36372489259 passed all 15 jobs after the Picotls-only
cleanup and CPAN switch to Alien::ngtcp2 0.03:

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

## Windows portability findings

Two real Windows issues were found and fixed.

First, the MinGW compiler used by the Windows Perl build defines WIN32. The
native monotonic-clock selection now recognizes WIN32 as well as _WIN32.

Second, raw C allocation from the XS DLL was unsafe on the threaded Windows
Perl configuration because Perl uses its own runtime allocation boundary.
Net::QUIC-owned memory now uses Perl allocation:

- Newx / Newxz
- Safefree

This includes the endpoint object, copied strings, and Picotls extension
storage.

Do not reintroduce malloc, calloc, or free for memory owned by the XS extension
without first considering the Windows Perl allocator boundary.

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

The event-loop boundary itself is implemented and tested.

The Picotls-only client baseline is green across all 15 CI jobs.

The next change on this branch adds a private server-side Connection
constructor used only by tests. It inspects the client's real Initial packet,
creates ngtcp2 server state with the correct CID roles, configures a Picotls
server session, and uses test-only certificate files.

The new handshake test exchanges generated datagrams between client and server
entirely in memory through the existing receive/write/timer methods. CI for
that handshake proof is the current gate.

After that proof is green:

1. Keep the private server constructor private while the public server Endpoint
   routing design is built.
2. Add stream callbacks/state needed for incoming and outgoing QUIC streams.
3. Design the public server Endpoint around CID routing and multiple Connection
   objects after the low-level server connection path is proven.
4. Write a small Linux::Event adapter as the first framework integration
   example after the raw contract is stable.
5. Keep HTTP/3 out of this transport layer for now.

## Repository hygiene

handoff.md is a development file and must not be included in a CPAN
distribution.
