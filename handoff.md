# Net::QUIC handoff

## Current branch

feature/client-endpoint

Base branch:

feature/initial-native-core

Current implementation head before this handoff update:

ab964def0742c745b71671f4daf63ddfd2245ec7

## Purpose

Net::QUIC is the public Perl QUIC transport distribution built on ngtcp2.

The native dependency is supplied by Alien::ngtcp2 0.02 or newer.

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
- provider-neutral TLS setup below the Perl API
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

GitHub Actions run 36366552646 passed all 15 jobs after the
Endpoint/Connection split:

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

Net::QUIC consumes the provider selected by Alien::ngtcp2.

Normal users must not receive backend-specific Perl objects.

Private native setup currently covers the provider families selected by
Alien::ngtcp2:

- OpenSSL
- GnuTLS
- BoringSSL
- wolfSSL
- Picotls

Keep provider-specific details below the Perl API.

## Native dependency detail

Alien::ngtcp2 0.02 supplies libngtcp2 and one usable TLS helper.

Alien::ngtcp2 can return absolute static archive filenames in crypto_libs.
ExtUtils::MakeMaker filters bare archive filenames out of LIBS, so Net::QUIC
translates those filenames to equivalent -L and -l flags before passing them
to MakeMaker.

CI still bootstraps Alien::ngtcp2 from the released v0.020 GitHub tag because
that was required while CPAN indexing lagged immediately after release.

## Next useful work

The event-loop boundary itself is now implemented and tested.

Next work should build upward from this without changing that boundary:

1. Add a private server-side Connection constructor used only by tests.
2. Exchange client and server datagrams entirely in memory and complete a real
   QUIC/TLS handshake, proving receive_datagram as well as packet generation.
3. Add stream callbacks/state needed for incoming and outgoing QUIC streams.
4. Design the public server Endpoint around CID routing and multiple Connection
   objects after the low-level server connection path is proven.
5. Write a small Linux::Event adapter as the first framework integration
   example after the raw contract is stable.
6. Keep HTTP/3 out of this transport layer for now.

## Repository hygiene

handoff.md is a development file and must not be included in a CPAN
distribution.
