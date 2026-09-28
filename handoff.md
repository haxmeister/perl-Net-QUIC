# Net::QUIC handoff

## Current branch

feature/server-front-door

Current main baseline:

1decd967f0a4944232d9790fcf3db58dac8a2eb9

Immediate branch scope:

- add the stateless server front door
- add Retry/address validation for new clients
- add version-negotiation responses
- keep UDP socket ownership outside Net::QUIC
- preserve the existing Endpoint receive/send/timer contract
- do not mix client certificate verification or Connection retirement into this branch unless required by the front-door design

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
- a real private bidirectional stream transport proof
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

GitHub Actions run 36465468171 passed all 15 jobs on stream-proof
source commit b3e82f8ed23317de0e87385d327eab970d9b1c81:

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
and requires both sides to complete the QUIC/TLS handshake.

The stream test then opens a real client-initiated bidirectional QUIC stream,
sends a multi-packet request with FIN, receives it completely on the server, and
sends a response with FIN back on the same stream. The final matrix reports
t/04-stream.t successful on every Linux Perl from 5.20 through 5.44, macOS
5.44, and Windows 5.44.

## Stream transport proof

The current stream methods are deliberately private development methods:

    _open_bidi_stream
    _queue_stream_data
    _take_stream_data

They prove that stream bytes, FIN, receive flow-control credit, and packet
generation work through the existing Endpoint datagram boundary. They are not
the public Net::QUIC::Stream API.

The proof uncovered two transport details that must be preserved.

First, receive offsets are absolute stream offsets. Receive state must remember
the next absolute offset across separate callbacks instead of treating every
callback as a new zero-based buffer.

Second, ngtcp2 packet transmit time must be updated after a drained packet batch,
not after every packet. Endpoint callers already drain next_datagram until it
returns undef. Net::QUIC now marks a transmit batch active while packets are
being returned and calls ngtcp2_conn_update_pkt_tx_time only when the batch is
drained.

The original proof used one send buffer and one receive accumulator per
Connection. That temporary storage has now been replaced by independent native
state for each stream.

The public stream slice now provides:

    $connection->open_bidi_stream
    $connection->open_uni_stream
    $connection->next_stream

and Net::QUIC::Stream provides:

    id
    local_initiated
    bidirectional
    can_send
    can_receive
    send
    finish
    next_data
    remote_finished
    reset
    remote_reset_code
    closed

Transmit buffers are copied into Net::QUIC-owned memory and kept immutable
until ngtcp2 reports acknowledgement or stream close. Receive flow-control
credit is returned when next_data consumes a queued chunk. Pending streams are
selected round-robin when producing packets.

The public stream test covers request/response, concurrent bidirectional
streams, unidirectional stream direction rules, FIN, and reset. The in-memory
tests also honor positive QUIC pacing timeouts, matching the real Endpoint timer
contract instead of relying on CPU timing.

Two stream memory improvements remain before calling this area finished:

- Closed stream state is currently retained until the Connection is destroyed.
  This is safe but should eventually be reclaimed when no Perl Stream object or
  incoming-stream queue entry still needs it.
- One large send call is one immutable transmit allocation, so partially
  acknowledged data cannot release part of that allocation. Fixed-size transmit
  chunks can improve memory release later without changing the public API.

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

The event-loop boundary, Picotls handshake, first public multi-stream API, and
first multi-connection server Endpoint are implemented.

Server Endpoint routing proof:

- branch: feature/server-endpoint
- implementation commit: cdde5a1308114564c1dfe34e179acf5ff2d5094c
- GitHub Actions run: 36466542380
- full 15-job matrix: PASS
- 7 test files / 77 tests on Linux 5.44 and Windows 5.44

The server Endpoint now owns a CID routing table and multiple Connection
objects behind one UDP boundary. New acceptable Initial packets create a
Connection. Server-issued connection IDs are queued from ngtcp2 callbacks and
registered with the Endpoint; retired IDs are removed. Short-header stream
traffic is therefore routed to the correct Connection after the handshake.

The public server-facing shape is:

    Net::QUIC::Endpoint->server(
        alpn             => ...,
        certificate_file => ...,
        private_key_file => ...,
    )

    $endpoint->next_connection

The ordinary Endpoint integration contract does not change:

    receive_datagram
    next_datagram
    timeout_after
    handle_timeout

For a server, next_datagram schedules managed Connections round-robin and
timeout_after returns the earliest Connection timeout.

The private Connection->_server_new constructor remains an implementation
detail behind Endpoint->server.

Server work still needed before calling this production-ready:

- Retry/address validation for new clients
- version-negotiation responses
- automatic retirement/removal of closed Connections and their routes
- one shared server TLS credential/context setup instead of loading the
  certificate and private key separately for every new Connection
- stateless-reset policy for unknown connection IDs

Next:

1. Build the remaining stateless server front door, starting with
   Retry/address validation and version negotiation.
2. Add production client certificate verification before treating the client
   TLS path as production-ready.
3. Add Connection retirement, then reclaim closed per-stream state when no
   public object or incoming queue entry needs it.
4. Consider fixed-size transmit chunks for earlier ACK memory release.
5. Write a small Linux::Event adapter after the raw contract is stable.
6. Keep HTTP/3 out of this transport layer for now.

Certificate verification is still future work. The current client proof does
not configure production server-certificate verification, so the self-signed
test certificate is only evidence that the QUIC/TLS handshake machinery works.

## Repository hygiene

handoff.md is a development file and must not be included in a CPAN
distribution.
