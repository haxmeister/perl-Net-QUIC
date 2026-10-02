# Net::QUIC handoff

## Current state

Current branch:

feature/tls-session-resumption

Current main baseline:

fc266928880a6ffa0519954dfc5bc2980131d922

Active draft PR:

- PR #15, "Add TLS session resumption"

PR #5, "Add generic event-loop integration driver", is merged.

Merged Driver checkpoint:

- feature head: 8c830427ae68e97a2d91f7c60be53dca920292c3
- merge commit: 46ef9dba2f7942f9703654aba6c9327b4f1900ca
- GitHub Actions run 36508560351: 15/15 PASS
- Linux Perl 5.20 through 5.44: PASS
- macOS Perl 5.44: PASS
- Windows Perl 5.44: PASS
- 15 test files / 249 tests on Linux Perl 5.44

Net::QUIC::Driver is now the recommended event-loop adapter boundary.

Recommended adapter contract:

    $driver->start;
    $driver->receive($bytes, $local, $peer);
    $driver->timeout;
    $driver->writable;

Adapter callbacks:

    send        => sub { ... }
    set_timeout => sub { ... }

Driver owns Endpoint output draining, UDP backpressure pause/resume state, and
QUIC timeout replacement. Stream send, finish, reset, received-data consumption,
and Connection close automatically notify the Driver when application work can
change QUIC output.

Net::QUIC::Endpoint remains the low-level integration boundary:

    receive_datagram
    next_datagram
    timeout_after
    handle_timeout

No event-loop-specific adapter is part of the distribution. Linux::Event,
IO::Async, AnyEvent, EV, Mojolicious, and other event systems can integrate
above Driver without changing Net::QUIC core.

## Core QUIC completeness roadmap

Net::QUIC 0.01 has the basic QUIC transport in place. The remaining work that
should be treated as core transport completeness is now grouped into five
engineering projects.

Recommended implementation order:

1. Directional stream abort semantics. COMPLETE.
   - Merged in PR #14.
   - Main merge commit: fc266928880a6ffa0519954dfc5bc2980131d922.
   - RESET_STREAM and STOP_SENDING are independent operations.
   - Local and remote error-code state is exposed separately.
   - Final CI matrix: 15/15 PASS.

2. Add TLS session resumption. IN PROGRESS.
   - Active branch: feature/tls-session-resumption.
   - Active draft PR: #15.
   - Save TLS session tickets and enough associated QUIC transport state to
     establish a resumed connection safely.
   - Define how applications opt into or provide resumable session state without
     making the event-loop adapter responsible for TLS policy.
   - Resumption must be complete and independently useful before 0-RTT is added.

3. Add 0-RTT / early data.
   - Build directly on the session-resumption state from project 2.
   - Permit application stream data before handshake completion only when the
     saved TLS and QUIC state allows it.
   - Handle rejection correctly and make the replay risk explicit to the
     application API.
   - Keep 0-RTT application policy above the event-loop-neutral Driver boundary.

4. Add active migration and full path management.
   - Represent and validate alternative network paths.
   - Support path probing, validation success/failure, path switching, and
     active connection migration.
   - Support server preferred-address behavior as part of this path work.
   - Preserve the existing architecture in which the adapter owns UDP sockets
     and Net::QUIC receives exact local/peer addresses.
   - Complete this path layer before adding features whose state is naturally
     per-path, especially PMTU and ECN.

5. Finish the remaining version/path network features.
   - NEW_TOKEN support for future-connection address validation.
   - PMTU discovery and per-path packet-size state.
   - ECN receive/transmit plumbing and validation state.
   - Complete QUIC v2 client selection and compatible version negotiation.
   - These belong last because PMTU and ECN should build on the finished path
     model, while version-selection work is comparatively self-contained and
     can be completed without disturbing the earlier APIs.

Dependency summary:

    directional stream aborts
              |
              +------------------------------+
                                             |
    session resumption -> 0-RTT              |
                                             |
    path management -> PMTU / ECN /          |
                       preferred address      |
                                             |
    version negotiation / NEW_TOKEN ----------+

The practical sequence is therefore:

    Stream abort semantics
        -> Session resumption
        -> 0-RTT
        -> Migration/path management
        -> NEW_TOKEN + PMTU + ECN + complete version negotiation

This order deliberately keeps the tightly coupled TLS work together, completes
the Stream API before adding more connection states, and ensures path-dependent
network features are built on one final path abstraction instead of being
retrofitted later.

Important features that remain valuable but are not required to finish these
five core projects include QUIC DATAGRAM, qlog, application-triggered key
update, client-certificate authentication, application PING/keepalive controls,
custom CID policy, QUIC-bit greasing controls, and advanced congestion-control
selection/tuning.

Keep HTTP/3 outside Net::QUIC transport.

## Branch cleanup status

After merging PR #5, every remaining feature branch was compared against main.
All are zero commits ahead of main and contain no unique unmerged work.

Safe to delete:

- feature/connection-retirement
- feature/fixed-size-transmit-chunks
- feature/integration-driver
- feature/shared-server-tls-context
- feature/stateless-reset
- feature/stream-state-reclamation

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
- stream state

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
                |
                +-- Net::QUIC::Stream

Endpoint is the UDP/event-loop boundary. Connection is one QUIC connection and
Stream is one application-facing QUIC byte stream.

The recommended integration contract is now Net::QUIC::Driver:

    $driver->start;
    $driver->receive($bytes, $local, $peer);
    $driver->timeout;
    $driver->writable;

The adapter provides only:

    send        => sub { ... }
    set_timeout => sub { ... }

Driver owns the repetitive Endpoint service cycle. Endpoint still exposes its
four primitive methods for tests and unusual low-level integrations:

    receive_datagram
    next_datagram
    timeout_after
    handle_timeout

Linux::Event, IO::Async, EV, AnyEvent, and other event systems can all map their
UDP receive, writable/backpressure, and one-shot timer facilities to the same
Driver contract.

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

GitHub Actions run 36499381840 passed all 15 jobs on the stateless-reset
checkpoint c691bf69fd3e01665ca1630472edcb6e37c9069d:

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

The validated suite contains 12 test files and 163 tests.

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

Closed per-stream state reclamation is now implemented. A public Stream object
retains its native record, and the pending incoming-stream queue owns a remote
stream until next_stream hands it to the application. Closed state is freed as
soon as neither owner remains. If the application drops a Stream before QUIC
close, the still-active native state remains until ngtcp2 later closes it and is
then reclaimed automatically.

The remaining stream transmit-memory improvement is now implemented. Large
send calls are stored as fixed 16 KiB native chunks. ngtcp2's ordered stream
ACK callback allows fully acknowledged leading chunks to be freed
independently, while later unacknowledged chunks remain immutable for
retransmission safety.

The public Stream->send API is unchanged and there is no public chunk-size
setting.

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

The stateless server front door now exists on feature/server-front-door.

Implemented:

- unsupported versions receive Version Negotiation without Connection state
- Version Negotiation advertises QUIC v1 and v2
- Endpoint->server(validate_address => 1) enables stateless Retry
- Retry tokens use an Endpoint-local random secret
- Retry tokens are bound to the peer packed socket address
- Retry tokens expire after 10 seconds
- a valid Retry token carries the original destination CID into the eventual
  Connection transport parameters
- the Retry SCID is also recorded in the server transport parameters
- invalid or address-replayed Retry tokens receive a stateless INVALID_TOKEN
  connection close and do not allocate Connection state
- the normal Endpoint receive/send/timer contract is unchanged

Address validation is optional and off by default so applications do not pay an
extra Retry round trip unless they request it.

The remaining server-front-door Stateless Reset item is now implemented on
feature/stateless-reset. Details are recorded below.

Client certificate verification is now implemented on
feature/client-certificate-verification.

Code-bearing checkpoint:

- head: 6476fb503c9b850f1b8a91d1a7bf61081486698e
- GitHub Actions run: 36483994305
- full 15-job matrix: PASS
- 9 test files / 106 tests
- Linux Perl 5.20 through 5.44: PASS
- macOS: PASS
- Windows: PASS

Client TLS behavior now is:

- server_name is required
- certificate verification is enabled by default
- Picotls' OpenSSL verifier validates the certificate chain
- DNS names and IP addresses are checked against server_name
- OpenSSL default trust locations are used
- ca_file optionally adds a PEM trust anchor for private/test CAs
- there is no insecure skip-verification switch
- untrusted certificates fail the handshake
- a trusted certificate for the wrong host name fails the handshake

The existing self-signed localhost fixture is now explicitly trusted by tests
through ca_file. This proves the real verification path rather than bypassing
verification.

Connection retirement and route cleanup are now implemented on
feature/connection-retirement.

Code-bearing checkpoint:

- head: 0efaa8ed974f3b89d804a3d4aa167d406a95be89
- GitHub Actions run: 36495035785
- full 15-job matrix: PASS
- 10 test files / 125 tests
- Linux Perl 5.20 through 5.44: PASS
- macOS: PASS
- Windows: PASS

Lifecycle behavior now is:

- Connection->close($application_error_code) starts a normal QUIC application
  close; the error code defaults to zero
- Connection->closed becomes true only after the connection no longer needs
  QUIC network or timer service
- peer CONNECTION_CLOSE enters draining without being treated as a Perl error
- local closing and peer draining are kept for 3 * PTO, matching ngtcp2's
  server example and QUIC closing semantics
- idle-close and drop-connection outcomes retire immediately
- a server Endpoint removes retired Connections from its owned connection list
- a retired Connection is also removed from the pending accept queue if the
  application never consumed it
- every CID route pointing at the retired Connection is removed together
- replaying an old reset-eligible short-header packet for a retired CID does
  not recreate a Connection and can receive a Stateless Reset
- the close packet reuses the existing per-Connection transmit buffer, so this
  feature does not add a second large packet buffer to every Connection

Shared server TLS credential/context state is now implemented on
feature/shared-server-tls-context.

Code-bearing checkpoint:

- head: b97c2c2bab4e296ba1671daceb140d4b9de945e5
- GitHub Actions run: 36496762568
- full 15-job matrix: PASS
- 11 test files / 136 tests
- Linux Perl 5.20 through 5.44: PASS
- macOS: PASS
- Windows: PASS

Server TLS behavior now is:

- Endpoint->server loads and parses the certificate and private key once
- the Endpoint owns one private native Picotls server credential context
- each accepted Connection creates its own ptls_server_new session from that
  shared context
- Connections retain an independent Perl reference to the shared TLS object,
  so they remain safe even if the caller or Endpoint releases another reference
- the credential files are not reopened or reparsed for each accepted client
- tests delete both credential files immediately after Endpoint construction
  and still complete two independent client handshakes
- invalid certificate or private-key paths fail during Endpoint construction
- no public API change was required

Stateless Reset handling is now implemented on
feature/stateless-reset.

Validated checkpoint:

- head: c691bf69fd3e01665ca1630472edcb6e37c9069d
- draft PR: #2
- GitHub Actions run: 36499381840
- full 15-job matrix: PASS
- 12 test files / 163 tests
- Linux Perl 5.20 through 5.44: PASS
- macOS: PASS
- Windows: PASS

Reset policy:

- the server Endpoint owns one private 32-byte server secret
- the same private secret is used by the existing Retry token machinery and
  the Stateless Reset token derivation helper, matching ngtcp2's server model
- the initial server-selected CID receives a reset token in the server
  transport parameters
- later server-issued CIDs receive deterministically derived reset tokens in
  get_new_connection_id2
- the front door still checks ngtcp2_accept first, so an acceptable Initial can
  create a new Connection instead of being reset
- an unknown short-header packet must be at least server CID length + 21 bytes
  before Net::QUIC will answer with a reset
- packets of 43 bytes or less get a reset one byte shorter than the trigger
- larger reset responses use a bounded random prefix and remain smaller than
  the triggering packet
- unknown long-header packets are dropped
- undersized short-header packets are dropped
- reset generation uses the existing stateless_tx / next_datagram path
- no Connection is allocated to generate a reset
- no public API change was required
- no persistent or user-configurable reset secret was added

Keeping the reset secret Endpoint-private is deliberate for now. It avoids
sharing one reset key across independent Endpoint instances, which would create
additional routing/oracle requirements. A persistent or cluster-shared reset
key can be considered later only if a concrete deployment requires resets to
survive complete Endpoint/process replacement.

Focused tests prove:

- an undersized unknown short-header packet is silently dropped
- an unknown long-header packet is silently dropped
- a sufficiently large unknown short-header packet gets a smaller reset without
  allocating a Connection
- after complete server Connection-state loss while the Endpoint secret remains,
  the client recognizes the derived reset token it was given during handshake
- after normal Connection retirement and CID route cleanup, a replayed eligible
  short-header packet receives a reset without recreating Connection state

Stream state reclamation is now implemented on
feature/stream-state-reclamation.

Code-bearing checkpoint:

- head: 189412c00bd71550f8cdf1ec094ea939fcc2a0ad
- draft PR: #3
- GitHub Actions run: 36501080050
- full 15-job matrix: PASS
- 13 test files / 201 tests
- Linux Perl 5.20 through 5.44: PASS
- macOS: PASS
- Windows: PASS

Lifetime behavior now is:

- every public Net::QUIC::Stream retains the corresponding native stream record
- Stream destruction releases that ownership
- an incoming stream waiting in Connection->next_stream has an independent
  queue hold, so it can close before the application accepts it without losing
  buffered data or final status
- next_stream transfers practical ownership from the queue to the returned
  public Stream object without exposing a gap where the native record can be
  collected
- closed native state is removed from the Connection stream list once no
  Stream object and no incoming queue entry needs it
- transmit round-robin cursor state is repaired when the removed stream was the
  current cursor
- reclamation after ngtcp2 activity happens only after the ngtcp2 call returns,
  avoiding free-from-inside-callback lifetime hazards
- dropping a Stream object before QUIC close leaves active native state intact
  long enough to finish queued transmission and later reclaims it automatically
- the old ID-only t/04 native development proof takes an explicit private
  lifetime hold because it intentionally operates without public Stream objects
- no public API change was required

Focused tests prove:

- closed stream status remains readable while the public Stream exists
- closed native state is reclaimed immediately after the last public Stream is
  released
- a closed incoming stream remains queued until next_stream accepts it
- buffered receive data remains readable after native stream close
- queue ownership transfers safely to the returned Stream object
- a Stream can be released before close without losing queued transmit data
- the later close callback reclaims that unowned native stream automatically
- native stream counts return to zero after ownership is gone

Fixed-size transmit chunking is now implemented on
feature/fixed-size-transmit-chunks.

Code-bearing checkpoint:

- head: 3aa52a3c05742e2df7150c5baf406b8726ff8690
- draft PR: #4
- GitHub Actions run: 36503056226
- full 15-job matrix: PASS
- 14 test files / 220 tests
- Linux Perl 5.20 through 5.44: PASS
- macOS: PASS
- Windows: PASS

Transmit behavior now is:

- Stream->send remains one public call regardless of internal chunking
- each send larger than 16 KiB is copied into a temporary linked list of
  fixed-size chunks plus one smaller final chunk when needed
- that temporary list is attached to the stream only after every allocation
  succeeds, so allocation failure leaves the stream queue unchanged
- each chunk has its own absolute stream offset
- ngtcp2 still receives immutable bytes and keeps them valid until ACK or
  stream close
- acknowledged leading chunks are freed as soon as the ordered ACK callback
  says their complete byte range is safe to release
- later chunks remain buffered and immutable
- finish marks only the final data chunk with FIN when possible; otherwise the
  existing zero-length FIN chunk path is used
- round-robin stream scheduling is unchanged
- no public API change was required

Focused tests prove:

- a 384 KiB+ send is split into 25 chunks
- partial ACK progress releases early chunks while later chunks are still
  buffered
- retained transmit byte count falls before the original send is fully
  acknowledged
- exact payload contents and ordering are preserved
- all data chunks are eventually released while the stream is still open
- FIN still follows the correct final byte offset
- normal stream close still works on both endpoints

Next:

1. Review PR #5 and merge the Driver work only with explicit user approval.
2. If framework adapters are pursued, keep them above the event-loop-neutral
   Driver boundary rather than teaching Net::QUIC core about a specific loop.
3. Do not add adapters to this distribution merely because examples exist;
   placement remains an explicit project decision.
4. Keep HTTP/3 out of this transport layer for now.

## Repository hygiene

handoff.md is a development file and must not be included in a CPAN
distribution.
