# Net::QUIC protocol-engine transport API plan

This file records the implementation plan for making Net::QUIC precise enough
to serve as a transport beneath advanced protocol engines such as an HTTP/3
implementation.

It is a development note, not public distribution documentation. Net::QUIC
must remain protocol-neutral. No HTTP/3, QPACK, nghttp3, request, response, or
header semantics belong here.

## Existing application API stays unchanged

Ordinary users should continue to use:

```perl
my $stream = $connection->open_bidi_stream;

$stream->send("hello");
$stream->finish;

while (defined(my $bytes = $stream->next_data)) {
    ...
}
```

Ordinary callers must not need to manage offsets, ACKs, native buffers, or
receive flow-control credit.

## Implementation status

Implemented on `feature/protocol-engine-api`:

- explicit receive delivery with `next_data_chunk`;
- explicit receive credit with `consume`;
- receive-mode protection so `next_data` and explicit consumption cannot be
  mixed accidentally;
- monotonic contiguous transmit acknowledgement visibility with
  `acked_offset`;
- opt-in coalesced Stream activity with `on_stream_activity` and
  `next_active_stream_id`;
- connection-wide retained-TX limits with `send_buffer_limit`;
- partial bounded writes with `send_some`;
- O(1) per-Stream and per-Connection retained-TX byte accounting;
- RX credit restoration when a closed Stream with unconsumed delivered data is
  abandoned;
- focused QUIC v2 coverage for the advanced protocol-engine path.

Exact FIN acknowledgement is deliberately not public yet. The ngtcp2 byte-ACK
callback precisely exposes contiguous acknowledged byte progress but does not
identify every data-plus-FIN acknowledgement in a form that Net::QUIC can
safely promise as an exact standalone `fin_acked` event. The current
protocol-engine use case needs acknowledged byte progress, so exposing an
imprecise FIN acknowledgement flag would add risk without adding a required
capability.

Performance validation found that the original linked-list Stream lookup did
not scale acceptably, while the advanced RX/TX interfaces were already fast
enough to avoid a more invasive native-consumer redesign.

A native Stream-ID hash index is therefore part of this implementation.

## Performance validation

Measured on GitHub Actions `ubuntu-latest` with Perl 5.44. These numbers are
for regression and architectural comparison, not absolute hardware claims.

Before the Stream-ID index:

```text
100 streams, last:   1,683,810 lookups/s
1000 streams, last:    173,626 lookups/s
5000 streams, last:     24,065 lookups/s
```

After the Stream-ID index:

```text
100 streams, last:   4,652,067 lookups/s
1000 streams, last:  4,743,400 lookups/s
5000 streams, last:  4,734,619 lookups/s
```

The 5000-Stream worst case improved by roughly 197x and lookup throughput is
now effectively independent of Stream position.

The post-index advanced data-path measurements were:

```text
send:                    826.16 MiB/s
send_some:              1064.27 MiB/s
next_data:               922.81 MiB/s
next_data_chunk+consume: 672.72 MiB/s
```

Explicit receive is slower because it returns both bytes and FIN state and
performs a separate explicit credit call. It still exceeded 670 MiB/s in this
benchmark. That does not justify adding a native zero-copy receive consumer at
this stage. Revisit only if a real upper-layer benchmark shows this copy/API
cost is material.

The repeatable benchmark is kept under:

```text
xt/benchmark/protocol_engine.pl
```

The GitHub benchmark workflow is manual-only so ordinary pushes do not spend
CI time on performance measurement.

## Required advanced capabilities

### 1. Explicit receive consumption

Advanced engines need to separate byte delivery from QUIC receive
flow-control consumption.

The intended model is:

```text
QUIC receives N bytes
    -> Net::QUIC delivers those bytes once
    -> protocol reports how many bytes are currently consumed
    -> Net::QUIC returns only that amount of receive credit
    -> protocol may report additional deferred consumption later
```

Initial public shape:

```perl
my ($bytes, $fin) = $stream->next_data_chunk;
$stream->consume($n);
```

Properties:

- `next_data_chunk` removes one receive chunk from the Net::QUIC RX queue
  without automatically extending QUIC receive credit.
- `consume($n)` returns exactly `$n` bytes of stream and connection credit.
- Partial consumption is allowed.
- Zero-byte consumption is valid.
- FIN remains visible even when received with data.
- Deferred consumption may happen after the original chunk was delivered.
- Advanced and ordinary receive modes must not be mixed on one stream.
- Existing `next_data` retains its current all-at-once consume semantics.

Initial implementation may copy a native RX chunk into a Perl scalar. A later
native consumer optimization is optional and must be justified by benchmarks.

### 2. Transmit acknowledgement visibility

Net::QUIC already receives ordered, non-overlapping ngtcp2 stream ACK progress
and tracks a contiguous native high-water mark.

Public shape:

```perl
my $offset = $stream->acked_offset;
```

`acked_offset` is a monotonic contiguous byte offset.

Do not expose `fin_acked` until Net::QUIC can represent it exactly for both a
standalone zero-length FIN and a STREAM frame carrying data and FIN together.
The current protocol-engine interface does not require a separate FIN-ACK
signal.

No ordinary Stream user is required to inspect ACK state.

### 3. Stream activity notification

A protocol engine must not scan all streams after each UDP packet.

Use a coalesced dirty-stream queue. Activity tracking should be opt-in.

Initial conceptual API:

```perl
$connection->on_stream_activity(sub {
    service_protocol($connection);
});

while (defined(my $id = $connection->next_active_stream_id)) {
    ...
}
```

Queue a stream ID when meaningful state changes, including:

- new peer stream;
- received data;
- received FIN;
- transmit ACK progress;
- RESET_STREAM;
- STOP_SENDING;
- stream close.

Multiple changes to one stream may coalesce into one pending activity record.
The callback is a wake-up signal, not one callback per transport event.

Existing `next_stream` remains the way to obtain peer-created Stream objects.
Existing `on_stream_available` remains the notification that the peer has
granted credit to open additional local streams.

### 4. Bounded transmit buffering

Current `send` copies all supplied bytes into Net::QUIC-owned native chunks
and can therefore queue unbounded memory.

Keep `send` unchanged for the friendly API. Add a separate bounded producer
path.

Initial conceptual API:

```perl
$connection->send_buffer_limit(4 * 1024 * 1024);

my $accepted = $stream->send_some($bytes);
```

Requirements:

- `send_some` returns the number of accepted prefix bytes.
- Accepted bytes are copied into Net::QUIC-owned memory.
- The caller may release its input after return.
- A connection-wide limit bounds total retained stream TX memory.
- Retained memory includes queued data and sent-but-not-yet-acknowledged data.
- ACK, reset, STOP_SENDING, and stream close must release accounting correctly.
- Producer resume is signalled without busy polling, using stream activity.
- QUIC stream flow control, connection flow control, and congestion control
  remain ngtcp2 responsibilities.

Add O(1) byte counters rather than using the existing diagnostic routine that
walks all TX chunks.

Likely introspection:

```perl
$stream->send_buffered_bytes;
$connection->send_buffered_bytes;
```

## Native state already available

Current native stream state already contains important pieces:

```text
rx_next_offset
tx_next_offset
tx_acked_through
fin_acked
RX chunk queue
TX chunk queue
remote_finished
remote_reset
remote_stop_sending
closed
```

Current `net_quic_stream_consume_rx` combines two operations that the
advanced receive API needs separated:

```text
remove RX chunk
+
extend stream receive credit
+
extend connection receive credit
```

Current `net_quic_acked_stream_data_offset_cb` already advances contiguous
ACK state and `net_quic_stream_release_acked` releases acknowledged native TX
chunks.

## Implementation order

### Phase 1 - receive accounting

1. Split native RX queue removal from receive-credit extension.
2. Preserve current `next_data` behavior exactly.
3. Add per-stream delivered-but-not-consumed accounting.
4. Add receive-mode protection so ordinary and advanced APIs cannot be mixed.
5. Expose `next_data_chunk` and `consume`.
6. Test partial, zero, deferred, FIN, reset, stop-sending, and regression cases.

### Phase 2 - ACK visibility

1. Expose monotonic `acked_offset`.
2. Test monotonic progress and final acknowledged byte length.
3. Keep exact FIN acknowledgement private until the underlying event can be
   represented without inference.

### Phase 3 - activity queue

1. Add opt-in native coalesced stream activity tracking.
2. Add `on_stream_activity` wake-up callback.
3. Add `next_active_stream_id`.
4. Generate activity for RX, FIN, ACK, reset, STOP_SENDING, close, and new
   remote streams.
5. Test multiple simultaneous active streams and event coalescing.

### Phase 4 - bounded TX

1. Add connection-wide and per-stream O(1) retained-TX byte accounting.
2. Add configurable connection send-buffer limit.
3. Add `send_some` partial acceptance.
4. Release accounting on ACK and all abort/close paths.
5. Signal producers when capacity becomes available again.
6. Test bounded memory behavior, pause/resume, flow-control blocking, congestion
   blocking, reset, STOP_SENDING, close, and many streams.

### Phase 5 - validation

1. Run the complete existing test suite.
2. Verify QUIC v1 and v2 behavior remains unchanged.
3. Verify Driver behavior remains unchanged.
4. Benchmark advanced RX/TX paths.
5. Measure stream-ID lookup cost under HTTP/3-like stream counts.
6. Consider a native consumer or faster stream index only if measurements
   justify it.

## Compatibility rules

- Do not remove or change ordinary Stream semantics.
- Do not expose ngtcp2 objects directly.
- Do not make Net::QUIC depend on Linux::Event.
- Do not add protocol-specific stream categories.
- Do not make protocol-engine callbacks closure-heavy in the hot path.
- Correctness comes before zero-copy optimization.
