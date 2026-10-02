# Missing QUIC Features

This document tracks canonical QUIC capabilities that Net::QUIC does not yet
implement or expose as supported public features.

It separates gaps in the base QUIC/TLS transport from standardized extensions
and from lower-level capabilities that ngtcp2 may already provide internally
but Net::QUIC does not yet expose.

## Base QUIC and TLS features not yet implemented

### TLS client-certificate authentication

The client verifies the server certificate today.

The server cannot currently request and validate a client certificate for
mutual TLS authentication.

## Base QUIC operations not yet exposed cleanly

### Application PING / keepalive

Net::QUIC does not expose an application-level way to request a QUIC PING or a
keepalive policy for deliberately preventing an otherwise idle connection from
timing out.

### Application-initiated key update

The required TLS/ngtcp2 key-update callback is already wired, so key update
support is not absent at the protocol level.

Net::QUIC does not currently expose a public operation for deliberately
initiating a new 1-RTT key phase.

### Connection-close reason text

Application connection close supports an error code, but Net::QUIC does not
currently expose the optional human-readable reason phrase carried by a QUIC
CONNECTION_CLOSE frame.

### Connection ID policy

Connection IDs are currently managed internally.

Net::QUIC does not expose deployment-specific CID policy such as:

- zero-length connection IDs
- custom connection ID generation
- custom CID lengths
- custom rotation policy

## Standardized QUIC extensions not yet implemented

### QUIC DATAGRAM

Net::QUIC does not implement the standardized QUIC DATAGRAM extension for
unreliable, unordered application datagrams carried inside a QUIC connection.

This is distinct from Net::QUIC::Datagram, which represents the UDP packets
that carry QUIC itself.

### QUIC bit greasing

Net::QUIC does not currently expose or deliberately configure QUIC-bit
greasing behavior.

### qlog

Net::QUIC does not expose ngtcp2 qlog events or provide a qlog output API.

This is an observability feature rather than an application transport feature,
but it is a common part of mature QUIC implementations.

### Congestion-controller selection and tuning

Congestion control is already present through ngtcp2.

Net::QUIC does not currently expose controller selection or lower-level
congestion-control tuning such as controller choice, initial RTT policy, or
other advanced recovery knobs.

## Highest-priority remaining transport features

The largest remaining feature groups are:

1. QUIC DATAGRAM
2. qlog and advanced congestion-control configuration

## Already implemented

The following should not be treated as missing:

- QUIC v1 transport
- server acceptance of negotiated QUIC versions
- Version Negotiation responses
- direct QUIC v2 client/server transport
- RFC 9368 Compatible Version Negotiation for QUIC v1 and v2
- client first-flight version selection and server compatible-version preference
- negotiated/client-chosen version introspection
- version-scoped session tickets, NEW_TOKEN, and 0-RTT state
- TLS 1.3
- TLS session resumption
- opaque client session ticket save/reuse with full-handshake fallback
- 0-RTT / early data
- opaque client early-data state containing TLS and QUIC resumption state
- explicit server early-data opt-in
- 0-RTT rejection rollback
- per-server 0-RTT replay protection
- active client connection migration
- path validation success/failure/abort reporting
- fallback to the previous validated path after migration failure
- server observation of peer path validation
- server preferred address advertisement and client validation
- preferred-address Connection ID routing
- ALPN
- server certificate verification
- optional private CA files
- bidirectional streams
- unidirectional streams
- concurrent stream limits
- stream-credit replenishment
- connection-level and stream-level flow control
- FIN
- independent RESET_STREAM and STOP_SENDING operations
- directional stream abort error-code reporting
- connection close
- closing and draining periods
- idle timeout
- handshake timeout
- loss recovery
- congestion control
- Retry
- Retry-token address validation
- NEW_TOKEN future-connection address validation
- opaque client address-token save/reuse
- NEW_TOKEN fallback to Retry when the token does not validate the address
- ngtcp2 PMTU discovery on established paths
- PMTU discovery restart after validated path changes
- Connection->path_max_udp_payload_size visibility
- ECN transmit marking through Datagram->ecn
- optional received ECN metadata through Endpoint and Driver
- native ngtcp2 ECN validation and automatic fallback to Not-ECT
- anti-amplification handling through ngtcp2
- connection IDs
- connection ID routing and retirement
- Stateless Reset
- explicit connection error information
- exact local-path handling
- UDP backpressure handling
- event-loop-neutral Driver integration

## Not currently considered part of the initial missing-feature list

Multipath QUIC is intentionally not included in the initial completeness list.

It is a newer extension area rather than part of the original base QUIC
transport feature set and should be evaluated separately after the core
remaining features above.
