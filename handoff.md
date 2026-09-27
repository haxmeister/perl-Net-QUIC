# Net::QUIC handoff

## Current branch

feature/initial-native-core

Base branch:

main

Initial main commit before implementation:

8c61ed16e1413365a76993111f47e8f9c199e256

## Purpose

Net::QUIC is the public Perl QUIC transport distribution built on ngtcp2.

The native dependency is supplied by Alien::ngtcp2 0.02 or newer.

## Fixed architecture boundary

Net::QUIC is event-loop neutral.

Net::QUIC owns:

- QUIC connection state
- TLS handshake integration
- streams
- packet generation and processing
- QUIC timers and expiry calculations

The caller or an integration layer owns:

- UDP sockets
- socket readiness
- receiving and sending UDP datagrams
- arranging timer callbacks
- the surrounding event loop

Linux::Event, IO::Async, PAGI, and other systems should be able to integrate
without Net::QUIC depending on any of them.

## TLS provider rule

Net::QUIC consumes the provider selected by Alien::ngtcp2.

Normal users must not receive backend-specific Perl objects.

Alien::ngtcp2 currently selects one of:

- openssl
- gnutls
- boringssl
- wolfssl
- picotls

The XS build uses the common ngtcp2 and ngtcp2_crypto APIs. Backend-specific
details should stay below the public Perl API.

## Initial implementation slice

The first slice intentionally does not define the connection API yet.

It establishes:

- Makefile.PL using Alien::ngtcp2 0.02
- XS linkage to libngtcp2
- XS linkage to the selected crypto helper
- ngtcp2_version
- ngtcp2_version_num
- crypto_backend diagnostic
- a crypto helper self-test
- basic tests
- CI
- basic documentation

Development version:

0.001_001

## Important upstream baseline

Alien::ngtcp2 0.02 requires system libngtcp2 1.25.0 or newer and bundles
ngtcp2 1.25.0 when it must build its own copy.

The initial Net::QUIC work should therefore use the ngtcp2 1.25.0 public API
as its minimum baseline.

## Next design work

Before adding a large XS wrapper, define the smallest useful Perl-facing
connection contract.

The next questions should center on:

1. How a caller creates client and server connection state.
2. How a received UDP datagram is fed into a connection.
3. How outbound datagrams are returned to the caller.
4. How Net::QUIC exposes the next expiry time.
5. How stream-open, stream-data, stream-close, and connection-close events
   reach Perl.
6. How writes are queued without tying the library to a particular event
   loop.
7. Which operations stay in XS to avoid unnecessary buffer copies and Perl
   callback overhead.

Do not add HTTP/3 behavior to the first QUIC transport layer while this API is
being defined.

## Repository hygiene

handoff.md is a development file and must not be included in a CPAN
distribution.
