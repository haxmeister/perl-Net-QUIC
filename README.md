# Net::QUIC

Net::QUIC is a QUIC transport library for Perl built on ngtcp2.

This repository is in early development.

## Design boundary

Net::QUIC owns QUIC and TLS protocol state.

It does not own an event loop. It does not require Linux::Event, IO::Async, or
another particular networking framework.

An integration layer will own:

- UDP sockets
- readable/writable readiness
- timers
- feeding received datagrams into Net::QUIC
- sending datagrams produced by Net::QUIC

This keeps the QUIC implementation reusable.

## Native dependency

Net::QUIC uses Alien::ngtcp2 0.02 or newer.

Alien::ngtcp2 supplies:

- libngtcp2
- one compatible ngtcp2 TLS helper

The TLS helper is selected to fit the host system. Normal Net::QUIC users
should not need to choose OpenSSL, GnuTLS, Picotls, or another backend.

## Current development step

The first XS layer proves that Net::QUIC can:

- compile against libngtcp2
- link against the selected ngtcp2 TLS helper
- report the linked ngtcp2 version
- report the selected TLS backend for diagnostics
- execute a small crypto helper self-test

The connection and stream API comes next.

## Development

    perl Makefile.PL
    make
    make test

## License

Net::QUIC is MIT licensed.
