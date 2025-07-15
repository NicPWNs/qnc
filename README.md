# qnc

A basic Netcat-like utility using [QUIC](https://datatracker.ietf.org/doc/html/rfc9000).

## Usage

```bash
./qnc [-l] [<host>] [<port>]
```

### Server Mode

> To start a server (listener) on port 12345:

```bash
./qnc -l 12345
```

or specify a host:

```bash
./qnc -l 127.0.0.1 12345
```

### Client

> To connect as a client:

```bash
./qnc <host> [<port>]
```

## Features

- Temporary self-signed certificate generation
- Simple stdin/stdout forwarding

## References

- Inspired by content and labs in [SANS SEC530](https://www.sans.org/cyber-security-courses/defensible-security-architecture-and-engineering/)
- QUIC transport using [aioquic](https://github.com/aiortc/aioquic)
