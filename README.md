# qnc

A basic Netcat-like utility using QUIC.

## Usage

```bash
./qnc [-l] [<host>] <port>
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
./qnc <host> <port>
```

## Features

- QUIC transport using [aioquic](https://github.com/aiortc/aioquic)
- Temporary self-signed certificate generation
- Simple stdin/stdout forwarding
