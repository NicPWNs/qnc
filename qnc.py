#!/usr/bin/env python3
"""
Basic Netcat-like Utility Using QUIC
"""


import ssl
import sys
import asyncio
import datetime
import tempfile
from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class SimpleQuicProtocol(QuicConnectionProtocol):
    """Basic QUIC implementation"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stream_id = None

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            # Print received data
            print(event.data.decode("utf-8", errors="replace"), end="")

    async def send_stdin(self):
        # Get or create stream
        if self.stream_id is None:
            self.stream_id = self._quic.get_next_available_stream_id()

        # Read from stdin and send
        while True:
            try:
                line = await asyncio.get_event_loop().run_in_executor(
                    None, sys.stdin.readline
                )
                if not line:
                    break
                self._quic.send_stream_data(self.stream_id, line.encode("utf-8"))
                self.transmit()
            except:
                break


def generate_temp_cert():
    """Generate a temporary self-signed certificate"""

    # Generate key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Create certificate
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )

    # Save to temp files
    cert_file = tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".crt")
    key_file = tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".key")

    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    cert_file.close()
    key_file.close()
    return cert_file.name, key_file.name


async def server_mode(host, port):
    config = QuicConfiguration(alpn_protocols=["simple"], is_client=False)

    # Generate temporary certificate
    cert_file, key_file = generate_temp_cert()
    config.load_cert_chain(cert_file, key_file)

    def create_protocol(*args, **kwargs):
        protocol = SimpleQuicProtocol(*args, **kwargs)
        asyncio.create_task(protocol.send_stdin())
        return protocol

    server = await serve(
        host, port, configuration=config, create_protocol=create_protocol
    )
    print(f"Listening on {host}:{port}")
    await asyncio.Future()  # Run forever


async def client_mode(host, port):
    config = QuicConfiguration(alpn_protocols=["simple"], is_client=True)
    config.verify_mode = ssl.CERT_NONE  # Skip certificate verification

    async with connect(
        host, port, configuration=config, create_protocol=SimpleQuicProtocol
    ) as protocol:
        await protocol.send_stdin()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: qnc [-l] [<host>] <port>")
        sys.exit(1)

    if sys.argv[1] == "-l":
        # Default host to 127.0.0.1 if not specified
        if len(sys.argv) == 4:
            host, port = sys.argv[2], int(sys.argv[3])
        elif len(sys.argv) == 3:
            host, port = "127.0.0.1", int(sys.argv[2])
        else:
            print("Usage: qnc -l [<host>] <port>")
            sys.exit(1)
        asyncio.run(server_mode(host, port))
    else:
        host, port = sys.argv[1], int(sys.argv[2])
        asyncio.run(client_mode(host, port))
