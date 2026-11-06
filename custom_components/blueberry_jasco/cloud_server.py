"""Jasco myTS balance/work-server emulator for local LAN control."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import shutil
import socket
import ssl
import subprocess
from pathlib import Path

from .protocol import JascoDevice, decode_frame, encode_frame, send_raw_frame

_LOGGER = logging.getLogger(__name__)
_BALANCE = 0x81
_WORK_LOGIN = 0x82
_HEARTBEAT = 0x61
_REGISTRATION = 0x86
_MAX_FRAME_LENGTH = 65551


def ensure_self_signed_certificate(directory: Path, advertised_ip: str) -> tuple[Path, Path]:
    """Create a persistent self-signed certificate accepted by the myTS app."""
    directory.mkdir(parents=True, exist_ok=True)
    cert_path = directory / "myts-cloud.crt"
    key_path = directory / "myts-cloud.key"
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    address = ipaddress.ip_address(advertised_ip)
    openssl = shutil.which("openssl")
    if openssl is None:
        raise RuntimeError("OpenSSL is required to create the local Jasco TLS certificate")
    subprocess.run([
        openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key_path), "-out", str(cert_path), "-days", "3650",
        "-sha256", "-subj", "/CN=myts.yunext.com", "-addext",
        f"subjectAltName=DNS:myts.yunext.com,IP:{address}",
    ], check=True, capture_output=True, text=True)
    key_path.chmod(0o600)
    cert_path.chmod(0o644)
    return cert_path, key_path


def detect_lan_ip() -> str:
    """Find the interface address used to reach other LANs without sending data."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("8.8.8.8", 53))
        address = probe.getsockname()[0]
    return str(ipaddress.ip_address(address))


def _server_frame(command: int, payload: bytes, protocol_index: int) -> bytes:
    frame = encode_frame(
        mac="00:00:00:00:00:00", payload=bytes((command,)) + payload,
        protocol_index=protocol_index, company_code=2, device_type=0xA1, auth_code=0,
    )
    # The app identifies cloud-originated frames with header flag 0x02.
    return frame[:1] + bytes((frame[1] | 0x02,)) + frame[2:]


class JascoCloudServer:
    """TLS balance and work-server endpoints on the same local listener.

    Device/account registration stays manual. One configured device MAC is
    routed to its private LAN address. Account fields in 0x82 are discarded.
    """

    def __init__(self, hass, *, bind: str, port: int, advertised_ip: str,
                 directory: Path, device: JascoDevice | None):
        self.hass = hass
        self.bind = bind
        self.port = port
        self.advertised_ip = str(ipaddress.ip_address(advertised_ip))
        self.directory = directory
        self.devices: dict[str, JascoDevice] = {}
        self.entries: set[str] = set()
        if device is not None:
            self.devices[device.mac.lower()] = device
        self._server: asyncio.AbstractServer | None = None

    async def async_start(self) -> None:
        cert, key = await self.hass.async_add_executor_job(
            ensure_self_signed_certificate, self.directory, self.advertised_ip
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(cert), str(key))
        self._server = await asyncio.start_server(
            self._handle_client, self.bind, self.port, ssl=context,
            ssl_handshake_timeout=15,
        )
        _LOGGER.warning("Jasco local TLS cloud listener active on %s:%d", self.bind, self.port)

    async def async_stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    def add_entry(self, entry_id: str, device: JascoDevice | None) -> None:
        self.entries.add(entry_id)
        if device is not None:
            self.devices[device.mac.lower()] = device

    def remove_entry(self, entry_id: str, device: JascoDevice | None) -> bool:
        self.entries.discard(entry_id)
        if device is not None:
            self.devices.pop(device.mac.lower(), None)
        return not self.entries

    async def _read_frame(self, reader: asyncio.StreamReader) -> bytes:
        header = await reader.readexactly(16)
        if header[0] != 0xA1:
            raise ValueError("unexpected Jasco frame marker")
        length = int.from_bytes(header[8:10], "big")
        if not 6 <= length <= _MAX_FRAME_LENGTH:
            raise ValueError("invalid Jasco frame length")
        return header + await reader.readexactly(length - 6)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        _LOGGER.info("Jasco TLS client connected from %s", peer)
        try:
            while True:
                frame = await self._read_frame(reader)
                message = decode_frame(frame)
                payload = message["payload"]
                if not payload:
                    continue
                command = payload[0]
                index = message["protocol_index"]

                if command == _BALANCE:
                    ip_bytes = ipaddress.ip_address(self.advertised_ip).packed
                    writer.write(_server_frame(
                        _BALANCE, ip_bytes + self.port.to_bytes(2, "big"), index,
                    ))
                    await writer.drain()
                    _LOGGER.debug("Returned local work-server address to myTS client %s", peer)
                    continue

                if command == _WORK_LOGIN:
                    # Do not persist or log the account token, username, or password.
                    writer.write(_server_frame(_WORK_LOGIN, b"", index))
                    await writer.drain()
                    _LOGGER.info("Accepted myTS work-server session from %s without cloud account registration", peer)
                    continue

                if command == _REGISTRATION:
                    # Device metadata frames initialize the app's relay session.
                    # The user supplied device mapping is the local authority.
                    continue

                if command == _HEARTBEAT:
                    writer.write(_server_frame(0x62, b"", index))
                    await writer.drain()
                    continue

                device = self.devices.get(message["mac"].lower())
                if device is None:
                    _LOGGER.debug("Ignoring unconfigured Jasco MAC %s", message["mac"])
                    continue

                try:
                    response = await self.hass.async_add_executor_job(
                        send_raw_frame, device, frame
                    )
                except (OSError, ValueError) as err:
                    _LOGGER.warning("Jasco local relay failed for %s: %s", device.ip, err)
                    continue
                if response:
                    # Mark the UDP device reply as a cloud-server frame for
                    # the app's TCP response parser. The device payload and
                    # device identifiers remain unchanged.
                    response = response[:1] + bytes((response[1] | 0x02,)) + response[2:]
                    writer.write(response)
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        except (ValueError, OSError) as err:
            _LOGGER.warning("Closing invalid Jasco TLS session from %s: %s", peer, err)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass
            _LOGGER.info("Jasco TLS client disconnected from %s", peer)
