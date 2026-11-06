"""Jasco myTouchSmart LAN frame codec and UDP/TCP transport.

Header layout and commands are transcribed from the app's t0.c.a frame
builder, t0.a command builders, and q0 transport classes. Device header
identifiers must come from the device record or a captured app exchange.
"""
from __future__ import annotations

import ipaddress
import itertools
import socket
import struct
from dataclasses import dataclass

MAGIC = 0xA1
HEADER_SIZE = 16
UDP_PORT = 35932
_login_sequence = itertools.count()


def _mac_bytes(mac: str) -> bytes:
    parts = mac.replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError("MAC must contain six hexadecimal octets")
    try:
        return bytes(int(part, 16) for part in reversed(parts))
    except ValueError as err:
        raise ValueError("MAC contains a non-hexadecimal octet") from err


def encode_frame(*, mac: str, payload: bytes, protocol_index: int = 1,
                 company_code: int, device_type: int, auth_code: int,
                 locked: bool = False) -> bytes:
    if not 0 <= protocol_index <= 0x7FFF:
        raise ValueError("protocol index must be between 0 and 32767")
    if len(payload) > 0xFFFF - 6:
        raise ValueError("payload is too large")
    if not (0 <= company_code <= 255 and 0 <= device_type <= 255 and 0 <= auth_code <= 65535):
        raise ValueError("company, device, or auth code is out of range")
    return b"".join((
        bytes((MAGIC, 4 if locked else 0)),
        _mac_bytes(mac),
        struct.pack(">HHBBH", len(payload) + 6, protocol_index,
                    company_code, device_type, auth_code),
        payload,
    ))


def decode_frame(frame: bytes) -> dict:
    if len(frame) < HEADER_SIZE or frame[0] != MAGIC:
        raise ValueError("invalid Jasco frame header")
    length, protocol_index, company_code, device_type, auth_code = struct.unpack(">HHBBH", frame[8:16])
    if length != len(frame) - HEADER_SIZE + 6:
        raise ValueError("Jasco frame length field does not match payload")
    mac = ":".join(f"{part:02x}" for part in reversed(frame[2:8]))
    return {"mac": mac, "locked": bool(frame[1] & 4), "protocol_index": protocol_index,
            "company_code": company_code, "device_type": device_type,
            "auth_code": auth_code, "payload": frame[16:]}


def command_payload(command: str, *, pin: int | None = None,
                    state: bool | None = None) -> bytes:
    if command == "query_state":
        return bytes((0x10,))
    if command == "refresh":
        return bytes((0x14,))
    if command == "read_pin":
        if pin is None or not 0 <= pin <= 255:
            raise ValueError("read_pin requires a pin from 0 to 255")
        return bytes((0x02, pin))
    if command == "set_switch":
        if pin is None or not 0 <= pin <= 255 or state is None:
            raise ValueError("set_switch requires pin and state")
        # The APK's t0.a.p emits {1, pin, 0xff|0} for relay writes.
        # Command 0x08 is a countdown query, not a switch command.
        return bytes((0x01, pin, 0xFF if state else 0x00))
    raise ValueError("command must be query_state, refresh, read_pin, or set_switch")


def login_payload(username: str, password: str, status: int = 0) -> bytes:
    """Build the APK's t0.b login payload. Credentials are not persisted."""
    user = (username + "_MYTS").encode("utf-8")
    secret = password.encode("utf-8")
    if len(user) > 255 or len(secret) > 253 or not 0 <= status <= 255:
        raise ValueError("login fields exceed the observed one-byte lengths")
    return bytes((0x88, len(user))) + user + bytes((len(secret) + 2, len(secret))) + secret + bytes((status,))


@dataclass(frozen=True)
class JascoDevice:
    ip: str
    mac: str
    company_code: int
    device_type: int
    auth_code: int
    port: int = UDP_PORT
    protocol_index: int = 1
    locked: bool = False

    def validate(self) -> None:
        address = ipaddress.ip_address(self.ip)
        if not (address.is_private or address.is_loopback or address.is_link_local):
            raise ValueError("Jasco control is restricted to local and link-local addresses")
        _mac_bytes(self.mac)
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")


def send_command(device: JascoDevice, command: str, *, pin: int | None = None,
                 state: bool | None = None, timeout: float = 3.0) -> dict:
    """Send a direct local UDP frame to the device on port 35932.

    The Android app's TCP path goes through its cloud work-server session on
    port 33491. This standalone local command path intentionally uses the
    separate UDP transport and does not emulate that cloud relay.
    """
    device.validate()
    payload = command_payload(command, pin=pin, state=state)
    frame = encode_frame(mac=device.mac, payload=payload,
                         protocol_index=device.protocol_index,
                         company_code=device.company_code,
                         device_type=device.device_type,
                         auth_code=device.auth_code, locked=device.locked)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(frame, (device.ip, device.port))
        try:
            response, _ = sock.recvfrom(4096)
        except socket.timeout:
            return {"transport": "udp", "response_timeout": True}
    try:
        decoded = decode_frame(response)
        return {"transport": "udp",
                "response": {k: v for k, v in decoded.items() if k != "payload"},
                "payload_hex": decoded["payload"].hex()}
    except ValueError:
        return {"transport": "udp", "raw_response_hex": response.hex()}


def send_raw_frame(device: JascoDevice, frame: bytes, *, timeout: float = 3.0) -> bytes | None:
    """Forward an already framed app command to its configured LAN device."""
    device.validate()
    decoded = decode_frame(frame)
    if decoded["mac"].lower() != device.mac.lower():
        raise ValueError("frame MAC does not match the configured device")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(frame, (device.ip, device.port))
        try:
            response, _ = sock.recvfrom(4096)
            return response
        except socket.timeout:
            return None


def send_login(ip: str, username: str, password: str, *, status: int = 0,
               timeout: float = 3.0) -> dict:
    """Send the app's all-zero-header login payload to local UDP port 35932."""
    address = ipaddress.ip_address(ip)
    if not (address.is_private or address.is_loopback or address.is_link_local):
        raise ValueError("Jasco login is restricted to local and link-local addresses")
    payload = login_payload(username, password, status)
    frame = encode_frame(mac="00:00:00:00:00:00", payload=payload,
                         protocol_index=next(_login_sequence) % 32768,
                         company_code=0, device_type=0, auth_code=0)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(frame, (ip, UDP_PORT))
        try:
            response, _ = sock.recvfrom(4096)
        except socket.timeout:
            return {"transport": "udp", "response_timeout": True}
    try:
        decoded = decode_frame(response)
        return {"transport": "udp",
                "response": {k: v for k, v in decoded.items() if k != "payload"},
                "payload_hex": decoded["payload"].hex()}
    except ValueError:
        return {"transport": "udp", "raw_response_hex": response.hex()}
