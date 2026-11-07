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
import threading
import time
from contextlib import contextmanager
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
    if command == "discover":
        return bytes((0x23,))
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
    raise ValueError("command must be discover, query_state, refresh, read_pin, or set_switch")


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


_TRANSPORT_LOCK = threading.Lock()
_SEQUENCE_LOCK = threading.Lock()
_COMMAND_SEQUENCES = {}

def next_protocol_index(device):
    """WifiDevice.getProtocolIndex advances for every outgoing command."""
    key=device.mac.lower().replace("-", ":")
    with _SEQUENCE_LOCK:
        index=_COMMAND_SEQUENCES.get(key,device.protocol_index)
        _COMMAND_SEQUENCES[key]=(index+1)%32768
        return index

@contextmanager
def local_socket(timeout=3.0,broadcast=False):
    """Match q0.a's fixed UDP source port and serialize requests in HA."""
    with _TRANSPORT_LOCK:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            if broadcast:sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
            sock.bind(('0.0.0.0',UDP_PORT))
            sock.settimeout(timeout)
            yield sock

def lan_interfaces():
    """Read IPv4 addresses and directed broadcasts without assuming a /24."""
    result=[]
    try:
        import fcntl
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            for _,name in socket.if_nameindex():
                try:
                    request=struct.pack('256s',name.encode()[:15])
                    ip=socket.inet_ntoa(fcntl.ioctl(sock.fileno(),0x8915,request)[20:24])
                    mask=socket.inet_ntoa(fcntl.ioctl(sock.fileno(),0x891b,request)[20:24])
                    address=ipaddress.IPv4Address(ip)
                    if not address.is_private or address.is_loopback:continue
                    network=ipaddress.IPv4Network(ip+'/'+mask,strict=False)
                    result.append({'ip':ip,'cidr':str(network),'broadcast':str(network.broadcast_address)})
                except OSError:continue
    except (ImportError,OSError):pass
    return result

def reply_matches(device,request_frame,response,ip,port):
    if ip!=device.ip or port!=device.port:return False
    try:
        request=decode_frame(request_frame);decoded=decode_frame(response)
    except ValueError:return False
    if decoded['mac']!=device.mac.lower().replace('-',':'):return False
    if any(decoded[key]!=getattr(device,key) for key in ('company_code','device_type','auth_code')):return False
    if decoded['protocol_index']&255 != request['protocol_index']&255:return False
    payload=decoded['payload'];expected=request['payload']
    if expected and (not payload or payload[0]!=expected[0]):return False
    if expected and expected[0] in (1,2):
        if len(payload)<3 or payload[1]!=expected[1] or payload[2] not in (0,255):return False
    return True


def observe_reply(frame,ip,port):
    """Summarize protocol evidence without exposing header authentication codes."""
    result={'ip':ip,'port':port,'bytes':len(frame)}
    try:decoded=decode_frame(frame)
    except ValueError:return {**result,'error':'Invalid myTS frame'}
    payload=decoded['payload']
    result.update({'mac':decoded['mac'],'sequence':decoded['protocol_index'],'flags':frame[1],
                   'company_code':decoded['company_code'],'device_type':decoded['device_type'],
                   'command':payload[0] if payload else None})
    if payload and payload[0] in (1,2,3):result['gpio_payload']=payload[:3].hex()
    return result


def _exchange(device,frame,timeout,attempts=1,observation=None):
    with local_socket(timeout) as sock:
        deadline=time.monotonic()+timeout
        retry_at=0;sent=0
        while time.monotonic()<deadline:
            now=time.monotonic()
            if sent<attempts and now>=retry_at:
                sock.sendto(frame,(device.ip,device.port))
                sent+=1;retry_at=now+timeout/attempts
            sock.settimeout(max(.01,min(deadline-time.monotonic(),retry_at-time.monotonic() if sent<attempts else timeout)))
            try:response,(ip,port)=sock.recvfrom(65535)
            except socket.timeout:continue
            if observation is not None:
                observation['received_packets']=observation.get('received_packets',0)+1
                observation['last_received']=observe_reply(response,ip,port)
            if reply_matches(device,frame,response,ip,port):return response
    return None


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
                         protocol_index=next_protocol_index(device),
                         company_code=device.company_code,
                         device_type=device.device_type,
                         auth_code=device.auth_code, locked=device.locked)
    observation={'received_packets':0,'last_received':None}
    response=_exchange(device,frame,timeout,attempts=3 if command in ("read_pin","discover") else 1,observation=observation)
    if response is None:return {"transport":"udp","response_timeout":True,**observation}
    try:
        decoded = decode_frame(response)
        return {"transport": "udp",**observation,
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
    return _exchange(device,frame,timeout)


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
    with local_socket(timeout) as sock:
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
