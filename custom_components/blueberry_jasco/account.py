"""Account inventory and LAN correlation using the myTS app's wire formats."""
from __future__ import annotations
import base64
import hashlib
import io
import ipaddress
import re
import zipfile
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = 'https://myts.yunext.com'


def load_app_key(path):
    """Find a valid RSA PKCS#8 string in app DEX files, without executing code."""
    def inspect(archive):
        for item in archive.infolist():
            if item.file_size > 80 * 1024 * 1024:
                continue
            if item.filename.endswith('.apk'):
                with zipfile.ZipFile(io.BytesIO(archive.read(item))) as nested:
                    result = inspect(nested)
                    if result is not None:
                        return result
            elif item.filename.endswith('.dex'):
                for candidate in re.findall(rb'30[0-9a-fA-F]{1200,10000}', archive.read(item)):
                    try:
                        key = serialization.load_der_private_key(bytes.fromhex(candidate.decode()), None)
                        if isinstance(key, rsa.RSAPrivateKey) and key.key_size >= 2048:
                            return key
                    except (ValueError, TypeError):
                        continue
        return None
    if Path(path).stat().st_size > 256 * 1024 * 1024:
        raise ValueError('App archive is too large')
    with zipfile.ZipFile(path) as archive:
        key = inspect(archive)
    if key is None:
        raise ValueError('No compatible signing material found in the app')
    return key


def signed_fields(fields, key):
    fields = {name: str(value) for name, value in fields.items()}
    message = '&'.join(f'{name}={fields[name]}' for name in sorted(fields)).encode()
    fields['sign'] = base64.b64encode(key.sign(message, padding.PKCS1v15(), hashes.SHA1())).decode()
    return fields


async def inventory(session, username, password, key):
    fields = signed_fields({'username': username, 'appType': '1',
                            'phoneType': 'Home Assistant', 'phoneSysVersion': 'Python', 'appVersion': '2.9',
                            'password': hashlib.md5(password.encode(), usedforsecurity=False).hexdigest().upper()}, key)
    async with session.post(ROOT + '/api/service/user/login/MYTS', data=fields, timeout=20) as response:
        response.raise_for_status()
        login = await response.json()
    if login.get('success') is not True or not isinstance(login.get('data'), dict):
        raise ValueError('myTS rejected account login')
    token = login['data'].get('token')
    if not token:
        raise ValueError('myTS login returned no token')
    async with session.get(ROOT + '/api/app/device/list', params=signed_fields({'token': token}, key), timeout=20) as response:
        response.raise_for_status()
        result = await response.json()
    if result.get('success') is not True or not isinstance(result.get('data'), list):
        raise ValueError('myTS did not return a device list')
    return result['data']


def normalize_mac(value):
    text = re.sub('[:-]', '', str(value)).lower()
    if len(text) != 12 or not re.fullmatch('[0-9a-f]{12}', text):
        raise ValueError('Invalid device MAC')
    return ':'.join(text[i:i + 2] for i in range(0, 12, 2))


def correlate(records, scan):
    addresses = {}
    for row in scan.get('arp', []):
        try:
            mac = normalize_mac(row.get('mac', row.get('hw-address', '')))
            ip = str(ipaddress.IPv4Address(row['ip']))
            if ipaddress.ip_address(ip).is_private:
                addresses[mac] = ip
        except (ValueError, KeyError, TypeError):
            continue
    found, missing = [], []
    for record in records:
        try:
            mac = normalize_mac(record['macAddress'])
            device = {'mac': mac, 'name': record.get('deviceName') or 'myTS device',
                      'company_code': int(str(record['companyCode']), 16),
                      'device_type': int(str(record['deviceType']), 16),
                      'auth_code': int(record['authCode']), 'pin': 1}
            if not (0 <= device['company_code'] <= 255 and 0 <= device['device_type'] <= 255 and 0 <= device['auth_code'] <= 65535):
                raise ValueError('Device identifiers out of range')
            if mac in addresses:
                found.append({**device, 'ip': addresses[mac]})
            else:
                missing.append(device)
        except (ValueError, KeyError, TypeError):
            continue
    return found, missing


def discover_local(devices, timeout=3.0):
    """Query only account-owned MACs and accept responses with matching headers."""
    import socket
    import time
    from .protocol import command_payload, decode_frame, encode_frame, UDP_PORT
    known = {device['mac']: device for device in devices[:128]}
    found = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('0.0.0.0', 0))
        for device in known.values():
            frame = encode_frame(mac=device['mac'], company_code=device['company_code'],
                                 device_type=device['device_type'], auth_code=device['auth_code'],
                                 protocol_index=1, payload=command_payload('query_state'))
            sock.sendto(frame, ('255.255.255.255', UDP_PORT))
        deadline = time.monotonic() + timeout
        while known and time.monotonic() < deadline:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                frame, (address, _) = sock.recvfrom(65535)
            except socket.timeout:
                break
            try:
                message = decode_frame(frame)
                device = known.get(message['mac'])
                if not device or not ipaddress.IPv4Address(address).is_private:
                    continue
                if any(message[key] != device[key] for key in ('company_code', 'device_type', 'auth_code')):
                    continue
                found[device['mac']] = {**device, 'ip': address}
                if len(found) == len(known):
                    break
            except (ValueError, KeyError):
                continue
    return list(found.values())
