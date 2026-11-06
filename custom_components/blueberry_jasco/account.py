"""Account inventory and LAN correlation using the myTS app's wire formats."""
from __future__ import annotations
import base64
import hashlib
import ipaddress
import re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = 'https://myts.yunext.com'


def load_app_key(path):
    """Compatibility helper for callers that only need signing material."""
    from .app_archive import load_app_material
    return load_app_material(path).key


def signed_fields(fields, key):
    fields = {name: str(value) for name, value in fields.items()}
    message = '&'.join(f'{name}={fields[name]}' for name in sorted(fields)).encode()
    fields['sign'] = base64.b64encode(key.sign(message, padding.PKCS1v15(), hashes.SHA1())).decode()
    return fields


class AccountError(ValueError):
    def __init__(self, stage, reason):
        self.stage = stage
        super().__init__(reason)


def provider_code(payload):
    value = str(payload.get('code', 'unknown'))
    # Do not echo response messages, credentials, tokens, or response bodies.
    return value if re.fullmatch(r'-?\d{1,10}', value) else 'unknown'


async def _provider_json(session, method, path, fields, stage):
    from aiohttp import ClientError, ClientConnectorCertificateError, ClientSSLError
    options = {'data': fields} if method == 'POST' else {'params': fields}
    try:
        async with session.request(method, ROOT + path, allow_redirects=False, timeout=20, **options) as response:
            if not 200 <= response.status < 300:
                raise AccountError(stage, f'myTS {stage} returned HTTP {response.status}.')
            try:
                # Retrofit decodes JSON regardless of the Content-Type header.
                payload = await response.json(content_type=None)
            except ValueError as err:
                raise AccountError(stage, f'myTS {stage} returned a non-JSON response.') from err
    except (ClientConnectorCertificateError, ClientSSLError) as err:
        raise AccountError('cloud_tls', f'HTTPS certificate verification failed during myTS {stage}.') from err
    except (ClientError, OSError, TimeoutError) as err:
        raise AccountError(stage, f'Could not reach the myTS {stage} endpoint.') from err
    if not isinstance(payload, dict):
        raise AccountError(stage, f'myTS {stage} returned an unexpected response shape.')
    if payload.get('success') not in (True, 'true'):
        raise AccountError(stage, f'myTS {stage} was rejected, provider code {provider_code(payload)}.')
    return payload.get('data')


async def _inventory(session, username, password, material):
    fields = signed_fields({'username': username.strip(), 'appType': '1',
                            'phoneType': 'Home Assistant', 'phoneSysVersion': 'Python',
                            'appVersion': material.version,
                            'password': hashlib.md5(password.encode(), usedforsecurity=False).hexdigest().upper()}, material.key)
    login = await _provider_json(session, 'POST', '/api/service/user/login/MYTS', fields, 'login')
    if not isinstance(login, dict) or not isinstance(login.get('token'), str) or not login['token']:
        raise AccountError('login', 'myTS login succeeded but returned no usable account token.')
    result = await _provider_json(session, 'GET', '/api/app/device/list',
                                  signed_fields({'token': login['token']}, material.key), 'inventory')
    if not isinstance(result, list):
        raise AccountError('inventory', 'myTS inventory returned an unexpected device list.')
    return result


async def inventory(session, username, password, material):
    from aiohttp import ClientSession, TCPConnector, ClientTimeout
    from .cloud_dns import MyTSResolver
    resolver = MyTSResolver(session)
    try:
        async with ClientSession(connector=TCPConnector(resolver=resolver, use_dns_cache=False),
                                 timeout=ClientTimeout(total=25)) as cloud:
            return await _inventory(cloud, username, password, material)
    finally:
        await resolver.close()


def normalize_mac(value):
    text = re.sub('[:-]', '', str(value)).lower()
    if len(text) != 12 or not re.fullmatch('[0-9a-f]{12}', text):
        raise ValueError('Invalid device MAC')
    return ':'.join(text[i:i + 2] for i in range(0, 12, 2))


def correlate(records, scan):
    addresses = {}
    for row in scan.get('arp', []):
        if not isinstance(row, dict):
            continue
        try:
            mac = normalize_mac(row.get('mac', row.get('hw-address', '')))
            ip = str(ipaddress.IPv4Address(row['ip']))
            if ipaddress.ip_address(ip).is_private:
                addresses[mac] = ip
        except (ValueError, KeyError, TypeError):
            continue
    found, missing = [], []
    for record in records:
        if not isinstance(record, dict):
            continue
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


def discover_local(devices, timeout=3.0, candidates=None):
    """Query only account-owned MACs and accept responses with matching headers."""
    import socket
    import time
    from .protocol import command_payload, decode_frame, encode_frame, UDP_PORT
    known = {device['mac']: device for device in devices[:128]}
    found = {}
    targets = ['255.255.255.255']
    for candidate in (candidates or [])[:256]:
        try:
            address = ipaddress.IPv4Address(candidate)
            if address.is_private and not address.is_loopback:
                targets.append(str(address))
        except ValueError:
            continue
    targets = list(dict.fromkeys(targets))
    if len(known) * len(targets) > 2048:
        targets = targets[:max(1, 2048 // max(1, len(known)))]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('0.0.0.0', 0))
        for device in known.values():
            frame = encode_frame(mac=device['mac'], company_code=device['company_code'],
                                 device_type=device['device_type'], auth_code=device['auth_code'],
                                 protocol_index=1, payload=command_payload('query_state'))
            for target in targets:
                try:
                    sock.sendto(frame, (target, UDP_PORT))
                except OSError:
                    continue
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
