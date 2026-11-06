"""Keep account HTTPS requests usable when local DNS redirects device traffic."""
from __future__ import annotations
import ipaddress
import socket
from aiohttp.abc import AbstractResolver
from aiohttp.resolver import DefaultResolver

PROVIDER_HOST = 'myts.yunext.com'


class CloudResolutionError(OSError):
    """The account endpoint cannot be resolved to a public server."""


class MyTSResolver(AbstractResolver):
    def __init__(self, session):
        self.session = session
        self.local = DefaultResolver()

    async def resolve(self, host, port=0, family=socket.AF_INET):
        if host != PROVIDER_HOST:
            return await self.local.resolve(host, port, family)
        try:
            rows = await self.local.resolve(host, port, family)
        except OSError:
            rows = []
        if rows and all(ipaddress.ip_address(row['host']).is_global for row in rows):
            return rows
        # This bypasses only the user's device DNS override. TLS still authenticates
        # myts.yunext.com using its real hostname and the normal CA trust store.
        async with self.session.get('https://cloudflare-dns.com/dns-query',
                                    params={'name': host, 'type': 'A'},
                                    headers={'Accept': 'application/dns-json'},
                                    timeout=10, allow_redirects=False) as response:
            response.raise_for_status()
            payload = await response.json(content_type=None)
        if not isinstance(payload, dict) or payload.get('Status') != 0:
            raise CloudResolutionError('Public DNS did not resolve the myTS endpoint')
        addresses = []
        for answer in payload.get('Answer', []):
            if not isinstance(answer, dict):
                continue
            if answer.get('type') != 1:
                continue
            try:
                address = ipaddress.IPv4Address(answer['data'])
                if address.is_global:
                    addresses.append(str(address))
            except (KeyError, ValueError):
                continue
        if not addresses:
            raise CloudResolutionError('Public DNS returned no public myTS addresses')
        return [{'hostname': host, 'host': address, 'port': port, 'family': socket.AF_INET,
                 'proto': 0, 'flags': socket.AI_NUMERICHOST} for address in dict.fromkeys(addresses)]

    async def close(self):
        await self.local.close()
