"""Use the proxy's background discovery jobs without repeating cloud sign-in."""
from __future__ import annotations
import asyncio
import time
import hashlib
from aiohttp import ClientError
from .account import correlate


async def discover_account_devices(session, base, records, local_probe, parameters=None, timeout=240, scanner_script=None):
    job_id = None
    scanner_id = None
    devices, missing, candidates = [], [], []
    details = ''
    async def read_scan():
        async with session.get(base + '/scan', timeout=15) as response:
            response.raise_for_status()
            scan = await response.json(content_type=None)
        if not isinstance(scan, dict):
            raise ValueError('Invalid BlueberryProxy scan response')
        return scan
    try:
        options = {'parameters': parameters or {}}
        if scanner_script:
            _, known = correlate(records, {'arp': []})
            if not known or len(known) > 128:
                raise ValueError('The account needs 1 to 128 supported devices for UDP discovery')
            identity = ','.join(sorted(device['mac'] for device in known))
            scanner_id = 'jasco-setup-' + hashlib.sha256(identity.encode()).hexdigest()[:16]
            profile = {'id': scanner_id, 'kind': 'graaljs', 'enabled': False, 'script': scanner_script,
                       'parameters': {'ports': [35932], 'timeout_ms': 50, 'deadline_ms': 120000,
                                      'devices': known}}
            async with session.post(base + '/uscan/scanners', json=profile, timeout=15) as response:
                if response.status == 404:
                    scanner_id = None
                elif response.status >= 400:
                    raise ValueError('Proxy rejected the myTS discovery scanner')
            if scanner_id:
                options['scanner_ids'] = [scanner_id]
        async with session.post(base + '/uscan/jobs', json=options, timeout=15) as response:
            if response.status == 404:
                details = 'This proxy does not support UScan yet. Update BlueberryProxy to 0.3 or later.'
            elif response.status >= 400:
                payload = await response.json(content_type=None)
                details = str(payload.get('error', 'UScan could not start'))[:240]
            else:
                payload = await response.json(content_type=None)
                job_id = payload['id']
        if job_id:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                async with session.get(base + '/uscan/jobs', params={'id': job_id}, timeout=10) as response:
                    response.raise_for_status()
                    job = await response.json(content_type=None)
                if job.get('status') not in ('queued', 'running'):
                    failures = [result.get('error') for result in job.get('results', []) if result.get('error')]
                    details = '; '.join(failures)[:240]
                    break
                await asyncio.sleep(1)
            else:
                details = 'UScan is still running. Increase scope budgets in the proxy dashboard or retry with narrower CIDRs.'
        scan = await read_scan()
        devices, missing = correlate(records, scan)
        candidates = [row.get('ip') for row in scan.get('discoveries', []) if isinstance(row, dict) and row.get('ip')]
        candidates.extend(ip for ip in scan.get('live', []) if isinstance(ip, str))
        if missing:
            direct = await local_probe(missing, list(dict.fromkeys(candidates)))
            devices.extend(direct)
            matched = {device['mac'] for device in direct}
            missing = [device for device in missing if device['mac'] not in matched]
    except (ClientError, TimeoutError, OSError, ValueError, KeyError) as error:
        details = f'LAN discovery failed ({type(error).__name__}).'
    finally:
        if job_id:
            try:
                async with session.delete(base + '/uscan/jobs', params={'id': job_id}, timeout=5):
                    pass
            except (ClientError, TimeoutError, OSError):
                pass
        if scanner_id:
            try:
                async with session.delete(base + '/uscan/scanners', params={'id': scanner_id}, timeout=5):
                    pass
            except (ClientError, TimeoutError, OSError):
                pass
    return {'devices': devices, 'missing': missing, 'details': details, 'job_id': job_id}
