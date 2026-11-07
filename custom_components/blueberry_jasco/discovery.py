"""Account-owned MAC correlation, fixed-port LAN discovery and scoped proxy fallback."""
from __future__ import annotations
import asyncio
import time
import uuid
from aiohttp import ClientError
from .account import correlate

async def discover_account_devices(session,base,records,local_probe,parameters=None,timeout=240,scanner_script=None,inventory_urls=None):
    job_id=scanner_id=None
    found={};_,missing=correlate(records,{'arp':[]})
    diagnostics=[];candidates=[]
    def merge(devices):
        for device in devices:
            found[device['mac']]=device
    def remaining():return [device for device in missing if device['mac'] not in found]
    async def read_scan():
        async with session.get(base+'/scan',timeout=15) as response:
            response.raise_for_status();scan=await response.json(content_type=None)
        if not isinstance(scan,dict):raise ValueError('Proxy returned an invalid scan')
        return scan
    async def gather(scan):
        merge(correlate(records,scan)[0])
        for row in [*scan.get('discoveries',[]),*scan.get('arp',[])]:
            if isinstance(row,dict) and row.get('ip'):candidates.append(row['ip'])
        candidates.extend(ip for ip in scan.get('live',[]) if isinstance(ip,str))
    async def direct():
        if not remaining():return
        try:merge(await local_probe(remaining(),list(dict.fromkeys(candidates))))
        except (OSError,TimeoutError,ValueError) as error:diagnostics.append('HA UDP discovery failed ('+str(error)[:160]+').')
    try:
        try:await gather(await read_scan())
        except (ClientError,TimeoutError,OSError,ValueError):diagnostics.append('Could not read proxy LAN inventory.')
        # Quantum supplies observed gateway MAC/IP records, not guessed addresses.
        for url in (inventory_urls or [])[:4]:
            try:
                async with session.get(url.rstrip('/')+'/api/providers',timeout=8) as response:
                    response.raise_for_status();catalog=await response.json(content_type=None)
                for provider in catalog.get('providers',[])[:8]:
                    async with session.get(url.rstrip('/')+'/api/providers/'+provider['id']+'/snapshot',timeout=10) as response:
                        if response.status!=200:continue
                        snapshot=await response.json(content_type=None)
                    rows=[row for row in snapshot.get('devices',[]) if isinstance(row,dict) and row.get('connected') is not False]
                    await gather({'discoveries':rows})
            except (ClientError,TimeoutError,OSError,ValueError,KeyError):diagnostics.append('Gateway inventory was unavailable; continuing LAN discovery.')
        await direct()
        if not remaining():return {'devices':list(found.values()),'missing':[],'details':'','job_id':None}
        options={'parameters':parameters or {}}
        if scanner_script and 1<=len(missing)<=128:
            scanner_id='jasco-setup-'+uuid.uuid4().hex
            profile={'id':scanner_id,'kind':'graaljs','enabled':False,'script':scanner_script,
                     'parameters':{'ports':[35932],'timeout_ms':100,'duration_ms':1500,'deadline_ms':120000,
                                   'udp_local_port':35932,'udp_broadcast':True,'devices':remaining()}}
            try:
                async with session.post(base+'/uscan/scanners',json=profile,timeout=15) as response:
                    if response.status>=400:
                        diagnostics.append('Proxy cannot register the discovery scanner (HTTP '+str(response.status)+').');scanner_id=None
                if scanner_id:options['scanner_ids']=[scanner_id]
            except (ClientError,TimeoutError,OSError,ValueError):
                scanner_id=None;diagnostics.append('Proxy discovery scanner registration failed.')
        async with session.post(base+'/uscan/jobs',json=options,timeout=15) as response:
            if response.status==404:diagnostics.append('Update BlueberryProxy to 0.3.1 or later for fixed-port UDP discovery.')
            elif response.status>=400:
                payload=await response.json(content_type=None);diagnostics.append(str(payload.get('error','UScan could not start'))[:240])
            else:job_id=(await response.json(content_type=None))['id']
        if job_id:
            deadline=time.monotonic()+timeout
            while time.monotonic()<deadline:
                async with session.get(base+'/uscan/jobs',params={'id':job_id},timeout=10) as response:
                    response.raise_for_status();job=await response.json(content_type=None)
                if job.get('status') not in ('queued','running'):
                    diagnostics.extend(str(row['error'])[:240] for row in job.get('results',[]) if row.get('error'))
                    break
                await asyncio.sleep(1)
            else:diagnostics.append('The scan exceeded the setup wait. Retry with narrower CIDRs.')
        await gather(await read_scan())
        await direct()
    except (ClientError,TimeoutError,OSError,ValueError,KeyError) as error:
        diagnostics.append('LAN discovery failed ('+type(error).__name__+').')
        await direct()
    finally:
        if job_id:
            try:
                async with session.delete(base+'/uscan/jobs',params={'id':job_id},timeout=5):pass
            except (ClientError,TimeoutError,OSError):pass
        if scanner_id:
            try:
                async with session.delete(base+'/uscan/scanners',params={'id':scanner_id},timeout=5):pass
            except (ClientError,TimeoutError,OSError):pass
    pending=remaining()
    if pending and not diagnostics:diagnostics.append('No matching UDP reply arrived. Verify the devices and HA/proxy are on the same LAN without client isolation, or enter the device IP/CIDR to target it directly.')
    return {'devices':list(found.values()),'missing':pending,'details':' '.join(dict.fromkeys(diagnostics))[:700],'job_id':job_id}
