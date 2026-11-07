"""Provider-owned protocol over HA LAN or the discovering proxy's LAN."""
from aiohttp import ClientError
from .protocol import command_payload, decode_frame, encode_frame, next_protocol_index, reply_matches, send_command, observe_reply

class JascoTransport:
    def __init__(self,hass,session,url,verify_ssl=True):
        self.hass,self.session,self.url,self.verify_ssl=hass,session,url.rstrip('/'),verify_ssl
        self.route='direct'
        self.direct_error=self.proxy_error=None
        self.direct_observation=self.proxy_observation=None

    async def _direct(self,device,command,**values):
        try:
            result=await self.hass.async_add_executor_job(lambda:send_command(device,command,**values))
            self.direct_observation={key:result.get(key) for key in ('received_packets','last_received')}
            self.direct_error='No matching UDP reply received by HA' if result.get('response_timeout') else None
            return result
        except (OSError,ValueError) as error:
            self.direct_error=str(error)[:200]
            return {'response_timeout':True,'transport':'udp'}

    async def _proxy(self,device,command,**values):
        frame=encode_frame(mac=device.mac,company_code=device.company_code,device_type=device.device_type,
                           auth_code=device.auth_code,locked=device.locked,protocol_index=next_protocol_index(device),
                           payload=command_payload(command,**values))
        try:
            async with self.session.post(self.url+'/network/udp',json={'ip':device.ip,'port':device.port,
                        'local_port':35932,'hex':frame.hex(),'timeout_ms':1000},timeout=15,
                        ssl=None if self.verify_ssl else False) as response:
                if response.status==404:
                    self.proxy_error='Update BlueberryProxy to 0.3.2 for LAN command forwarding'
                    return {'response_timeout':True,'transport':'proxy UDP'}
                if response.status!=200:
                    self.proxy_error='Proxy UDP exchange returned HTTP '+str(response.status)
                    return {'response_timeout':True,'transport':'proxy UDP'}
                body=await response.json()
            replies=body.get('replies',[])
            self.proxy_observation={'received_packets':len(replies),'last_received':None}
            for reply in replies:
                packet=bytes.fromhex(reply.get('hex',''))
                self.proxy_observation['last_received']=observe_reply(packet,reply.get('ip'),reply.get('port'))
                if reply_matches(device,frame,packet,reply.get('ip'),reply.get('port')):
                    message=decode_frame(packet);self.proxy_error=None
                    return {'transport':'proxy UDP','payload_hex':message.pop('payload').hex(),'response':message}
            self.proxy_error='No matching UDP reply received by BlueberryProxy'
        except (ClientError,TimeoutError,OSError,ValueError,TypeError) as error:
            self.proxy_error='Proxy UDP exchange failed ('+type(error).__name__+')'
        return {'response_timeout':True,'transport':'proxy UDP'}

    async def send(self,device,command,**values):
        # Once a path works, use it first on subsequent polls and controls.
        methods=[('proxy',self._proxy),('direct',self._direct)] if self.route=='proxy' else [('direct',self._direct),('proxy',self._proxy)]
        for route,method in methods:
            result=await method(device,command,**values)
            if not result.get('response_timeout'):
                self.route=route
                return result
        return result
