"""Runtime diagnostics remain readable even when HA hides switch attributes."""
from .const import DOMAIN, INTEGRATION_VERSION

def switch_key(record):
    return f"{DOMAIN}_{record['mac'].lower().replace(':','')}_{int(record.get('pin',1))}"

def device_diagnostics(hass,entry_id,record):
    entity=hass.data.get(DOMAIN,{}).get(entry_id,{}).get('switches',{}).get(switch_key(record))
    if entity is None:
        return {'status':'starting','integration_version':INTEGRATION_VERSION,'ip_address':record.get('ip'),
                'last_error':'Switch platform has not registered this device','last_poll':None,'poll_count':0}
    attributes=entity.extra_state_attributes
    status='connected' if entity.available else 'offline' if attributes['last_poll'] else 'starting'
    return {'status':status,**attributes}

async def async_get_config_entry_diagnostics(hass,entry):
    return {'integration_version':INTEGRATION_VERSION,'devices':[
        device_diagnostics(hass,entry.entry_id,record)
        for record in entry.data.get('devices',[entry.data]) if record.get('mac')]}
