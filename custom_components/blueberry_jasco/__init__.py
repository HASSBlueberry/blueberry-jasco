from pathlib import Path
from aiohttp import ClientError
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from .protocol import JascoDevice, send_command, send_login
from .const import DOMAIN
from .cloud_server import JascoCloudServer, detect_lan_ip

async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    session = async_get_clientsession(hass)
    base = entry.data["url"].rstrip("/")
    for filename, transformer_id, kind in [("jasco-request.js", "jasco-request", "request-script"), ("jasco-response.js", "jasco-response", "response-script")]:
        script = (Path(__file__).parent / "transforms" / filename).read_text()
        try:
            async with session.post(f"{base}/proxy/transformers", json={"id": transformer_id, "type": kind, "script": script}, timeout=10, ssl=None if entry.data.get("verify_ssl", True) else False) as response:
                response.raise_for_status()
        except (ClientError, TimeoutError):
            break
    domain_data = hass.data.setdefault(DOMAIN, {})
    relay_servers = domain_data.setdefault("relay_servers", {})
    entry_data = {"url": base, "verify_ssl": entry.data.get("verify_ssl", True)}
    if entry.data.get("cloud_relay", True):
        values = entry.data
        device = None
        if all(values.get(key) not in (None, "") for key in
               ("ip", "mac", "company_code", "device_type", "auth_code")):
            device = JascoDevice(
                ip=values["ip"], mac=values["mac"],
                company_code=int(values["company_code"]),
                device_type=int(values["device_type"]), auth_code=int(values["auth_code"]),
            )
        advertised_ip = values.get("relay_advertise_ip") or await hass.async_add_executor_job(detect_lan_ip)
        port = int(values.get("relay_port", 33491))
        relay = relay_servers.get(port)
        if relay is None:
            relay = JascoCloudServer(
                hass, bind="0.0.0.0", port=port, advertised_ip=advertised_ip,
                directory=Path(hass.config.path(".storage", DOMAIN, "certificates")),
                device=None,
            )
            await relay.async_start()
            relay_servers[port] = relay
        relay.add_entry(entry.entry_id, device)
        entry_data["relay_server"] = relay
        entry_data["relay_port"] = port
        entry_data["relay_device"] = device
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = entry_data
    if not hass.services.has_service(DOMAIN, "send_local_command"):
        async def handle_local_command(call):
            values = call.data
            device = JascoDevice(
                ip=values["ip"], mac=values["mac"],
                company_code=int(values["company_code"]),
                device_type=int(values["device_type"]),
                auth_code=int(values["auth_code"]),
                port=int(values.get("port", 35932)),
                protocol_index=int(values.get("protocol_index", 1)),
                locked=bool(values.get("locked", False)),
            )
            command = values["command"]
            if command == "set_switch" and not values.get("confirm_control", False):
                raise ValueError("set_switch requires confirm_control")
            result = await hass.async_add_executor_job(
                lambda: send_command(device, command, pin=values.get("pin"), state=values.get("state"))
            )
            hass.bus.async_fire(f"{DOMAIN}_command_result", {"ip": device.ip, "command": command, **result})
        hass.services.async_register(DOMAIN, "send_local_command", handle_local_command)
        async def handle_local_login(call):
            values = call.data
            result = await hass.async_add_executor_job(
                lambda: send_login(values["ip"], values["username"], values["password"],
                                   status=int(values.get("status", 0)))
            )
            hass.bus.async_fire(f"{DOMAIN}_command_result", {
                "ip": values["ip"], "command": "login", **result
            })
        hass.services.async_register(DOMAIN, "send_local_login", handle_local_login)
    await hass.config_entries.async_forward_entry_setups(entry, ["sensor", "switch"])
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, ["sensor", "switch"])
    if unloaded:
        domain_data = hass.data.get(DOMAIN, {})
        entry_data = domain_data.pop(entry.entry_id, {})
        relay = entry_data.get("relay_server")
        if relay and relay.remove_entry(entry.entry_id, entry_data.get("relay_device")):
            await relay.async_stop()
            domain_data.get("relay_servers", {}).pop(entry_data.get("relay_port"), None)
        if not [key for key in domain_data if key != "relay_servers"]:
            hass.services.async_remove(DOMAIN, "send_local_command")
            hass.services.async_remove(DOMAIN, "send_local_login")
    return unloaded
