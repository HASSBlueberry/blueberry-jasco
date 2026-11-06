from datetime import timedelta
import logging
from aiohttp import ClientError
from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, CoordinatorEntity
from .const import DOMAIN, DEFAULT_NAME

async def async_setup_entry(hass, entry, async_add_entities):
    base = hass.data[DOMAIN][entry.entry_id]["url"]
    session = async_get_clientsession(hass)
    async def update():
        result = {"available": False}
        for key, path in (("status", "/status"), ("scan", "/scan"), ("queries", "/queries?n=100"), ("maps", "/proxy/maps")):
            try:
                async with session.get(base + path, timeout=8, ssl=None if entry.data.get("verify_ssl", True) else False) as response:
                    response.raise_for_status()
                    result[key] = await response.json()
            except (ClientError, TimeoutError):
                return result
        result["available"] = True
        return result
    coordinator = DataUpdateCoordinator(hass, logging.getLogger(__name__), name=DEFAULT_NAME, update_method=update, update_interval=timedelta(seconds=30))
    await coordinator.async_config_entry_first_refresh()
    async_add_entities([BlueberryDeviceSensor(coordinator), JascoCandidateSensor(coordinator)])

class BlueberryDeviceSensor(CoordinatorEntity, SensorEntity):
    _attr_has_entity_name = True
    _attr_name = "LAN devices"
    _attr_icon = "mdi:lan"
    def __init__(self, coordinator):
        super().__init__(coordinator)
        self._attr_unique_id = DOMAIN + "_lan_devices"
    @property
    def native_value(self):
        scan = self.coordinator.data.get("scan", {})
        return len({row.get("ip") for row in scan.get("arp", [])} | set(scan.get("live", [])))
    @property
    def extra_state_attributes(self):
        data = self.coordinator.data or {}
        scan = data.get("scan", {})
        return {"proxy_available": data.get("available", False),
                "arp_devices": scan.get("arp", []),
                "live_hosts": scan.get("live", []),
                "proxy_maps": data.get("maps", {}).get("maps", []),
                "recent_dns_queries": data.get("queries", {}).get("queries", []),
                "proxy_status": data.get("status", {})}


class JascoCandidateSensor(CoordinatorEntity, SensorEntity):
    _attr_has_entity_name = True
    _attr_name = "Jasco network candidates"
    _attr_icon = "mdi:power-plug"

    def __init__(self, coordinator):
        super().__init__(coordinator)
        self._attr_unique_id = DOMAIN + "_jasco_candidates"

    @property
    def native_value(self):
        return len(self.extra_state_attributes["candidates"])

    @property
    def extra_state_attributes(self):
        data = self.coordinator.data or {}
        queries = data.get("queries", {}).get("queries", [])
        domains = ("yunext.com", "iotworkshop.com")
        vendor_rows = [row for row in queries if row.get("client")
                       and any(str(row.get("qname", "")).lower().rstrip(".").endswith(domain)
                               for domain in domains)]
        scan = data.get("scan", {})
        candidate_ips = {row.get("client") for row in vendor_rows}
        scanned_ips = {row.get("ip") for row in scan.get("arp", []) if row.get("ip")}
        scanned_ips.update(ip for ip in scan.get("live", []) if ip)
        candidates = []
        arp_by_ip = {row.get("ip"): row for row in data.get("scan", {}).get("arp", [])}
        for ip in sorted(candidate_ips | scanned_ips):
            names = sorted({row.get("qname") for row in vendor_rows if row.get("client") == ip})
            evidence = (["observed Jasco-related DNS query"] if names else [])
            if ip in scanned_ips:
                evidence.append("LAN scan only, identity unverified")
            candidates.append({"ip": ip, **arp_by_ip.get(ip, {}),
                               "observed_names": names, "evidence": evidence,
                               "vendor_match": bool(names)})
        return {"candidates": candidates,
                "disclaimer": "A network scan finds hosts, not device identity. DNS names are leads only."}
