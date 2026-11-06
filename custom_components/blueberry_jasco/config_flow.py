import voluptuous as vol
import ipaddress
from aiohttp import ClientError
from homeassistant import config_entries
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from .const import DOMAIN

class BlueberryProxyConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1
    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input:
            url = user_input["url"].rstrip("/")
            verify_ssl = user_input["verify_ssl"]
            try:
                async with async_get_clientsession(self.hass).get(url + "/status", timeout=8, ssl=None if verify_ssl else False) as response:
                    response.raise_for_status()
                    status = await response.json()
                if status.get("name") != "blueberryProxy":
                    errors["base"] = "not_blueberry_proxy"
                else:
                    mac = user_input.get("mac", "").strip().lower()
                    fields = ("ip", "mac", "company_code", "device_type", "auth_code")
                    configured = any(user_input.get(field) not in (None, "") for field in fields)
                    if configured and any(user_input.get(field) in (None, "") for field in fields):
                        errors["base"] = "incomplete_device"
                        return self.async_show_form(step_id="user", data_schema=self._schema(url, verify_ssl), errors=errors)
                    await self.async_set_unique_id(url.lower() + ("|" + mac if configured else ""))
                    self._abort_if_unique_id_configured()
                    data = {"url": url, "verify_ssl": verify_ssl}
                    data["cloud_relay"] = bool(user_input.get("cloud_relay", True))
                    data["relay_port"] = int(user_input.get("relay_port", 33491))
                    data["relay_advertise_ip"] = user_input.get("relay_advertise_ip", "").strip()
                    if data["relay_advertise_ip"]:
                        try:
                            address = ipaddress.ip_address(data["relay_advertise_ip"])
                            if address.version != 4 or not address.is_private:
                                raise ValueError("relay address must be a private IPv4 address")
                        except ValueError:
                            errors["base"] = "invalid_relay_address"
                            return self.async_show_form(step_id="user", data_schema=self._schema(url, verify_ssl), errors=errors)
                    if configured:
                        data.update({key: user_input[key] for key in fields})
                        for key in ("company_code", "device_type", "auth_code"):
                            data[key] = int(data[key])
                        data["name"] = user_input.get("name") or "Jasco switch"
                        data["pin"] = int(user_input.get("pin", 1))
                    return self.async_create_entry(title="BlueberryProxy Jasco", data=data)
            except (ClientError, TimeoutError, ValueError):
                errors["base"] = "cannot_connect"
        return self.async_show_form(step_id="user", data_schema=self._schema("http://127.0.0.1:8054", True), errors=errors)

    @staticmethod
    def _schema(url, verify_ssl):
        return vol.Schema({
            vol.Required("url", default=url): str,
            vol.Optional("verify_ssl", default=verify_ssl): bool,
            vol.Optional("cloud_relay", default=True): bool,
            vol.Optional("relay_port", default=33491): vol.All(vol.Coerce(int), vol.Range(min=1, max=65535)),
            vol.Optional("relay_advertise_ip", default=""): str,
            vol.Optional("name", default="Jasco switch"): str,
            vol.Optional("ip", default=""): str,
            vol.Optional("mac", default=""): str,
            vol.Optional("company_code"): vol.Any(int, str),
            vol.Optional("device_type"): vol.Any(int, str),
            vol.Optional("auth_code"): vol.Any(int, str),
            vol.Optional("pin", default=1): vol.All(vol.Coerce(int), vol.Range(min=0, max=255)),
        })
