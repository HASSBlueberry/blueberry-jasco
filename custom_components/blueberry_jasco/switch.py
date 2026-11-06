"""Local Jasco GPIO switch control, based on the myTS app's UDP frames."""
from __future__ import annotations

import logging

from homeassistant.components.switch import SwitchEntity
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo

from .const import DOMAIN
from .protocol import JascoDevice, send_command

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, entry, async_add_entities):
    data = entry.data
    required = ("ip", "mac", "company_code", "device_type", "auth_code")
    if not all(data.get(key) not in (None, "") for key in required):
        return
    device = JascoDevice(
        ip=data["ip"], mac=data["mac"], company_code=int(data["company_code"]),
        device_type=int(data["device_type"]), auth_code=int(data["auth_code"]),
    )
    async_add_entities([JascoSwitch(device, int(data.get("pin", 1)), data.get("name", "Jasco switch"))], update_before_add=True)


class JascoSwitch(SwitchEntity):
    """Read GPIO state and control one configured relay pin."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:power-socket-us"

    def __init__(self, device: JascoDevice, pin: int, name: str):
        self._device = device
        self._pin = pin
        self._attr_name = name
        self._attr_unique_id = f"{DOMAIN}_{device.mac.lower().replace(':', '')}_{pin}"
        self._is_on = None
        self._available = False

    @property
    def is_on(self):
        return self._is_on

    @property
    def available(self):
        return self._available

    @property
    def extra_state_attributes(self):
        return {"ip_address": self._device.ip, "mac_address": self._device.mac,
                "pin": self._pin, "transport": "local UDP port 35932"}

    @property
    def device_info(self):
        return DeviceInfo(
            identifiers={(DOMAIN, self._device.mac.lower().replace(":", "").replace("-", ""))},
            name=self._attr_name,
            manufacturer="Jasco",
            model=f"myTouchSmart {self._device.device_type}",
            connections={("mac", self._device.mac.lower().replace("-", ":"))},
        )

    async def async_update(self):
        try:
            result = await self.hass.async_add_executor_job(
                lambda: send_command(self._device, "read_pin", pin=self._pin)
            )
            self._set_state(result)
        except (OSError, ValueError) as err:
            _LOGGER.debug("Jasco GPIO query failed for %s: %s", self._device.ip, err)
            self._available = False

    def _set_state(self, result):
        payload = bytes.fromhex(result.get("payload_hex", ""))
        if result.get("response_timeout") or len(payload) < 3:
            self._available = False
            return
        # The app's GPIO callback reads absolute frame byte 18, payload byte 2.
        if payload[2] not in (0, 255):
            self._available = False
            return
        self._is_on = payload[2] == 255
        self._available = True

    async def async_turn_on(self, **kwargs):
        await self._set_power(True)

    async def async_turn_off(self, **kwargs):
        await self._set_power(False)

    async def _set_power(self, state):
        try:
            await self.hass.async_add_executor_job(
                lambda: send_command(self._device, "set_switch", pin=self._pin, state=state)
            )
            result = await self.hass.async_add_executor_job(
                lambda: send_command(self._device, "read_pin", pin=self._pin)
            )
            self._set_state(result)
            if not self._available:
                raise HomeAssistantError("Jasco device did not return a readable GPIO state")
        except (OSError, ValueError) as err:
            self._available = False
            raise HomeAssistantError(f"Jasco local command failed: {err}") from err
