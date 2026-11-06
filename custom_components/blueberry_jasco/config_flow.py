import voluptuous as vol
from homeassistant.helpers import selector
import ipaddress
from aiohttp import ClientError
from homeassistant import config_entries
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from .const import DOMAIN
from .account import inventory, correlate, discover_local, AccountError
from .app_archive import load_app_material, AppArchiveError
from homeassistant.helpers import config_validation as cv
import logging
from pathlib import Path

_LOGGER = logging.getLogger(__name__)


class BlueberryProxyConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1
    async def async_step_user(self, user_input=None):
        if not self.show_advanced_options:
            return await self.async_step_account(user_input)
        if user_input:
            if user_input['mode'] == 'account':
                return await self.async_step_account()
            return await self.async_step_manual()
        return self.async_show_form(step_id='user', data_schema=vol.Schema({
            vol.Required('mode', default='account'): vol.In({'account': 'Find devices from myTS account', 'manual': 'Advanced local setup'})
        }))

    async def async_step_reconfigure(self, user_input=None):
        self._reconfigure_entry = self.hass.config_entries.async_get_entry(self.context['entry_id'])
        return await self.async_step_account()

    async def async_step_account(self, user_input=None):
        errors = {}
        default_app = self.hass.config.path('.storage', DOMAIN, 'myts.apks')
        source_app = Path(__file__).resolve().parents[2] / 'myTouchSmart_2.9_apkcube.apks'
        if not Path(default_app).is_file() and source_app.is_file():
            default_app = str(source_app)
        existing_urls = [entry.data['url'] for entry in self.hass.config_entries.async_entries()
                         if entry.domain in ('blueberry_jasco', 'blueberry_velux') and entry.data.get('url')]
        default_url = existing_urls[0] if existing_urls else 'http://127.0.0.1:8054'
        phase = 'archive'
        version = getattr(self, '_detected_version', 'not yet read')
        details = ''
        if user_input:
            version = 'not yet read'
            default_app = user_input.get('app_archive') or default_app
            default_url = user_input['url'].strip().rstrip('/')
            try:
                material = await self.hass.async_add_executor_job(load_app_material, default_app)
                self._detected_version = version = material.version
                session = async_get_clientsession(self.hass)
                phase = 'proxy'
                base = default_url
                async with session.get(base + '/status', timeout=8) as response:
                    response.raise_for_status()
                    status = await response.json(content_type=None)
                    if not isinstance(status, dict) or status.get('name') != 'blueberryProxy':
                        raise ValueError('not_blueberry_proxy')
                phase = 'login'
                records = await inventory(session, user_input['username'], user_input['password'], material)
                phase = 'scan'
                async with session.get(base + '/scan', timeout=15) as response:
                    response.raise_for_status()
                    scan = await response.json(content_type=None)
                    if not isinstance(scan, dict) or not isinstance(scan.get('arp', []), list):
                        raise ValueError('invalid_proxy_scan')
                    devices, missing = correlate(records, scan)
                if missing:
                    try:
                        local = await self.hass.async_add_executor_job(discover_local, missing)
                    except OSError:
                        local = []
                    devices.extend(local)
                    local_macs = {device['mac'] for device in local}
                    missing = [device for device in missing if device['mac'] not in local_macs]
                if not records:
                    errors['base'] = 'no_devices'
                elif not devices and not missing:
                    errors['base'] = 'unsupported_inventory'
                elif not devices:
                    errors['base'] = 'no_lan_match'
                else:
                    self._account_data = {'url': base, 'verify_ssl': True, 'cloud_relay': False,
                                          'devices': devices, 'unmatched_devices': missing,
                                          'app_version': material.version}
                    self._account_username = user_input['username'].strip().lower()
                    return await self.async_step_devices()
            except FileNotFoundError:
                errors['base'] = 'app_required'
            except AppArchiveError as err:
                errors['base'] = 'archive_failed'
                details = str(err)
            except AccountError as err:
                errors['base'] = err.stage + '_failed'
                details = str(err)
                _LOGGER.warning('myTS setup failed during %s', err.stage)
            except (ClientError, TimeoutError, OSError, ValueError) as err:
                errors['base'] = phase + '_failed'
                status = getattr(err, 'status', None)
                details = f'{phase.capitalize()} returned HTTP {status}.' if status else f'{phase.capitalize()} failed ({type(err).__name__}).'
                if phase == 'proxy' and str(err) == 'not_blueberry_proxy':
                    details = 'The URL returned a service other than BlueberryProxy.'
                _LOGGER.warning('myTS setup failed during %s (%s)', phase, type(err).__name__)
        return self.async_show_form(step_id='account', data_schema=vol.Schema({
            vol.Required('username', default=(user_input or {}).get('username', '')): str,
            vol.Required('password'): selector.TextSelector({'type': 'password'}),
            vol.Required('url', default=default_url): str,
            vol.Optional('app_archive', default=default_app): str,
        }), errors=errors, description_placeholders={'app_version': str(version), 'details': details})

    async def async_step_devices(self, user_input=None):
        devices = self._account_data['devices']
        choices = {device['mac']: f"{device['name']} ({device['ip']}, type {device['device_type']:02X})" for device in devices}
        if user_input:
            selected = set(user_input['devices'])
            chosen = [device for device in devices if device['mac'] in selected]
            if not chosen:
                return await self.async_step_devices()
            await self.async_set_unique_id('account:' + self._account_username)
            data = {'url': self._account_data['url'], 'verify_ssl': True, 'cloud_relay': False, 'devices': chosen, 'app_version': self._account_data['app_version']}
            if getattr(self, '_reconfigure_entry', None):
                if self._reconfigure_entry.unique_id != self.unique_id:
                    return self.async_abort(reason='wrong_account')
                self.hass.config_entries.async_update_entry(self._reconfigure_entry, data=data)
                await self.hass.config_entries.async_reload(self._reconfigure_entry.entry_id)
                return self.async_abort(reason='reconfigure_successful')
            self._abort_if_unique_id_configured()
            return self.async_create_entry(title='myTS devices', data=data)
        return self.async_show_form(step_id='devices', data_schema=vol.Schema({
            vol.Required('devices', default=list(choices)): cv.multi_select(choices)
        }), description_placeholders={'unmatched': str(len(self._account_data['unmatched_devices']))})

    async def async_step_manual(self, user_input=None):
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
                        return self.async_show_form(step_id="manual", data_schema=self._schema(url, verify_ssl), errors=errors)
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
                            return self.async_show_form(step_id="manual", data_schema=self._schema(url, verify_ssl), errors=errors)
                    if configured:
                        data.update({key: user_input[key] for key in fields})
                        for key in ("company_code", "device_type", "auth_code"):
                            data[key] = int(data[key])
                        data["name"] = user_input.get("name") or "Jasco switch"
                        data["pin"] = int(user_input.get("pin", 1))
                    return self.async_create_entry(title="BlueberryProxy Jasco", data=data)
            except (ClientError, TimeoutError, ValueError):
                errors["base"] = "cannot_connect"
        return self.async_show_form(step_id="manual", data_schema=self._schema("http://127.0.0.1:8054", True), errors=errors)

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
