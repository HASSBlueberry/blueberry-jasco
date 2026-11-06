# Jasco myTouchSmart initial reverse engineering

## Simplified Home Assistant setup

Version 0.4 starts with a myTS email/password form and the BlueberryProxy URL.
Supply a copy of your myTS APK or APKS once on the HA filesystem at
`/config/.storage/blueberry_jasco/myts.apks`, or enter its path in setup.
The supplied 2.9 app archive has been checked with the extractor. The
integration reads signing material directly from DEX without running the app
and without embedding the key in Python. It signs the app's login and device
inventory requests, then discards the password, token, and signing key after
setup. Cloud inventory discovery has not been validated with a live account.

Account discovery fills device names, MACs, company codes, device types, and
auth codes. It matches MACs through BlueberryProxy's ARP scan and makes a
bounded, read-only broadcast query for unmatched account devices. Select the
relay switches to add in one step. Only matching account devices become
controllable entities. Types are shown as the app's raw device type codes;
GPIO pin 1 is supported by the simplified path. Dimmers, multiple outputs,
and other product types still need model-specific implementation. Their
presence in the cloud inventory is not proof of supported control.

Use Reconfigure on the account entry to rescan or change the selection.
Restarting the integration refreshes IPs from BlueberryProxy's ARP table.
Advanced setup retains the manual fields and experimental TLS listener. The
simple account path leaves that listener disabled and uses local UDP for
control. Devices absent from the LAN remain unmatched and are not given
invented IP addresses or usable-looking controls.

## Advanced local integration

The `custom_components/blueberry_jasco` package connects to BlueberryProxy's
admin API. It reports LAN scan results, recent DNS queries, proxy maps and
service health, and registers the Jasco request and response GraalJS scripts.
Install the directory as `custom_components/blueberry_jasco` in Home Assistant
and add it through the integration UI. The integration now starts a vendor
specific TLS listener on port `33491` by default. It answers the app's `0x81`
balance request with the configured or detected LAN address, accepts its
`0x82` work-server login without storing the token or account credentials, and
relays framed device commands to manually configured LAN devices over UDP.
This is modeled on the app's TLS listener path, not on BlueberryProxy. It
generates a persistent self-signed `myts.yunext.com` certificate. The APK's
TCP client uses a trust-all TLS manager, so it does not validate that
certificate. Redirect TCP port `33491` to this listener. A DNS override affects
all ports for the hostname, so keep the separate REST API on port `443` routed
to the vendor service, either with a port-aware passthrough route or a firewall
redirect that targets only the relay port.

Supplying a device IP, MAC, company code, device type and auth code creates a
stateful local switch for one GPIO pin and adds that MAC to the TCP relay map.
Add one integration entry per device, using the same relay port, to build a
manual device map. The switch polls with the APK-observed pin read and uses
the returned byte at frame offset 18 as its state. The integration also
offers `blueberry_jasco.send_local_command` for observed query, pin-read,
refresh and relay-write frames. `send_local_login` remains an optional direct
UDP diagnostic service, and credentials are not stored. No live hardware
capture has confirmed the decoded identifiers or behavior across device
models.

Use the standard Home Assistant Jasco integration for Jasco Z-Wave products
with a Z-Wave controller. That path is local and is maintained separately from
this myTouchSmart Wi-Fi work. For myTS Wi-Fi products, the vendor's myTS app is
the supported remote-control path. The account API here supplies inventory for setup; remote cloud command transport
is not yet implemented. If the local UDP or relay path cannot be made to work, retain
control in the vendor app rather than treating this experimental TLS server as
a supported provider replacement.

Target APK archive is `myTouchSmart_2.9_apkcube.apks`, package `com.bugull.socket.myts`, version code 29. `base.apk` was decoded with apktool to inspect the manifest and Smali. The manifest grants Internet, Wi-Fi state and multicast state permissions, and the app permits cleartext traffic.

The first useful protocol clue is `com.bugull.socket.myts.communication.network.ap.ApLinkServFind`. It calls `http://find.device.iotworkshop.com:8028/web?aplink=<url-encoded value>`, sends `accept: text/plain;charset=utf-8`, and uses a legacy browser user agent. The `aplink` parameter is Base64 around AES-CBC encrypted and zero padded UTF-8. Its key and IV material is derived from the MD5 digest of the phone's local IP concatenated with the access point SSID. The fixed 16-byte service key `` `aPliNkseRViCe$' `` is used by the separate service lookup helper.

The AP configuration path is clearer now. `ApLinker.sendApCommand` POSTs to `http://<AP address>/` up to five times. `ApLinkHttper` serializes an `ApLinkCommand` JSON object, encrypts it with the AP SSID and local IP derived key, and decodes an encrypted response. Config command ID `0x7535` carries `PL` with `SSID`, `Password`, and `Userdata`; response ID is `0x7536`. Restart uses IDs `0x7537` and `0x7538`. This is AP onboarding traffic, not yet evidence for the plug's normal LAN control API. The app chooses the AP address from the Wi-Fi connection and uses the device SSID in its encryption key.

The normal local protocol is present in the app too. `t0.c.a` builds a 16-byte `0xA1` frame header with a Wi-Fi lock flag, six MAC bytes in least-significant-byte-first order, a big-endian length equal to payload size plus six, a 15-bit protocol index, and company, device-type, and auth-code fields. The app transports UDP frames directly to the device on port 35932. Its TCP transport uses the app-managed TLS work server at `myts.yunext.com:33491`, rather than a direct TCP connection to the device. `t0.a.p` builds relay writes with payload `{0x01, pin, 0xff|0x00}`. `t0.a.h` queries a pin with `{0x02, pin}`. `0x08` is a countdown query, not the relay write command. The SRE-owned `custom_components/blueberry_jasco/protocol.py` implements the local frame and UDP transport. The login builder `t0.b.c` uses an all-zero device header, username suffixed with `_MYTS`, a length-prefixed password and trailing status byte. The integration exposes this as an optional local service and does not persist credentials.

The app's cloud relay path is a TLS client to the balance server on port 33491. It sends a `0x81` balance request, receives a work-server address, then authenticates that server with a `0x82` frame containing a token, account name, password and `MYTS` marker. The SRE listener answers both handshake steps, discards account fields, and routes device frames using the manually configured MAC to LAN address map. Device registration frames are accepted without cloud registration. The work-server and direct UDP paths use the app's same framed device protocol, so schedules and relay commands are forwarded to the device. This implementation still needs validation against a live device and app session.

The AP configuration API and local frame protocol are distinct. The next step is to capture a known device's MAC, company code, device type, auth code, login exchange, and state response. Capture only an owned device on the home LAN. No live device traffic has been captured yet, so the frame layout is grounded in app code while command behavior remains provisional.

## Full decompilation artifacts

- `apktool d` output (decoded `AndroidManifest.xml`, `res/`, `smali/`, `assets/`): `decompiled/apktool/`
- `jadx` output (2970 Java sources): `decompiled/jadx/sources/`
- `aapt2 dump badging`: package `com.bugull.socket.myts`, versionName 2.9 / versionCode 29, minSdk 21, targetSdk 33, compileSdk 33, launch activity `com.bugull.socket.myts.ui.activity.login.SplashActivity`, label `myTS`.

Permissions of interest for device discovery: `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION`, `CHANGE_WIFI_STATE`, `ACCESS_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE`, `NEARBY_WIFI_DEVICES`, `INTERNET`.

## Network endpoints

| Endpoint | Purpose | Source |
|---|---|---|
| `https://myts.yunext.com/` | production REST API base (Retrofit interface `g1.a`, paths under `/api/app/...`, `/api/service/...`) | `g1/a.java`, `s0/b.java` |
| `https://hdg-sandbox.yunext.com` | sandbox API base, toggled by debug flag `e2.l.f7437d` | `g1/a.java` |
| `http://find.device.iotworkshop.com:8028/web?aplink=...` | AP-provisioning device finder (AES+Base64 payload) | `ApLinkServFind.java` |
| `http://hengdagao-test.yunext.com/uploadedFile/*.bin` | firmware upgrade images for several device types | `e2/l.java` |
| `http://userdata.link2home.com/uploadedFile/*.bin` | firmware images (LPT220 variant) | `e2/l.java` |
| `https://mytouchsmart.com`, `https://byjasco.com` | marketing/support links | `TermsOfServiceActivity`, `PrivacyActivity` |

All of these are candidates for BlueberryProxy DNS overrides: pin `myts.yunext.com` and `find.device.iotworkshop.com` at a local mock to keep devices off the cloud during development.

## LAN / provisioning protocol

- **SmartLink provisioning** (hiflying `com.hiflying.smartlink`): UDP broadcast to `255.255.255.255:48899` (`PORT_SEND_SMART_LINK_FIND`), smartconfig replies received on `49999`, multicast send action on port `6000`.
- **AP-mode provisioning**: `ApLinkUdpSender` talks to the device's AP IP over **UDP port 48888**, sending AES-encrypted JSON (`ApLinkEncrypter`/`AESCrypt`, same key as the finder service),5 s socket timeout, response decrypted and parsed with fastjson.
- **Local control**: `q0` package is a UDP transport (`DatagramSocket` map keyed by port, `UdpReceiver` logging `start udp receiver: <port>`); `m0.i` surfaces `LocalNetworkEvent{networkCode, localPort}` states (`LOCAL_SOCKET_CONNECTED/DISCONNECTED/CONNECT_FAILED/ERROR`). Device port comes from the per-device record (`WifiDevice.protocolIndex`, `localIpAddress`, `tcpOnline`/`udpOnline`).
- **Command framing** (`t0.c.a`): every local command is a 16-byte header plus payload:

  | Offset | Field |
  |---|---|
  | 0 | magic `0xA1` |
  | 1 | flags (`0x04` when Wi-Fi locked) |
  | 2-7 | device MAC, wire order is LSB first: display `aa:bb:cc:dd:ee:ff` goes on the wire as `ff ee dd cc bb aa` (`r0.c.g`/`r0.c.h`) |
  | 8-9 | length (payload + 6), big-endian |
  | 10-11 | protocol index / sequence (0-32767) |
  | 12 | company code |
  | 13 | device type |
  | 14-15 | auth code |
  | 16.. | payload: command byte + arguments (for example `{1, pin, 0xff}` or `{2, pin}`) |

  `t0.b` additionally builds a login-style payload (`<user>_MYTS` length-prefixed strings, command `0x88`).

- **Transports**: direct local UDP uses port `35932` (`q0.c...f(localIpAddress, 35932, frame)`). The app TCP path uses its authenticated work-server connection at `myts.yunext.com:33491` when the device record reports `tcpOnline`.

- **Payload command bytes** (from the `t0.a` builders; pin/level semantics follow `SocketStates`, verify against live traffic):

  | Cmd | Layout | Builder |
  |---|---|---|
  | `0x01` | `[pin, 0xff\|0x00]` relay write | `t0.a.p` |
  | `0x02` | `[pin]` read pin state | `t0.a.h` |
  | `0x04` | 15-byte schedule block | `t0.a.r` |
  | `0x05` | `[pin, on]` + extras | `t0.a.k` |
  | `0x06` | `[pin, on, x]` | `t0.a.d` |
  | `0x07` | `[pin, on, level, flag, flag]` + bytes | `t0.a.m` |
  | `0x08` | `[pin, on, 0]` countdown query | `t0.a.e` (DeviceBehavior) |
  | `0x09` | `[pin, on, level]` | `t0.a.c` |
  | `0x0B` | `[pin, on]` | `t0.a.j` |
  | `0x0F` | `[u16 idx][len s][s]` ×3 countdown | `t0.a.n` |
  | `0x10` | `[]` query all state | `t0.a.f` |
  | `0x11` | `[pin, !on]` | `t0.a.q` |
  | `0x12` | `[pin]` | `t0.a.i` |
  | `0x14` | `[]` refresh all | `t0.a.l` |
  | `0x86` | `[on, 3, idx]` | `t0.a.s`/`t0.a.t` |
  | `0x88` | login (see `t0.b`) | `t0.b.c` |
  | `0xC3` | `[idx]` | `t0.a.o` |
  | `0xC4` | `[]` | `t0.a.g` |

- **Local implementation**: `custom_components/blueberry_jasco/protocol.py` encodes and decodes frames, emits the observed query/read/write payloads, and sends directly to the local device over UDP. It is deliberately kept in this integration tree.

## Local control workflow

The integration registers protocol commands without registering a device. Use the proxy's `LAN devices` sensor to correlate ARP entries with DNS clients that queried `yunext.com` or `iotworkshop.com`. These are candidates, not positive device identification. Obtain MAC, company code, device type, and auth code from the app's device record or a local capture, then call `blueberry_jasco.send_local_command` with `query_state`. Use `set_switch` only after confirming the target and supply `confirm_control: true`. The result event is `blueberry_jasco_command_result`, with payload bytes kept as hex for protocol analysis.

If the device requires app authentication, call `blueberry_jasco.send_local_login` with the account username and password. The username suffix and zero-filled login header match `t0.b.c` and `t0.c.a`. Credentials are not saved by this component. The service has not been validated against a live device, so a timeout is recorded as no response rather than interpreted as a protocol failure.

The next reverse-engineering step is to capture an owned device's `0x88`, `0x10`, and `0x14` exchange, then decode returned state bytes before adding state entities. The APK exposes command builders, but field meanings still need live confirmation.


## TCP relay distinction

The APK `procedure.e` initializes a remote work-server address at `myts.yunext.com:33491`. `procedure.d` sends device commands through that established connection when `WifiDevice.tcpOnline` is true, then uses `q0` UDP to the device IP on port 35932 when UDP is available. A direct TCP connection to `<device-ip>:35932` would not reproduce the app's TCP route, so this integration does not make one.
