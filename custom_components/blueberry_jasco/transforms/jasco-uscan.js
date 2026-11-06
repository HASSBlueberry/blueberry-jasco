/* Read-only myTS account-device queries through UScan's scoped UDP capability. */
function scan(ctx) {
  const devices = ctx.parameters.devices || [];
  const found = new Set();
  function octets(hex) {
    if (!hex || hex.length % 2) return [];
    const result = [];
    for (let i = 0; i < hex.length; i += 2) result.push(parseInt(hex.slice(i, i + 2), 16));
    return result;
  }
  function hex(bytes) { return bytes.map(value => value.toString(16).padStart(2, '0')).join(''); }
  const frames = devices.map(device => {
    const mac = device.mac.split(':').map(value => parseInt(value, 16)).reverse();
    return {device, mac, payload: hex([0xa1, 0, ...mac, 0, 7, 0, 1,
      device.company_code, device.device_type, device.auth_code >> 8, device.auth_code & 255, 0x10])};
  });
  for (const ip of ctx.targets) {
    for (const frame of frames) {
      if (found.has(frame.device.mac)) continue;
      const reply = ctx.udp(ip, 35932, frame.payload);
      if (!reply || reply.ip !== ip) continue;
      const bytes = octets(reply.hex);
      if (bytes.length < 16 || bytes[0] !== 0xa1 || bytes[8] * 256 + bytes[9] !== bytes.length - 10) continue;
      if (!frame.mac.every((value, index) => bytes[index + 2] === value)) continue;
      const device = frame.device;
      if (bytes[12] !== device.company_code || bytes[13] !== device.device_type || bytes[14] * 256 + bytes[15] !== device.auth_code) continue;
      found.add(device.mac);
      ctx.emit({ip, mac: device.mac, ports: [35932], evidence: 'myts-query-response', services: ['myts-local-udp']});
    }
    if (found.size === frames.length) break;
  }
}
