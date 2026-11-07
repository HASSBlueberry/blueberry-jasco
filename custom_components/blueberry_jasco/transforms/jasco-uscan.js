/* myTS t0.d.e discovery, with fixed-port broadcast and scoped unicast fallback. */
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
    const packet = command => hex([0xa1, device.locked ? 4 : 0, ...mac, 0, 7, 0, 1,
      device.company_code, device.device_type, device.auth_code >> 8, device.auth_code & 255, command]);
    return {device, mac, discovery:packet(0x23), query:packet(0x10)};
  });
  function accept(reply) {
    const bytes = octets(reply?.hex);
    if (bytes.length < 16 || bytes[0] !== 0xa1 || bytes[8] * 256 + bytes[9] !== bytes.length - 10) return;
    for (const frame of frames) {
      const device = frame.device;
      if (found.has(device.mac) || !frame.mac.every((value, index) => bytes[index + 2] === value)) continue;
      if (bytes[12] !== device.company_code || bytes[13] !== device.device_type || bytes[14] * 256 + bytes[15] !== device.auth_code) continue;
      found.add(device.mac);
      ctx.emit({ip:reply.ip, mac:device.mac, ports:[35932], evidence:'myts-discovery-response',services:['myts-local-udp']});
    }
  }
  if (typeof ctx.udpBatch === 'function') {
    const window = Math.min(ctx.parameters.duration_ms || 1500, 1500);
    for (let attempt = 0; attempt < 3 && found.size < frames.length; attempt++) {
      const packets = [];
      for (const ip of ctx.parameters.broadcasts || []) for (const frame of frames) {
        if (!found.has(frame.device.mac)) packets.push({ip,hex:frame.discovery});
      }
      if (packets.length) for (const reply of ctx.udpBatch(35932,packets,window)) accept(reply);
    }
    let packets = [];
    function flush() { if (packets.length) { for (const reply of ctx.udpBatch(35932,packets,Math.min(window,750))) accept(reply); packets = []; } }
    for (const ip of ctx.targets) {
      if (found.size === frames.length) break;
      for (const frame of frames) if (!found.has(frame.device.mac)) {
        packets.push({ip,hex:frame.discovery},{ip,hex:frame.query});
        if (packets.length >= 256) flush();
      }
    }
    flush();
  } else {
    // Compatibility with proxy 0.3.0. HA also runs a fixed-port local probe.
    for (const ip of ctx.targets) {
      for (const frame of frames) if (!found.has(frame.device.mac)) {
        const reply = ctx.udp(ip,35932,frame.discovery);
        if (reply && reply.ip === ip) accept(reply);
      }
      if (found.size === frames.length) break;
    }
  }
}
