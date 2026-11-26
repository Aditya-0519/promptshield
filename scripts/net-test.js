// Tests whether THIS computer can open an HTTPS connection to Google's Gemini servers,
// the same way the ABTalks backend does (Node.js, not the browser).
// Usage (from the promptshield folder):  node scripts/net-test.js
const https = require('https');
const http = require('http');

const target = process.argv[2] || 'https://generativelanguage.googleapis.com/';
const url = new URL(target);
const lib = url.protocol === 'https:' ? https : http;
const TIMEOUT_MS = 10000;

// family: 0 = Node default, 4 = IPv4 only, 6 = IPv6 only
function probe(label, family) {
  return new Promise((resolve) => {
    const started = Date.now();
    const req = lib.get(url, { family, timeout: TIMEOUT_MS }, (res) => {
      res.resume();
      res.on('end', () =>
        resolve({ ok: true, text: `${label} OK    (HTTP ${res.statusCode}, ${Date.now() - started} ms)` })
      );
    });
    req.on('timeout', () => req.destroy(new Error(`no answer after ${TIMEOUT_MS / 1000} s`)));
    req.on('error', (err) =>
      resolve({ ok: false, text: `${label} FAIL  (${err.code || err.message}, ${Date.now() - started} ms)` })
    );
  });
}

(async () => {
  console.log(`\nTesting ${target}`);
  console.log(`Node ${process.version}  (each test waits up to ${TIMEOUT_MS / 1000} s)\n`);

  const def = await probe('Default   ', 0);
  console.log(def.text);
  const v4 = await probe('IPv4 only ', 4);
  console.log(v4.text);
  const v6 = await probe('IPv6 only ', 6);
  console.log(v6.text);
  console.log('');

  if (!def.ok && !v4.ok && !v6.ok) {
    console.log('RESULT: this computer cannot reach Google over HTTPS at all.');
    console.log('Likely causes: VPN, proxy, firewall, a campus or hotspot network that blocks or throttles it, or no internet.');
    console.log('Try: turn off any VPN, switch network (for example a different hotspot), then run this again.');
  } else if (v4.ok && !def.ok) {
    console.log('RESULT: IPv4 works but the default path hangs. Your IPv6 route is broken.');
    console.log('Fix: add these two lines at the very top of abtalks-ai-interviewer/server/index.js, then restart the backend:');
    console.log('  import dns from "node:dns";');
    console.log('  dns.setDefaultResultOrder("ipv4first");');
  } else if (def.ok && v4.ok) {
    console.log('RESULT: your connection to Google works. If Gemini still hangs, the delay is on Google\'s side. Try again later.');
  } else {
    console.log('RESULT: mixed. Share these lines and we can work out the next step.');
  }
  console.log('');
})();