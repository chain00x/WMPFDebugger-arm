// Native debug-protocol adapter only. This entry point never imports Frida,
// attaches a process, configures a business proxy or evaluates application JS.
import { createRelay } from './cdp-relay';

function port(flag: string, fallback: number) {
    const i = process.argv.indexOf(flag);
    if (i < 0) return fallback;
    const value = process.argv[i + 1];
    if (!value || !/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535) {
        throw new Error(`${flag} requires a TCP port in 1..65535`);
    }
    return Number(value);
}

const debugPort = port('--debug-port', 9421);
const cdpPort = port('--cdp-port', 62000);
if (debugPort === cdpPort) throw new Error('Debug and CDP ports must differ');
const relay = createRelay({ debugPort, cdpPort });
let stopping = false;
const stop = () => {
    if (stopping) return;
    stopping = true;
    for (const server of [relay.debug, relay.proxy]) for (const ws of server.clients) ws.terminate();
    let remaining = 2;
    for (const server of [relay.debug, relay.proxy]) server.close(() => { if (!--remaining) process.exit(0); });
    setTimeout(() => process.exit(1), 2000).unref();
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
for (const server of [relay.debug, relay.proxy]) server.on('error', e => { console.error(e.message); process.exitCode = 1; stop(); });
console.log(`Native-only relay; no process injection, no wx.request wrappers, no polling.`);
console.log(`WMPF: ws://127.0.0.1:${debugPort}`);
console.log(`DevTools: devtools://devtools/bundled/inspector.html?ws=127.0.0.1:${cdpPort}`);
console.log(`Status: http://127.0.0.1:${cdpPort}/status`);
console.log('Waiting for a runtime already configured for LanDebug. Starting this adapter alone does not enable WeChat debugging.');
