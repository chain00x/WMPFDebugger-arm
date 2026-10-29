// Non-evicting native-protocol diagnostics. No Runtime.evaluate, JS injection,
// HTTP refetch or business API calls. Bodies are NOT printed to the terminal.
import WebSocket from 'ws';
const at = process.argv.indexOf('--body');
const requestId = at >= 0 ? process.argv[at + 1] : null;
const sessionAt = process.argv.indexOf('--session');
const sessionId = sessionAt >= 0 ? process.argv[sessionAt + 1] : null;
if (at >= 0 && !requestId) throw new Error('--body requires the native requestId');
if (sessionAt >= 0 && !sessionId) throw new Error('--session requires the native CDP sessionId');
let received = false;
const ws = new WebSocket('ws://127.0.0.1:62000/?diagnostic=1');
const timer = setTimeout(() => { console.error('Native diagnostic command timed out'); ws.terminate(); process.exitCode = 1; }, 10000);
ws.on('open', () => ws.send(JSON.stringify(requestId
  ? { id: 1, ...(sessionId ? { sessionId } : {}), method: 'Network.getResponseBody', params: { requestId } }
  : { id: 1, method: 'WMPF.getStatus' })));
ws.on('message', raw => {
  const message = JSON.parse(raw.toString());
  if (message.id !== 1) return;
  received = true;
  if (message.error) { console.error(JSON.stringify(message.error)); process.exitCode = 1; }
  else if (requestId) console.log(JSON.stringify({ requestId, bodyReturned: typeof message.result.body === 'string',
    bodyBytes: Buffer.byteLength(message.result.body || ''), base64Encoded: !!message.result.base64Encoded }));
  else console.log(JSON.stringify(message.result, null, 2));
  clearTimeout(timer); ws.close();
});
ws.on('error', e => { clearTimeout(timer); console.error(e.message); process.exitCode = 1; });
ws.on('close', () => { clearTimeout(timer); if (!received) process.exitCode = 1; });
