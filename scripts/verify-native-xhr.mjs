// Observe authentic runtime XHR/Fetch messages via a non-evicting diagnostic
// connection. Never issues a business request; body lookup uses native protocol.
// Prints only ids/types/counts/length, not URLs, headers or response contents.
import WebSocket from 'ws';
const ws = new WebSocket('ws://127.0.0.1:62000/?diagnostic=1');
const types = {}, sessions = new Set(['']);
let seq = 10, selected, bodyCommand, status, done = false;
const send = (method, params = {}, sessionId = '', id = ++seq) => {
  ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) })); return id;
};
const subscribe = session => { if (sessions.has(session)) return; sessions.add(session); send('Network.enable', {}, session); };
const timer = setTimeout(() => {
  done = true;
  console.log(JSON.stringify({ realRuntime: true, xhrObserved: !!selected, bodyVerified: false, requestTypes: types,
    reason: selected ? 'No matching native body response before deadline' : 'No original XHR/Fetch requestWillBeSent observed', status }));
  process.exitCode = 1; ws.terminate();
}, 20000);
ws.on('open', () => { send('Network.enable'); send('WMPF.getStatus', {}, '', 1); });
ws.on('message', raw => {
  const m = JSON.parse(raw.toString());
  if (m.id === 1) {
    status = m.result;
    for (const s of status?.networkSessions || []) subscribe(s);
    return;
  }
  if (m.method === 'Target.attachedToTarget' && m.params?.sessionId) subscribe(m.params.sessionId);
  if (m.method === 'Network.requestWillBeSent') {
    const p = m.params;
    types[p.type || 'unspecified'] = (types[p.type || 'unspecified'] || 0) + 1;
    if (!selected && ['XHR', 'Fetch'].includes(p.type)) selected = { requestId: p.requestId, sessionId: m.sessionId || '' };
  }
  if (selected && m.method === 'Network.loadingFinished' && m.params?.requestId === selected.requestId &&
      (m.sessionId || '') === selected.sessionId && !bodyCommand) {
    bodyCommand = send('Network.getResponseBody', { requestId: selected.requestId }, selected.sessionId);
  }
  if (bodyCommand && m.id === bodyCommand) {
    const verified = typeof m.result?.body === 'string';
    console.log(JSON.stringify({ realRuntime: true, xhrObserved: true, bodyVerified: verified, ...selected,
      bodyBytes: verified ? Buffer.byteLength(m.result.body) : undefined,
      base64Encoded: verified ? !!m.result.base64Encoded : undefined, error: m.error, requestTypes: types }));
    done = true; clearTimeout(timer); if (!verified) process.exitCode = 1; ws.close();
  }
});
ws.on('error', e => { done = true; clearTimeout(timer); console.error(e.message); process.exitCode = 1; });
ws.on('close', () => {
  clearTimeout(timer);
  if (!done) { console.error('Native connection closed before XHR/body verification completed'); process.exitCode = 1; }
});
