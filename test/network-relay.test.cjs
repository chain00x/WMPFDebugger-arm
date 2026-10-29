const { test } = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const WebSocket = require('ws');
const { CdpRelay } = require('../src/cdp-relay.ts');
const codex = require('../src/third-party/RemoteDebugCodex.js');
const pb = require('../src/third-party/WARemoteDebugProtobuf.js').mmbizwxadevremote;
const delay = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, msg = 'condition not met') {
  const end = Date.now() + 2000;
  while (!fn()) { if (Date.now() > end) throw new Error(msg); await delay(5); }
}
const request = (id = '1.7') => ({ method: 'Network.requestWillBeSent', params: {
  requestId: id, request: { url: 'https://example.invalid/native', method: 'POST', headers: { 'Content-Type': 'application/json' }, postData: '{"test":true}' },
  timestamp: 1700000000, type: 'XHR', documentURL: 'https://servicewechat.com',
} });
const response = (id = '1.7') => ({ method: 'Network.responseReceived', params: {
  requestId: id, timestamp: 1700000000.1, type: 'XHR', response: {
    url: 'https://example.invalid/native', status: 200, statusText: 'OK', headers: { 'Content-Type': 'application/json' }, mimeType: 'application/json',
  },
} });
const finished = (id = '1.7') => ({ method: 'Network.loadingFinished', params: { requestId: id, timestamp: 1700000000.2, encodedDataLength: 4 } });

// A native-protocol fixture ONLY; no JS instrumentation, wx implementation,
// Frida, HTTP requests or business endpoints are used by any test.
async function fixture(t, options = {}) {
  const logs = [];
  const relay = new CdpRelay({ debugPort: 0, cdpPort: 0, timeoutMs: 100, log: s => logs.push(s), ...options });
  await Promise.all([once(relay.debug, 'listening'), once(relay.proxy, 'listening')]);
  const debugUrl = `ws://127.0.0.1:${relay.debug.address().port}`;
  const cdpUrl = `ws://127.0.0.1:${relay.proxy.address().port}`;
  t.after(async () => {
    for (const server of [relay.debug, relay.proxy]) for (const c of server.clients) c.terminate();
    await Promise.all([new Promise(r => relay.debug.close(r)), new Promise(r => relay.proxy.close(r))]);
  });
  async function peer(diagnostic = false) {
    const ws = new WebSocket(cdpUrl + (diagnostic ? '/?diagnostic=1' : ''));
    const messages = [];
    ws.on('message', raw => messages.push(JSON.parse(raw.toString())));
    await once(ws, 'open');
    return { ws, messages, send: m => ws.send(JSON.stringify(m)) };
  }
  async function applet(settings = {}) {
    const commands = [], seqs = [];
    const ws = new WebSocket(debugUrl);
    function emit(msg, transport = 'cdp', extras = {}) {
      let category, data;
      if (transport === 'cdp') {
        category = 'chromeDevtoolsResult';
        data = pb.WARemoteDebug_ChromeDevtoolsResult.encode({ payload: JSON.stringify(msg), ...extras }).finish();
      } else if (transport === 'custom') {
        category = 'customMessage';
        data = pb.WARemoteDebug_CustomMessage.encode({ method: '__networkDebug', payload: JSON.stringify(msg) }).finish();
      } else {
        category = 'domEvent';
        data = pb.WARemoteDebug_DomEvent.encode({ webviewId: extras.webviewId || 100,
          params: JSON.stringify(extras.callbackID != null
            ? { command: 'DEBUGGEE_CALLBACK', callbackID: extras.callbackID, data: msg }
            : { command: 'DEBUGGEE_EVENT', data: msg }) }).finish();
      }
      ws.send(pb.WARemoteDebug_DebugMessage.encode({ seq: 1, category, data, compressAlgo: 0 }).finish());
    }
    ws.on('message', raw => {
      const env = pb.WARemoteDebug_DebugMessage.decode(raw);
      seqs.push(env.seq);
      const d = codex.unwrapDebugMessageData(env).data;
      const m = env.category === 'chromeDevtools' ? JSON.parse(d.payload) : d;
      commands.push({ category: env.category, ...m });
      if (settings.onCommand?.(env.category, m, emit) === false) return;
      if (env.category === 'chromeDevtools') {
        emit({ id: m.id, ...(m.sessionId ? { sessionId: m.sessionId } : {}), result: m.method === 'Network.getResponseBody' ? { body: 'from-cdp', base64Encoded: false } : {} });
      } else if (env.category === 'customMessage' && m.method === '__getNetworkResponseBody') {
        const p = JSON.parse(m.payload);
        emit({ id: p.devtoolsMsgId, result: { body: settings.body ?? 'from-custom', base64Encoded: settings.base64 ?? false } }, 'custom');
      } else if (env.category === 'domOp') {
        const p = JSON.parse(m.params);
        emit({ result: { body: 'from-dom', base64Encoded: false } }, 'dom', { callbackID: p.callbackID, webviewId: m.webview_id });
      }
    });
    await once(ws, 'open');
    return { ws, emit, commands, seqs };
  }
  return { relay, logs, peer, applet, cdpUrl };
}

test('idle native relay sends zero evaluations, probes, polling or unsolicited commands', async t => {
  const f = await fixture(t); const a = await f.applet(); await delay(250);
  assert.equal(a.commands.length, 0);
  assert.equal(f.relay.status().mode, 'native-only');
});

test('native events replay AFTER Network.enable, even if inspector Network.enable never replies', async t => {
  const f = await fixture(t);
  const a = await f.applet({ onCommand: (_, m) => m.method !== 'Network.enable' });
  for (const ev of [request(), response(), finished()]) a.emit(ev, 'custom');
  await until(() => f.relay.status().bufferedEvents === 3);
  const p = await f.peer();
  assert.equal(p.messages.length, 0);
  p.send({ id: 1, method: 'Network.enable' });
  await until(() => p.messages.some(m => m.method === 'Network.loadingFinished'));
  assert.deepEqual(p.messages[0], { id: 1, result: {} });
  assert.equal(p.messages.find(m => m.method === 'Network.requestWillBeSent').params.request.url, request().params.request.url);
  p.send({ id: 2, method: 'Network.enable' });
  await until(() => p.messages.some(m => m.id === 2));
  assert.equal(p.messages.filter(m => m.method === 'Network.requestWillBeSent').length, 1, 'repeat enable must not replay twice');
});

test('native getResponseBody uses official custom-message task/API mapping and correct response channel', async t => {
  const f = await fixture(t); const a = await f.applet(); const p = await f.peer();
  a.emit(request('1.72'), 'custom'); await until(() => f.relay.status().nativeRequests === 1);
  p.send({ id: 9, method: 'Network.getResponseBody', params: { requestId: '1.72' } });
  await until(() => p.messages.some(m => m.id === 9));
  assert.deepEqual(p.messages.find(m => m.id === 9).result, { body: 'from-custom', base64Encoded: false });
  const c = a.commands.find(c => c.category === 'customMessage');
  const payload = JSON.parse(c.payload);
  assert.equal(c.method, '__getNetworkResponseBody'); assert.equal(payload.id, '72'); assert.equal(payload.api, 'request');
  assert.notEqual(payload.devtoolsMsgId, 9, 'frontend ids must be remapped');
  assert.equal(a.commands.some(c => c.method === 'Runtime.evaluate'), false);
});

for (const [prefix, api] of [['2', 'download'], ['3', 'upload'], ['4', 'socket']]) {
  test(`native ${api} response-body mapping is ${prefix}.task`, async t => {
    const f = await fixture(t); const a = await f.applet(); const p = await f.peer();
    a.emit(request(prefix + '.88'), 'custom'); await until(() => f.relay.status().nativeRequests === 1);
    p.send({ id: 1, method: 'Network.getResponseBody', params: { requestId: prefix + '.88' } });
    await until(() => p.messages.some(m => m.id === 1));
    assert.equal(JSON.parse(a.commands[0].payload).api, api);
  });
}

for (const body of ['', 'AAECAw==']) {
  test(`native body preserves ${body === '' ? 'empty text' : 'base64'} without fabricating data`, async t => {
    const f = await fixture(t); const a = await f.applet({ body, base64: body !== '' }); const p = await f.peer();
    a.emit(request(), 'custom'); await until(() => f.relay.status().nativeRequests === 1);
    p.send({ id: 7, method: 'Network.getResponseBody', params: { requestId: '1.7' } });
    await until(() => p.messages.some(m => m.id === 7));
    assert.deepEqual(p.messages.find(m => m.id === 7).result, { body, base64Encoded: body !== '' });
  });
}

test('CDP-native and webview DomOp body retrieval retain their own transport', async t => {
  const f = await fixture(t); const a = await f.applet(); const p = await f.peer();
  a.emit(request('cdp-rid')); a.emit(request('dom-rid'), 'dom');
  await until(() => f.relay.status().nativeRequests === 2);
  p.send({ id: 1, method: 'Network.getResponseBody', params: { requestId: 'cdp-rid' } });
  p.send({ id: 2, method: 'Network.getResponseBody', params: { requestId: 'dom-rid' } });
  await until(() => p.messages.some(m => m.id === 1) && p.messages.some(m => m.id === 2));
  assert.equal(p.messages.find(m => m.id === 1).result.body, 'from-cdp');
  assert.equal(p.messages.find(m => m.id === 2).result.body, 'from-dom');
});

test('native request postData is served from received event, not re-requested from business API', async t => {
  const f = await fixture(t); const a = await f.applet(); const p = await f.peer();
  a.emit(request(), 'custom'); await until(() => f.relay.status().nativeRequests === 1);
  p.send({ id: 1, method: 'Network.getRequestPostData', params: { requestId: '1.7' } });
  await until(() => p.messages.some(m => m.id === 1));
  assert.equal(p.messages[0].result.postData, '{"test":true}'); assert.equal(a.commands.length, 0);
});

test('body timeout returns an explicit error; reconnect permits the same request id', async t => {
  const f = await fixture(t); const a = await f.applet({ onCommand: () => false }); const p = await f.peer();
  a.emit(request(), 'custom'); await until(() => f.relay.status().nativeRequests === 1);
  p.send({ id: 1, method: 'Network.getResponseBody', params: { requestId: '1.7' } });
  await until(() => p.messages.some(m => m.id === 1));
  assert.match(p.messages.find(m => m.id === 1).error.message, /native runtime did not reply/);
  const a2 = await f.applet(); a2.emit(request(), 'custom'); await until(() => f.relay.status().nativeRequests === 1 && f.relay.status().generation >= 2);
  p.send({ id: 2, method: 'Network.getResponseBody', params: { requestId: '1.7' } });
  await until(() => p.messages.some(m => m.id === 2));
  assert.equal(p.messages.find(m => m.id === 2).result.body, 'from-custom');
});

test('diagnostic peer preserves controller; frontend reconnect/reused ids cannot cross-route', async t => {
  const f = await fixture(t); const a = await f.applet(); const p = await f.peer(); const d = await f.peer(true);
  d.send({ id: 1, method: 'WMPF.getStatus' }); await until(() => d.messages.some(m => m.id === 1));
  assert.equal(p.ws.readyState, WebSocket.OPEN);
  p.send({ id: 1, method: 'Runtime.evaluate', params: { expression: '1+1', contextId: 42, returnByValue: true } });
  await until(() => p.messages.some(m => m.id === 1));
  const p2 = await f.peer(); p2.send({ id: 1, method: 'Runtime.evaluate', params: { expression: '2+2', contextId: 43 } });
  await until(() => p2.messages.some(m => m.id === 1));
  const evals = a.commands.filter(c => c.method === 'Runtime.evaluate');
  assert.equal(evals[0].params.contextId, 42); assert.equal(evals[1].params.contextId, 43);
  assert.notEqual(evals[0].id, evals[1].id);
  assert.ok(a.seqs.every((v, i) => !i || v > a.seqs[i - 1]));
});

test('bare ACK, malformed payload and stale results are never forwarded as CDP events', async t => {
  const f = await fixture(t); const a = await f.applet(); const p = await f.peer();
  a.emit({}); a.emit({ id: 999, result: {} }); a.emit(null); a.emit(request(), 'custom');
  await until(() => f.relay.status().nativeRequests === 1);
  assert.equal(p.messages.length, 0);
});

test('history is bounded and preserves raw native event fields', async t => {
  const f = await fixture(t, { historyLimit: 3 }); const a = await f.applet(); const p = await f.peer();
  for (let n = 0; n < 5; n++) a.emit(request('1.' + n), 'custom');
  await until(() => f.relay.status().nativeRequests === 5);
  assert.equal(f.relay.status().bufferedEvents, 3);
  p.send({ id: 1, method: 'Network.enable' }); await until(() => p.messages.length >= 4);
  assert.deepEqual(p.messages.slice(1, 4).map(m => m.params.requestId), ['1.2', '1.3', '1.4']);
  assert.equal(p.messages[1].params.timestamp, 1700000000);
});

test('frontend may subscribe before applet connects; enable is replayed once, not polled', async t => {
  const f = await fixture(t); const p = await f.peer();
  p.send({ id: 1, method: 'Network.enable' }); await until(() => p.messages.some(m => m.id === 1));
  const a = await f.applet(); a.emit(request(), 'custom');
  await until(() => p.messages.some(m => m.method === 'Network.requestWillBeSent'));
  await delay(150);
  assert.equal(a.commands.filter(m => m.method === 'Network.enable').length, 1);
  assert.equal(a.commands.some(m => m.method === 'Runtime.evaluate'), false);
});


test('flattened child CDP session keeps Network.enable, events and body replies in that session', async t => {
  const f = await fixture(t); const a = await f.applet(); const p = await f.peer();
  const sessionId = 'child-session-A';
  a.emit({ ...request('child-rid'), sessionId });
  await until(() => f.relay.status().nativeRequests === 1);
  p.send({ id: 1, method: 'Network.enable' });
  await until(() => p.messages.some(m => m.id === 1));
  // Root subscription now covers child-target sessions (single-target DevTools).
  await until(() => p.messages.some(m => m.method === 'Network.requestWillBeSent'));
  assert.equal(p.messages.filter(m => m.method === 'Network.requestWillBeSent').length, 1, 'child request replays exactly once to root');
  p.send({ id: 1, method: 'Network.enable', sessionId });
  await until(() => p.messages.some(m => m.id === 1 && m.sessionId === sessionId));
  await delay(80);
  assert.equal(p.messages.filter(m => m.method === 'Network.requestWillBeSent').length, 1, 'no duplicate replay after explicit child enable');
  await until(() => a.commands.some(m => m.method === 'Network.enable' && m.sessionId === sessionId));
  p.send({ id: 2, method: 'Network.getResponseBody', sessionId, params: { requestId: 'child-rid' } });
  await until(() => p.messages.some(m => m.id === 2));
  assert.equal(p.messages.find(m => m.id === 2).sessionId, sessionId);
  assert.equal(p.messages.find(m => m.id === 2).result.body, 'from-cdp');
  assert.equal(a.commands.find(m => m.method === 'Network.getResponseBody').sessionId, sessionId);
});

test('same requestId in root and child sessions does not mix body transports or POST data', async t => {
  const f = await fixture(t); const a = await f.applet(); const p = await f.peer();
  a.emit(request('1.7'), 'custom');
  const child = request('1.7'); child.params.request.postData = 'child-post';
  a.emit({ ...child, sessionId: 'child' });
  await until(() => f.relay.status().nativeRequests === 2);
  p.send({ id: 1, method: 'Network.getResponseBody', params: { requestId: '1.7' } });
  p.send({ id: 2, method: 'Network.getResponseBody', sessionId: 'child', params: { requestId: '1.7' } });
  p.send({ id: 3, method: 'Network.getRequestPostData', sessionId: 'child', params: { requestId: '1.7' } });
  await until(() => p.messages.some(m => m.id === 1) && p.messages.some(m => m.id === 2) && p.messages.some(m => m.id === 3));
  assert.equal(p.messages.find(m => m.id === 1).result.body, 'from-custom');
  assert.equal(p.messages.find(m => m.id === 2).result.body, 'from-cdp');
  assert.equal(p.messages.find(m => m.id === 3).result.postData, 'child-post');
});

test('generic frontend commands retain sessionId and contextId; wrong-session native response is ignored', async t => {
  const f = await fixture(t);
  let complete;
  const a = await f.applet({ onCommand: (_, m, emit) => {
    if (m.method !== 'Runtime.evaluate') return;
    emit({ id: m.id, result: { result: { value: 'wrong-root' } } });
    complete = () => emit({ id: m.id, sessionId: m.sessionId, result: { result: { value: 'correct-child' } } });
    return false;
  } });
  const p = await f.peer();
  p.send({ id: 7, sessionId: 'child', method: 'Runtime.evaluate', params: { expression: '1+1', contextId: 42 } });
  await until(() => complete);
  await delay(15); assert.equal(p.messages.some(m => m.id === 7), false);
  complete(); await until(() => p.messages.some(m => m.id === 7));
  assert.equal(p.messages[0].result.result.value, 'correct-child');
  assert.equal(p.messages[0].sessionId, 'child');
  assert.equal(a.commands[0].params.contextId, 42);
});


test('networkDebugAPI with a native URL becomes one XHR and issues no evaluate', async t => {
  const f = await fixture(t); const p = await f.peer(); const a = await f.applet();
  p.send({ id: 1, method: 'Network.enable' });
  await until(() => p.messages.some(m => m.id === 1));
  f.relay.receive('networkDebugAPI', {
    api_name: 'request', task_id: '44', request_headers: JSON.stringify({ Referer: 'https://servicewechat.com/app' }),
    url: 'https://bank.example/apply', timestamp: 1700000000000,
  });
  await until(() => p.messages.some(m => m.method === 'Network.requestWillBeSent'));
  const ev = p.messages.find(m => m.method === 'Network.requestWillBeSent');
  assert.equal(ev.params.requestId, '1.44');
  assert.equal(ev.params.request.url, 'https://bank.example/apply');
  assert.equal(ev.params.documentURL, 'https://servicewechat.com/app');
  assert.equal(a.commands.some(c => c.method === 'Runtime.evaluate'), false);
  assert.equal(f.relay.status().nativeRequests, 1);
});

test('networkDebugAPI without a URL is counted and never fabricated', async t => {
  const f = await fixture(t); const p = await f.peer(); const a = await f.applet();
  p.send({ id: 1, method: 'Network.enable' });
  await until(() => p.messages.some(m => m.id === 1));
  f.relay.receive('networkDebugAPI', { api_name: 'request', task_id: '45', request_headers: '{}' });
  await delay(50);
  assert.equal(p.messages.some(m => m.method === 'Network.requestWillBeSent'), false);
  assert.equal(f.relay.status().categories.networkDebugApiWithoutUrl, 1);
  assert.equal(f.relay.status().nativeRequests, 0);
  assert.equal(a.commands.some(c => c.method === 'Runtime.evaluate'), false);
});

test('a native response URL is shown when requestWillBeSent never arrived', async t => {
  const f = await fixture(t); const p = await f.peer(); const a = await f.applet();
  p.send({ id: 1, method: 'Network.enable' });
  await until(() => p.messages.some(m => m.id === 1));
  a.emit({ method: 'Network.responseReceived', params: { requestId: '1.9', timestamp: 10, type: 'XHR', response: { url: 'https://bank.example/apply', status: 200, headers: {} } } }, 'custom');
  await until(() => p.messages.some(m => m.method === 'Network.requestWillBeSent'));
  const sent = p.messages.filter(m => m.method?.startsWith('Network.'));
  assert.equal(sent[0].method, 'Network.requestWillBeSent');
  assert.equal(sent[0].params.request.url, 'https://bank.example/apply');
  assert.equal(sent[1].method, 'Network.responseReceived');
  assert.equal(f.relay.status().nativeRequests, 1);
  assert.equal(a.commands.some(c => c.method === 'Runtime.evaluate'), false);
});

test('a response without a URL does not invent a request', async t => {
  const f = await fixture(t); const p = await f.peer(); const a = await f.applet();
  p.send({ id: 1, method: 'Network.enable' });
  await until(() => p.messages.some(m => m.id === 1));
  a.emit({ method: 'Network.responseReceived', params: { requestId: '1.8', response: { status: 200 } } }, 'custom');
  await delay(40);
  assert.equal(p.messages.some(m => m.method === 'Network.requestWillBeSent'), false);
  assert.equal(f.relay.status().nativeRequests, 0);
});

test('native filter tap accepts only original dropped Network frames and preserves session/payload', async t => {
  const f = await fixture(t);
  assert.equal(f.relay.ingestNativeFilteredFrame(JSON.stringify(request())), false, 'no active native session');
  const a = await f.applet(); const p = await f.peer();
  p.send({ id: 1, method: 'Network.enable', sessionId: 'child' });
  await until(() => p.messages.some(m => m.id === 1));
  const raw = { ...request('dropped-native'), sessionId: 'child' };
  assert.equal(f.relay.ingestNativeFilteredFrame(JSON.stringify(raw)), true);
  await until(() => p.messages.some(m => m.method === 'Network.requestWillBeSent'));
  const received = p.messages.find(m => m.method === 'Network.requestWillBeSent');
  assert.equal(received.sessionId, 'child');
  assert.deepEqual(received.params.request, raw.params.request);
  assert.equal(f.relay.ingestNativeFilteredFrame(JSON.stringify({ method: 'Runtime.evaluate', params: {} })), false);
  assert.equal(f.relay.status().nativeRequests, 1);
  assert.equal(a.commands.some(c => c.method === 'Runtime.evaluate'), false);
});

test('body actually present in a dropped native CDP response can complete its matching transaction', async t => {
  const f = await fixture(t); const p = await f.peer();
  const a = await f.applet({ onCommand: (_, m) => {
    if (m.method !== 'Network.getResponseBody') return;
    setTimeout(() => f.relay.ingestNativeFilteredFrame(JSON.stringify({ id: m.id, sessionId: m.sessionId, result: { body: 'native-original-body', base64Encoded: false } })), 5);
    return false;
  } });
  a.emit({ ...request('raw-rid'), sessionId: 'child' });
  await until(() => f.relay.status().nativeRequests === 1);
  p.send({ id: 1, sessionId: 'child', method: 'Network.getResponseBody', params: { requestId: 'raw-rid' } });
  await until(() => p.messages.some(m => m.id === 1));
  assert.equal(p.messages[0].result.body, 'native-original-body');
  assert.equal(p.messages[0].sessionId, 'child');
});
