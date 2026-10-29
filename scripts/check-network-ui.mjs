// Opt-in UI integration test: isolated Chrome + native-protocol FIXTURE, never
// WeChat or real business traffic. Temporary Chrome profile is killed on exit.
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { createRequire } from 'node:module';
import WebSocket from 'ws';
const require = createRequire(import.meta.url);
const { CdpRelay } = require('../src/cdp-relay.ts');
const pb = require('../src/third-party/WARemoteDebugProtobuf.js').mmbizwxadevremote;
const codex = require('../src/third-party/RemoteDebugCodex.js');
const chromePath = process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const profile = mkdtempSync(join(tmpdir(), 'wmpf-native-ui-fixture-'));
const relay = new CdpRelay({ debugPort: 0, cdpPort: 0, timeoutMs: 1000, log: () => {} });
await Promise.all([once(relay.debug, 'listening'), once(relay.proxy, 'listening')]);
const cdpPort = relay.proxy.address().port;
const fixture = new WebSocket(`ws://127.0.0.1:${relay.debug.address().port}`);
const send = (payload, category = 'chromeDevtoolsResult') => {
  const data = category === 'customMessage'
    ? pb.WARemoteDebug_CustomMessage.encode({ method: '__networkDebug', payload: JSON.stringify(payload) }).finish()
    : pb.WARemoteDebug_ChromeDevtoolsResult.encode({ payload: JSON.stringify(payload) }).finish();
  fixture.send(pb.WARemoteDebug_DebugMessage.encode({ seq: 1, category, data, compressAlgo: 0 }).finish());
};
const body = '{"nativeProtocolFixture":true}';
fixture.on('message', raw => {
  const env = pb.WARemoteDebug_DebugMessage.decode(raw);
  const data = codex.unwrapDebugMessageData(env).data;
  if (env.category === 'customMessage') {
    const p = JSON.parse(data.payload);
    if (data.method === '__getNetworkResponseBody') send({ id: p.devtoolsMsgId, result: { body, base64Encoded: false } }, 'customMessage');
    return;
  }
  const m = JSON.parse(data.payload);
  let result = {};
  if (m.method === 'Page.getResourceTree' || m.method === 'Page.getFrameTree') result = { frameTree: { frame: {
    id: 'native-fixture-frame', loaderId: '', url: 'https://example.invalid/native-fixture',
    securityOrigin: 'https://example.invalid', mimeType: 'text/html',
  } } };
  if (m.method === 'Debugger.enable') result = { debuggerId: 'native-fixture' };
  if (m.method === 'Target.getTargets') result = { targetInfos: [] };
  if (m.method === 'DOM.getDocument') result = { root: { nodeId: 1, backendNodeId: 1, nodeType: 9, nodeName: '#document', localName: '', nodeValue: '' } };
  send({ id: m.id, result });
});
await once(fixture, 'open');
const chrome = spawn(chromePath, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
  '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-background-networking',
  '--disable-component-update', '--disable-sync',
  `devtools://devtools/bundled/inspector.html?ws=127.0.0.1:${cdpPort}&panel=network`], { stdio: 'ignore' });
let browserWs;
const delay = ms => new Promise(r => setTimeout(r, ms));
const timeout = setTimeout(() => { chrome.kill('SIGKILL'); process.exit(1); }, 30000);
const pending = new Map(); let seq = 0;
const call = (method, params = {}) => new Promise((resolve, reject) => {
  const id = ++seq;
  const timer = setTimeout(() => { pending.delete(id); reject(new Error(method + ' timeout')); }, 5000);
  pending.set(id, { resolve, reject, timer }); browserWs.send(JSON.stringify({ id, method, params }));
});
async function evaluate(expression) {
  const r = await call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
  return r.result?.value;
}
try {
  let port;
  for (let i = 0; i < 80 && !port; i++) {
    try { port = Number(readFileSync(join(profile, 'DevToolsActivePort'), 'utf8').split('\n')[0]); } catch { await delay(100); }
  }
  if (!port) throw new Error('Isolated Chrome failed to start');
  let targets = [], target;
  for (let i = 0; i < 50 && !target; i++) {
    targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    target = targets.find(t => t.url.startsWith('devtools://'));
    if (!target) await delay(100);
  }
  // Some managed Chrome builds replace the command-line startup URL. Navigate
  // only a page belonging to this fresh temporary profile through CDP.
  const needsNavigation = !target;
  target = target || targets.find(t => t.type === 'page');
  if (!target) throw new Error('No page in isolated Chrome profile');
  browserWs = new WebSocket(target.webSocketDebuggerUrl);
  browserWs.on('message', raw => {
    const m = JSON.parse(raw.toString()), p = pending.get(m.id);
    if (!p) return;
    clearTimeout(p.timer); pending.delete(m.id);
    if (m.error) p.reject(new Error(m.error.message)); else p.resolve(m.result);
  });
  await once(browserWs, 'open');
  if (needsNavigation) {
    const nav = await call('Page.navigate', { url: `devtools://devtools/bundled/inspector.html?ws=127.0.0.1:${cdpPort}&panel=network` });
    if (nav.errorText) throw new Error('Isolated frontend navigation: ' + nav.errorText);
  }
  for (let i = 0; i < 80 && !relay.status().networkEnabled; i++) await delay(100);
  if (!relay.status().networkEnabled) throw new Error('Real DevTools did not subscribe to Network');
  await evaluate(`(async()=>{const UI=await import('./ui/legacy/legacy.js');await UI.ViewManager.ViewManager.instance().showView('network');return true})()`);
  const timestamp = Date.now() / 1000;
  send({ method: 'Network.requestWillBeSent', params: { requestId: '1.7', request: {
    url: 'https://example.invalid/native-fixture', method: 'POST', headers: { 'Content-Type': 'application/json' }, postData: '{"fixture":true}' },
    timestamp, type: 'XHR', documentURL: 'https://example.invalid/native-fixture',
  } }, 'customMessage');
  send({ method: 'Network.responseReceived', params: { requestId: '1.7', timestamp: timestamp + .05, type: 'XHR', response: {
    url: 'https://example.invalid/native-fixture', status: 200, statusText: 'OK', headers: { 'Content-Type': 'application/json' }, mimeType: 'application/json',
  } } }, 'customMessage');
  send({ method: 'Network.loadingFinished', params: { requestId: '1.7', timestamp: timestamp + .06, encodedDataLength: body.length } }, 'customMessage');
  await delay(300);
  const result = await evaluate(`(async()=>{const L=await import('./models/logs/logs.js');const requests=L.NetworkLog.NetworkLog.instance().requests();const r=requests.find(r=>r.url().includes('native-fixture'));if(!r)return {found:false,count:requests.length};const content=await r.requestContentData();return {found:true,url:r.url(),status:r.statusCode,type:r.resourceType().name(),body:content.text??content.content,error:content.error}})()`);
  if (!result?.found || result.status !== 200 || result.body !== body) throw new Error('Real frontend did not retain native request/body: ' + JSON.stringify(result));
  console.log('PASS: real isolated Chrome DevTools Network model accepted native-protocol fixture and retrieved body over __getNetworkResponseBody.');
  console.log(JSON.stringify({ fixture: true, status: result.status, type: result.type, bodyMatched: result.body === body, wechatAttached: false }));
} catch (e) { console.error('FAIL:', e.message); process.exitCode = 1; }
finally {
  clearTimeout(timeout);
  if (browserWs) browserWs.terminate(); chrome.kill('SIGTERM');
  for (const p of pending.values()) clearTimeout(p.timer);
  fixture.terminate();
  for (const server of [relay.debug, relay.proxy]) for (const client of server.clients) client.terminate();
  await Promise.all([new Promise(r => relay.debug.close(r)), new Promise(r => relay.proxy.close(r))]);
  await delay(200); if (chrome.exitCode === null) chrome.kill('SIGKILL');
}
