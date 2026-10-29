const { test } = require('node:test');
const assert = require('node:assert/strict');
const { attachChecked, detachChecked } = require('../src/frida-session.ts');
const delay = ms => new Promise(r => setTimeout(r, ms));
function fixture(mode = 'ready') {
  const calls = []; let notify;
  const script = {
    message: { connect(fn) { notify = fn; } },
    async load() {
      calls.push('load');
      if (mode === 'load-error') throw new Error('native agent load failed');
      if (mode === 'ready') notify({ type: 'send', payload: { type: 'wmpf-ready' } });
    },
    async unload() { calls.push('unload'); },
  };
  const session = {
    async createScript() { calls.push('create'); return script; },
    async detach() { calls.push('detach'); },
  };
  const device = { async attach() { calls.push('attach'); if (mode === 'late') await delay(60); return session; } };
  return { device, session, script, calls };
}

test('native attachment is successful only after load and explicit hook readiness', async () => {
  const f = fixture();
  const handle = await attachChecked(f.device, 42, 'source', { requireReady: true, timeoutMs: 30 });
  assert.equal(handle.session, f.session);
  await detachChecked(handle);
  assert.deepEqual(f.calls, ['attach', 'create', 'load', 'unload', 'detach']);
});

test('native agent load error triggers unload and detach, not false success', async () => {
  const f = fixture('load-error');
  await assert.rejects(attachChecked(f.device, 42, 'source', { requireReady: true, timeoutMs: 30 }), /native agent load failed/);
  assert.deepEqual(f.calls.slice(-2), ['unload', 'detach']);
});

test('missing native hook readiness fails with bounded cleanup', async () => {
  const f = fixture('no-ready');
  await assert.rejects(attachChecked(f.device, 42, 'source', { requireReady: true, timeoutMs: 20 }), /readiness timed out/);
  assert.deepEqual(f.calls.slice(-2), ['unload', 'detach']);
});

test('late attachment after timeout is detached and never loads a script', async () => {
  const f = fixture('late');
  await assert.rejects(attachChecked(f.device, 42, 'source', { timeoutMs: 15 }), /attach timed out/);
  await delay(80);
  assert.deepEqual(f.calls, ['attach', 'detach']);
});


test('consumed native CDP payloads are not dumped to logs', async () => {
  const f = fixture(); const originalLoad = f.script.load;
  let callback;
  f.script.message.connect = fn => { callback = fn; };
  f.script.load = async () => {
    callback({type:'send',payload:{type:'wmpf-ready'}});
    callback({type:'send',payload:{type:'wmpf-native-cdp',payload:'PRIVATE-NATIVE-RESPONSE'}});
  };
  const logs=[];let received=false;
  const handle=await attachChecked(f.device,42,'source',{requireReady:true,timeoutMs:30,log:s=>logs.push(s),onMessage:m=>{
    if(m.payload?.type!=='wmpf-native-cdp')return false;received=true;return true;
  }});
  assert.equal(received,true);assert.equal(logs.some(s=>s.includes('PRIVATE-NATIVE-RESPONSE')),false);
  await detachChecked(handle);
});
