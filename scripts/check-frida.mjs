// Isolated Frida load/hook/unload test. The ONLY target is a C executable built
// from test/frida-smoke-host.c in a private temporary directory. No WeChat PID.
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import * as frida from 'frida';
const require = createRequire(import.meta.url);
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const dir = mkdtempSync(join(tmpdir(), 'wmpf-frida-smoke-'));
const binary = join(dir, 'smoke-host');
execFileSync('/usr/bin/clang', ['-O0', '-g', '-Wl,-export_dynamic', join(root, 'test/frida-smoke-host.c'), '-o', binary, '-lpthread']);
const entitlement = join(dir, 'entitlements.plist');
writeFileSync(entitlement, '<?xml version="1.0"?><plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>');
execFileSync('/usr/bin/codesign', ['--force', '--sign', '-', '--entitlements', entitlement, binary], { stdio: ['ignore', 'ignore', 'pipe'] });
const target = spawn(binary, [], { stdio: ['ignore', 'pipe', 'pipe'] });
let heartbeats = 0, hooks = 0, session;
target.stdout.on('data', b => { heartbeats += b.toString().split('\n').filter(x => x.startsWith('heartbeat')).length; });
const watchdog = setTimeout(() => { target.kill('SIGKILL'); console.error('FAIL: isolated smoke timeout; disposable target killed'); process.exit(1); }, 15000);
const delay = ms => new Promise(r => setTimeout(r, ms));
async function bounded(p, label) {
  let timer;
  try { return await Promise.race([p, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} timed out`)), 3000); })]); }
  finally { clearTimeout(timer); }
}
try {
  await delay(200);
  session = await bounded((await frida.getLocalDevice()).attach(target.pid), 'attach');
  for (let cycle = 0; cycle < 3; cycle++) {
    const script = await bounded(session.createScript(`
      const count = new NativeFunction(Module.getGlobalExportByName('_dyld_image_count'), 'uint', []);
      const malloc = new NativeFunction(Module.getGlobalExportByName('malloc'), 'pointer', ['ulong']);
      const free = new NativeFunction(Module.getGlobalExportByName('free'), 'void', ['pointer']);
      const p = malloc(32); p.writeUtf8String('local-smoke-only'); free(p);
      if (count() < 1) throw new Error('dyld image table unavailable');
      let hits=0;
      Interceptor.attach(Module.getGlobalExportByName('wmpf_smoke_tick'), { onEnter() { if (++hits===1) send({type:'hook-hit'}); } });
      send({type:'ready'});
    `), 'createScript');
    let ready = false;
    script.message.connect(m => {
      if (m.type === 'error') console.error(m.stack);
      if (m.type === 'send' && m.payload.type === 'ready') ready = true;
      if (m.type === 'send' && m.payload.type === 'hook-hit') hooks++;
    });
    const before = heartbeats;
    await bounded(script.load(), 'script.load');
    await delay(250);
    if (!ready || heartbeats <= before || hooks < cycle + 1) throw new Error('agent ready/hook/host liveness check failed');
    await bounded(script.unload(), 'script.unload');
    console.log(`PASS cycle ${cycle + 1}: ready, native hook hit, host heartbeat advancing, unloaded`);
  }
  await bounded(session.detach(), 'detach'); session = null;
  const before = heartbeats; await delay(150);
  if (heartbeats <= before) throw new Error('host stopped after detach');
  console.log('PASS: isolated Frida smoke test only; this does NOT establish WeChat compatibility.');
} catch (e) { console.error('FAIL:', e.message); process.exitCode = 1; }
finally { clearTimeout(watchdog); target.kill('SIGKILL'); }
