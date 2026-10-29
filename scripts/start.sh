#!/bin/bash
# Native protocol relay ONLY. No sudo, process injection or business proxy.
set -euo pipefail
export PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="${TMPDIR:-/tmp}/wmpf-native-$(id -u)"
if [ "$(id -u)" = 0 ]; then
  echo '只启动原生协议适配不需要 sudo，请以普通用户运行。' >&2
  exit 1
fi
umask 077
mkdir -p "$STATE"
python3 - "$ROOT" "$STATE" "$(command -v node)" <<'PY'
import sys, os, subprocess, json, time, urllib.request, socket
root,state,node=sys.argv[1:]
pidfile=os.path.join(state,'relay.pid')
if os.path.exists(pidfile):
 try:
  pid=int(open(pidfile).read())
  args=subprocess.check_output(['/bin/ps','-p',str(pid),'-o','args='],text=True)
  if os.path.join(root,'src/relay.ts') in args:
   raise SystemExit('原生协议适配已运行，PID '+str(pid))
 except (ValueError,subprocess.CalledProcessError): pass
# Refuse occupied ports; never mistake another adapter for this child.
for port in (9421,62000):
 with socket.socket() as probe:
  try: probe.bind(('127.0.0.1',port))
  except OSError: raise SystemExit('端口 '+str(port)+' 已被占用；不会终止占用进程。')
# No pkill, port-owner killing, certificate settings, proxy changes or injection.
env=os.environ.copy();env['TS_NODE_COMPILER_OPTIONS']=json.dumps({'module':'CommonJS'})
logpath=os.path.join(state,'relay.log')
with open(logpath,'w') as log:
 child=subprocess.Popen([node,'-r',os.path.join(root,'node_modules/ts-node/register'),os.path.join(root,'src/relay.ts')],cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
 open(pidfile,'w').write(str(child.pid))
for _ in range(40):
 if child.poll() is not None:
  raise SystemExit('启动失败，查看 '+logpath)
 try:
  with urllib.request.urlopen('http://127.0.0.1:62000/status',timeout=.2) as r: status=json.load(r)
  if status.get('mode')=='native-only':
   print('原生协议适配已启动，PID',child.pid,'；微信连接：',status.get('connected'))
   print('日志：'+logpath)
   break
 except Exception: pass
 time.sleep(.1)
else:
 child.terminate();raise SystemExit('启动超时，已停止新进程；查看 '+logpath)
PY
