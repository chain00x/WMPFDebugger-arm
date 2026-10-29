#!/bin/bash
# Stop ONLY the native relay started by start.sh. Never kill WeChat/Chrome.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="${TMPDIR:-/tmp}/wmpf-native-$(id -u)"
python3 - "$ROOT" "$STATE" <<'PY'
import os,sys,signal,subprocess,time
root,state=sys.argv[1:];file=os.path.join(state,'relay.pid')
if not os.path.exists(file): raise SystemExit('没有由此脚本启动的 relay。手动运行的工具请在对应终端 Ctrl+C。')
pid=int(open(file).read())
try: args=subprocess.check_output(['/bin/ps','-p',str(pid),'-o','args='],text=True)
except subprocess.CalledProcessError:
 os.unlink(file);raise SystemExit('原生协议适配已退出。')
if os.path.join(root,'src/relay.ts') not in args: raise SystemExit('PID 已被其他进程复用，拒绝终止。')
os.kill(pid,signal.SIGTERM)
for _ in range(30):
 time.sleep(.1)
 if subprocess.run(['/bin/ps','-p',str(pid),'-o','pid='],stdout=subprocess.DEVNULL).returncode!=0: break
os.unlink(file)
print('已向原生协议适配发送停止信号；未操作微信或 Chrome。')
PY
