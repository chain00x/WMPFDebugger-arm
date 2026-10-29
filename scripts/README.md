# 原生协议适配与独立检查

- `start.sh` / `stop.sh`：普通用户启动/停止 `src/relay.ts`，不需要 sudo。
  仅转换原生 LanDebug/CDP 协议，不抓包、不装证书、不注入、不包装 wx API。
  不会终止端口占用者、微信或 Chrome。
- `check-frida.mjs`：仅在临时目录编译的自有 C 测试进程中验证 Frida，
  包括 dyld 加载、三轮挂钩/卸载、心跳和 detach。绝不附加微信。
- `find-offsets.py`：capstone/numpy 静态偏移候选定位；必须人工复核，
  扫描成功并不代表实机安全或功能通过。

```bash
./ctl.sh start
./ctl.sh status
./ctl.sh stop
npm test
npm run typecheck
npm run test:frida
```

`connected=false` 表示没有已启用 LanDebug 的微信运行时连接 9421。
单独启动适配器不能让普通微信自动进入调试模式。
25800 曾发生实机注入卡死，注入路径仍为单 PID、显式实验开关；
参见 [README.md](../README.md) 与 [原生协议说明](../docs/native-protocol.md)。
