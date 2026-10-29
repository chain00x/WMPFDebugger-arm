# New Version Adaptation

Please follow the guidelines (version 14199 as an example)
to find the offset values if you wish to support a new WMPF
version on your own.

Also, PR welcome!

## LoadStartHookOffset

Locate the `AppletIndexContainer::OnLoadStart` function
by searching `[perf] AppletIndexContainer::OnLoadStart`
in strings.

![OnLoadStartHook.1](./screenshots/adaptation/onload_start_hook.1.png)

Hit `x`, the only x-ref function address is the offset.

![OnLoadStartHook.2](./screenshots/adaptation/onload_start_hook.2.png)

Also, check the struct offset in these two marked functions.
These offsets are being used in the `onLoadStartHook` function
in [frida/hook.js](frida/hook.js)

![OnLoadStartHook.3](./screenshots/adaptation/onload_start_hook.3.png)

## CDPFilterHookOffset

Locate the filter by searching `SendToClientFilter` in
strings.

![CDPFilterHook.1](./screenshots/adaptation/cdp_filter_hook.1.png)

Hit `x`, go to the only function that references this string.

![CDPFilterHook.2](./screenshots/adaptation/cdp_filter_hook.2.png)

The hook target function `sub_1824839E0` is the very first
function called in the x-refed function `sub_181DB82D0`.

![CDPFilterHook.3](./screenshots/adaptation/cdp_filter_hook.3.png)

## ResourceCachePolicyHookOffset

Not sure if this function affects the sources shown in the
devtools, keep hooking this just in case.

Locate the resource cache policy function by searching
`WAPCAdapterAppIndex.js` in strings, select the second
search result.

![ResourceCacheHook.1](./screenshots/adaptation/resource_cache_hook.1.png)

Hit `x`, the only function that references this string
is the target function.


![ResourceCacheHook.2](./screenshots/adaptation/resource_cache_hook.2.png)

## macOS (darwin / arm64) 适配要点

以 WMPF 7.25716（微信 4.1.15）为例，可直接用
`lipo -thin arm64` 提取框架切片后用 capstone 扫 ADRP+ADD xref，
无需 IDA：

* `LoadStartHookOffset`：搜字符串
  `virtual void applet::AppletIndexContainer::OnLoadStart(bool, const std::string &)`
  （mac 版没有 `[perf]` 前缀日志串，改用该签名串），唯一 xref 所在函数。
* `LoadStartHookOffset2`：全二进制唯一匹配
  `ldr x8,[x0,#8]; ldr x9,[x8,#0x5F0]; ldr x9,[x9,#0x10]` 的函数
  （`0x5F0`=StructOffset、后续 `[x9,#0x1C8]`=SceneOffset，可顺便校验两结构体偏移）。
* `CDPFilterHookOffset`：搜 `SendToClientFilter`，其 xref 函数体内
  第一个 `BL` 的目标函数。
* `ResourceCachePolicyHookOffset`：搜 `WAPCAdapterAppIndex.js`
  （首个出现在 `WAServiceMainContext.js/WASubContext.js/WAWebview.js/
  WAGame.js/...` 资源名列表中），唯一 ADRP xref 所在函数，
  即懒加载构造 hash-set 的调试资源谓词函数。

注意：`xweb_script_host.cc`/`SaveFile` 附近的函数不是本 hook 目标
（25716 曾误配到 0x57D1BA8，已修正为 0x57D4008）。




### macOS 25716 运行时适配（与 Windows 版行为差异）

1. **runtime 指针在 `this+0x38`**（Windows 为 `this+8`）。
   链路：`this+0x38`(runtime) → `+0x5F0`(holder) → `+0x10`(启动参数对象)；
   该对象内嵌于 runtime（`runtime+0xE0` 处），因此其 `+0x1A0` 与
   `runtime+0x280` 是**同一个字段**——LanDebug 调试服务器地址 std::string。
2. **门禁条件（OnLoadStart 尾部 0x576ebec..0x576ec30）**：
   bool 参数非 0（hook 强制）→ 链路有效 → `obj[0x2D4]==1` →
   `scene(obj[0x1C8])==1101(0x44D)` → `runtime+0x280` 串非空 →
   才调用 0x9349894（devtools_web_socket_server 会话工厂）。
   补丁在 `OnAfterCreated`（0x576E524）onEnter 一次性写入三项即可，
   后续每次 OnLoadStart 尾部自然走调试分支。
3. **URL 必须写 std::string 长串形态**：`ptr@0, size@8, cap@0x10(cap 高位=1)`。
   - 只写 SSO 内联字节会污染 cap 高位字节，对象析构时被误判为长串，
     对垃圾指针 double-free → EXC_BREAKPOINT 闪退（崩溃栈特征：
     `std::string` dealloc + CHECK 失败）。
   - 数据指针必须用**进程 malloc**（`Module.getGlobalExportByName('malloc')`，
     Frida 17 已移除 `Module.getExportByName(null,...)`）分配，
   这样 runtime 析构 `operator delete→free` 能正确匹配；
   Frida `Memory.alloc` 的池内存会被系统 free 视为非法。
4. **`DisableCDPFilter: true`（mac 必需）**：Windows 版的 SendToClientFilter
   补丁（messageType 6→0）在 mac 25716 上会把所有 CDP 响应变成 `{}`，
   必须通过配置禁用（`Arch.arm64.DisableCDPFilter`）。
5. **Frida 兼容**：`NativePointer.writeU64` 在部分版本不存在，
   统一用 `writeByteArray` 小端字节写入。
6. **hook 位置**：只 hook 函数入口，禁止在函数中间插探针
   （曾因偏移算错 hook 到指令中间导致闪退）。
7. **进程/启动顺序**：必须先打开小程序让 WeChatAppEx 进程存在，再启动本工具；
   小程序闪退/微信重启后 PID 变化需重启工具重新注入。

## 8. 门禁前打点（25755+ 推荐方法，不再需要函数入口）

入口查找在部分版本不可行（unwind 条目缺失、冷路径块伪装成入口）。更稳的锚点是 **OnLoadStart 尾部调试分支门禁链**——它紧邻日志字符串 xref，模式固定：

```
ldr  x8, [sp, ...]        ; 拆本地串
bl   operator delete
add  x0, sp, #0x20        ; ← 打点在这（门禁链前最后一条）
bl   <string dtor>
cbz  w20, <skip>          ; w20 = bool 调试参数
ldr  x8, [x19, #0x38]     ; x19 = this（this+0x38=runtime）
ldr  x9, [x8, #0x5f0]
ldr  x9, [x9, #0x10]      ; 启动参数对象
...校验 [x9+0x2d4]==1 / [x9+0x1c8]==1101 / 串非空...
bl   <会话工厂>
```

hook 该点（onEnter）：`context.w20 = 1`；`patchLanDebug(context.x19)` 写 scene/state/URL；返回后门禁立即消费补丁。要求：地址必须指令边界（capstone 验证）、x19/w20 在该点未被改写（看门禁后续指令引用即可确认）。

## 9. 自动化运行时（macOS）

- `src/index.ts`：启动时 `killStaleServers()` 清 9421/62000 残留（注意 `lsof -ti :9421; lsof -ti :62000`，`tcp:a,tcp:b` 语法无效）；`frida_server` 内 500ms 轮询新 WeChatAppEx PID 自动注入（小程序每次打开触发多次 OnLoadStart，晚 attach 仍可命中）。
- root 守护 `/tmp/wmpfctl/wrapper.sh`：等微信→杀旧 ts-node→起工具→监控 restart 信号/进程死亡/主进程变化。重启注入：`touch /tmp/wmpfctl/restart`。
- UI 自动化工具（/tmp/wmpfctl/）：`ocr_box`（Vision OCR 带框）、`click`/`move`（CGEvent）。微信需授权终端「辅助功能+屏幕录制」。

## 10. 稳定性三连坑（25755 调试实录，务必遵守）

1. **新进程注入竞态 = 小程序闪退**：WeApp（小程序独立渲染进程，cmdline 带 `--wmpf-appid=`）spawn 后立即 frida attach 会撞上 dyld dlopen（崩溃栈：pthread_kill←abort←dlopen←notifyDebuggerLoad）。自动轮询注入必须过滤 `ps -o etimes= -p PID` ≥ 2s 才 attach。生命周期事件都在常驻 Framework 进程，晚注入无损。
2. **attach 永久挂起**：被 kill -9 的进程残留半注入状态，此后 attach 全 hang（日志停在 "Attaching to PID"）。所有 attach 必须 Promise.race 超时（15s）跳过；卡死进程直接 kill 换新（微信会重启全家桶）。
3. **pgrep 模式**：小程序生命周期在 `WeChatAppEx Framework` 的 Helper(Renderer)/WeApp 进程里，`pgrep -f 'WeChatAppEx'` 宽匹配（勿用主二进制路径窄匹配）。
4. **URL 双写**：门禁读 `obj+0x1a0`（obj = [rt+0x5f0]+0x10 链式解析），工厂读 `rt+0x280`，仅当 obj 恰嵌于 rt+0xE0 时同址——两处都写长串。
5. **arm64 寄存器写**：`context.x20 = 1`（勿用 w20 视图）。
6. **守护**：wrapper3.sh 只认 restart 文件 / 工具死亡(3s 确认) / stop 文件；"主进程变更重启"逻辑必须去掉（PID 回绕后 min-pid 误判会打碎加载窗口）。停止一切 `touch /tmp/wmpfctl/stop`；重启注入 `touch /tmp/wmpfctl/restart`。

## 11. 稳定性五坑（25755 macOS arm64 实战，2026-09-29）

详见上文 §10/§11 合并段落。

1. **frida ≥17.19 必须**：17.3.2 在 macOS 26 dyld4 下，agent 的 dyld 模块追踪回调会在 notifyDebuggerLoad 内重入 dladdr → abort（栈特征：abort←?+0x1xxxxx10c←dladdr←triggerNotification←dlopen）。升级：npmmirror 装 tgz(--ignore-scripts) + gh-proxy.com 镜像下 prebuilt `frida-vN-napi-v8-darwin-arm64.tar.gz` 手动放 node_modules/frida/build/frida_binding.node。
2. **hook 里禁用 frida Module 枚举**（Process.findModuleByName 等）：会装 dyld interposition。用 `_dyld_image_count/_dyld_get_image_name/_dyld_get_image_header` 原生函数找模块基址。
3. **只 attach 主进程（无 --type）**：WeApp/渲染进程注入与其初始化 dlopen 竞态 → 小程序闪退。生命周期 hook（tailGate/factory）全在主进程。
4. **主进程会被 AppKit 自动回收**（无窗口时 AutomaticTermination）→ 每次开小程序可能是全新主进程 → attach 延迟必须 ≤0.3s + 200ms 轮询，抢在 OnLoadStart 前。但仍要防 spawn 竞态：age<0.3s 不碰。
5. **URL 缓冲区每次写入都重新 malloc**：微信关闭 applet 时按 std::string 析构语义 free 掉我们写入的指针。缓存缓冲区=悬垂指针：第二次 applet 写回空串（连不上 9421）+ 二次析构 double-free → 堆损坏随机崩（CALayer alloc/Security 框架栈）。绝对不要用定时器反复重写字段（与微信自身写入撕裂竞争，同样堆损坏）——单次写、只在 factory 入口兜底一次。
6. **非小程序容器要跳过**：面板/公众号文章也走主进程 OnLoadStart（scene 同为 1256）。patchLanDebug 前扫 obj+0x1000 内有无 'wx'+16hex appid 标记，没有就放行不碰（否则面板被误导入 LanDebug 卡死/空白）。

### 运维速查
- 工具被杀时正在 attach 的进程会永久半注入（后续 attach 全 hang）→ kill 该进程让微信重拉。
- 树反复崩后微信本体 WMPF 宿主管理器会僵死（小程序面板点击无反应）→ 重启微信本体。
- 崩溃风暴会写坏 radium profile（~/Library/Containers/com.tencent.xinWeChat/Data/Documents/app_data/radium/web/profiles/ 下 game*/webview*/multitab*）→ 整族移走让微信重建。
- Network 面板数据源 = customMessage 类目 method=__networkDebug（payload 即标准 CDP Network JSON，直接转发给 CDP client）；domEvent 的 DEBUGGEE_EVENT 转发可得 Elements 面板。

## 12. 回滚微信 25716（4.1.15.19/270099）与门禁偏移重提（2026-09-30）

### 为什么回滚
- 25755（4.1.15.22/270102）的网络事件走 customMessage/__networkDebug 单向遥测，**无响应体存储**，getResponseBody 对 XHR 型必失败（厂商工具靠内置 MITM 才有 body）。
- 25716（4.1.5.19）网络事件走 **domEvent/DEBUGGEE_EVENT**（含 Network.responseReceived），且 CDP 命令通道（chromeDevtoolsResult）有完整应答——**Network 面板+Response body 原生可用**。

### 回滚操作
1. 版本考古：`~/Library/Logs/DiagnosticReports/WeChatAppEx-*.ips` 首行 `app_version` 还原时间线（09-23=25561、09-26/27=25716、09-29=25755）。
2. 找包：微信更新清单在 `xplugin/plugins/MacUpdate/<n>/extracted/MacUpdate_universal.xml`（sparkle 格式，enclosure url 是真实 CDN 地址 `xWeChatMac_universal_<ver>_<build>.dmg`）。4.1.15.19=WeChatAppEx 7.25716、4.1.15.22=7.25755、4.1.13=6.25561。
3. **hosts 锁版本**（防自动升级）后下载要绕过（`curl --resolve 真实IP`，本机 127.0.0.1 的 Burp 会劫持应答）。
4. 回滚前**清 radium 缓存**（25755 写入的新格式会让 25716 SIGTRAP 崩）：`mv ~/Library/Containers/.../app_data/radium ~/wmpf-backup/`，微信会重建。
5. 老包安装包留存：/tmp/wc411519.dmg（25716）、~/Downloads/chrome_download/WeChatMac_4.1.15.dmg（25755 备份也改名在 /Applications/微信_4.1.15_备份.app）。

### 25716 门禁偏移（§8 方法重提）
- OnLoadStart 签名串 @0xa2ae883，xref 0x576ea58。
- **tailGate=0x576ebe0**（`add x0,sp,#0x20`→`bl 0xc014ac`→`cbz w20`→`ldr x8,[x19,#0x38]`→`ldr x9,[x8,#0x5f0]`→`ldr x9,[x9,#0x10]`→state[+0x2d4]==1→scene[+0x1c8]==0x44d→URL 非空([+0x1b7] flag/[+0x1a8] ptr)→`bl 0x9349894`）。
- 工厂=0x9349894（与老配置 LoadStartHookOffset2 一致，无需改）；字段偏移与 25755 完全相同，hook.js patchLanDebug 无需改动。
- 老配置 LoadStartHookOffset=0x576E978 是旧函数入口法提的，tailGate 语义下无效——**每个版本都要按 §8 重找打点**。

### 25716 特有坑
- **frida 17.3.2 可用**（09-26 验证过），17.19 未在 25716 实测；当前环境 node_modules 已锁 17.3.2，17.19 binding 备份在 /tmp/frida-prebuilt/build/frida_binding.node.17.19。
- 框架 dylib 装载晚于早期附加：hook.js main() 里 getMainModule 失败要 **200ms×25 次重扫**，不要一次失败就放弃。
- attach 年龄门槛 0.5s（太晚会错过新进程的 OnLoadStart；太早 0.3s 有 spawn 竞态）。zombie 进程（ps stat=Z）createScript 必 hang，跳过。
- Promise.race 超时定时器必须 clearTimeout，否则成功后还打 TIMEOUT 噪音误导排障。
- 小程序关窗≠退出：宿主进程温存 applet，OnLoadStart 不重触发；要触发冷启动就 kill 宿主全家再开。

### 运行状态（2026-09-30 15:4x）
tailGate(24668) scene 1256→1101 → factory → miniapp 连 9421 → CDP 连 62000 → 220 条网络事件重放 → fanout answered（getResponseBody 有应答=body 正常）。frida 17.3.2 + 0.5s 抢跑 + 框架重试 + 25716 门禁 0x576ebe0。

## 13. 4.1.0.240 专用链路 + 代理三大修复（2026-10-05）

### 版本决策
- 25716（4.1.15.19）曾被验证全通，但用户实测后选择回退 **4.1.0.240**（WeChatAppEx 4.16434）：项目上游官方支持版本，专用 hook 在 `frida/4.1.0.240.js`（自带偏移 0x7D71940/0x7D80A10/0x4EAF204/0x4F0555C，函数入口法+写 scene=1101+X1|=1，**无需写调试 URL**——该版本 applet 进 LanDebug 后默认连 127.0.0.1:9421）。
- 启动：`sudo bash /tmp/wmpfctl/start.sh`（内部 `--script frida/4.1.0.240.js`）；停：`stop.sh`。纯手动，无守护无自启（用户明确要求）。
- 4.1.0.240.js 已打两个补丁：getMainModule 改 `_dyld_image_*` 扫描（防 frida Module 枚举 interposition 崩）+ 子进程空保护（框架未加载直接退出）。
- frida 17.3.2 与 16434 兼容良好。

### 「过一会就断/刷新即死」四层根因（按发现顺序）
1. **双工具实例互杀**：工具启动时 killStaleServers 会杀端口占用者；用户手动 `sudo npx` 与脚本实例并存 → 互杀循环。约定：只走 start.sh/stop.sh 单实例。
2. **Chrome 刷新后 CDP id 撞车**：inspector 刷新后命令 id 从 1 重编，applet 端记着旧会话 id → 全部拒为 `Duplicate id`（-32600）→ 会话报废。**修复=op_id 改写代理**：发往 applet 一律用全局单调 opSeq（pendingOpToCdp 映射回 Chrome id，应答时还原；查不到的陈旧应答直接丢弃）。
3. **双 CDP 客户端重复转发**：Chrome 刷新时旧 ws 残留，62000 上两个并发客户端把同一命令转发两次 → applet 状态错乱断开（miniapp 连接循环 78 次的元凶）。**修复=单客户端策略**：新 CDP 连接自动 close 旧连接（close code 4000 "replaced"）。
4. **Console 拿不到 wx**：16434 的 CDP 会话有多个 execution context，**wx 在逻辑层 context（探测=4/5/6），默认 context(1) 是渲染层**；且 context 上报只在 applet 连接后头几秒发，Chrome 后连/刷新即错过 → 下拉空+默认 undefined。**修复=两件套**：
   - `ctx-replay`：代理持续收集 executionContextCreated，新 CDP 客户端连上 600ms 后重放全部已知 contexts（对应厂商工具的 ctx-replay 机制）
   - `evaluate_appservice`：对每个新 context 发一次 `typeof wx==="object"` 探针（probeOpToCtx 映射），命中者记为 appserviceCtxId；此后**无 contextId 的 Runtime.evaluate 自动改写**到逻辑层——Console 直接输 wx 即可用，无需手选上下文。

### 已验证机制（勿回退）
- `Page.startScreencast`/`screencastFrameAck` 曾被屏蔽（怀疑 ack 风暴杀会话），单客户端修复后**已恢复透传且稳定**——真正的杀手是 #3。
- Promise.race 超时必须 clearTimeout（TIMEOUT 噪音日志误导排障）。
- zombie 进程（stat=Z）createScript 必 hang：跳过即可（对死人说话）。
- 启动时 pgrep 无 WeChatAppEx 不算错误（清缓存/刚启动场景），返回空数组等 auto-attach。
- hook.js main() 框架未找到时 200ms×25 重扫（25716 框架装载晚于附加）。
- 上游 codex.wrapDebugMessageData 不支持 evaluateJavascript 类目（wrap 无此 case）——逻辑层不走该通道，勿再尝试。

### 运维
- `/tmp` 重启即清：wrapper/日志/安装包都会丢。耐久副本：`scripts/`（wrapper3.sh、start/stop、plist 已弃用）、`~/wmpf-backup/WeChatMac_4.1.15.19_25716.dmg`、17.19 binding 备份 `/tmp/frida-prebuilt/build/frida_binding.node.17.19`（重启会丢，需要时从 gh-proxy 重下）。
- hosts 屏蔽更新域名仍在（防自动升级）；查微信实际版本：`/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" /Applications/*/Contents/MacOS/WeChatAppEx.app/Contents/Info.plist`（4.1.0.240 的在同名子路径）。
- 版本考古：崩溃报告 ips 首行 app_version + MacUpdate sparkle 清单（`xplugin/plugins/MacUpdate/*/extracted/MacUpdate_universal.xml` 的 enclosure url 是真实 CDN 地址）。

## 14. WMPF 25800（微信 4.1.15，macOS 27 arm64）适配（2026-10-12）

> **2026-10-29 纠正：以下是静态定位记录，不代表实机验证通过。**
> 实际日志收到过 `customMessage/__networkDebug` 的 request/response/loadingFinished，
> 之前依据二进制字符串搜索宣称“25800 原生网络上报已移除”是错误推论。
> 旧代理存在采集 in-flight 跨会话未复位、序列号冲突、上下文改写晚于序列化、
> getResponseBody 回错 socket、Network.enable 之前回放事件等问题。
> 新协议模块在本地 mock/protobuf/WebSocket 回归中通过，但尚未获得实机成功证据；
> 再次注入时出现 `script.load Timeout` 且用户反馈微信卡死。已停止调试进程、
> 结束被注入 WMPF 宿主；主微信未被强退、未清缓存/聊天数据。
> **25800 普通启动已阻止；自动附加和逻辑层网络桥均改为显式选择加入。暂停实机测试。**

当前目标版本：`WeChat.app 4.1.15` → `WeChatAppEx 7.25800`。
配置：`config/addresses.25800.darwin.json`（`src/index.ts` 按已安装 plist 自动选版本）。
hook 脚本仍用 `frida/hook.js`（7.x 链路），**不需要**改 JS —— 字段偏移全未变。

### 偏移（相对 WeChatAppEx Framework 镜像基址）

| 项 | 25800 | 25755 | 25716 |
|---|---|---|---|
| `LoadStartHookOffset`（tailGate） | **0x577787C** | 0x57753D8 | 0x576EBE0 |
| `LoadStartHookOffset2`（会话工厂） | **0x9359258** | 0x9356CC8 | 0x9349894 |
| `ResourceCachePolicyHookOffset` | **0x57DCC9C** | （未配） | 0x57D4008 |
| `StructOffset` / `SceneOffset` | 0x5F0 / 0x1C8 | 同 | 同 |

门禁链（tailGate 处 x19=this、w20=bool 调试参数，已被 0x577760C 入口处的
`mov x20,x1 / mov x19,x0` 证实）：

```
0x5777874  add  x0, sp, #0x20        ; 本地 std::string 析构
0x5777878  bl   0xc014ac
0x577787C  cbz  w20, 0x57778c8       ; ← 打点（Hook 点）
0x5777880  ldr  x8, [x19, #0x38]     ; runtime
0x5777884  ldr  x9, [x8, #0x5f0]
0x5777888  ldr  x9, [x9, #0x10]      ; 启动参数对象 obj
0x5777890  ldr  w10, [x9, #0x2d4]; cmp w10,#1
0x577789C  ldr  w10, [x9, #0x1c8]; cmp w10,#0x44d   ; scene == 1101
0x57778A8  ldrsb x10,[x9,#0x1b7]; tbz → ldr x10,[x9,#0x1a8] ; URL 非空
0x57778C4  bl   0x9359258           ; 会话工厂
```

工厂 `0x9359258`：入口 `ldr x8,[x0,#8]` → `[x8+0x5f0]` → `[+0x10]`，
URL 走 `rt+0x280`（0x93592C0 处 `ldr x1,[x8,#0x280]`）——`hook.js`
的 `patchLanDebug`/`interceptorLoadStart2` 语义完全通用。

`ResourceCachePolicyHookOffset = 0x57DCC9C`：`WAPCAdapterAppIndex.js`
首个（资源名列表里的那个，字符串 @0x9fb369d）在 25800 只有 **1 个**
ADRP+ADD xref @0x57dcff8，落在该函数的冷块（懒加载构造调试资源
hash-set，0x57dcdc4..0x57dd2e4）；函数入口 0x57DCC9C
（`sub sp,sp,#0x70`，返回 bool，4 个调用点）。`onLeave retval→0` 语义不变。

`SendToClientFilter` @0xae5f180 的 xref 变成 3 处
（0x9353778 / 0x9355afc / 0x9355c68），mac 仍用
`DisableCDPFilter: true`（应用后 CDP 响应会被清成 `{}`）。

### 如何重提（本版不再需要 IDA）

```bash
python3 scripts/find-offsets.py      # capstone + numpy，约 1.5s
```

输出 tailGate / 工厂 / ResourceCache 候选；脚本用
`lipo -thin arm64` + ADRP+ADD 向量化 xref + 门禁链模式匹配，
不依赖 unwind/符号表（25800 的 `__unwind_info` 会把大函数的冷块
合并到别的函数区间，不能用它判断函数入口）。仍需按 §8 人工
复核指令边界与寄存器语义再写进 config。

### 验证

- 启动：`sudo npx ts-node src/index.ts --script frida/hook.js`
  （root 下 `PATH` 要含 `/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin`，
  否则 `lsof`/`node` 找不到）。
- 日志应出现 `Loaded config for version: 25800 (arch: arm64)`、
  `Successfully attached to PID <主进程>`。
- 打开小程序后应出现 `[tailGate ...] LanDebug enabled (scene ... -> 1101)`、
  `[interceptor2] patch ...`、miniapp 连上 9421，再访问
  `devtools://devtools/bundled/inspector.html?ws=127.0.0.1:62000`。
