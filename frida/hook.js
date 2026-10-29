const getMainModule = () => {
  // ⚠️ 不用 Process.findModuleByName/Module 枚举：那会安装 frida 的 dyld 追踪 interposition，
  // 微信进程后续 dlopen 时在 notifyDebuggerLoad 崩溃（SIGABRT）。
  // 改用 _dyld_* 原生函数直接读镜像表，零 interposition。
  try {
    const cnt = new NativeFunction(Module.getGlobalExportByName('_dyld_image_count'), 'ulong', [])
    const getName = new NativeFunction(Module.getGlobalExportByName('_dyld_get_image_name'), 'pointer', ['ulong'])
    const getHdr = new NativeFunction(Module.getGlobalExportByName('_dyld_get_image_header'), 'pointer', ['ulong'])
    const n = cnt()
    for (let i = 0; i < n; i++) {
      const namePtr = getName(i)
      if (namePtr.isNull()) continue
      const name = namePtr.readCString()
      if (name && name.indexOf('WeChatAppEx Framework') !== -1) {
        return { base: getHdr(i) }
      }
    }
  } catch (e) {}
  return null
}

const parseConfig = () => {
  const rawConfig = `@@CONFIG@@`
  if (rawConfig.includes('@@')) throw new Error('No exact WMPF native-hook configuration supplied; refusing fallback offsets')
  return JSON.parse(rawConfig)
}

const resolveArchConfig = (config) => {
  if (config && typeof config === 'object' && config.LoadStartHookOffset) {
    return config
  }
  const arch = Process.arch
  const table = config?.Arch || config?.ARCH || config?.arch || null
  if (!table || typeof table !== 'object') return null
  const candidates = [arch]
  if (arch === 'x86_64' || arch === 'amd64') candidates.push('x64')
  for (const key of candidates) {
    const picked = table[key]
    if (picked && typeof picked === 'object' && picked.LoadStartHookOffset) {
      return { ...picked, Version: config.Version ?? picked.Version, __arch: key }
    }
  }
  return null
}

const validateConfig = (config) => {
  const required = ['LoadStartHookOffset', 'LoadStartHookOffset2', 'StructOffset', 'SceneOffset']
  const missing = required.filter((key) => config?.[key] === undefined || config?.[key] === null)
  if (missing.length) {
    throw new Error(`missing config fields: ${missing.join(', ')}`)
  }
}

// ---------- macOS arm64 LanDebug 补丁 ----------
// OnLoadStart 尾部调试分支的门禁(25755: 0x57753e0 起):
//   w20=bool参数 && x19=this; this+0x38(runtime) → +0x5F0 → +0x10 = 启动参数对象
//   (内嵌于 runtime+0xE0, 其 +0x1A0 == runtime+0x280 为调试服务器地址 std::string)
//   门禁: obj[0x2D4]==1 && scene(obj[0x1C8])==1101 && 串非空 → bl 会话工厂
// 补丁点: 门禁链第一条指令之前(0x57753D8), 此时寄存器语义完整, 补丁后门禁立即执行。

const ALLOWED_SCENES = [
  1005, 1007, 1008, 1012, 1027, 1035, 1053, 1074, 1101, 1145, 1168, 1178, 1256, 1260, 1302, 1308
]

const DEBUG_URL = 'ws://127.0.0.1:9421'
let activeConfig = null
const identitySeen = new Set()
const publicAppIdAt = (addr) => {
  try {
    const flag = addr.add(0x17).readU8()
    const length = (flag & 0x80) ? Number(addr.add(8).readU64().toString()) : flag
    if (length !== 18) return ''
    const data = (flag & 0x80) ? addr.readPointer() : addr
    const value = data.readUtf8String(length)
    return /^wx[0-9a-f]{16}$/.test(value) ? value : ''
  } catch (_) { return '' }
}

const allocDebugUrl = () => {
  // ⚠️ 每次都重新 malloc：不能缓存！上一个 applet 关闭时微信会按 std::string
  // 析构语义 free 掉我们写入的指针，缓存缓冲区会变悬垂（二次写入=空串，二次析构=double-free 堆损坏）
  const mallocPtr = Module.getGlobalExportByName
    ? Module.getGlobalExportByName('malloc')
    : Module.getExportByName(null, 'malloc')
  const malloc = new NativeFunction(mallocPtr, 'pointer', ['ulong'])
  const buf = malloc(32)
  buf.writeUtf8String(DEBUG_URL)
  return buf
}

const writeUrlLongForm = (addr) => {
  // std::string 长串形态: ptr@0, size@8, cap@0x10(cap 高位=长串标志)。
  // 禁止写 SSO 内联字节: 会污染 cap 高位, 析构误判长串 → double-free 闪退
  addr.writePointer(allocDebugUrl())
  addr.add(8).writeByteArray([19, 0, 0, 0, 0, 0, 0, 0])
  // malloc(32): capacity must describe the allocation, not the 19-byte length.
  addr.add(0x10).writeByteArray([0x20, 0, 0, 0, 0, 0, 0, 0x80])
}

const readStr = (a) => {
  try {
    const flag = a.add(0x17).readU8()
    if (flag & 0x80) {
      const p = a.readPointer()
      return p.isNull() ? '' : p.readCString()
    }
    // Alternate libc++ string layout: byte +0x17 holds the short length itself.
    return a.readCString(flag)
  } catch (e) {
    return ''
  }
}

const tryReadPointer = (addr) => {
  try {
    const p = addr.readPointer()
    if (p.isNull()) return null
    // macOS arm64 堆指针高 32 位在 0x1..0xffff 区间（实测 0x104/0x10c/0x12c...）
    const hi = p.shr(32)
    if (hi.compare(0x1) < 0 || hi.compare(0x10000) >= 0) return null
    return p
  } catch (e) {
    return null
  }
}

const looksLikeApplet = (obj) => {
  // 小程序 runtime 对象头部附近会有 'wx'+16位hex 的 appid；
  // 面板/公众号文章等纯 webview 容器没有 → 不碰，避免误导入调试模式导致面板卡死
  try {
    const u8 = new Uint8Array(obj.readByteArray(0x1000))
    const hex = '0123456789abcdef'
    for (let i = 0; i < u8.length - 18; i++) {
      if (u8[i] === 0x77 && u8[i + 1] === 0x78) {
        let ok = true
        for (let j = 2; j < 18; j++) {
          if (!hex.includes(String.fromCharCode(u8[i + j]))) { ok = false; break }
        }
        if (ok) return true
      }
    }
  } catch (e) {}
  return false
}

const patchLanDebug = (self, tag) => {
  try {
    const rt = tryReadPointer(self.add(0x38))
    if (!rt) return false
    const holder = tryReadPointer(rt.add(0x5f0))
    if (!holder) return false
    let obj
    try {
      obj = holder.add(0x10).readPointer()
    } catch (e) {
      return false
    }
    if (obj.isNull()) return false

    let scene
    try {
      scene = obj.add(0x1c8).readInt()
    } catch (e) {
      return false
    }
    const rtAppId = publicAppIdAt(rt.add(0xa8))
    const identityKey = tag + ':' + self.toString() + ':' + rtAppId
    if (!identitySeen.has(identityKey)) {
      identitySeen.add(identityKey)
      send({ type: 'wmpf-container-identity', phase: tag, pid: Process.id,
        container: self.toString(), runtime: rt.toString(), appid: rtAppId || null, scene: scene })
    }
    if (activeConfig?.ObserveOnly === true) return false
    if (activeConfig?.TargetAppId && rtAppId !== activeConfig.TargetAppId) return false
    // Scene allow-list is only a first filter. Newer WeChat builds use scenes
    // (e.g. 1183) that older lists never had; a container that carries a real
    // appid plus an applet marker is a miniapp regardless of scene. Panels and
    // articles reach here with appid null and are still skipped.
    if (!ALLOWED_SCENES.includes(scene) && !rtAppId) return false
    if (!looksLikeApplet(obj)) {
      console.log('[' + tag + ' pid=' + Process.id + '] skip non-applet load (scene ' + scene + ', no appid marker)')
      return false
    }

    obj.add(0x1c8).writeInt(1101)
    if (obj.add(0x2d4).readU32() !== 1) obj.add(0x2d4).writeU32(1)

    const urlAddr = rt.add(0x280)
    if (readStr(urlAddr) !== DEBUG_URL) {
      writeUrlLongForm(urlAddr)
    }
    // 门禁读的是 obj+0x1a0（flag@+0x1b7/ptr@+0x1a8）；
    // 仅当 obj 嵌于 rt+0xE0 时才等于 rt+0x280，两处都写才稳
    const urlAddr2 = obj.add(0x1a0)
    if (!urlAddr2.equals(urlAddr) && readStr(urlAddr2) !== DEBUG_URL) {
      writeUrlLongForm(urlAddr2)
    }
    console.log('[' + tag + ' pid=' + Process.id + '] LanDebug enabled (scene ' + scene + ' -> 1101)')
    return true
  } catch (e) {
    return false
  }
}

const interceptorTailGate = (base, offset) => {
  // OnLoadStart 尾部门禁前的补丁点: w20=bool, x19=this
  // ⚠️ 只有验证是小程序容器(链+场景合法)才强写 x20=1；
  // 网页/其他容器 this+0x38 不是 runtime，强写后门禁会解引用垃圾指针→主进程崩溃
  let diagCount = 0
  Interceptor.attach(base.add(offset), {
    onEnter() {
      if (Process.arch !== 'arm64') return
      const ok = patchLanDebug(this.context.x19, 'tailGate')
      if (ok) this.context.x20 = 1
      if (ok && diagCount < 3) {
        diagCount++
        try {
          const rt = tryReadPointer(this.context.x19.add(0x38))
          const holder = rt ? tryReadPointer(rt.add(0x5f0)) : null
          const obj = holder ? holder.add(0x10).readPointer() : null
          if (obj && !obj.isNull()) {
            const s = obj.add(0x1a0)
            const flag = s.add(0x17).readU8()
            const rtStr = rt ? readStr(rt.add(0x280)) : '?'
            const objStr = readStr(s)
            console.log('[diag' + diagCount + ' pid=' + Process.id + '] objEqRtE0=' + (rt ? obj.equals(rt.add(0xe0)) : '?') +
              ' flag=0x' + flag.toString(16) +
              ' rt280="' + rtStr + '" obj1a0="' + objStr + '"')
          }
        } catch (e) {
          console.log('[diag] err ' + e.message)
        }
      }
    }
  })
}

const interceptorLoadStart2 = (base, offset) => {
  // devtools_web_socket_server 会话工厂(函数入口, 已验证 prologue): 兜底补 URL
  // ⚠️ 切换小程序时，前一个 applet 的异步 teardown 会反复清空 rt/obj 的 URL、scene、state，
  // 单次写入会被踩掉。这里用定时器粘性重写 500ms，等 teardown 停手后字段稳定指向调试 URL。
  Interceptor.attach(base.add(offset), {
    onEnter(args) {
      console.log('[interceptor2 pid=' + Process.id + '] factory CALLED this=' + args[0] + ' arg1=' + args[1])
      try {
        const rt = tryReadPointer(args[0].add(8))
        if (!rt) return
        // 工厂读 rt+0x280；同时补链式 obj+0x1a0
        const a = rt.add(0x280)
        if (readStr(a) !== DEBUG_URL) {
          writeUrlLongForm(a)
          console.log('[interceptor2] patched url (rt+0x280)')
        }
        let chainObj = null
        try {
          const holder = tryReadPointer(rt.add(0x5f0))
          if (holder) {
            const obj = holder.add(0x10).readPointer()
            if (!obj.isNull()) {
              chainObj = obj
              const b = obj.add(0x1a0)
              if (!b.equals(a) && readStr(b) !== DEBUG_URL) {
                writeUrlLongForm(b)
                console.log('[interceptor2] patched url (obj+0x1a0)')
              }
            }
          }
        } catch (e) {}
      } catch (e) {}
    }
  })
}

// Read-only native protocol tap. Capture an original CDP frame ONLY when the
// native filter returns empty/{}. Do not alter JSON type tags, request APIs,
// business traffic, native allocations or the filter's return value.
const observeNativeFilter = (base, item) => {
  let reported = false
  Interceptor.attach(base.add(item.Offset), {
    onEnter(args) {
      this.nativeFrame = null
      try {
        if (args[1].isNull() || args[2].compare(2 * 1024 * 1024) > 0) return
        const size = args[2].toUInt32()
        if (!size) return
        const bytes = new Uint8Array(args[1].readByteArray(Math.min(size, 512)))
        const prefix = Array.from(bytes).map(b => String.fromCharCode(b)).join('')
        if (!prefix.includes('"Network.requestWillBeSent"') && !prefix.includes('"Network.responseReceived"') &&
            !(prefix.includes('"result"') && prefix.includes('"body"'))) return
        const original = args[1].readUtf8String(size)
        const parsed = JSON.parse(original)
        if (parsed.method !== 'Network.requestWillBeSent' && parsed.method !== 'Network.responseReceived' &&
            !(parsed.id != null && typeof parsed.result?.body === 'string')) return
        this.nativeFrame = original
        this.nativeMethod = parsed.method || 'Network.getResponseBody result'
        // arm64 ABI: a 24-byte std::string return uses hidden sret in x8.
        this.output = this.context.x8
      } catch (_) {}
    },
    onLeave() {
      if (!this.nativeFrame) return
      try {
        const flag = this.output.add(0x17).readU8()
        const length = (flag & 0x80) ? Number(this.output.add(8).readU64().toString()) : flag
        const data = (flag & 0x80) ? this.output.readPointer() : this.output
        if (length !== 0 && !(length === 2 && data.readUtf8String(2) === '{}')) return
        if (!reported) {
          reported = true
          send({ type: 'wmpf-filter-drop', filter: item.Name, method: this.nativeMethod })
        }
        send({ type: 'wmpf-native-cdp', payload: this.nativeFrame })
      } catch (_) {}
    }
  })
}

const main = () => {
  const mainModule = getMainModule()

  if (!mainModule) {
    // 25716：框架 dylib 装载可能晚于附加，隔 200ms 重扫，最多 25 次（5s）
    let tries = 0
    const timer = setInterval(() => {
      tries++
      const m = getMainModule()
      if (m) {
        clearInterval(timer)
        boot(m)
      } else if (tries >= 25) {
        clearInterval(timer)
        console.error('[frida] WeChatAppEx Framework module not found (after retries)')
      }
    }, 200)
    return
  }
  boot(mainModule)
}

const boot = (mainModule) => {
  const rawConfig = parseConfig()
  const config = resolveArchConfig(rawConfig)
  if (!config) {
    console.error(`[frida] no usable config for Process.arch=${Process.arch}`)
    return
  }
  try {
    validateConfig(config)
  } catch (error) {
    console.error(`[frida] config validation failed: ${error.message}`)
    return
  }

  activeConfig = config
  console.log(`[frida] Loaded config for version: ${config.Version} (arch: ${config.__arch || Process.arch})`)

  // Verify every optional hook BEFORE installing any interceptor, so a stale
  // configuration cannot leave a partially patched process.
  if (config.EnableResourceCacheHook === true) {
    if (!config.ResourceCachePolicyHookOffset || !config.ExpectedResourceBytes) throw new Error('Native resource policy hook requires an exact instruction anchor')
    const expected = config.ExpectedResourceBytes.toLowerCase()
    const bytes = new Uint8Array(mainModule.base.add(config.ResourceCachePolicyHookOffset).readByteArray(expected.length / 2))
    const actual = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
    if (actual !== expected) throw new Error('Native resource policy instruction anchor mismatch; no hook installed')
  }
  if (config.OnAfterCreatedOffset) {
    if (!config.ExpectedAfterCreatedBytes) throw new Error('Early native debug activation requires verified instruction bytes')
    const expected = config.ExpectedAfterCreatedBytes.toLowerCase()
    const bytes = new Uint8Array(mainModule.base.add(config.OnAfterCreatedOffset).readByteArray(expected.length / 2))
    const actual = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
    if (actual !== expected) throw new Error('OnAfterCreated instruction anchor mismatch; no hook installed')
  }
  for (const item of (config.NativeFilterTaps || [])) {
    if (!item.Offset || !item.ExpectedBytes) throw new Error('Native protocol tap requires verified instruction bytes')
    const expected = item.ExpectedBytes.toLowerCase()
    const bytes = new Uint8Array(mainModule.base.add(item.Offset).readByteArray(expected.length / 2))
    const actual = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
    if (actual !== expected) throw new Error('Native protocol tap anchor mismatch; no hook installed')
  }
  if (config.ObserveOnly === true) for (const item of (config.IdentityProbeHooks || [])) {
    const expected = item.ExpectedBytes.toLowerCase()
    const bytes = new Uint8Array(mainModule.base.add(item.Offset).readByteArray(expected.length / 2))
    const actual = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
    if (actual !== expected) throw new Error('Native identity probe anchor mismatch; no hook installed')
  }
  // Entry byte checks must also finish before any interceptor is installed.
  if (config.EntryHookOffset) {
    if (!config.ExpectedEntryBytes) throw new Error('Entry hook requires verified instruction bytes')
    const expected = config.ExpectedEntryBytes.toLowerCase()
    const bytes = new Uint8Array(mainModule.base.add(config.EntryHookOffset).readByteArray(expected.length / 2))
    const actual = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
    if (actual !== expected) throw new Error('Native entry instruction anchor mismatch; no hook installed')
  }
  const activatedContainers = new Set()
  let hooks = 0
  if (config.EnableEarlyActivation === true && config.OnAfterCreatedOffset) {
    // OnAfterCreated constructs the runtime configuration and starts LoadURL.
    // Activate native LanDebug BEFORE that initialization, not only later at
    // OnLoadStart's logging/server tail. No application JS is injected.
    Interceptor.attach(mainModule.base.add(config.OnAfterCreatedOffset), {
      onEnter(args) {
        activatedContainers.delete(args[0].toString())
        patchLanDebug(args[0], 'afterCreated')
      }
    })
    hooks++
  }
  if (config.EntryHookOffset) {
    const addr = mainModule.base.add(config.EntryHookOffset)
    // Verified entry: x0=container, x1=bool. Avoid intercepting/relocating a
    // conditional branch in the middle of OnLoadStart.
    Interceptor.attach(addr, {
      onEnter(args) {
        const key = args[0].toString()
        if (activatedContainers.has(key)) {
          try {
            const rt = tryReadPointer(args[0].add(0x38))
            const holder = rt && tryReadPointer(rt.add(0x5f0))
            const obj = holder && tryReadPointer(holder.add(0x10))
            if (obj && obj.add(0x1c8).readInt() === 1101) return
          } catch (_) { return }
        }
        if (patchLanDebug(args[0], 'loadEntry')) {
          args[1] = ptr(1)
          if (activatedContainers.size > 256) activatedContainers.clear()
          activatedContainers.add(key)
        }
      }
    })
    hooks++
  } else {
    interceptorTailGate(mainModule.base, config.LoadStartHookOffset)
    hooks++
  }
  if (config.EnableFactoryHook === true) {
    interceptorLoadStart2(mainModule.base, config.LoadStartHookOffset2)
    hooks++
  }
  if (config.EnableResourceCacheHook === true && config.ResourceCachePolicyHookOffset) {
    let calls = 0
    Interceptor.attach(mainModule.base.add(config.ResourceCachePolicyHookOffset), {
      onLeave(retval) {
        retval.replace(0x0)
        if (++calls === 1) send({ type: 'wmpf-resource-policy', called: true })
      }
    })
    hooks++
  }
  if (config.ObserveOnly === true) for (const item of (config.IdentityProbeHooks || [])) {
    let hit = false
    Interceptor.attach(mainModule.base.add(item.Offset), {
      onEnter(args) {
        if (!hit) { hit = true; send({ type: 'wmpf-probe-hit', name: item.Name, pid: Process.id }) }
        patchLanDebug(args[0], 'probe:' + item.Name) // ObserveOnly returns before any native write
      }
    })
    hooks++
  }
  for (const item of (config.NativeFilterTaps || [])) { observeNativeFilter(mainModule.base, item); hooks++ }
  send({ type: 'wmpf-ready', version: config.Version, hooks: hooks, mode: config.ObserveOnly ? 'observe-only' : (config.EntryHookOffset ? 'verified-entry' : 'tail-gate') })
}

main()
