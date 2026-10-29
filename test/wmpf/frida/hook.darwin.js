const VERBOSE = false

const getMainModule = () => {
  return Process.findModuleByName('WeChatAppEx Framework')
}

const patchResourceCachePolicy = (base, offset) => {
  // xref: WAPCAdapterAppIndex.js
  Interceptor.attach(base.add(offset), {
    onEnter() {
      // VERBOSE && console.log(`[patch] lib cache policy ${offset} on enter`)
    },
    onLeave(retval) {
      // VERBOSE &&
      //   console.log(
      //     `[patch] lib cache policy ${offset} onLeave with retval:`,
      //     retval.toInt32(),
      //     '; patch to 0x0'
      //   )
      retval.replace(0x0)
    }
  })
}

const enableChromeInspector = (base, offset) => {
  // Hook sub_4E24620 to force enable chrome inspector
  // This function checks for "enable-chrome-inspector" and sets remote-debugging-port to 62168
  Interceptor.attach(base.add(offset), {
    onEnter(args) {
      // console.log('[hook] sub_4E24620 called')
    },
    onLeave(retval) {
      console.log('[hook] enableChromeInspector: forcing debug mode enabled')
      // The function sets up remote-debugging-port=62168 when enable-chrome-inspector is present
      // We can also set a global flag or do additional setup here
    }
  })
}

const patchCDPFilter = (base, offset) => {
  // filter function: SendToClientFilter
  // xref: devtools_message_filter_applet_webview.cc
  Interceptor.attach(base.add(offset), {
    onEnter() {
      // VERBOSE && console.log(`[patch] CDP filter ${offset} on enter`)
    },
    onLeave(retval) {
      if (retval && !retval.isNull()) {
        const v8_2_address = retval.add(8)
        // VERBOSE && console.log(`[patch] CDP filter - Current v8[2] value:`, v8_2_address.readU32())
        if (v8_2_address.readU32() == 6) {
          v8_2_address.writeU32(0x0)
        }
      }
    }
  })
}

const onLoadStartHook = (a1, structOffset) => {
  // 结构体偏移处理（兼容 ARM64 和 x64）
  // structOffset 从配置文件读取，不同版本和架构可能不同
  try {
    const result = a1
    const v4 = result.add(8).readPointer()

    if (v4 && !v4.isNull()) {
      const qword1 = v4.add(structOffset).readPointer()
      if (qword1 && !qword1.isNull()) {
        const qword2 = qword1.add(16).readPointer()
        if (qword2 && !qword2.isNull()) {
          const targetAddress = qword2.add(488)
          const currentValue = targetAddress.readInt()
          console.log('[hook] scene:', currentValue)

          // 允许的场景值列表
          const allowedValues = [
            1005, 1007, 1008, 1012, 1027, 1035, 1053, 1074, 1145, 1168, 1178, 1256, 1260, 1302, 1308
          ]
          if (allowedValues.includes(currentValue)) {
            console.log('[hook] hook scene condition -> 1101')
            targetAddress.writeInt(1101)
          }
        }
      }
    }
  } catch (error) {
    console.error('[hook] onLoadStartHook error:', error)
  }
}

const interceptorLoadStart = (base, offset) => {
  // xref: [perf] AppletIndexContainer::OnLoadStart (第一个)
  Interceptor.attach(base.add(offset), {
    onEnter() {
      console.log('[interceptor] AppletIndexContainer::OnLoadStart onEnter')
      // 根据架构选择正确的寄存器来修改第二个参数
      const arch = Process.arch
      if (arch === 'arm64') {
        // ARM64 架构中，第二个参数通过 X1 寄存器传递
        // 修改 X1 寄存器确保始终为 true
        this.context.x1 = (this.context.x1 & ~0xff) | 0x1
      } else if (arch === 'x64' || arch === 'x86_64') {
        // x64 架构中，第二个参数通过 RSI 寄存器传递（macOS System V ABI）
        // 修改 RSI 寄存器确保始终为 true
        this.context.rsi = (this.context.rsi & ~0xff) | 0x1
      } else {
        console.warn(`[interceptor] 未支持的架构: ${arch}，跳过寄存器修改`)
      }
    },
    onLeave() {
      // do nothing
    }
  })
}

const interceptorLoadStart2 = (base, offset, structOffset) => {
  // xref: [perf] AppletIndexContainer::OnLoadStart (最后一个函数)
  Interceptor.attach(base.add(offset), {
    onEnter(args) {
      VERBOSE && console.log('[interceptor] OnLoadStart2 onEnter, first_param:', args[0])
      onLoadStartHook(args[0], structOffset)
    },
    onLeave() {
      // do nothing
    }
  })
}

const parseConfig = () => {
  const rawConfig = `@@CONFIG@@`
  if (rawConfig.includes('@@')) {
    // 测试地址 - 默认使用 17078 版本
    return {
      Version: 17078,
      LoadStartHookOffset: '0x4F0620C',
      LoadStartHookOffset2: '0x81CEC08',
      CDPFilterHookOffset: '0x81BFC04',
      ResourceCachePolicyHookOffset: '0x4F699E8',
      StructOffset: 1376
    }
  }
  return JSON.parse(rawConfig)
}

const resolveArchConfig = (config) => {
  // 兼容旧格式（顶层直接是偏移字段）
  if (config && typeof config === 'object' && config.LoadStartHookOffset) {
    return config
  }

  // 新格式（通用配置）：{ Version, Arch: { arm64: {...}, x64: {...} } }
  const arch = Process.arch // 'arm64' | 'x64' | ...
  const table = config?.Arch || config?.ARCH || config?.arch || null
  if (!table || typeof table !== 'object') return null

  // 常见别名兜底
  const candidates = [arch]
  if (arch === 'x86_64') candidates.push('x64')
  if (arch === 'amd64') candidates.push('x64')
  if (arch === 'ia32') candidates.push('x86')

  for (const key of candidates) {
    const picked = table[key]
    if (picked && typeof picked === 'object' && picked.LoadStartHookOffset) {
      return { ...picked, Version: config.Version ?? picked.Version, __arch: key }
    }
  }
  return null
}

const validateConfig = (config) => {
  const required = [
    'LoadStartHookOffset',
    'LoadStartHookOffset2',
    'CDPFilterHookOffset',
    'ResourceCachePolicyHookOffset',
    'StructOffset'
  ]
  const missing = required.filter((k) => config?.[k] === undefined || config?.[k] === null)
  if (missing.length) {
    throw new Error(`配置缺少字段: ${missing.join(', ')}`)
  }
}

const main = () => {
  const rawConfig = parseConfig()
  const config = resolveArchConfig(rawConfig)
  const mainModule = getMainModule()

  if (!mainModule) {
    console.error('[frida] WeChatAppEx Framework module not found')
    return
  }

  if (!config) {
    console.error(
      `[frida] 未找到可用配置。Process.arch=${Process.arch}，请检查配置文件是否包含对应架构(arm64/x64)的偏移`
    )
    return
  }

  try {
    validateConfig(config)
  } catch (e) {
    console.error(`[frida] 配置校验失败: ${e.message}`)
    return
  }

  console.log(
    `[frida] Loaded config for version: ${config.Version} (arch: ${config.__arch || Process.arch})`
  )
  console.log(`[frida] Module base: ${mainModule.base}`)

  interceptorLoadStart(mainModule.base, config.LoadStartHookOffset)
  interceptorLoadStart2(mainModule.base, config.LoadStartHookOffset2, config.StructOffset)
  patchResourceCachePolicy(mainModule.base, config.ResourceCachePolicyHookOffset)
  patchCDPFilter(mainModule.base, config.CDPFilterHookOffset)
}

main()
