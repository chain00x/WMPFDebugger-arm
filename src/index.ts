// 注意：如果你的环境不支持 TypeScript 类型，可以将文件扩展名改为 .js 并移除类型注解
import { promises } from "node:fs";
import path from "node:path";
import * as frida from "frida";
import WebSocket, { WebSocketServer } from "ws";
import { execFileSync, execSync } from "child_process";
import { argv } from "node:process";

import { createRelay } from "./cdp-relay";
import { attachChecked, detachChecked } from "./frida-session";

// 默认调试端口，请勿更改
const DEBUG_PORT = 9421;
// CDP 端口，可按需更改
// 通过导航到 devtools://devtools/bundled/inspector.html?ws=127.0.0.1:${CDP_PORT} 使用此端口
const CDP_PORT = 62000;
// --- 全局变量用于存储服务器和 Frida 会话实例 ---
let debugWSS: WebSocketServer | null = null;
let proxyWSS: WebSocketServer | null = null;
let fridaSessions: Array<{session: frida.Session, script: frida.Script, pid: number}> = [];

const fileExists = async (filePath: string): Promise<boolean> => {
    try {
        await promises.access(filePath);
        return true;
    } catch {
        return false;
    }
};

const getInstalledWMPFVersion = (): number | null => {
    const plistCandidates = [
        "/Applications/微信.app/Contents/MacOS/WeChatAppEx.app/Contents/Info.plist",
        "/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Info.plist",
    ];

    for (const plistPath of plistCandidates) {
        try {
            const rawVersion = execFileSync(
                "/usr/libexec/PlistBuddy",
                ["-c", "Print :CFBundleVersion", plistPath],
                { encoding: "utf-8" }
            ).trim();
            const match = rawVersion.match(/(\d+)$/);
            if (match) {
                return Number.parseInt(match[1], 10);
            }
        } catch {
            // Try the next known installation path.
        }
    }

    return null;
};

const getArgValue = (name: string): string | null => {
    for (let i = 0; i < argv.length; i++) {
        if (argv[i] === name && i + 1 < argv.length) {
            return argv[i + 1];
        }
    }
    return null;
};

const escapeForTemplateLiteral = (value: string): string => {
    return value.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\$\{/g, "\\${");
};

const loadHookConfig = async (projectRoot: string): Promise<string | null> => {
    const explicitConfigPath = getArgValue("--config");
    if (explicitConfigPath) {
        const absoluteConfigPath = path.isAbsolute(explicitConfigPath)
            ? explicitConfigPath
            : path.join(projectRoot, explicitConfigPath);
        console.log(`[frida] Using custom config: ${absoluteConfigPath}`);
        return (await promises.readFile(absoluteConfigPath)).toString();
    }

    const version = getInstalledWMPFVersion();
    if (!version) {
        console.warn("[frida] Unable to detect installed WMPF version; using hook fallback config");
        return null;
    }

    const candidates = [
        path.join(projectRoot, "config", `addresses.${version}.darwin.json`),
        path.join(projectRoot, "test", "wmpf", "frida", "config", `addresses.${version}.darwin.json`),
        path.join(projectRoot, "config", `addresses.${version}.json`),
        path.join(projectRoot, "test", "wmpf", "frida", "config", `addresses.${version}.json`),
    ];

    for (const candidate of candidates) {
        if (await fileExists(candidate)) {
            console.log(`[frida] Loaded config from: ${candidate}`);
            return (await promises.readFile(candidate)).toString();
        }
    }

    console.warn(`[frida] No config found for WMPF version ${version}; using hook fallback config`);
    return null;
};

const ensurePortsAvailable = (): void => {
    // Never kill established clients: the previous `lsof -ti :port` also
    // selected Chrome and WeChat, not just stale server listeners.
    for (const port of [DEBUG_PORT, CDP_PORT]) {
        let listeners = "";
        try {
            listeners = execFileSync("/usr/sbin/lsof", ["-nP", "-t", "-sTCP:LISTEN", `-iTCP:${port}`], { encoding: "utf-8" }).trim();
        } catch (e: any) {
            if (e.status !== 1) throw e;
        }
        if (listeners) throw new Error(`Port ${port} already has listener PID(s) ${listeners.replace(/\n/g, ",")}; stop the previous tool instance first`);
    }
};

// All websocket/CDP state is scoped to the active applet session in the relay.
// Keep Frida process management below unchanged.
let relay: ReturnType<typeof createRelay> | null = null;
const debug_server = () => {
    relay = createRelay({ debugPort: DEBUG_PORT, cdpPort: CDP_PORT });
    console.log(`[server] debug server: ws://127.0.0.1:${DEBUG_PORT}`);
    console.log(`[server] CDP server: ws://127.0.0.1:${CDP_PORT}; status: http://127.0.0.1:${CDP_PORT}/status`);
    return relay.debug;
};
const proxy_server = () => relay!.proxy;

// 动态获取 WeChatAppEx 进程 PID 的函数
// 只 attach 主进程（无 --type）。
// WeApp/渲染进程一律不碰：历史日志证明生命周期 hook 全在主进程触发，
// WeApp 注入只会和它的初始化 dlopen 竞态导致小程序闪退。
const isTargetProcess = (pid: number): boolean => {
    try {
        const executable = execFileSync('/bin/ps', ['-p', String(pid), '-o', 'comm='], { encoding: 'utf-8' }).trim();
        const cmd = execFileSync('/bin/ps', ['-p', String(pid), '-o', 'args='], { encoding: 'utf-8' });
        return executable.includes('/WeChatAppEx.app/') && executable.endsWith('/Contents/MacOS/WeChatAppEx') && !cmd.includes(' --type=');
    } catch {
        return false;
    }
};

const getWeChatAppExPID = (): number[] => {
    try {
        // 注意：路径可能需要根据你的实际安装位置调整
        const output = execFileSync('/usr/bin/pgrep', ['-x', 'WeChatAppEx'], { encoding: 'utf-8' }).trim();
        const pids = output
            .split("\n")
            .map((pid) => parseInt(pid.trim(), 10))
            .filter((pid) => !isNaN(pid))
            .filter(isTargetProcess);

        // 无进程不报错：微信刚启动/刚清缓存时 WeChatAppEx 还没 spawn，
        // 靠 auto-attach 轮询抓后续进程即可
        if (pids.length === 0) {
            console.log("[frida] no main WeChatAppEx process; open the miniapp first (auto-attach is disabled)");
            return [];
        }

        // 返回所有找到的 PID
        console.log(`[frida] Found WeChatAppEx PIDs: ${pids.join(", ")}`);
        return pids;
    } catch (error) {
        // pgrep 无匹配退出码=1，execSync 会抛——同样返回空等 auto-attach
        console.log("[frida] no main WeChatAppEx process (auto-attach is disabled)");
        return [];
    }
};

const isAppserviceProcess = (pid: number): boolean => {
    try {
        const cmd = execFileSync('/bin/ps', ['-p', String(pid), '-o', 'args='], { encoding: 'utf-8' });
        return cmd.includes('/WeApp.app/Contents/MacOS/WeApp') && cmd.includes('--wmpf-render-type=4') && !cmd.includes('--wmpf-appid=preload-');
    } catch {
        return false;
    }
};

const frida_server = async () => {
    if (argv.includes('--auto-attach')) throw new Error('Automatic process attachment is disabled; select a single --pid instead');
    const explicit = getArgValue('--pid');
    if (explicit && !/^[1-9][0-9]*$/.test(explicit)) throw new Error('--pid must be an integer');
    const pids = explicit ? [Number(explicit)] : getWeChatAppExPID();
    const appservice = argv.includes('--appservice');
    if (appservice) {
        if (pids.length !== 1 || !isAppserviceProcess(pids[0])) {
            throw new Error('--appservice requires one already-running WeApp logic process; preloads and page renderers are refused');
        }
    } else if (pids.length !== 1 || !isTargetProcess(pids[0])) {
        throw new Error('Select exactly one main WeChatAppEx process with --pid; helpers, shells and renderers are never attached');
    }
    const projectRoot = path.join(__dirname, '..');
    const metadata = JSON.parse(await promises.readFile(path.join(projectRoot, 'node_modules/frida/package.json'), 'utf8'));
    const version = String(metadata.version).split('.').map(Number);
    if ((version[0] < 17) || (version[0] === 17 && version[1] < 24)) {
        throw new Error('Frida >=17.24 is required for this macOS validation path; the old 17.3.2 runtime is not allowed');
    }
    const scriptPath = getArgValue('--script') || 'frida/hook.js';
    let source = await promises.readFile(path.resolve(projectRoot, scriptPath), 'utf8');
    if (source.includes('@@CONFIG@@')) {
        const config = await loadHookConfig(projectRoot);
        if (!config) throw new Error('No exact native-hook configuration; refusing fallback offsets');
        const parsed = JSON.parse(config);
        const native = parsed.Arch?.arm64 || parsed;
        const appid = getArgValue('--appid');
        if (appid && !/^wx[0-9a-f]{16}$/.test(appid)) throw new Error('--appid must be an exact native miniapp id');
        if (appid) native.TargetAppId = appid;
        if (argv.includes('--observe-only')) {
            native.ObserveOnly = true;
            native.EnableEarlyActivation = true;
            native.EnableResourceCacheHook = false;
            native.EnableFactoryHook = false;
            native.NativeFilterTaps = [];
            console.log('[frida] read-only container identity observation; no native debug fields or API functions modified');
        }
        source = source.replace('@@CONFIG@@', escapeForTemplateLiteral(JSON.stringify(parsed)));
    }
    const pid = pids[0];
    console.log(`[frida] single attach PID=${pid}, Frida=${metadata.version}, script=${scriptPath}; no auto-attach`);
    const handle = await attachChecked(await frida.getLocalDevice(), pid, source, {
        timeoutMs: 5000,
        requireReady: source.includes('wmpf-ready'),
        log: text => console.log(`[frida PID=${pid}] ${text}`),
        onMessage: message => {
            if (message.type !== 'send' || message.payload?.type !== 'wmpf-native-cdp') return false;
            relay?.ingestNativeFilteredFrame(String(message.payload.payload));
            return true;
        },
    });
    console.log(`[frida] native hooks ready in PID ${pid}`);
    return [handle];
};

// --- 关闭服务器和清理资源的函数 ---
let stopping = false;
const shutdown = async (exitCode = 0) => {
    if (stopping) return;
    stopping = true;
    console.log("\n[shutdown] Shutting down servers and cleaning up...");
    const watchdog = setTimeout(() => process.exit(1), 8000);
    watchdog.unref();

    const closePromises: Promise<void>[] = [];

    // 关闭所有 Frida 会话和脚本
    if (fridaSessions.length > 0) {
        console.log(`[shutdown] Detaching ${fridaSessions.length} Frida sessions...`);
        
        for (const handle of fridaSessions) {
            console.log(`[shutdown] Unloading/detaching PID ${handle.pid} (bounded cleanup)`);
            await detachChecked(handle);
        }
        
        // 清空会话数组
        fridaSessions = [];
        console.log("[shutdown] All Frida sessions detached.");
    }

    // 关闭 Debug WebSocket Server
    if (debugWSS) {
        console.log("[shutdown] Closing debug WebSocket connections...");
        // 关闭所有活动客户端连接
        debugWSS.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN || client.readyState === WebSocket.CLOSING) {
                client.terminate(); // 强制关闭客户端连接
            }
        });
        console.log("[shutdown] Closing debug WebSocket server...");
        closePromises.push(
            new Promise<void>((resolve, reject) => {
                debugWSS!.close((err) => {
                    if (err) {
                        console.error(
                            "[shutdown] Error closing debug WSS:",
                            err
                        );
                    } else {
                        console.log(
                            "[shutdown] Debug WebSocket server closed."
                        );
                    }
                    resolve(); // 总是 resolve 以继续关闭流程
                });
            })
        );
        debugWSS = null; // 清除引用
    }

    // 关闭 Proxy WebSocket Server
    if (proxyWSS) {
        console.log("[shutdown] Closing proxy WebSocket connections...");
        proxyWSS.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN || client.readyState === WebSocket.CLOSING) {
                client.terminate();
            }
        });
        console.log("[shutdown] Closing proxy WebSocket server...");
        closePromises.push(
            new Promise<void>((resolve, reject) => {
                proxyWSS!.close((err) => {
                    if (err) {
                        console.error(
                            "[shutdown] Error closing proxy WSS:",
                            err
                        );
                    } else {
                        console.log(
                            "[shutdown] Proxy WebSocket server closed."
                        );
                    }
                    resolve();
                });
            })
        );
        proxyWSS = null; // 清除引用
    }

    // 等待所有 WebSocket 服务器关闭
    if (closePromises.length > 0) {
        try {
            await Promise.all(closePromises);
        } catch (err) {
            console.error(
                "[shutdown] Error waiting for WebSocket servers to close:",
                err
            );
        }
    }

    console.log("[shutdown] Shutdown complete. Exiting.");
    process.exit(exitCode);
};
// --- 主函数 ---

const main = async () => {
    try {
        const lease = getArgValue('--session-seconds');
        if (lease && (!/^[1-9][0-9]*$/.test(lease) || Number(lease) > 3600)) throw new Error('--session-seconds requires 1..3600');
        ensurePortsAvailable();
        process.once('SIGINT', () => void shutdown());
        process.once('SIGTERM', () => void shutdown());
        // 启动服务器并保存实例引用
        debugWSS = debug_server();
        proxyWSS = proxy_server();
        const fridaObjects = await frida_server();
        fridaSessions = fridaObjects; // 保存所有会话和脚本引用

        if (lease) {
            setTimeout(() => { console.log('[session] lease expired; detaching'); void shutdown(); }, Number(lease) * 1000).unref();
        }

        // 可选：监听未捕获的异常，防止程序意外崩溃而不清理
        process.on('uncaughtException', (err) => {
            console.error('[main] Uncaught Exception:', err);
        });
        // Node 15+ 默认 unhandledRejection 直接退出进程——必须兑底
        process.on('unhandledRejection', (reason) => {
            console.error('[main] Unhandled Rejection:', reason);
        });

        console.log(
            "[main] Servers started. Press Ctrl+C to stop.\n" +
            `Debug endpoint: ws://localhost:${DEBUG_PORT}\n` +
            `CDP endpoint:   ws://localhost:${CDP_PORT}`
        );
    } catch (error) {
        console.error("[main] Error starting services:", error);
        await shutdown(1);
    }
};

// --- 程序入口 ---
(async () => {
    await main();
})();
