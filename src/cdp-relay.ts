import WebSocket, { WebSocketServer } from 'ws';
import { createServer } from 'node:http';
const codex = require('./third-party/RemoteDebugCodex.js');
const proto = require('./third-party/WARemoteDebugProtobuf.js').mmbizwxadevremote.WARemoteDebug_DebugMessage;

type Source = ({ transport: 'cdp'; jscontextId: string } | { transport: 'custom' } | { transport: 'dom'; webviewId: number } | { transport: 'observed' }) & { sessionId?: string };
type Pending = { source: Source; resolve: (value: any) => void; reject: (error: Error) => void; timer: NodeJS.Timeout };
type Peer = { ws: WebSocket; diagnostic: boolean; networks: Set<string>; runtimes: Set<string>; replayed: Set<string> };
type RequestInfo = { source: Source; postData?: string; url?: string };
type Options = { debugPort: number; cdpPort: number; timeoutMs?: number; historyLimit?: number; observeWxRequest?: boolean; log?: (s: string) => void };

// This is exclusively a native debug-protocol adapter. It does not configure
// HTTP proxies, issue business requests, evaluate instrumentation, patch wx APIs,
// poll JS contexts, synthesize network traffic or install certificates.
// Injected into the appservice context on explicit request. Wraps wx.request
// once, calls the original unchanged, and reports the real values through the
// Runtime binding. It never fabricates a request and never changes headers/URLs.
const WX_OBSERVER_SOURCE = `(function () {
  try {
    var g = typeof globalThis !== 'undefined' ? globalThis : window;
    if (g.__wmpfWxObserverInstalled) return 'installed';
    if (typeof wx !== 'object' || !wx || typeof wx.request !== 'function') return 'no-wx';
    var orig = wx.request;
    var seq = 0;
    var finished = {};
    var text = function (v) {
      try { if (v === undefined) return undefined; return typeof v === 'string' ? v : JSON.stringify(v); } catch (e) { return undefined; }
    };
    var report = function (payload) {
      try {
        var fn = g.__wmpfWxRequest;
        if (typeof fn === 'function') fn(JSON.stringify(payload));
      } catch (e) {}
    };
    var finish = function (id, res) {
      if (finished[id]) return;
      finished[id] = true;
      var err = res && (res.errMsg || '');
      if (res && typeof res.statusCode === 'number' && res.statusCode > 0) {
        var body = text(res.data);
        if (body !== undefined && body.length > 2097152) body = body.slice(0, 2097152);
        report({ phase: 'done', id: id, status: res.statusCode, headers: res.header || {}, body: body, timestamp: Date.now() });
      } else if (err && /fail/i.test(err)) {
        report({ phase: 'fail', id: id, error: err, timestamp: Date.now() });
      } else {
        report({ phase: 'done', id: id, status: 0, headers: (res && res.header) || {}, body: text(res && res.data), timestamp: Date.now() });
      }
    };
    var wrapped = function (options) {
      if (!options || typeof options !== 'object') return orig.apply(wx, arguments);
      var id = 'wx.' + (++seq) + '.' + Date.now().toString(36);
      var headers = options.header && typeof options.header === 'object' ? options.header : {};
      report({
        phase: 'start', id: id, url: String(options.url || ''),
        method: String(options.method || 'GET').toUpperCase(), headers: headers,
        postData: text(options.data), timestamp: Date.now()
      });
      var copy = {};
      for (var k in options) copy[k] = options[k];
      copy.success = function (res) { try { finish(id, res); } catch (e) {} return typeof options.success === 'function' ? options.success.apply(this, arguments) : undefined; };
      copy.fail = function (res) { try { finish(id, res); } catch (e) {} return typeof options.fail === 'function' ? options.fail.apply(this, arguments) : undefined; };
      copy.complete = function (res) { try { finish(id, res); } catch (e) {} return typeof options.complete === 'function' ? options.complete.apply(this, arguments) : undefined; };
      return orig.call(wx, copy);
    };
    try { wx.request = wrapped; } catch (e) {
      try { Object.defineProperty(wx, 'request', { value: wrapped, configurable: true, writable: true }); } catch (e2) { return 'assign-failed'; }
    }
    g.__wmpfWxObserverInstalled = true;
    return 'installed';
  } catch (e) { return 'error:' + e.message; }
})()`;

export class CdpRelay {
    readonly debug: WebSocketServer;
    readonly proxy: WebSocketServer;
    private applet: WebSocket | null = null;
    private peers = new Set<Peer>();
    private controller: Peer | null = null;
    private pending = new Map<number, Pending>();
    private contexts = new Map<string, { context: any; sessionId?: string }>();
    private requests = new Map<string, RequestInfo>();
    private history: Array<{ event: any; bytes: number }> = [];
    private historyBytes = 0;
    private counts: Record<string, number> = {};
    private methods: Record<string, number> = {};
    private generation = 0;
    private seq = 0;
    private op = 1000000;
    private forwarded = 0;
    private nativeRequests = 0;
    private bodyResponses = 0;
    private malformed = 0;
    private lastError = '';
    private lastSession: Record<string, unknown> | null = null;
    private backendNetworkRequested = new Set<string>();
    private targets = new Map<string, any>();
    private autoAttached = 0;
    private closed = false;
    private observedBodies = new Map<string, string>();
    private wxObserverRequested = false;
    private wxObserverInstalled = new Set<string>();
    private log: (s: string) => void;
    private timeout: number;

    constructor(private options: Options) {
        this.log = options.log || console.log;
        this.timeout = options.timeoutMs || 7000;
        this.debug = new WebSocketServer({ host: '127.0.0.1', port: options.debugPort });
        const http = createServer((req, res) => {
            const address = this.proxy.address();
            const port = address && typeof address === 'object' ? address.port : options.cdpPort;
            const ws = `127.0.0.1:${port}`;
            const endpoints: Record<string, unknown> = {
                '/status': this.status(),
                '/json/version': { Browser: 'WMPF native protocol relay', 'Protocol-Version': '1.3' },
                '/json': [{ id: 'wmpf', type: 'page', title: 'WeChat miniapp (native)', url: '',
                    webSocketDebuggerUrl: `ws://${ws}`, devtoolsFrontendUrl: `devtools://devtools/bundled/inspector.html?ws=${ws}` }],
            };
            endpoints['/json/list'] = endpoints['/json'];
            if (req.method === 'GET' && Object.prototype.hasOwnProperty.call(endpoints, req.url || '')) {
                res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
                res.end(JSON.stringify(endpoints[req.url!]));
            } else { res.writeHead(404); res.end(); }
        });
        this.proxy = new WebSocketServer({ server: http });
        http.listen(options.cdpPort, '127.0.0.1');
        this.proxy.on('close', () => { http.close(); this.reset(); this.closed = true; });
        this.debug.on('close', () => { this.applet = null; this.reset(); });
        this.debug.on('connection', ws => this.attachApplet(ws));
        this.proxy.on('connection', (ws, req) => this.attachPeer(ws, /[?&]diagnostic=1(?:&|$)/.test(req.url || '')));
        for (const server of [this.debug, this.proxy]) server.on('error', e => this.log(`[server] ${e.message}`));
    }

    status() {
        return { mode: 'native-only', connected: this.applet?.readyState === WebSocket.OPEN,
            generation: this.generation, controller: this.controller?.ws.readyState === WebSocket.OPEN,
            networkEnabled: !!this.controller?.networks.size, networkSessions: [...(this.controller?.networks || [])], contexts: [...this.contexts.keys()],
            targets: [...this.targets.entries()].map(([sid, info]) => ({ sessionId: sid, type: info?.type, title: info?.title, url: info?.url })),
            pending: this.pending.size, nativeRequests: this.nativeRequests, bodyResponses: this.bodyResponses,
            networkMessagesSent: this.forwarded, bufferedEvents: this.history.length,
            bufferedBytes: this.historyBytes, malformedMessages: this.malformed,
            categories: this.counts, eventMethods: this.methods, lastError: this.lastError,
            lastSession: this.lastSession };
    }

    // Native instrumentation may report an ORIGINAL CDP frame which WMPF's
    // SendToClientFilter turned into empty/{}. No business API is wrapped or
    // called. The native payload/id/session are preserved; no event is invented.
    ingestNativeFilteredFrame(payload: string): boolean {
        if (!this.applet || this.applet.readyState !== WebSocket.OPEN || payload.length > 2 * 1024 * 1024) return false;
        try {
            const message = JSON.parse(payload);
            const event = message?.method;
            const allowedEvent = event === 'Network.requestWillBeSent' || event === 'Network.responseReceived';
            const bodyResult = message?.id != null && typeof message.result?.body === 'string';
            if (!allowedEvent && !bodyResult) return false;
            this.counts.nativeFilteredFrames = (this.counts.nativeFilteredFrames || 0) + 1;
            this.receiveCdp(message, { transport: 'cdp', jscontextId: '' });
            return true;
        } catch { this.malformed++; return false; }
    }

    private reset() {
        if (this.generation > 0 && (this.nativeRequests || this.history.length || this.pending.size)) {
            this.lastSession = { generation: this.generation, nativeRequests: this.nativeRequests,
                bodyResponses: this.bodyResponses, networkMessagesSent: this.forwarded,
                events: this.history.length, lastError: this.lastError };
            this.log(`[session-summary] ${JSON.stringify(this.lastSession)}`);
        }
        this.generation++;
        for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(new Error('Applet session changed')); }
        this.pending.clear(); this.contexts.clear(); this.requests.clear();
        for (const peer of this.peers) {
            for (const session of peer.networks) if (session) peer.networks.delete(session);
            peer.runtimes.clear();
        }
        this.history = []; this.historyBytes = 0;
        this.nativeRequests = 0; this.bodyResponses = 0; this.forwarded = 0;
        this.backendNetworkRequested.clear(); this.targets.clear(); this.autoAttached = 0; this.lastError = '';
        this.observedBodies.clear(); this.wxObserverInstalled.clear();
    }

    private attachApplet(ws: WebSocket) {
        const previous = this.applet;
        this.reset(); this.applet = ws;
        if (previous && previous !== ws) previous.close(1000, 'new applet session');
        this.log(`[conn] miniapp connected generation=${this.generation}`);
        ws.on('message', raw => {
            if (this.applet !== ws || this.closed) return;
            try {
                const message = codex.unwrapDebugMessageData(proto.decode(raw));
                if (message) this.receive(message.category, message.data || {});
            } catch (e) { this.malformed++; this.lastError = `protocol decode: ${(e as Error).message}`; }
        });
        ws.on('error', e => this.log(`[applet] ${e.message}`));
        ws.on('close', code => {
            if (this.applet !== ws) return;
            this.applet = null; this.reset();
            this.log(`[conn] miniapp disconnected code=${code}; pending operations cancelled`);
        });
        // No unsolicited Runtime.enable/evaluate/disable or periodic work.
        // Reapply only a Network subscription explicitly requested by a frontend.
        for (const p of this.peers) if (!p.diagnostic) for (const sessionId of p.networks) this.enableBackendNetwork(sessionId);
        // Ask the native runtime once per generation which debug targets exist
        // and to keep us attached to new ones (flatten, no waitForDebugger).
        // This discovers the appservice/logic-layer target before any frontend
        // could name it; it evaluates nothing and wraps nothing.
        const gen = this.generation;
        setTimeout(() => {
            if (gen !== this.generation || this.applet !== ws) return;
            void this.command('Target.getTargets', {}).then(r => {
                for (const t of r?.targetInfos || []) this.log(`[target] ${t.type} ${t.title || ''} ${t.url || ''}`);
            }).catch(() => undefined);
            void this.command('Target.setAutoAttach', { autoAttach: true, flatten: true, waitForDebuggerOnStart: false })
                .then(() => { if (gen === this.generation) { this.autoAttached = gen; this.log('[target] autoAttach requested on root session'); } })
                .catch(e => { if (gen === this.generation) this.lastError = `Target.setAutoAttach: ${e.message}`; });
        }, 500);
    }

    private send(category: string, data: any) {
        if (!this.applet || this.applet.readyState !== WebSocket.OPEN) throw new Error('No miniapp connected');
        const wrapped = codex.wrapDebugMessageData(data, category, 0);
        this.applet.send(proto.encode({ seq: ++this.seq, category, data: wrapped.buffer,
            compressAlgo: 0, originalSize: wrapped.originalSize }).finish(), { binary: true });
    }

    private transaction(source: Source, make: (id: number) => void, label: string): Promise<any> {
        if (!this.applet || this.applet.readyState !== WebSocket.OPEN) return Promise.reject(new Error('No miniapp connected'));
        const id = ++this.op;
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.pending.delete(id);
                reject(new Error(`${label}: native runtime did not reply (no response was fabricated)`));
            }, this.timeout);
            timer.unref(); this.pending.set(id, { source, resolve, reject, timer });
            try { make(id); }
            catch (e) { clearTimeout(timer); this.pending.delete(id); reject(e); }
        });
    }

    private command(method: string, params: any = {}, source: Source = { transport: 'cdp', jscontextId: '' }) {
        return this.transaction(source, id => {
            if (source.transport === 'dom') {
                this.send('domOp', { webview_id: source.webviewId,
                    params: JSON.stringify({ method, commandParams: params, callbackID: id }) });
            } else if (source.transport === 'cdp') {
                this.send('chromeDevtools', { op_id: id, jscontext_id: source.jscontextId,
                    payload: JSON.stringify({ id, method, params, ...(source.sessionId ? { sessionId: source.sessionId } : {}) }) });
            } else throw new Error('Custom messages require their native method, not generic CDP');
        }, method);
    }

    private enableBackendNetwork(sessionId = '') {
        if (this.backendNetworkRequested.has(sessionId) || !this.applet) return;
        this.backendNetworkRequested.add(sessionId);
        const gen = this.generation;
        // customMessage/__networkDebug is a native telemetry stream independent
        // of the JS inspector's Network domain. Failure of the latter must not
        // prevent Chrome from subscribing to events already received by relay.
        void this.command('Network.enable', {}, { transport: 'cdp', jscontextId: '', sessionId: sessionId || undefined }).catch(e => {
            if (gen === this.generation) this.lastError = `inspector Network.enable: ${e.message}; native event forwarding remains enabled`;
        });
    }

    receive(category: string, data: any) {
        this.counts[category] = (this.counts[category] || 0) + 1;
        if (category === 'chromeDevtoolsResult') {
            this.receiveCdp(JSON.parse(String(data.payload)), { transport: 'cdp', jscontextId: String(data.jscontext_id ?? data.jscontextId ?? '') }, data.op_id ?? data.opId);
        } else if (category === 'customMessage' && data.method === '__networkDebug') {
            this.receiveCdp(JSON.parse(data.payload), { transport: 'custom' });
        } else if (category === 'networkDebugAPI') {
            this.receiveNetworkDebugApi(data);
        } else if (category === 'domEvent') {
            const p = typeof data.params === 'string' ? JSON.parse(data.params) : data.params;
            const source: Source = { transport: 'dom', webviewId: Number(data.webview_id ?? data.webviewId ?? 0) };
            if (p?.command === 'DEBUGGEE_EVENT' && p.data?.method) this.receiveCdp(p.data, source);
            else if (p?.command === 'DEBUGGEE_CALLBACK') {
                const d = p.data || {};
                this.settle(p.callbackID, source, d.error, Object.prototype.hasOwnProperty.call(d, 'result') ? d.result : d);
            }
        }
    }

    private settle(id: unknown, source: Source, error: any, result: any) {
        const p = this.pending.get(Number(id));
        if (!p || p.source.transport !== source.transport) return;
        if (p.source.transport === 'dom' && source.transport === 'dom' && p.source.webviewId !== source.webviewId) return;
        if (p.source.transport === 'cdp' && (p.source.sessionId || '') !== (source.sessionId || '')) return;
        this.pending.delete(Number(id)); clearTimeout(p.timer);
        if (error) p.reject(new Error(error.message || JSON.stringify(error)));
        else p.resolve(result);
    }

    private receiveCdp(message: any, source: Source, envelopeId?: number) {
        if (!message || typeof message !== 'object' || Array.isArray(message)) { this.malformed++; return; }
        const sessionId = typeof message.sessionId === 'string' ? message.sessionId : '';
        source = { ...source, sessionId: sessionId || undefined };
        // An event may carry an unrelated envelope opId. Only actual CDP results
        // settle pending commands. In particular, the common bare {} is an ACK.
        if (typeof message.method !== 'string') {
            if ('result' in message || 'error' in message) this.settle(message.id ?? envelopeId, source, message.error, message.result);
            return;
        }
        this.methods[message.method] = (this.methods[message.method] || 0) + 1;
        const key = (id: number) => `${sessionId}\u0000${id}`;
        if (message.method === 'Runtime.executionContextCreated') {
            const ctx = message.params?.context;
            if (typeof ctx?.id === 'number') {
                this.contexts.set(key(ctx.id), { context: ctx, sessionId: sessionId || undefined });
                if (!sessionId) void this.maybeInstallWxObserver();
            }
        } else if (message.method === 'Runtime.executionContextDestroyed') {
            this.contexts.delete(key(message.params?.executionContextId));
        } else if (message.method === 'Runtime.executionContextsCleared') {
            for (const [k, v] of this.contexts) if ((v.sessionId || '') === sessionId) this.contexts.delete(k);
        } else if (message.method === 'Target.attachedToTarget') {
            const sid = message.params?.sessionId;
            if (typeof sid === 'string') {
                const info = message.params.targetInfo || {};
                this.targets.set(sid, info);
                this.log(`[target] attached ${info.type || '?'} session=${sid} url=${info.url || ''}`);
                this.enableBackendNetwork(sid);
            }
        } else if (message.method === 'Target.targetCreated' || message.method === 'Target.targetInfoChanged') {
            const info = message.params?.targetInfo;
            if (info?.targetId) for (const [sid, t] of this.targets) if (t?.targetId === info.targetId) this.targets.set(sid, info);
        } else if (message.method === 'Target.detachedFromTarget') {
            const detached = message.params?.sessionId;
            if (typeof detached === 'string') {
                this.backendNetworkRequested.delete(detached);
                for (const peer of this.peers) { peer.networks.delete(detached); peer.runtimes.delete(detached); }
                for (const [k, v] of this.contexts) if (v.sessionId === detached) this.contexts.delete(k);
            }
        }
        if (message.method === 'Runtime.bindingCalled' && message.params?.name === '__wmpfWxRequest') {
            this.wxObserverEvent(String(message.params.payload || ''));
            return;
        }
        if (sessionId) this.enableBackendNetwork(sessionId); // every observed child session gets Network domain
        if (message.method.startsWith('Network.')) this.network(message, source);
        else this.emit(message);
    }

    // WMPF 25800 reports wx.request starts on networkDebugAPI (api, task, headers).
    // A URL is forwarded only when that native message already carries one.
    // The official IDE asks a separate simulator for the URL; this adapter does
    // not evaluate appservice JS or invent a request when the URL is absent.
    private receiveNetworkDebugApi(data: any) {
        const api = String(data?.api_name || data?.apiName || '').toLowerCase();
        const task = String(data?.task_id || data?.taskId || '');
        const prefix: Record<string, string> = { request: '1', download: '2', upload: '3', socket: '4' };
        if (!prefix[api] || !task) { this.malformed++; return; }
        let headers: Record<string, string> = {};
        const rawHeaders = data.request_headers ?? data.requestHeaders;
        if (typeof rawHeaders === 'string' && rawHeaders) {
            try {
                const parsed = JSON.parse(rawHeaders);
                if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) { this.malformed++; return; }
                headers = parsed;
            } catch { this.malformed++; return; }
        }
        const url = typeof data.url === 'string' ? data.url : '';
        if (!url) {
            this.counts.networkDebugApiWithoutUrl = (this.counts.networkDebugApiWithoutUrl || 0) + 1;
            this.lastError = 'networkDebugAPI arrived without a native URL; request was not fabricated';
            return;
        }
        const method = typeof data.method === 'string' && data.method ? data.method : 'GET';
        const stamp = Number(data.timestamp);
        this.receiveCdp({
            method: 'Network.requestWillBeSent',
            params: {
                requestId: `${prefix[api]}.${task}`,
                documentURL: typeof headers.Referer === 'string' ? headers.Referer : '',
                request: { url, method, headers },
                timestamp: Number.isFinite(stamp) && stamp > 0 ? stamp / 1000 : Date.now() / 1000,
                type: 'XHR',
            },
        }, { transport: 'custom' });
    }

    private rememberRequest(source: Source, requestId: string, postData?: unknown) {
        this.nativeRequests++;
        const key = `${source.sessionId || ''}\u0000${requestId}`;
        const previous = this.requests.get(key);
        this.requests.set(key, { source, postData: typeof postData === 'string' ? postData : previous?.postData, url: previous?.url });
        if (this.requests.size > 1000) this.requests.delete(this.requests.keys().next().value!);
        this.log(`[network] native ${source.transport} request id=${requestId}`);
    }

    // WMPF 25800 exposes no native network telemetry. When the frontend asks
    // for Network, install an observer inside the appservice context instead:
    // wx.request is wrapped once, the original call and its callbacks are
    // forwarded unchanged, and only the actual url/method/status/body are
    // reported back through a Runtime binding. No request is synthesized.
    private async maybeInstallWxObserver() {
        if (!this.options.observeWxRequest || !this.applet || this.applet.readyState !== WebSocket.OPEN) return;
        const gen = this.generation;
        try {
            await this.command('Runtime.addBinding', { name: '__wmpfWxRequest' }, { transport: 'cdp', jscontextId: '' });
            for (const value of this.contexts.values()) {
                if (value.sessionId) continue;
                const ctxId = value.context?.id;
                if (typeof ctxId !== 'number') continue;
                const key = String(ctxId);
                if (this.wxObserverInstalled.has(key)) continue;
                this.wxObserverInstalled.add(key);
                const probe = await this.command('Runtime.evaluate', { expression: 'typeof wx', contextId: ctxId, returnByValue: true }, { transport: 'cdp', jscontextId: '' });
                if (gen !== this.generation) return;
                if (probe?.result?.value !== 'object') continue;
                const result = await this.command('Runtime.evaluate', { expression: WX_OBSERVER_SOURCE, contextId: ctxId, returnByValue: true }, { transport: 'cdp', jscontextId: '' });
                this.log(`[wx-observer] context ${ctxId}: ${result?.result?.value ?? 'no result'}`);
            }
        } catch (e) {
            if (gen === this.generation) this.lastError = `wx observer: ${(e as Error).message}`;
        }
    }

    private wxObserverEvent(payload: string) {
        let p: any;
        try { p = JSON.parse(payload); } catch { this.malformed++; return; }
        if (!p || typeof p.id !== 'string' || !p.id) { this.malformed++; return; }
        const source: Source = { transport: 'observed' };
        const mapKey = `\u0000${p.id}`;
        if (p.phase === 'start') {
            if (typeof p.url !== 'string' || !p.url) { this.counts.wxRequestWithoutUrl = (this.counts.wxRequestWithoutUrl || 0) + 1; return; }
            const headers = p.headers && typeof p.headers === 'object' ? p.headers : {};
            this.requests.set(mapKey, { source, url: p.url, postData: typeof p.postData === 'string' ? p.postData : undefined });
            if (this.requests.size > 1000) this.requests.delete(this.requests.keys().next().value!);
            this.receiveCdp({
                method: 'Network.requestWillBeSent',
                params: {
                    requestId: p.id, loaderId: '', documentURL: '',
                    request: { url: p.url, method: typeof p.method === 'string' && p.method ? p.method : 'GET', headers,
                        ...(typeof p.postData === 'string' ? { postData: p.postData } : {}) },
                    timestamp: (Number(p.timestamp) || Date.now()) / 1000, wallTime: Date.now() / 1000,
                    initiator: { type: 'other' }, type: 'XHR',
                },
            }, source);
        } else if (p.phase === 'done') {
            const url = this.requests.get(mapKey)?.url || '';
            const body = typeof p.body === 'string' ? p.body : '';
            if (body.length <= 2 * 1024 * 1024) {
                this.observedBodies.set(p.id, body);
                while (this.observedBodies.size > 300) this.observedBodies.delete(this.observedBodies.keys().next().value!);
            }
            const ts = (Number(p.timestamp) || Date.now()) / 1000;
            this.receiveCdp({
                method: 'Network.responseReceived',
                params: {
                    requestId: p.id, loaderId: '', timestamp: ts, type: 'XHR',
                    response: { url, status: Number(p.status) || 0, statusText: '', headers: p.headers && typeof p.headers === 'object' ? p.headers : {}, mimeType: '', connectionId: p.id },
                },
            }, source);
            this.receiveCdp({ method: 'Network.loadingFinished', params: { requestId: p.id, timestamp: ts, encodedDataLength: body.length } }, source);
        } else if (p.phase === 'fail') {
            this.receiveCdp({
                method: 'Network.loadingFailed',
                params: { requestId: p.id, timestamp: (Number(p.timestamp) || Date.now()) / 1000, type: 'XHR', errorText: typeof p.error === 'string' ? p.error : 'request failed', canceled: false },
            }, source);
        } else this.malformed++;
    }

    private network(event: any, source: Source) {
        const p = event.params;
        if (!p || typeof p !== 'object') { this.malformed++; return; }
        const rid = p.requestId;
        if (event.method === 'Network.requestWillBeSent') {
            if (typeof rid !== 'string' || typeof p.request?.url !== 'string') { this.malformed++; return; }
            this.rememberRequest(source, rid, p.request.postData);
        } else if (event.method === 'Network.responseReceived' && typeof rid === 'string' && typeof p.response?.url === 'string' && !this.requests.has(`${source.sessionId || ''}\u0000${rid}`)) {
            // 25800 can emit the response before requestWillBeSent. Chrome hides
            // that response, so record the URL the runtime already provided.
            this.rememberRequest(source, rid);
            this.stash({
                method: 'Network.requestWillBeSent',
                ...(source.sessionId ? { sessionId: source.sessionId } : {}),
                params: {
                    requestId: rid, loaderId: p.loaderId || '', documentURL: '',
                    request: { url: p.response.url, method: 'GET', headers: p.response.requestHeaders || {} },
                    timestamp: typeof p.timestamp === 'number' ? p.timestamp : Date.now() / 1000,
                    wallTime: Date.now() / 1000, initiator: { type: 'other' }, type: p.type || 'XHR',
                },
            });
        }
        // These are protocol defaults only. Never invent a URL, request,
        // response, timing measurement, status code or body not sent by WMPF.
        const params = { ...p };
        if (event.method === 'Network.requestWillBeSent') {
            if (params.loaderId === undefined) params.loaderId = '';
            if (params.initiator === undefined) params.initiator = { type: 'other' };
            if (params.request.headers === undefined) params.request = { ...params.request, headers: {} };
        } else if (event.method === 'Network.responseReceived' && params.loaderId === undefined) params.loaderId = '';
        const normalized = { ...event, params };
        this.stash(normalized);
    }

    private stash(event: any) {
        const bytes = Buffer.byteLength(JSON.stringify(event));
        this.history.push({ event, bytes }); this.historyBytes += bytes;
        while (this.history.length > (this.options.historyLimit || 2000) || this.historyBytes > 8 * 1024 * 1024) {
            this.historyBytes -= this.history.shift()!.bytes;
        }
        this.emit(event);
    }

    private async responseBody(requestId: string, sessionId = '') {
        const info = this.requests.get(`${sessionId}\u0000${requestId}`);
        let body: any;
        if (info?.source.transport === 'observed') {
            // The observer captured data only when the app's own callback ran.
            const body = this.observedBodies.get(String(requestId));
            if (body === undefined) throw new Error('Observed request body unavailable (callback not yet returned or body too large)');
            this.bodyResponses++;
            return { body, base64Encoded: false };
        }
        if (info?.source.transport === 'custom') {
            // Observed in the installed official IDE's onRemoteDebugDevtoolsMessage:
            // prefix 1=request, 2=download, 3=upload, 4=socket. No JS evaluation.
            const m = /^([1-4])\.(.+)$/.exec(requestId);
            if (!m) throw new Error('Native custom-message requestId has no supported API/task mapping');
            const api: Record<string, string> = { '1': 'request', '2': 'download', '3': 'upload', '4': 'socket' };
            body = await this.transaction({ transport: 'custom' }, id => {
                this.send('customMessage', { method: '__getNetworkResponseBody',
                    payload: JSON.stringify({ id: m[2], devtoolsMsgId: id, api: api[m[1]] }) });
            }, 'Network.getResponseBody (__getNetworkResponseBody)');
        } else body = await this.command('Network.getResponseBody', { requestId }, info?.source || { transport: 'cdp', jscontextId: '', sessionId: sessionId || undefined });
        if (typeof body?.body !== 'string') throw new Error('Native runtime did not provide a response body');
        this.bodyResponses++;
        return { body: body.body, base64Encoded: !!body.base64Encoded };
    }

    private sendPeer(peer: Peer, message: any) {
        if (peer.ws.readyState === WebSocket.OPEN) peer.ws.send(JSON.stringify(message));
    }

    private emit(message: any) {
        for (const p of this.peers) {
            // A root-session Network subscription covers child-target events too.
            if (message.method?.startsWith('Network.') && !p.networks.has('') && !p.networks.has(message.sessionId || '') && !p.diagnostic) continue;
            if (/^Runtime\.executionContext/.test(message.method || '') && !p.runtimes.has(message.sessionId || '') && !p.diagnostic) continue;
            this.sendPeer(p, message);
            if (message.method?.startsWith('Network.') && p.ws.readyState === WebSocket.OPEN) this.forwarded++;
        }
    }

    private attachPeer(ws: WebSocket, diagnostic: boolean) {
        const peer: Peer = { ws, diagnostic, networks: new Set(), runtimes: new Set(), replayed: new Set() };
        if (!diagnostic) {
            if (this.controller) {
                this.peers.delete(this.controller); // don't forward while its close handshake is pending
                this.controller.ws.close(4000, 'replaced');
            }
            this.controller = peer;
        }
        this.peers.add(peer);
        this.log(`[conn] ${diagnostic ? 'diagnostic (controller preserved)' : 'CDP'} client connected`);
        ws.on('message', raw => {
            let message: any;
            try { message = JSON.parse(raw.toString()); } catch { return; }
            if (this.peers.has(peer)) void this.frontend(peer, message);
        });
        ws.on('close', () => { this.peers.delete(peer); if (this.controller === peer) this.controller = null; });
        ws.on('error', e => this.log(`[cdp] ${e.message}`));
    }

    private async frontend(peer: Peer, message: any) {
        const { id, method } = message || {};
        if (id == null || typeof method !== 'string') return;
        const sessionId = typeof message.sessionId === 'string' ? message.sessionId : '';
        const tag = sessionId ? { sessionId } : {};
        const reply = (result: any) => this.sendPeer(peer, { id, ...tag, result });
        const params = { ...(message.params || {}) };
        const gen = this.generation;
        try {
            if (method === 'WMPF.getStatus') { reply(this.status()); return; }
            if (method === 'Network.enable') {
                const first = !peer.networks.has(sessionId);
                peer.networks.add(sessionId);
                reply({});
                if (first) {
                    let replayed = 0;
                    for (const item of this.history) {
                        if (sessionId !== '' && (item.event.sessionId || '') !== sessionId) continue;
                        if (sessionId !== '' && peer.networks.has('')) continue; // root subscription already covered it
                        const ev = item.event;
                        const key = `${ev.sessionId || ''}|${ev.method}|${ev.params?.requestId}|${ev.params?.timestamp}`;
                        if (peer.replayed.has(key)) continue;
                        peer.replayed.add(key);
                        this.sendPeer(peer, ev); this.forwarded++; replayed++;
                    }
                    this.log(`[network] replayed ${replayed} native events AFTER Network.enable session=${sessionId || 'root'}`);
                }
                if (!peer.diagnostic) this.enableBackendNetwork(sessionId);
                if (this.options.observeWxRequest) void this.maybeInstallWxObserver();
                return;
            }
            if (method === 'Network.disable') { peer.networks.delete(sessionId); reply({}); return; }
            if (method === 'Network.getResponseBody') {
                reply(await this.responseBody(String(params.requestId || ''), sessionId)); return;
            }
            const info = this.requests.get(`${sessionId}\u0000${params.requestId}`);
            if (method === 'Network.getRequestPostData' && info?.postData !== undefined) {
                reply({ postData: info.postData }); return;
            }
            // Retain flattened CDP sessionId as well as all frontend params.
            // Never send child-target commands to the root inspector session.
            const result = await this.command(method, params, { transport: 'cdp', jscontextId: '', sessionId: sessionId || undefined });
            reply(result);
            if (method === 'Runtime.enable' && gen === this.generation) {
                if (!peer.runtimes.has(sessionId)) for (const value of this.contexts.values()) {
                    if ((value.sessionId || '') === sessionId) this.sendPeer(peer, { method: 'Runtime.executionContextCreated', ...tag, params: { context: value.context } });
                }
                peer.runtimes.add(sessionId);
            }
        } catch (e) {
            this.lastError = (e as Error).message;
            this.sendPeer(peer, { id, ...tag, error: { code: -32000, message: this.lastError } });
        }
    }
}

export function createRelay(options: Options) { return new CdpRelay(options); }
