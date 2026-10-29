# Native-only Network protocol adapter

## Boundary

This implementation does **not** configure an HTTP/SOCKS proxy, install a CA,
intercept/decrypt business traffic, modify `wx.request`, inject application JS,
probe/evaluate JS contexts or poll for network data. Runtime.evaluate issued by
the user in DevTools is forwarded unchanged; the adapter never generates one.

The only servers are local debug-protocol endpoints, bound to `127.0.0.1`:

- 9421: WMPF's existing LanDebug protobuf-over-WebSocket connection.
- 62000: Chrome CDP-over-WebSocket; `/status` is read-only health/counter data.

Starting the adapter does **not** enable debugging in an unmodified WeChat
runtime. Native hook initialization remains separate, explicit and experimental
on WMPF 25800 following the earlier real-process hang.

## Supported native message paths

| Native input | Forwarding | Response-body retrieval |
| --- | --- | --- |
| `customMessage`, method `__networkDebug` | Original `Network.*` events | `customMessage/__getNetworkResponseBody` |
| `chromeDevtoolsResult` | Original CDP events/results | CDP `Network.getResponseBody`, retaining the originating jscontext id |
| `domEvent/DEBUGGEE_EVENT` | Original webview CDP events | `domOp` with native webview id; correlate `DEBUGGEE_CALLBACK` |

For native custom messages, request ids have an official API/task prefix:
`1.<task>` request, `2.<task>` download, `3.<task>` upload, `4.<task>` socket.
The body command payload is `{id: <task>, api: <name>, devtoolsMsgId: <remapped id>}`.
A returned `{id, result:{body,base64Encoded}}` arrives on `__networkDebug` and is
sent to the correct DevTools socket. Empty strings and base64 are preserved.

The adapter does not promise a body exists. Unsupported/expired body caches,
missing native responses and malformed results return explicit CDP errors;
they are never replaced with fake successful bodies or HTTP refetches.

`Network.getRequestPostData` uses the postData actually supplied in the native
request event. No application API is called to reconstruct it.

## Network panel subscription

Network.enable subscribes the frontend to this adapter's native event stream.
The adapter acknowledges that subscription before replaying retained native
events. It additionally sends a single native inspector Network.enable per
applet session if the frontend requested it. An unresponsive JS inspector does
not block display of independent customMessage telemetry already received.
Subscriptions are scoped by the flattened CDP `sessionId`, not just websocket.
Every child target gets its own native Network.enable. Commands, results, errors,
request/body routing, context caches and replay all preserve sessionId; identical
request ids in different sessions do not collide. Root requests are never
replayed into a child session or vice versa.
Repeated Network.enable does not replay twice to the same frontend/session. A new
DevTools connection receives retained history after its own Network.enable.
Network.disable unsubscribes locally. Retention is bounded to 2,000 events / 8 MiB.

Both outgoing protobuf seq and internal command ids are monotonic across
frontend reconnects. Applet reconnect cancels pending commands and clears
request/context/history state. Bare `{}` ACKs and stale results are not events.
Only the newest ordinary CDP frontend controls the session. `?diagnostic=1`
provides an explicit non-evicting diagnostic connection; it does not replace
DevTools. Logs contain source/id counters, not banking URLs/headers/bodies.

## Evidence and limits

Static source: installed `/Applications/wechatwebdevtools.app/Contents/Resources/app.asar`,
member `js/a4d0c2f489c9b3e9ca844bf83a0d5ed2.js` (45,213 bytes), SHA-256
`94479f86480e34ac7773f0aba7d79c0317f89dd00a7aaf250ae1a3c9dbe514b1`.

Focused REA analysis of the extracted member (not the entire installed IDE):
`ev_66c65396a84ea2a6f2ad19d75047bd0c3926bfad2f93af01b0779b70086b87cf`.
Complete temporary evidence: `/tmp/wmpf-native-protocol-evidence.json`.
The original ASAR/member offsets and literal method/payload observations were
also checked with a format-aware ASAR header parser. Relevant source anchors:

- member byte ~2,195: API/task prefix map `B`.
- ~14,481: `onRemoteDebugDevtoolsMessage`, native response-body command.
- `onCustomMessage`: forwards `__networkDebug` JSON to DevTools.
- `onDomEvent`: correlates native `DEBUGGEE_CALLBACK` by callbackID.

These are static protocol observations. They do not establish that every
WeChat version implements/retains every response body.

Prior live logs at `/tmp/wmpf-network-fix-backup/old-server.log` contain native
requestWillBeSent, responseReceived and loadingFinished events. They establish
that native telemetry has existed in this local WMPF session; the earlier claim
that "25800 removed native Network" was unsupported and has been corrected.

## Verification

- `npm test`: local native protobuf/WebSocket fixtures plus bounded attachment
  lifecycle tests; zero actual business requests and zero WeChat injection.
- `npm run typecheck`: TypeScript check.
- `npm run test:frida`: builds and instruments only a disposable C host, tests
  concurrent dyld loading, three hook/load/unload cycles, heartbeat and detach.
  Passing this is **not** proof of WeChat compatibility.
- `npm run test:ui`: launches an isolated temporary Chrome profile and a native
  protobuf fixture (not WeChat). The real DevTools Network model accepts an XHR
  and reads its body through __getNetworkResponseBody. This has passed locally;
  it is frontend/adapter verification, not evidence of real miniapp traffic.
- `npm run relay`: native adapter only, no Frida import/attachment and no sudo.
- `node scripts/native-status.mjs`: non-evicting diagnostics. `--body <id>` with
  optional `--session <native sessionId>` verifies native body retrieval but
  prints only length/encoding, never the response content.

Optional native filter observation is implemented but defaults OFF. It only
forwards an original native CDP request/response frame if a verified native
filter returned empty/{}; it never edits the native JSON type or filter output.
No such discarded frame was observed in the real bounded check. Raw frames are
consumed by the adapter, not dumped to logs. Early native activation also remains
OFF because it did not establish a working real XHR stream.

Current limits: live WeChat 25800 end-to-end XHR/body validation is still required.
Bounded real-process checks with Frida 17.24.3 have confirmed native hook readiness,
a live LanDebug connection and CDP telemetry, followed by successful timed unload;
WeChat remained responsive. Those checks did not yet observe requestWillBeSent
or prove the real XHR list/body working. They exposed a missing sessionId route,
which has since been fixed with root/child-session regression tests.
No claim of a working real Network panel or real response-body retrieval should
be made solely from fixture/static tests. Auto-attach remains removed. The
injection entry requires an explicit experimental flag, exactly one verified
main-process PID, bounded load/cleanup, and a native hook readiness signal.
