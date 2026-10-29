# WMPF 25800 native-only validation status (2026-10-29)

## Implemented and verified locally

- No business HTTP proxy, certificate installation, wx.request wrapping,
  application-JS instrumentation or JS network polling.
- Native protobuf/CDP/customMessage/domOp event/result routing; per-session
  Network.enable, sessionId preservation, bounded history and original ids.
- Official __getNetworkResponseBody custom command; native CDP/webview body
  retrieval; explicit errors instead of HTTP refetches or invented bodies.
- 25 local regressions; isolated real Chrome DevTools accepts a native-protocol
  XHR fixture and retrieves its body. Fixtures are not real WeChat requests.
- Actual installed Frida upgraded from 17.3.2 to pinned 17.24.3; three load/hook/
  unload cycles on a disposable C/dyld target passed.

## Real-process observations — NOT a successful XHR acceptance test

Bounded attachments selected only main WeChatAppEx PID 40729. Native entry byte
anchors and explicit wmpf-ready messages were checked. Each session expired,
unloaded and detached; WeChat accessibility queries continued to return its
window. No automatic process attachment or chat/profile deletion occurred.

Logs retained locally:

| Log under /tmp/wmpf25800/ | Observation |
| --- | --- |
| native-server.log | 1 verified entry hook; LanDebug and native CDP telemetry connected, but no requestWillBeSent |
| native-resource-check.log | Resource predicate hook was actually called; dataReceived/loadingFinished and extra-info events arrived, no request starts |
| native-session-check.log | Native child targets were observed; missing sessionId routing was fixed; real request starts still not observed |
| native-filter-check.log | Two read-only native SendToClientFilter taps installed. No discarded target frame was reported. This does not prove those functions were invoked or identify the earlier source of loss. Taps default OFF. |
| native-early-check.log | Verified OnAfterCreated startup experiment; repeated LanDebug connections, still no real request starts. Early activation defaults OFF because benefit was not established. |

Real-session counters consistently showed nativeRequests=0 and bodyResponses=0.
There is **no basis to claim the real miniapp XHR list/body now works**.
The absence is scoped to these sessions and targets; it does not prove WMPF
25800 lacks native Network support. Older local logs included __networkDebug.

## Native hook safety changes

- No pgrep -f / shell attachment, no helper/renderer attachment, no spawn retry.
- Exactly one verified main executable PID; start via `sudo npx ts-node src/index.ts`.
- Network panel shows only webview frame traffic; no wx.request observer is installed.
- Actual load success and hook readiness required; load/cleanup have deadlines.
- Native branch/memory anchors checked before hook installation.
- Verified OnLoadStart entry 0x577760C (x0=this, x1=bool), not a relocated cbz.
- macOS alternate libc++ short-string length is byte +0x17, not length>>1;
  native malloc(32) URL buffer declares capacity 32 rather than 19.
- Container activation is idempotent to avoid forcing a new server on every
  OnLoadStart of an already-debugging container.
- Resource predicate is the upstream native predicate at 0x57DCC9C.
- OnAfterCreated 0x57771B8 and read-only filter taps remain experimental/OFF.

Do **not** revive the old JSON type-tag patch: 0x934B61C parses a dictionary,
and the SendToClientFilter code checks type 6 as a JSON dictionary. On this
macOS build, a non-dictionary branch constructs '{}'; changing 6 to 0 corrupts
protocol parsing rather than enabling Network. This conclusion is from bounded
Capstone instruction inspection, not a live modified-parser experiment.

## 2026-10-29 Network panel is still empty

DevTools is connected and recording, but `nativeRequests` stayed 0 in every
25800 session. Searching `mMortgageLoanApply` finds nothing because no
`Network.requestWillBeSent` was forwarded.

The adapter now accepts `networkDebugAPI` when that native message already
contains a URL, and a regression covers both that case and the no-URL case.
The installed 25800 framework has no `networkDebugAPI`, `__networkDebug`, or
`getNetworkRequestInfo` string. `requestWillBeSent` there is only the Chrome
protocol name. The official IDE gets the URL from a separate simulator
exchange, which this native session does not have. No URL is invented and no
appservice JS is evaluated to fill it in.

Do not treat a connected DevTools Network tab as evidence that wx.request
telemetry is flowing.

Locate why authentic wx/renderer request-start events are missing from the
selected native runtime/session. A protocol adapter cannot reconstruct a URL,
method, request id or body that the runtime never provides. Do not label extra
info/loadingFinished as evidence that real XHR request starts were seen.

Further live experiments need a specific native hypothesis and a bounded
single-process check. Do not reinstate wx API wrappers, business proxies,
certificates, fabricated Network events, blind offsets or automatic reattachment
as a workaround. Ordinary 25800 injection startup remains blocked.
