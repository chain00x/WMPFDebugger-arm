#!/bin/bash
# Only manages the non-privileged native protocol adapter; never auto-injects.
set -euo pipefail
cd "$(dirname "$0")"
case "${1:-}" in
  start) exec bash scripts/start.sh ;;
  stop) exec bash scripts/stop.sh ;;
  status)
    if ! curl --max-time 2 -fsS http://127.0.0.1:62000/status; then
      echo '原生协议适配未运行（不会自动启动或注入微信）。'
    fi
    echo
    ;;
  *) echo "用法: $0 start|stop|status（仅协议适配，不注入微信）" ;;
esac
