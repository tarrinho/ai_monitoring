#!/usr/bin/env bash
# tunnel.sh — start a PERSISTENT public tunnel to the AI-Monitoring dashboard.
#
# Tool-call shells get reaped, so a tunnel must run as a systemd --user unit to
# survive. This launches ngrok (preferred, has a config here) or cloudflared as
# a transient unit, then prints the public URL. Re-run to restart.
#
# Usage:  ./deploy/tunnel.sh [ngrok|cloudflared] [port]
set -euo pipefail

BACKEND="${1:-ngrok}"
PORT="${2:-9925}"
UNIT="aimon-tunnel"

systemctl --user stop  "$UNIT" 2>/dev/null || true
systemctl --user reset-failed "$UNIT" 2>/dev/null || true

case "$BACKEND" in
  ngrok)
    command -v ngrok >/dev/null || { echo "ngrok not installed"; exit 1; }
    systemd-run --user --unit="$UNIT" --collect \
      ngrok http "$PORT" --log=stdout --log-format=logfmt >/dev/null
    echo "waiting for ngrok…"
    for _ in $(seq 1 15); do
      URL=$(curl -s http://127.0.0.1:4040/api/tunnels 2>/dev/null \
            | python3 -c 'import sys,json;print(json.load(sys.stdin)["tunnels"][0]["public_url"])' 2>/dev/null || true)
      [ -n "${URL:-}" ] && break; sleep 2
    done
    ;;
  cloudflared)
    command -v cloudflared >/dev/null || { echo "cloudflared not installed"; exit 1; }
    LOG="/tmp/${UNIT}.log"; : > "$LOG"
    systemd-run --user --unit="$UNIT" --collect \
      cloudflared tunnel --no-autoupdate --url "http://localhost:${PORT}" \
      --logfile "$LOG" >/dev/null
    echo "waiting for cloudflared…"
    for _ in $(seq 1 20); do
      URL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$LOG" 2>/dev/null | head -1 || true)
      [ -n "${URL:-}" ] && break; sleep 2
    done
    ;;
  *) echo "unknown backend: $BACKEND (use ngrok|cloudflared)"; exit 1 ;;
esac

if [ -z "${URL:-}" ]; then
  echo "tunnel did not report a URL; check: systemctl --user status $UNIT"
  exit 1
fi

# append the dashboard token if one is configured in .env
TOK=""
[ -f .env ] && TOK=$(grep -E '^MONITOR_DASHBOARD_TOKEN=' .env | cut -d= -f2- || true)
echo
echo "Tunnel unit : $UNIT (systemctl --user status/stop $UNIT)"
echo "Public URL  : $URL"
[ -n "$TOK" ] && echo "Full URL    : ${URL}/?token=${TOK}"
