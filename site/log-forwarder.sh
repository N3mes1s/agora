#!/bin/sh
# Bot → Umami log forwarder (polling version — more reliable than tail -F on alpine)
# Reads nginx access logs, extracts bot/AI traffic, forwards to Umami.

UMAMI_URL="https://umami-production-750a.up.railway.app/api/send"
WEBSITE_ID="a073911e-d857-4c25-998e-719a1ba6baf1"
LOG_FILE="/var/log/nginx/access.log"
SPOOF_UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
LAST_POS=0

# Wait for log file to exist
i=0
while [ ! -f "$LOG_FILE" ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done
echo "[forwarder] Started, polling $LOG_FILE"

while true; do
  # Get current file size
  CUR_SIZE=$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)

  if [ "$CUR_SIZE" -gt "$LAST_POS" ] 2>/dev/null; then
    # Read new bytes since last position
    tail -c +"$((LAST_POS + 1))" "$LOG_FILE" 2>/dev/null | while IFS= read -r line; do
      # Extract agent class
      agent_class=$(echo "$line" | grep -o 'class=[^ ]*' | cut -d= -f2 | tr -d ' \r\n')
      [ -z "$agent_class" ] && continue
      [ "$agent_class" = "human" ] && continue

      # Extract URL
      url=$(echo "$line" | grep -o '"[A-Z]* [^ ]*' | cut -d' ' -f2)
      remote_addr=$(echo "$line" | awk '{print $1}')
      [ -z "$url" ] && continue

      echo "[forwarder] $agent_class → $url"

      case "$url" in
        /|/docs.html|/security.html|/plugins.html|/swarm.html|/fund.html)
          curl -s -o /dev/null -X POST "$UMAMI_URL" \
            -H "Content-Type: application/json" \
            -H "User-Agent: $SPOOF_UA" \
            -H "X-Agora-Client-IP: $remote_addr" \
            -d "{\"type\":\"event\",\"payload\":{\"website\":\"$WEBSITE_ID\",\"url\":\"$url\",\"referrer\":\"\",\"screen\":\"1920x1080\",\"tag\":\"$agent_class\"}}" &
          ;;
        /llms.txt|/AGENTS.md|/robots.txt|/sitemap.xml|/openapi.yaml|/mcp-server.json|/install|/.well-known/agent-card.json|/.well-known/ai-plugin.json)
          curl -s -o /dev/null -X POST "$UMAMI_URL" \
            -H "Content-Type: application/json" \
            -H "User-Agent: $SPOOF_UA" \
            -H "X-Agora-Client-IP: $remote_addr" \
            -d "{\"type\":\"event\",\"payload\":{\"website\":\"$WEBSITE_ID\",\"url\":\"$url\",\"referrer\":\"\",\"name\":\"agent-discovery\",\"data\":{\"path\":\"$url\",\"agent\":\"$agent_class\"},\"tag\":\"$agent_class\"}}" &
          ;;
      esac
    done
    LAST_POS=$CUR_SIZE
  fi

  sleep 2
done
