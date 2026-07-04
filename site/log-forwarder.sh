#!/bin/sh
# Bot → Umami log forwarder (polling version — more reliable than tail -F on alpine).
#
# Reads the nginx access log, and for every non-human hit forwards it to the
# umami fork's /api/collect endpoint with the REAL user-agent + an API key, so
# the server classifies it into agent_event and it shows in the AI Traffic
# report (RFD-0002/0006).
#
# Requires env UMAMI_COLLECT_KEY (a umami_ak_ API key whose user can view the
# site). Without it, the forwarder runs but skips posting (safe no-op).
#
# NOTE: the old version POSTed to /api/send with a SPOOFED human user-agent to
# dodge the pre-fork isbot() drop. That now mis-records crawlers as humans —
# do not reintroduce the spoof.

UMAMI_ORIGIN="${UMAMI_ORIGIN:-https://umami-production-1d14.up.railway.app}"
UMAMI_URL="$UMAMI_ORIGIN/api/collect"
WEBSITE_ID="${UMAMI_WEBSITE_ID:-a073911e-d857-4c25-998e-719a1ba6baf1}"
HOSTNAME_VAL="${UMAMI_HOSTNAME:-theagora.dev}"
LOG_FILE="/var/log/nginx/access.log"
LAST_POS=0

# JSON-escape a string (backslash + double quote).
esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

if [ -z "$UMAMI_COLLECT_KEY" ]; then
  echo "[forwarder] WARNING: UMAMI_COLLECT_KEY not set — running but NOT posting."
fi

# Wait for log file to exist
i=0
while [ ! -f "$LOG_FILE" ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done
echo "[forwarder] Started, polling $LOG_FILE → $UMAMI_URL"

while true; do
  CUR_SIZE=$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)

  if [ "$CUR_SIZE" -gt "$LAST_POS" ] 2>/dev/null; then
    tail -c +"$((LAST_POS + 1))" "$LOG_FILE" 2>/dev/null | while IFS= read -r line; do
      # Only non-human traffic (nginx already classifies into class=...).
      agent_class=$(echo "$line" | grep -o 'class=[^ ]*' | cut -d= -f2 | tr -d ' \r\n')
      [ -z "$agent_class" ] && continue
      [ "$agent_class" = "human" ] && continue

      # Request path from the "METHOD /path HTTP/x" request field (anchored on
      # HTTP so it can't mis-match the status code or the user-agent field).
      url=$(printf '%s' "$line" | sed -n 's/.*"[A-Z][A-Z]* \([^ ]*\) HTTP[^"]*".*/\1/p')
      [ -z "$url" ] && continue

      # Skip static assets; keep pages, discovery files, extensionless routes.
      case "$url" in
        *.css|*.js|*.mjs|*.png|*.jpg|*.jpeg|*.gif|*.svg|*.webp|*.avif|*.ico|*.woff|*.woff2|*.ttf|*.map) continue ;;
      esac

      remote_addr=$(echo "$line" | awk '{print $1}')
      # referer and user-agent are the two adjacent quoted fields before " class=".
      referer=$(printf '%s' "$line" | sed -n 's/.*"\([^"]*\)" "[^"]*" class=.*/\1/p')
      user_agent=$(printf '%s' "$line" | sed -n 's/.*"[^"]*" "\([^"]*\)" class=.*/\1/p')
      [ -z "$user_agent" ] && continue

      [ -z "$UMAMI_COLLECT_KEY" ] && { echo "[forwarder] (skip, no key) $agent_class → $url"; continue; }

      echo "[forwarder] $agent_class → $url"

      ua_j=$(esc "$user_agent")
      ref_j=$(esc "$referer")
      body="{\"websiteId\":\"$WEBSITE_ID\",\"url\":\"$url\",\"hostname\":\"$HOSTNAME_VAL\",\"userAgent\":\"$ua_j\",\"ip\":\"$remote_addr\""
      [ -n "$referer" ] && [ "$referer" != "-" ] && body="$body,\"referrer\":\"$ref_j\""
      body="$body}"

      curl -s -o /dev/null -X POST "$UMAMI_URL" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $UMAMI_COLLECT_KEY" \
        -d "$body" &
    done
    LAST_POS=$CUR_SIZE
  fi

  sleep 2
done
