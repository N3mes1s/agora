#!/bin/sh
# Bot → Umami log forwarder (stream version).
#
# Reads nginx's access-log stream on stdin (nginx is piped into this script by
# the Dockerfile CMD) and, for every non-human hit, forwards it to the umami
# fork's /api/collect with the REAL user-agent + an API key, so the server
# classifies it into agent_event (AI Traffic report — RFD-0002/0006).
#
# Reading nginx's stdout stream avoids the base image's access.log→/dev/stdout
# symlink, which made the old file-polling version silently forward nothing.
#
# Requires env UMAMI_COLLECT_KEY (a umami_ak_ key whose user can view the site).
# Without it, log lines still pass through (so Railway keeps its logs) but
# nothing is posted.
#
# NOTE: do not go back to POSTing /api/send with a spoofed human UA — that
# mis-records crawlers as humans on the fork.

UMAMI_ORIGIN="${UMAMI_ORIGIN:-https://umami-production-1d14.up.railway.app}"
UMAMI_URL="$UMAMI_ORIGIN/api/collect"
WEBSITE_ID="${UMAMI_WEBSITE_ID:-a073911e-d857-4c25-998e-719a1ba6baf1}"
HOSTNAME_VAL="${UMAMI_HOSTNAME:-theagora.dev}"

esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

if [ -z "$UMAMI_COLLECT_KEY" ]; then
  echo "[forwarder] WARNING: UMAMI_COLLECT_KEY not set — passing logs through, not posting."
fi
echo "[forwarder] Reading nginx log stream → $UMAMI_URL"

while IFS= read -r line; do
  # Pass every line through so Railway still captures nginx's access/error logs.
  printf '%s\n' "$line"

  # Classify from the access-log's class=... field (set by nginx's UA map).
  case "$line" in *" class="*) ;; *) continue ;; esac
  agent_class=$(printf '%s' "$line" | grep -o 'class=[^ ]*' | cut -d= -f2 | tr -d ' \r\n')
  [ -z "$agent_class" ] && continue
  [ "$agent_class" = "human" ] && continue

  # Request path from the "METHOD /path HTTP/x" field (anchored on HTTP).
  url=$(printf '%s' "$line" | sed -n 's/.*"[A-Z][A-Z]* \([^ ]*\) HTTP[^"]*".*/\1/p')
  [ -z "$url" ] && continue
  case "$url" in
    *.css|*.js|*.mjs|*.png|*.jpg|*.jpeg|*.gif|*.svg|*.webp|*.avif|*.ico|*.woff|*.woff2|*.ttf|*.map) continue ;;
  esac

  [ -z "$UMAMI_COLLECT_KEY" ] && continue

  user_agent=$(printf '%s' "$line" | sed -n 's/.*"[^"]*" "\([^"]*\)" class=.*/\1/p')
  [ -z "$user_agent" ] && continue
  referer=$(printf '%s' "$line" | sed -n 's/.*"\([^"]*\)" "[^"]*" class=.*/\1/p')
  ip=$(printf '%s' "$line" | awk '{print $1}')

  echo "[forwarder] $agent_class → $url"

  ua_j=$(esc "$user_agent")
  ref_j=$(esc "$referer")
  body="{\"websiteId\":\"$WEBSITE_ID\",\"url\":\"$url\",\"hostname\":\"$HOSTNAME_VAL\",\"userAgent\":\"$ua_j\",\"ip\":\"$ip\""
  [ -n "$referer" ] && [ "$referer" != "-" ] && body="$body,\"referrer\":\"$ref_j\""
  body="$body}"

  curl -s -o /dev/null -X POST "$UMAMI_URL" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $UMAMI_COLLECT_KEY" \
    -d "$body" &
done
