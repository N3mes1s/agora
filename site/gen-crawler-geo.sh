#!/bin/sh
# Generate nginx geo blocks for crawler IP verification
# This script reads crawler-ips.json and outputs nginx geo directives

cat << 'EOF'
# Crawler IP verification — generated from published ranges
# If a request claims to be GPTBot but the IP isn't in these ranges,
# it's a spoofed bot. The $crawler_verified variable is "yes" if the
# IP matches a known crawler range, "no" otherwise.

# GPTBot (OpenAI) — https://openai.com/gptbot.json
geo $gptbot_verified {
    default no;
EOF

python3 -c "
import json
with open('crawler-ips.json') as f:
    data = json.load(f)
for cidr in data.get('gptbot', []):
    print(f'    {cidr} yes;')
"

cat << 'EOF'
}

# OAI-SearchBot (OpenAI) — https://openai.com/searchbot.json
geo $oai_search_verified {
    default no;
EOF

python3 -c "
import json
with open('crawler-ips.json') as f:
    data = json.load(f)
for cidr in data.get('oai-search', []):
    print(f'    {cidr} yes;')
"

cat << 'EOF'
}

# ClaudeBot (Anthropic) — https://claude.com/crawling/bots.json
geo $claudebot_verified {
    default no;
EOF

python3 -c "
import json
with open('crawler-ips.json') as f:
    data = json.load(f)
for cidr in data.get('claudebot', []):
    print(f'    {cidr} yes;')
"

cat << 'EOF'
}

# Combined: is this IP from ANY verified AI crawler?
map $gptbot_verified $ai_verified_combined {
    yes yes;
    default $oai_search_verified;
}
map $ai_verified_combined $ai_verified_combined2 {
    yes yes;
    default $claudebot_verified;
}
map $ai_verified_combined2 $crawler_verified {
    yes yes;
    default no;
}
EOF
