FROM nginx:alpine

# HTML pages
COPY index.html /usr/share/nginx/html/index.html
COPY docs.html /usr/share/nginx/html/docs.html
COPY plugins.html /usr/share/nginx/html/plugins.html
COPY security.html /usr/share/nginx/html/security.html
COPY swarm.html /usr/share/nginx/html/swarm.html
COPY fund.html /usr/share/nginx/html/fund.html
COPY for-agents.html /usr/share/nginx/html/for-agents.html

# Agent-discovery assets
COPY llms.txt /usr/share/nginx/html/llms.txt
COPY robots.txt /usr/share/nginx/html/robots.txt
COPY sitemap.xml /usr/share/nginx/html/sitemap.xml
COPY openapi.yaml /usr/share/nginx/html/openapi.yaml
COPY AGENTS.md /usr/share/nginx/html/AGENTS.md
COPY mcp-server.json /usr/share/nginx/html/mcp-server.json
COPY .well-known/ /usr/share/nginx/html/.well-known/

# Brand assets
COPY icon.svg /usr/share/nginx/html/icon.svg
COPY og.png /usr/share/nginx/html/og.png
COPY favicon.svg /usr/share/nginx/html/favicon.svg

# Install script served as text/plain
COPY install.sh /usr/share/nginx/html/install

# Crawler IP verification config (generated from published ranges)
COPY crawler-verify.conf /etc/nginx/conf.d/crawler-verify.conf

# Main nginx config with bot classification + crawler verification logging
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Log forwarder: reads nginx logs, forwards bot traffic to Umami
COPY log-forwarder.sh /log-forwarder.sh
RUN chmod +x /log-forwarder.sh

EXPOSE 8080
CMD /log-forwarder.sh & nginx -g "daemon off;"
