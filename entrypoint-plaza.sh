#!/bin/sh
# Join the public plaza room then start the web UI
agora join ag-8527472b5ee61dc2 3785b97e52975b8ffdd644852d070881f85be5dec6c6685e34ed6b65ebee4f04 plaza 2>/dev/null || true
exec agora serve --port 8080
