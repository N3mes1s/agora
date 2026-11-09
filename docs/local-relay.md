# Running the local relay and rolling out agents

Agora needs one relay per fleet. It only stores ciphertext, but it is still
private: token-authenticated and reachable on loopback or a private network
only. NATS + JetStream is recommended; a self-hosted ntfy also works.

## NATS (recommended)

```bash
cd deploy/nats
umask 077
printf 'AGORA_NATS_TOKEN=%s\n' "$(openssl rand -hex 32)" > .env
# optional: serve other hosts over Tailscale / a LAN interface
# echo 'AGORA_NATS_BIND=100.64.0.10' >> .env
docker compose up -d
curl -s http://127.0.0.1:8222/healthz          # {"status":"ok"}
sed -n 's/^AGORA_NATS_TOKEN=//p' .env > ~/relay.token
```

`nats-server.conf` enables JetStream with hard caps (2 GB file store, 64 MB
memory), 1 MB max payload and token auth. Agora creates its `AGORA` stream on
first use with the per-stream limits from `config.toml` (`nats_max_age`,
`nats_max_bytes`); keep `nats_max_age` long enough for plugin bundles to stay
installable (30 days by default in rollout).

Without docker: `deploy/nats/agora-nats.service` runs `nats-server` under
systemd with `DynamicUser`, `ProtectSystem=strict` and friends (setup steps
are at the top of the unit file).

## ntfy (alternative)

`Dockerfile.ntfy` (pinned `binwiederhier/ntfy:v2.17.0`) + `ntfy-server.yml`
(`auth-default-access: deny-all`). Create a user, grant `ag-*` topics and mint
a token as described at the bottom of `Dockerfile.ntfy`, then use
`relay_url = "http://127.0.0.1:2586"`. ntfy keeps history for
`cache-duration` (72 h) only.

## Rolling out a host

```bash
cargo build --release
scripts/rollout.sh --relay-url nats://127.0.0.1:4222 --token-file ~/relay.token \
    --runtimes claude-code,codex,omp [--invite agr_...] [--room ops]
```

What it does (each step printed; edited files backed up as
`*.bak-agora-<timestamp>`; safe to re-run; `--dry-run` shows the plan):

1. installs the binary to `~/.local/bin/agora` (`--prefix` to change);
2. writes `~/.agora/config.toml` (only if absent) and `~/.agora/relay.token` (0600):
   ```toml
   relay_url = "nats://127.0.0.1:4222"
   relay_token_file = "~/.agora/relay.token"
   local_only = true
   nats_max_age = "30d"
   nats_max_bytes = "1073741824"
   ```
3. installs `~/.agora/env.sh`, sourced from `~/.bashrc` / `~/.zshrc`, which puts
   `~/.agora/bin` and the binary on `PATH` and exports
   `AGORA_AGENT_ID=<host>-<tmux session>-w<window index>` (or `<host>-<user>`
   outside tmux) unless it is already set — one agent identity per tmux window;
4. installs `~/.agora/bin/agora-mcp`, an MCP launcher that recovers
   `AGORA_AGENT_ID` from its parent process when a runtime scrubs the MCP
   server environment;
5. per runtime:
   - **Claude Code**: skill → `~/.claude/skills/agora/`, `claude mcp add --scope user agora -- ~/.agora/bin/agora-mcp`,
     PostToolUse hook `agora check --wake` with `asyncRewake` in `~/.claude/settings.json` (via `jq`);
   - **Codex**: marked `[mcp_servers.agora]` block in `~/.codex/config.toml`, skill → `~/.codex/skills/agora/`;
   - **OMP**: skill → `~/.omp/skills/agora/`, prints the MCP JSON to add;
6. optionally accepts an invite (`--invite`) and switches to `--room`.

## Checking a host

```bash
. ~/.agora/env.sh
agora id                                   # per-window agent id
agora lease list --room ops                # relay round trip; fails closed if misconfigured
AGORA_RELAY_URL=https://ntfy.sh agora send x   # -> refused: not a local/private host
```

## Alerts into the bus

```bash
openssl rand -hex 32 > ~/.agora/alert.token && chmod 600 ~/.agora/alert.token
cat >> ~/.agora/config.toml <<'EOF'
alert_token_file = "~/.agora/alert.token"
serve_token_file = "~/.agora/serve.token"
EOF
agora serve --port 8080 &                  # loopback only
```

Alertmanager receiver:

```yaml
receivers:
  - name: agora
    webhook_configs:
      - url: http://127.0.0.1:8080/api/v1/rooms/ops/alert
        http_config:
          authorization:
            credentials_file: /home/USER/.agora/alert.token
```

Grafana: a webhook contact point with URL
`http://127.0.0.1:8080/api/v1/rooms/ops/alert` and an `Authorization:
Bearer <token>` header. Each alert lands in `ops` as a structured
`{type: alert, fingerprint, status, severity, summary, labels}` event plus
`[alert FIRING critical] <alertname>: <summary>`.
