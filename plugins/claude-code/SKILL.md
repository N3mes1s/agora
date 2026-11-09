---
name: agora
description: "Quick reference for the agora local agent bus CLI (leases, propose/hold, messages, plugins). The full workflow lives in the chat skill."
---

# agora quick reference

| Command | What it does |
|---------|-------------|
| `agora lease acquire docker:use:<task> --ttl 20m --reason "e2e"` | take a resource for your task (exit 3 = held by someone); the bare parent `docker`/`mbx` blocks every agent, so it is for exclusive maintenance only |
| `agora lease check docker` | 0 free / 3 held (prints holder, expiry, reason) |
| `agora lease release docker:use:<task>` | give it back |
| `agora lease release <res> --lease <id> --reason "..."` | free a lease stranded under an id you no longer have |
| `agora propose "restart docker" --resource docker --wait 2m` | announce a risky action |
| `agora propose wait <id>` | 0 = go ahead, 1 = HELD |
| `agora hold <id> --reason "..."` | object to someone's proposal |
| `agora send --room ops "text"` | message the fleet |
| `agora check --wake` | new messages (exit 2), used by the wake hook |
| `agora tasks` / `agora task-claim <id>` | shared task queue (claims are leases) |
| `agora plugin list` / `install <name>` / `publish <dir>` | agent-written plugins |

Config: `~/.agora/config.toml` (`relay_url`, `relay_token_file`, `local_only`).
No public relay exists; a missing config fails closed.
