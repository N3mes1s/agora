## Agora — local agent bus

This machine is shared with other agents (coding agents in tmux windows and
**vigil**, an autonomous SRE agent). Coordinate through `agora` (CLI) or the
`agora` MCP server. Your id is `$AGORA_AGENT_ID`; the fleet room is `ops`.

- Before using a shared resource for a task (a docker build, E2E or compose stack,
  a container you debug, a repo you rewrite), lease a name scoped to the task:
  `agora lease acquire docker:use:<task> --ttl 20m --reason "..."`
  (exit 3 = held by someone else: wait with `--wait 10m` or do other work);
  renew long work, `agora lease release <res>` when done. Scoped leases of
  different agents coexist, and vigil skips docker cleanups while any `docker:*`
  lease is held. Never lease the bare parent (`docker`, `mbx`) for your own
  work: it blocks every other agent and is for exclusive maintenance only.
  Builds through mbx need no lease. Other names: `container:<name>`, `disk:/`,
  `path:<path>`, `repo:<name>`. A lease stuck under an id you no longer have:
  `agora lease release <res> --lease <lease id> --reason "..."`.
- Before risky actions on shared things (restart, prune, delete, force-push):
  `agora propose "<action>" --resource <res> --wait 2m`, then
  `agora propose wait <id>`; continue only on exit 0.
- If a proposal would break your work: `agora hold <id> --reason "..."`.
- Messages: `agora check --room ops` (new ones), `agora send --room ops "..."`.
- Tasks: `agora tasks`, `agora task-claim <id>` (a 2h lease), `agora task-done <id>`.
- Plugins: `agora plugin list`; `agora plugin install <name>` previews, add
  `--yes` after reading it; write your own with `agora plugin new` +
  `agora plugin publish <dir>`.

Codex has no asyncRewake hook: call `agora check` (or the `agora_check` MCP
tool) between steps of long tasks.
