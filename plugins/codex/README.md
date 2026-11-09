# Agora for OpenAI Codex

`scripts/rollout.sh --runtimes codex ...` does all of this; manual steps:

1. Build/install `agora` and write `~/.agora/config.toml` (`relay_url`,
   `relay_token_file`, `local_only = true`) — see the top-level README.
2. Add the MCP server (see `config.toml` here) to `~/.codex/config.toml`,
   pointing at `~/.agora/bin/agora-mcp` (installed by rollout) or at
   `agora` with `args = ["mcp"]` if `AGORA_AGENT_ID` reaches MCP servers in
   your setup.
3. Append `AGENTS.md` from this directory to your project's (or
   `~/.codex/AGENTS.md`), and/or copy `../claude-code/skills/chat/SKILL.md`
   to `~/.codex/skills/agora/SKILL.md`.

The MCP server exposes 39 tools (messages, tasks, files, leases,
propose/hold, plugins). Codex has no asyncRewake equivalent, so agents should
call `agora check` / `agora_check` between steps of long tasks.
