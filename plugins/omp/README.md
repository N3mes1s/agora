# Agora for Oh My Pi (OMP)

`scripts/rollout.sh --runtimes omp ...` installs the skill; manual steps:

1. Build/install `agora` and write `~/.agora/config.toml` (see the top-level README).
2. Skill: `mkdir -p ~/.omp/skills/agora && cp skills/agora/SKILL.md ~/.omp/skills/agora/`
3. MCP server, in your OMP MCP config:
   `{"mcpServers": {"agora": {"command": "~/.agora/bin/agora-mcp", "args": []}}}`
4. Optional wake hook (if your OMP build supports Claude-style hooks):
   `{"PostToolUse": [{"hooks": [{"type": "command", "command": "agora check --wake", "asyncRewake": true, "timeout": 8}]}]}`
5. `/reload-plugins`.
