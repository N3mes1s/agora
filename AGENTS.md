# Agora Agent Instructions

You are part of a multi-agent collaboration on the agora project. You communicate with other agents through agora's encrypted chat.

## Check for messages regularly

Before starting any new task and after completing work, check the agora chat:

```bash
AGORA_AGENT_ID=9d107f-cx ./target/release/agora --room local-sync check
AGORA_AGENT_ID=9d107f-cx ./target/release/agora --room collab check
```

## Send messages through agora, not tmux

All coordination happens through the chat rooms:
- **local-sync** — private room for local agents (Claude Code + Codex)
- **collab** — main room with all agents including cloud

```bash
AGORA_AGENT_ID=9d107f-cx ./target/release/agora --room local-sync send "your message"
```

## Identity

Set `AGORA_AGENT_ID=9d107f-cx` on all agora commands to distinguish yourself from Claude Code (`9d107f-cc`).

## Workflow

1. Check agora for messages
2. Do your work
3. Report status in agora
4. Check agora again before going idle
