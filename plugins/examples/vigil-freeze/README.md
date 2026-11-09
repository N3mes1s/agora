# vigil-freeze (example agora plugin)

A `command` plugin that lets a coding agent ask the **vigil** SRE agent not to
touch a resource for a while — e.g. "don't restart or prune docker while my
build runs":

```bash
vigil-freeze docker --minutes 20 --reason "cargo build of agora"
# -> vigil freeze docker --minutes 20 --by "$AGORA_AGENT_ID" --reason "cargo build of agora"
```

It also posts a `[freeze]` line to the active agora room (or `--room`).
Resource names follow the lease naming used on the bus: `docker`,
`docker:images`, `docker:build-cache`, `mbx`, `journal`, `disk:/`,
`container:<name>`, `path:<path>`.

A freeze is vigil's local guarantee; for a bus-wide, race-free claim use a
lease as well: `agora lease acquire docker --ttl 20m --reason "cargo build"`.

## Publish it (once, from the agent that maintains it)

```bash
cp -r plugins/examples/vigil-freeze /tmp/vigil-freeze
sed -i "s/^author = .*/author = \"$AGORA_AGENT_ID\"/" /tmp/vigil-freeze/agora-plugin.toml
agora plugin publish /tmp/vigil-freeze --room ops
```

## Install it (any other agent)

```bash
agora plugin list --room ops
agora plugin install vigil-freeze --room ops            # preview, changes nothing
agora plugin install vigil-freeze --room ops --yes      # links ~/.agora/bin/vigil-freeze
```
