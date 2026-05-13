# NATS Relay

Agora can use NATS JetStream as the encrypted relay backend. The relay still
only sees ciphertext; the transport change replaces the ntfy-compatible HTTP
relay with JetStream publish, fetch, and stream consumers.

## Requirements

- NATS server with JetStream enabled
- `AGORA_RELAY_URL` using `nats://` or `tls://`
- optional `AGORA_RELAY_TOKEN` for token auth

Minimal local server:

```sh
nats-server -js
export AGORA_RELAY_URL=nats://127.0.0.1:4222
```

## Stream Model

Agora stores all relay events in one stream and maps each room/topic to one
stable NATS subject:

```text
stream:   AGORA
subjects: agora.>
topic:    agora.<base64url(room-topic)>
```

The topic segment is base64url encoded so room ids and DM topic names do not
need to obey NATS subject token rules.

## Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `AGORA_RELAY_URL` | `https://ntfy.theagora.dev` | Use `nats://host:4222` or `tls://host:4222` for NATS. |
| `AGORA_RELAY_TOKEN` | unset | Token passed to NATS connect options. |
| `AGORA_NATS_STREAM` | `AGORA` | JetStream stream name. Invalid stream-name chars are converted to `_`. |
| `AGORA_NATS_SUBJECT_PREFIX` | `agora` | Subject prefix; stream subject becomes `<prefix>.>`. |
| `AGORA_NATS_CREATE_STREAM` | `true` | Create the stream on connect if it is missing. Set `false` for locked-down servers. |
| `AGORA_NATS_STORAGE` | `file` | `file` or `memory`. |
| `AGORA_NATS_MAX_BYTES` | `0` | Stream byte cap. `0` keeps the NATS server default/unlimited behavior. |
| `AGORA_NATS_MAX_AGE` | `0` | Stream age cap. Supports seconds, `m`, `h`, and `d`, for example `7d`. |

Production-ish single stream with bounded retention:

```sh
export AGORA_RELAY_URL=nats://nats.internal:4222
export AGORA_RELAY_TOKEN=replace-me
export AGORA_NATS_STREAM=AGORA
export AGORA_NATS_SUBJECT_PREFIX=agora
export AGORA_NATS_STORAGE=file
export AGORA_NATS_MAX_BYTES=1073741824
export AGORA_NATS_MAX_AGE=7d
```

Rust, Node, and Python embedders can set the same options per client; see
[Rust SDK](rust-sdk.md), [`sdk/npm/README.md`](../sdk/npm/README.md), and
[`sdk/python/README.md`](../sdk/python/README.md).

## Locked-Down Servers

If the Agora process is not allowed to create streams, create the stream out of
band and disable auto-create:

```sh
nats stream add AGORA --subjects 'agora.>' --storage file --retention limits
export AGORA_NATS_CREATE_STREAM=false
```

The NATS credentials used by Agora need permissions for:

- publish to `<prefix>.*`
- create pull consumers on the configured stream
- fetch stream messages
- read stream metadata
- create the stream only when `AGORA_NATS_CREATE_STREAM=true`

Retention and storage settings are applied when Agora creates the stream. If an
existing stream already exists, update those settings with NATS operational
tooling so Agora does not unexpectedly rewrite production stream policy.

## Verification

Fast unit coverage, with live NATS tests ignored by default:

```sh
cargo test transport::
```

Run live JetStream tests against a real server:

```sh
AGORA_LIVE_NATS_URL=nats://127.0.0.1:4222 \
  cargo test transport::nats::tests::live_nats_publish_and_fetch_work -- --ignored
```

The disconnect/reconnect live test also needs the container name used for the
server:

```sh
AGORA_LIVE_NATS_URL=nats://127.0.0.1:4222 \
AGORA_LIVE_NATS_CONTAINER=agora-nats \
  cargo test transport::nats::tests::live_nats_publish_fetch_and_stream_work -- --ignored
```
