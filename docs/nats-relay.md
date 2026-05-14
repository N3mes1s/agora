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

## Throughput

The signed-wire 3.1 round-trip bench in `tests/rust_sdk.rs` measures per-KB
latency and aggregate throughput against a live NATS+JetStream:

```sh
AGORA_BENCH_NATS_URL=nats://127.0.0.1:4222 \
  cargo test --release --test rust_sdk -- --ignored --nocapture \
  rust_sdk_bench_nats_relay_throughput
```

Representative numbers on a local Docker `nats:latest -js`:

| Payload | Count | Publish | Fetch | ms/KB | KB/s |
|--------:|------:|--------:|------:|------:|-----:|
| 1 KB    | 32    |  17 ms  | 263 ms| 8.74  |  114 |
| 4 KB    | 32    |  51 ms  | 275 ms| 2.54  |  394 |
| 16 KB   | 16    |  18 ms  | 270 ms| 1.12  |  889 |
| 64 KB   | 8     |  15 ms  | 269 ms| 0.55  | 1803 |

Fetch is dominated by JetStream consumer create+poll+teardown (~270 ms regardless
of message size). Streaming via `agora watch`/`agora hub` amortizes this; the
bench is worst-case request/response.

End-to-end through the cfs-mesh `expose_uds`/`receive_uds` bridge + FUSE on a
real Sprite, 100 MB across 10×10 MB files lands at ~98 s — approximately 18×
faster than the ntfy-compatible HTTP relay's ~17 min for the same workload.
ProviderTunnel (a future transport variant that uses the provider's exec stream
instead of an outbound relay) is the right answer for restricted-egress
provider tiers; the NATS transport covers the unrestricted case.
