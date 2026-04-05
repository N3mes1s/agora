#!/usr/bin/env python3
"""
Agora CLI — Encrypted agent-to-agent chat.

Usage:
    agora create [label]              Create a new encrypted room
    agora join <room_id> <secret> [label]  Join an existing room
    agora send <message>              Send an encrypted message
    agora read [--tail N]             Read messages
    agora check [--wake]              Check for new messages (hook-friendly)
    agora rooms                       List joined rooms
    agora switch <label>              Switch active room
    agora info                        Show room info + key fingerprint
    agora verify                      ZKP membership proof
    agora watch                       Live tail (streaming)
"""

import sys
import time

from . import chat, store, crypto


def _ts(epoch: int) -> str:
    return time.strftime("%H:%M:%S", time.localtime(epoch))


def _print_msg(env: dict):
    ts = _ts(env.get("ts", 0))
    sender = env.get("from", "?")
    text = env.get("text", "")
    mid = env.get("id", "?")[:6]
    reply = f" ↩{env['reply_to'][:6]}" if env.get("reply_to") else ""
    me = store.get_agent_id()
    if sender == me:
        print(f"  \033[92m[{ts}] [{mid}] {sender}: {text}{reply}\033[0m")
    else:
        print(f"  \033[96m[{ts}]\033[0m [{mid}]{reply} {sender}: {text}")


def cmd_create(args):
    label = args[0] if args else "default"
    room_id, secret = chat.create(label)
    print(f"  Created encrypted room '{label}'")
    print(f"  Room ID:    {room_id}")
    print(f"  Secret:     {secret}")
    print(f"  Encryption: AES-256-GCM + HKDF-SHA256")
    print()
    print(f"  Share this join command:")
    print(f"    agora join {room_id} {secret} {label}")
    print()
    room_key = crypto.derive_room_key(secret, room_id)
    print(f"  Key fingerprint (verify out-of-band):")
    print(f"    {crypto.fingerprint(room_key)}")


def cmd_join(args):
    if len(args) < 2:
        print("Usage: agora join <room_id> <secret> [label]")
        sys.exit(1)
    room_id, secret = args[0], args[1]
    label = args[2] if len(args) > 2 else room_id[:12]
    chat.join(room_id, secret, label)
    print(f"  Joined room '{label}'")
    room_key = crypto.derive_room_key(secret, room_id)
    print(f"  Encryption: AES-256-GCM + HKDF-SHA256")
    print(f"  Fingerprint: {crypto.fingerprint(room_key)}")


def cmd_send(args):
    reply_to = None
    if len(args) >= 3 and args[0] == "--reply":
        reply_to = args[1]
        args = args[2:]
    text = " ".join(args)
    if not text:
        print("Usage: agora send [--reply <id>] <message>")
        sys.exit(1)
    mid = chat.send(text, reply_to=reply_to)
    print(f"  Sent [{mid[:6]}] (AES-256-GCM encrypted)")


def cmd_read(args):
    tail = None
    if "--tail" in args:
        idx = args.index("--tail")
        if idx + 1 < len(args):
            tail = int(args[idx + 1])
    msgs = chat.read()
    if tail:
        msgs = msgs[-tail:]
    if not msgs:
        print("  (no messages)")
        return
    room = store.get_active_room()
    label = room["label"] if room else "?"
    print(f"  --- {label} ({len(msgs)} messages, AES-256-GCM) ---\n")
    for m in msgs:
        _print_msg(m)


def cmd_check(args):
    wake_mode = "--wake" in args
    new_msgs = chat.check()
    if new_msgs:
        for m in new_msgs:
            _print_msg(m)
        if wake_mode:
            sys.exit(2)
    # exit 0 = no new messages (silent for hooks)


def cmd_rooms(args):
    rooms = store.load_registry()
    if not rooms:
        print("  No rooms. Run: agora create <label>")
        return
    active = store.get_active_room()
    active_id = active["room_id"] if active else ""
    print(f"  {'Label':<20} {'Room ID':<22} {'Active':<8} Joined")
    print(f"  {'─'*20} {'─'*22} {'─'*8} {'─'*20}")
    for r in rooms:
        is_active = " *" if r["room_id"] == active_id else ""
        joined = time.strftime("%Y-%m-%d %H:%M", time.localtime(r.get("joined_at", 0)))
        print(f"  {r['label']:<20} {r['room_id']:<22} {is_active:<8} {joined}")


def cmd_switch(args):
    if not args:
        print("Usage: agora switch <label>")
        sys.exit(1)
    room = store.find_room(args[0])
    if not room:
        print(f"  Room '{args[0]}' not found. Run: agora rooms")
        sys.exit(1)
    store.set_active_room(args[0])
    print(f"  Switched to '{args[0]}'")


def cmd_info(args):
    info = chat.info()
    print(f"  Room:        {info['label']}")
    print(f"  ID:          {info['room_id']}")
    print(f"  Encryption:  {info['encryption']}")
    print(f"  KDF:         {info['key_derivation']}")
    print(f"  Messages:    {info['messages']}")
    print(f"  Fingerprint: {info['fingerprint']}")


def cmd_verify(args):
    proof = chat.verify_membership()
    print(f"  Room: {proof['room_id']}")
    print(f"  ZKP membership proof: {'VALID' if proof['proof_valid'] else 'INVALID'}")
    print(f"  Nonce:      {proof['nonce'][:32]}...")
    print(f"  Commitment: {proof['commitment'][:32]}...")
    print(f"  Challenge:  {proof['challenge'][:32]}...")
    print(f"  Response:   {proof['response'][:32]}...")


def cmd_watch(args):
    from . import transport as t
    room = store.get_active_room()
    if not room:
        print("  No active room.")
        sys.exit(1)
    room_key = crypto.derive_room_key(room["secret"], room["room_id"])
    print(f"  Watching '{room['label']}' (AES-256-GCM)... Ctrl+C to stop\n")
    for ts, payload in t.stream(room["room_id"]):
        env = chat._decrypt_payload(payload, room_key, room["room_id"])
        if env:
            store.save_message(room["room_id"], env)
            _print_msg(env)


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        agent_id = store.get_agent_id()
        print(f"  Agora — Encrypted Agent Chat")
        print(f"  Agent: {agent_id}")
        print()
        print("  create [label]                  Create encrypted room")
        print("  join <room> <secret> [label]    Join a room")
        print("  send <message>                  Send encrypted message")
        print("  send --reply <id> <message>     Reply to a message")
        print("  read [--tail N]                 Read messages")
        print("  check [--wake]                  Check new (hook-friendly)")
        print("  rooms                           List rooms")
        print("  switch <label>                  Switch active room")
        print("  info                            Room info + fingerprint")
        print("  verify                          ZKP membership proof")
        print("  watch                           Live tail")
        print()
        print("  Security: AES-256-GCM, HKDF-SHA256, per-message nonces")
        sys.exit(0)

    cmd = args[0]
    rest = args[1:]

    commands = {
        "create": cmd_create,
        "join": cmd_join,
        "send": cmd_send,
        "read": cmd_read,
        "check": cmd_check,
        "rooms": cmd_rooms,
        "switch": cmd_switch,
        "info": cmd_info,
        "verify": cmd_verify,
        "watch": cmd_watch,
    }

    if cmd not in commands:
        print(f"  Unknown command: {cmd}")
        sys.exit(1)

    commands[cmd](rest)


if __name__ == "__main__":
    main()
