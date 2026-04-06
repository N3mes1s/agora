"""Minimal CLI for agora-chat Python SDK."""

import argparse
import json
import sys


def main() -> None:
    parser = argparse.ArgumentParser(prog="agora-chat", description="agora encrypted chat")
    sub = parser.add_subparsers(dest="cmd")

    # join
    p_join = sub.add_parser("join", help="Join a room")
    p_join.add_argument("room_id")
    p_join.add_argument("secret")
    p_join.add_argument("label", nargs="?", default="default")

    # send
    p_send = sub.add_parser("send", help="Send a message")
    p_send.add_argument("room_id")
    p_send.add_argument("secret")
    p_send.add_argument("message")

    # check
    p_check = sub.add_parser("check", help="Check for messages")
    p_check.add_argument("room_id")
    p_check.add_argument("secret")
    p_check.add_argument("--since", default="1h")

    # heartbeat
    p_hb = sub.add_parser("heartbeat", help="Send heartbeat")
    p_hb.add_argument("room_id")
    p_hb.add_argument("secret")

    args = parser.parse_args()

    from .client import AgoraClient

    client = AgoraClient()

    if args.cmd == "join":
        room = client.join(args.room_id, args.secret, args.label)
        fp = client.fingerprint()
        print(f"  Joined room '{room.label}'")
        print(f"  Encryption: AES-256-GCM + HKDF-SHA256")
        print(f"  Fingerprint: {fp}")

    elif args.cmd == "send":
        client.join(args.room_id, args.secret)
        msg_id = client.send(args.message)
        print(f"  Sent [{msg_id}]")

    elif args.cmd == "check":
        client.join(args.room_id, args.secret)
        messages = client.check(since=args.since)
        if not messages:
            print("  (no new messages)")
        for msg in messages:
            ts = msg.timestamp
            print(f"  [{msg.sender}] {msg.text}")

    elif args.cmd == "heartbeat":
        client.join(args.room_id, args.secret)
        ok = client.heartbeat()
        print("  Heartbeat sent." if ok else "  Heartbeat failed.")

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
