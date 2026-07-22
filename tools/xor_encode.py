#!/usr/bin/env python3
"""Encode text with the project XOR key (0x5A) for use in Rust sources."""

from __future__ import annotations

import argparse
import sys

KEY = 0x5A


def encode(text: str) -> list[int]:
    return [b ^ KEY for b in text.encode("utf-8")]


def decode(data: list[int]) -> str:
    return bytes(b ^ KEY for b in data).decode("utf-8")


def fmt_array(data: list[int]) -> str:
    return ", ".join(f"0x{b:02X}" for b in data)


def fmt_encoded_str(name: str, data: list[int]) -> str:
    return f"encoded_str!({name}, {len(data)}, [{fmt_array(data)}]);"


def fmt_as_bytes(name: str, data: list[int]) -> str:
    return f"encoded_bytes!({name}, {len(data)}, [{fmt_array(data)}]);"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="XOR-encode UTF-8 text with key 0x5A (same as enc::decode in src/main.rs)."
    )
    parser.add_argument(
        "text",
        nargs="?",
        help="Text to encode. If omitted, reads from stdin.",
    )
    parser.add_argument(
        "--name",
        default="S_MY_STRING",
        help="Const name for Rust macro output (default: S_MY_STRING)",
    )
    parser.add_argument(
        "--bytes",
        action="store_true",
        help="Output encoded_bytes! instead of encoded_str!",
    )
    args = parser.parse_args()

    text = args.text if args.text is not None else sys.stdin.read()
    if not text:
        print("error: empty input", file=sys.stderr)
        return 1

    data = encode(text)

    print(f"Input : {text!r}")
    print(f"Length: {len(data)} bytes")
    print()
    print("Decoded check:", decode(data))
    print()
    print("Byte array:")
    print(f"[{fmt_array(data)}]")
    print()
    if args.bytes:
        print("Rust macro:")
        print(fmt_as_bytes(args.name, data))
    else:
        print("Rust macro:")
        print(fmt_encoded_str(args.name, data))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
