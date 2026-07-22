#!/usr/bin/env python3
"""Replace XOR-obfuscated strings/bytes in Rust sources with plain literals."""

from __future__ import annotations

import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STR_KEY = 0x5A
GUID_KEY = 0xAA


def decode_str(data: list[int]) -> str:
    return bytes(b ^ STR_KEY for b in data).decode("utf-8")


def decode_bytes(data: list[int]) -> list[int]:
    return [b ^ STR_KEY for b in data]


def rust_str_literal(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 32 or ord(ch) == 127:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def rust_byte_array(data: list[int]) -> str:
    return ", ".join(f"0x{b:02X}" for b in data)


def parse_hex_array(text: str) -> list[int]:
    return [int(x, 16) for x in re.findall(r"0x[0-9A-Fa-f]+", text)]


def replace_xor_str(content: str) -> str:
    pattern = re.compile(
        r"xor_str\s*\(\s*&\s*\[((?:\s*0x[0-9A-Fa-f]+,\s*)*0x[0-9A-Fa-f]+)\s*\]\s*\)",
        re.DOTALL,
    )

    def repl(match: re.Match[str]) -> str:
        data = parse_hex_array(match.group(1))
        return rust_str_literal(decode_str(data))

    return pattern.sub(repl, content)


def replace_xor_bytes_call(content: str) -> str:
    pattern = re.compile(
        r"xor_bytes\s*\(\s*&\s*\[((?:\s*0x[0-9A-Fa-f]+,\s*)*0x[0-9A-Fa-f]+)\s*\]\s*\)",
        re.DOTALL,
    )

    def repl(match: re.Match[str]) -> str:
        data = parse_hex_array(match.group(1))
        decoded = decode_bytes(data)
        return f"[{rust_byte_array(decoded)}]"

    return pattern.sub(repl, content)


def replace_named_xor_const(content: str, old_name: str, new_name: str) -> str:
    pattern = re.compile(
        rf"const {old_name}: \[u8; (\d+)\] = \[\n((?:\s*0x[0-9A-Fa-f]+,\s*)*0x[0-9A-Fa-f]+),\n\];",
        re.DOTALL,
    )
    match = pattern.search(content)
    if not match:
        return content
    size = int(match.group(1))
    data = parse_hex_array(match.group(2))
    decoded = decode_bytes(data)
    replacement = f"const {new_name}: [u8; {size}] = [\n    {rust_byte_array(decoded)},\n];"
    return pattern.sub(replacement, content, count=1)


def replace_main_enc_module(content: str) -> str:
    start = content.find("mod enc {")
    if start == -1:
        return content
    end = content.find("\nfn files_part_name", start)
    if end == -1:
        return content

    block = content[start:end]
    encoded_str = re.compile(
        r"encoded_str!\((\w+),\s*\d+,\s*\[((?:0x[0-9A-Fa-f]+,\s*)*0x[0-9A-Fa-f]+)\]\);"
    )
    encoded_bytes = re.compile(
        r"encoded_bytes!\((\w+),\s*\d+,\s*\[((?:0x[0-9A-Fa-f]+,\s*)*0x[0-9A-Fa-f]+)\]\);"
    )

    lines = ["mod enc {", "    //! Plain string constants (XOR removed).", ""]
    for match in encoded_str.finditer(block):
        name = match.group(1)
        data = parse_hex_array(match.group(2))
        lines.append(f"    pub const {name}: &str = {rust_str_literal(decode_str(data))};")
    for match in encoded_bytes.finditer(block):
        name = match.group(1)
        data = parse_hex_array(match.group(2))
        decoded = decode_bytes(data)
        lines.append(
            f"    pub const {name}: [u8; {len(decoded)}] = [{rust_byte_array(decoded)}];"
        )
    lines.append("}")
    return content[:start] + "\n".join(lines) + content[end:]


def guid_from_xor(data: list[int]) -> tuple[int, int, int, list[int]]:
    bytes_ = bytes(b ^ GUID_KEY for b in data)
    data1 = struct.unpack("<I", bytes_[0:4])[0]
    data2 = struct.unpack("<H", bytes_[4:6])[0]
    data3 = struct.unpack("<H", bytes_[6:8])[0]
    data4 = list(bytes_[8:16])
    return data1, data2, data3, data4


def replace_guid_xor_blocks(content: str) -> str:
    pattern = re.compile(
        r"// ((?:IID|CLSID)_[A-Z0-9_]+)\s*:\s*([0-9A-Fa-f-]+)\n"
        r"const ((?:IID|CLSID)_[A-Z0-9_]+)_XOR: &\[u8\] = &\[\n"
        r"\s*((?:0x[0-9A-Fa-f]+,\s*)*0x[0-9A-Fa-f]+),\n\];",
        re.DOTALL,
    )

    def repl(match: re.Match[str]) -> str:
        comment_name = match.group(1)
        guid_str = match.group(2)
        const_name = match.group(3)
        data = parse_hex_array(match.group(4))
        d1, d2, d3, d4 = guid_from_xor(data)
        d4_arr = ", ".join(f"0x{b:02X}" for b in d4)
        return (
            f"// {comment_name}: {guid_str}\n"
            f"const {const_name}: GUID = GUID {{\n"
            f"    data1: 0x{d1:08X},\n"
            f"    data2: 0x{d2:04X},\n"
            f"    data3: 0x{d3:04X},\n"
            f"    data4: [{d4_arr}],\n"
            f"}};"
        )

    content = pattern.sub(repl, content)
    content = re.sub(
        r"fn get_((?:iid|clsid)_[a-z0-9_]+)\(\) -> GUID \{ xor_guid\(((?:IID|CLSID)_[A-Z0-9_]+)_XOR\) \}",
        r"fn get_\1() -> GUID { \2 }",
        content,
    )
    return content


def remove_xor_infrastructure(content: str) -> str:
    content = re.sub(r"^const XOR_KEY: u8 = 0x5A;\n", "", content, flags=re.MULTILINE)
    content = re.sub(r"^const XOR_KEY: u8 = 0xAA;\n", "", content, flags=re.MULTILINE)
    content = re.sub(r"^const STR_XOR_KEY: u8 = 0x5A;\n", "", content, flags=re.MULTILINE)

    helpers = [
        r"pub\(crate\) fn xor_str\(data: &\[u8\]\) -> String \{\n    String::from_utf8\(data\.iter\(\)\.map\(\|&b\| b \^ XOR_KEY\)\.collect\(\)\)\.unwrap_or_default\(\)\n\}\n\n",
        r"pub\(crate\) fn xor_bytes\(data: &\[u8\]\) -> Vec<u8> \{\n    data\.iter\(\)\.map\(\|&b\| b \^ XOR_KEY\)\.collect\(\)\n\}\n\n",
        r"fn xor_str\(data: &\[u8\]\) -> String \{\n    String::from_utf8\(data\.iter\(\)\.map\(\|&b\| b \^ (?:XOR_KEY|STR_XOR_KEY)\)\.collect\(\)\)\.unwrap_or_default\(\)\n\}\n\n",
        r"fn xor_guid\(data: &\[u8\]\) -> GUID \{\n    let bytes: Vec<u8> = data\.iter\(\)\.map\(\|&b\| b \^ XOR_KEY\)\.collect\(\);\n    let data1 = u32::from_le_bytes\(\[bytes\[0\], bytes\[1\], bytes\[2\], bytes\[3\]\]\);\n    let data2 = u16::from_le_bytes\(\[bytes\[4\], bytes\[5\]\]\);\n    let data3 = u16::from_le_bytes\(\[bytes\[6\], bytes\[7\]\]\);\n    let mut data4 = \[0u8; 8\];\n    data4\.copy_from_slice\(&bytes\[8\.\.16\]\);\n    GUID \{ data1, data2, data3, data4 \}\n\}\n\n",
    ]
    for helper in helpers:
        content = re.sub(helper, "", content)
    return content


def replace_imports(content: str) -> str:
    replacements = [
        ("use super::{env_configured, xor_bytes, xor_str};", "use super::env_configured;"),
        ("use super::{env_configured, xor_str};", "use super::env_configured;"),
        ("use super::{xor_bytes, xor_str};", ""),
        ("use super::{xor_str};", ""),
        (", xor_bytes, xor_str", ""),
        (", xor_str", ""),
        ("xor_bytes, ", ""),
        ("xor_str, ", ""),
    ]
    for old, new in replacements:
        content = content.replace(old, new)
    return content


def replace_fn_string_helpers(content: str) -> str:
    pattern = re.compile(r"fn (s_[a-z0-9_]+)\(\) -> String \{ ([^\n]+) \}")

    def repl(match: re.Match[str]) -> str:
        value = match.group(2).strip()
        if value.startswith('"') and not value.endswith(".to_string()"):
            return f"fn {match.group(1)}() -> String {{ {value}.to_string() }}"
        return match.group(0)

    return pattern.sub(repl, content)


def replace_payload_key(content: str) -> str:
    pattern = re.compile(
        r"const PAYLOAD_KEY_ENC: &\[u8\] = &\[\n((?:\s*0x[0-9A-Fa-f]+,\s*)*0x[0-9A-Fa-f]+),\n\];",
        re.DOTALL,
    )
    match = pattern.search(content)
    if not match:
        return content
    data = parse_hex_array(match.group(1))
    key = bytes(b ^ STR_KEY for b in data).decode()
    content = pattern.sub(f'const PAYLOAD_KEY: &[u8] = b"{key}";', content)
    content = content.replace(
        """fn payload_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    for (i, slot) in key.iter_mut().enumerate() {
        *slot = PAYLOAD_KEY_ENC[i] ^ XOR_KEY;
    }
    key
}""",
        """fn payload_key() -> &'static [u8] {
    PAYLOAD_KEY
}""",
    )
    return content


def simplify_build_rs(content: str) -> str:
    content = re.sub(
        r"const PAYLOAD_KEY: &\[u8\] = b\"chrome_payload_k\";\n\n"
        r"fn xor_payload\(data: &\[u8\]\) -> Vec<u8> \{\n"
        r"    data\.iter\(\)\n"
        r"        \.enumerate\(\)\n"
        r"        \.map\(\|\(i, &b\)\| b \^ PAYLOAD_KEY\[i % PAYLOAD_KEY\.len\(\)\]\)\n"
        r"        \.collect\(\)\n"
        r"\}\n\n",
        "",
        content,
    )
    return content.replace(
        "let encrypted = xor_payload(&raw);\n\n        if let Err(error) = fs::write(&out_enc, &encrypted)",
        "if let Err(error) = fs::write(&out_enc, &raw)",
    )


def fix_dpapi_fallback(content: str) -> str:
    content = replace_named_xor_const(content, "AES_ELEV_KEY_XOR", "AES_ELEV_KEY")
    content = replace_named_xor_const(content, "CHACHA_ELEV_KEY_XOR", "CHACHA_ELEV_KEY")
    content = content.replace(
        """fn aes_elev_key() -> [u8; 32] {
    let decoded = xor_bytes(&AES_ELEV_KEY_XOR);
    decoded.try_into().unwrap_or([0u8; 32])
}""",
        "fn aes_elev_key() -> [u8; 32] {\n    AES_ELEV_KEY\n}",
    )
    content = content.replace(
        """fn chacha_elev_key() -> [u8; 32] {
    let decoded = xor_bytes(&CHACHA_ELEV_KEY_XOR);
    decoded.try_into().unwrap_or([0u8; 32])
}""",
        "fn chacha_elev_key() -> [u8; 32] {\n    CHACHA_ELEV_KEY\n}",
    )
    return content


def process_file(path: Path) -> bool:
    original = path.read_text(encoding="utf-8")
    content = original

    if path.name == "main.rs":
        content = replace_main_enc_module(content)
    if path.name == "elevator.rs":
        content = replace_guid_xor_blocks(content)
    if path.name == "chrome_inject.rs":
        content = replace_payload_key(content)
    if path.name == "build.rs":
        content = simplify_build_rs(content)
    if path.name == "dpapi_fallback.rs":
        content = fix_dpapi_fallback(content)

    content = replace_xor_str(content)
    content = replace_xor_bytes_call(content)
    content = remove_xor_infrastructure(content)
    content = replace_fn_string_helpers(content)
    content = replace_imports(content)

    if content != original:
        path.write_text(content, encoding="utf-8")
        return True
    return False


def main() -> None:
    changed = []
    for path in sorted(ROOT.rglob("*.rs")):
        if "target" in path.parts:
            continue
        if process_file(path):
            changed.append(path.relative_to(ROOT))
    print(f"Updated {len(changed)} files:")
    for path in changed:
        print(f"  - {path}")


if __name__ == "__main__":
    main()
