#!/usr/bin/env python3
"""
String encryptor for FuckProtect native code (T8.4).

Encrypts plaintext strings using the XOR key from string_obfuscate.cpp
and outputs the encrypted byte arrays ready for inclusion in the C source.

Usage:
    python3 encrypt_strings.py "string1" "string2" ...
    python3 encrypt_strings.py --file strings.txt

The XOR key must match STR_XOR_KEY in string_obfuscate.cpp.
"""

import sys

XOR_KEY = [0xA7, 0x3C, 0xE1, 0x5D]

def encrypt_string(plaintext: str) -> list:
    """Encrypt a string with rotating XOR key."""
    result = []
    for i, c in enumerate(plaintext.encode('utf-8')):
        result.append(c ^ XOR_KEY[i % 4])
    return result

def format_c_array(name: str, encrypted: list) -> str:
    """Format as a C static const uint8_t array."""
    lines = []
    lines.append(f"/* {name} */")
    lines.append(f"static const uint8_t _str_{len(encrypted)}[] = {{")

    # Format in rows of 16 bytes
    for i in range(0, len(encrypted), 16):
        chunk = encrypted[i:i+16]
        hex_vals = ", ".join(f"0x{b:02x}" for b in chunk)
        lines.append(f"    {hex_vals},")

    lines.append("};")
    lines.append("")
    return "\n".join(lines)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 encrypt_strings.py <string> ...")
        print("       python3 encrypt_strings.py --file <file>")
        print()
        print("Each string is encrypted and output as a C array.")
        sys.exit(1)

    strings = []
    if sys.argv[1] == "--file":
        with open(sys.argv[2], 'r') as f:
            strings = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    else:
        strings = sys.argv[1:]

    for i, s in enumerate(strings):
        encrypted = encrypt_string(s)
        print(format_c_array(f"STR_{i}", encrypted))
        print(f"/* Plaintext: \"{s}\" */")
        print(f"/* Length: {len(encrypted)} bytes */")
        print()

if __name__ == "__main__":
    main()
