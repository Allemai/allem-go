"""Encode a corpus with the REAL Matrix Canonical JSON package.

The Go encoder in `canonicaljson.go` is a reimplementation, and the Python SDK's
own module docstring says why that is dangerous: an encoder that agrees on every
payload anyone tested and disagrees on one customer's unicode key surfaces as
intermittent `signature_verified: false` on a live agent.

So this is the other half of the pair. `canonicaljson_python_test.go` writes a
corpus here, this encodes it with `canonicaljson.encode_canonical_json` -- the
same import the backend and the Python SDK use, not a restatement of it -- and
the test compares bytes.

Input (stdin), one JSON object per line:

    {"id": "...", "expr": "<a Python expression>"}
    {"id": "...", "f64": "<16 hex digits, big-endian IEEE-754>"}

Output (stdout), one JSON object per line:

    {"id": "...", "hex": "<the canonical bytes, hex>"}
    {"id": "...", "error": "<the exception, if Python refuses the value>"}

`expr` is evaluated. This script reads only what the test process writes to its
own stdin, runs in a subprocess the test owns, and is never given anything from
a network or a repository file.
"""

import json
import struct
import sys

import canonicaljson


def encode(value):
    return canonicaljson.encode_canonical_json(value).hex()


def main() -> int:
    out = sys.stdout
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        case = json.loads(line)
        result = {"id": case["id"]}
        try:
            if "f64" in case:
                (value,) = struct.unpack(">d", bytes.fromhex(case["f64"]))
                # The float on its own, so a mismatch names repr() rather than
                # an object that happens to contain a float.
                result["repr"] = repr(value)
                result["hex"] = encode(value)
            else:
                result["hex"] = encode(eval(case["expr"], {"__builtins__": {}}, {}))
        except Exception as exc:  # noqa: BLE001 - a refusal is a result, not a crash
            result["error"] = f"{type(exc).__name__}: {exc}"
        out.write(json.dumps(result) + "\n")
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
