#!/usr/bin/env python3
"""
encode_payloads.py

Read a payload file (one per line) and write out the same payloads under
several encodings, one output file per encoding.

Usage:
    python3 encode_payloads.py <input_file> [--outdir DIR]
"""

import argparse
import os
import sys
from urllib.parse import quote


# ---------------------------------------------------------------------------
# Encoders
# ---------------------------------------------------------------------------

def enc_url(s: str) -> str:
    """Percent-encode everything that isn't unreserved."""
    return quote(s, safe="")


def enc_url_double(s: str) -> str:
    """Percent-encode twice."""
    return quote(quote(s, safe=""), safe="")


def enc_html_entity_dec(s: str) -> str:
    """Every character -> decimal HTML entity."""
    return "".join(f"&#{ord(c)};" for c in s)


def enc_html_entity_hex(s: str) -> str:
    """Every character -> hex HTML entity."""
    return "".join(f"&#x{ord(c):X};" for c in s)


def enc_html_entity_mixed(s: str) -> str:
    """Only encode < > & " ' . Useful for attribute contexts."""
    table = {"<": "&#60;", ">": "&#62;", "&": "&#38;", '"': "&#34;", "'": "&#39;"}
    return "".join(table.get(c, c) for c in s)


def enc_js_hex(s: str) -> str:
    r"""Every character -> \xNN."""
    return "".join(f"\\x{ord(c):02x}" for c in s)


def enc_js_unicode(s: str) -> str:
    r"""Every character -> \uNNNN."""
    return "".join(f"\\u{ord(c):04x}" for c in s)


def enc_js_unicode_cp(s: str) -> str:
    r"""Every character -> \u{NNNN} (ES6 code point escapes)."""
    return "".join(f"\\u{{{ord(c):x}}}" for c in s)


def enc_js_octal(s: str) -> str:
    r"""Every character -> \NNN (3-digit octal, sloppy JS)."""
    return "".join(f"\\{ord(c):03o}" for c in s)


def enc_css_hex(s: str) -> str:
    r"""Every character -> \NNNNNN (CSS 6-digit hex escape)."""
    return "".join(f"\\{ord(c):06X} " for c in s)


def enc_css_hex_short(s: str) -> str:
    r"""Every character -> \NN (CSS 2-digit hex escape, plus space)."""
    return "".join(f"\\{ord(c):02X} " for c in s)


def enc_unicode_escape(s: str) -> str:
    """Python-style \\uXXXX escapes (for JSON-ish sinks)."""
    return "".join(f"\\u{ord(c):04X}" for c in s)


def enc_base64(s: str) -> str:
    import base64
    return base64.b64encode(s.encode()).decode()


def enc_hex(s: str) -> str:
    return s.encode().hex()


# Registry: filename stem -> encoder function
ENCODERS = {
    "url":              enc_url,
    "url_double":       enc_url_double,
    "html_entity_dec":  enc_html_entity_dec,
    "html_entity_hex":  enc_html_entity_hex,
    "html_entity_mixed":enc_html_entity_mixed,
    "js_hex":           enc_js_hex,
    "js_unicode":       enc_js_unicode,
    "js_unicode_cp":    enc_js_unicode_cp,
    "js_octal":         enc_js_octal,
    "css_hex":          enc_css_hex,
    "css_hex_short":    enc_css_hex_short,
    "unicode_escape":   enc_unicode_escape,
    "base64":           enc_base64,
    "hex":              enc_hex,
}


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Encode a payload file many ways.")
    ap.add_argument("input", help="source payload file (one payload per line)")
    ap.add_argument("--outdir", default=None,
                    help="output directory (default: alongside input, in <input>_encoded/)")
    ap.add_argument("--only", default=None,
                    help="comma-separated list of encoding names to emit")
    args = ap.parse_args()

    if not os.path.isfile(args.input):
        sys.exit(f"input file not found: {args.input}")

    base = os.path.splitext(os.path.basename(args.input))[0]
    outdir = args.outdir or os.path.join(
        os.path.dirname(os.path.abspath(args.input)),
        f"{base}_encoded",
    )
    os.makedirs(outdir, exist_ok=True)

    # Read payloads, strip newlines, keep order, drop blank / comment lines.
    payloads = []
    with open(args.input, "r", encoding="utf-8", errors="surrogateescape") as f:
        for raw in f:
            line = raw.rstrip("\r\n")
            if not line or line.lstrip().startswith("#"):
                continue
            payloads.append(line)

    if not payloads:
        sys.exit("no payloads found in input file")

    # Pick encoders.
    names = list(ENCODERS.keys())
    if args.only:
        wanted = [n.strip() for n in args.only.split(",") if n.strip()]
        missing = [n for n in wanted if n not in ENCODERS]
        if missing:
            sys.exit(f"unknown encodings: {', '.join(missing)}")
        names = wanted

    print(f"input   : {args.input}")
    print(f"outdir  : {outdir}")
    print(f"payloads: {len(payloads)}")
    print(f"encoders: {len(names)}")
    print()

    for name in names:
        fn = ENCODERS[name]
        out_path = os.path.join(outdir, f"{name}.txt")
        with open(out_path, "w", encoding="utf-8", errors="surrogateescape") as out:
            for p in payloads:
                try:
                    out.write(fn(p))
                except Exception as e:
                    # Don't let one bad line kill the run.
                    out.write(f"# ENCODE ERROR on {p!r}: {e}")
                out.write("\n")
        print(f"  wrote {len(payloads):>6} lines -> {out_path}")

    print("\ndone.")


if __name__ == "__main__":
    main()