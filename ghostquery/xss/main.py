#!/usr/bin/env python3
"""
ghostquery/xss/generate_payloads.py

Reads xss.json (same directory by default) and writes one XSS payload
per line to payloads.txt.

Usage:
    python3 generate_payloads.py [xss.json] [payloads.txt]

Placeholders understood:
    {tag}               entry from tags[category].list
    {event}             entry from the events pool (per generation_options)
    {function}          function name from functions[]
    {value}             value from functions[]
    {base64}            base64 of "{function}({value})"
    {base64_full_page}  literal from xss.json (full_page_base64)

Encodings with apply_to == "full_payload" produce additional variants.
base64_eval (apply_to == "function_call") is already covered by the
script/breakout_script templates, so it is not applied a second time.
"""

import base64
import json
import os
import random
import sys
from urllib.parse import quote

# Deterministic output: rerunning gives the same payloads.txt
random.seed(0xC0FFEE)


# --------------------------------------------------------------------------- #
# Config loading
# --------------------------------------------------------------------------- #
def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_event_pool(cfg):
    """Flatten the events sections per generation_options."""
    ev = cfg.get("events", {})
    opts = cfg.get("generation_options", {})

    pool = list(ev.get("standard", []))
    if opts.get("include_interaction_events", True):
        pool += ev.get("extended", [])
    if opts.get("include_media_events", False):
        pool += ev.get("media", [])
    if opts.get("include_document_body_events", False):
        pool += ev.get("document_body", [])
    if opts.get("include_animation_svg_events", False):
        pool += ev.get("animation_svg", [])

    # Deduplicate, preserve order
    seen, out = set(), []
    for e in pool:
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out or [""]          # templates with no {event} still work


# --------------------------------------------------------------------------- #
# Placeholder substitution
# --------------------------------------------------------------------------- #
def substitute(template, tag, event, fn_name, fn_value, full_page_b64):
    call = f"{fn_name}({fn_value})"
    b64  = base64.b64encode(call.encode("utf-8")).decode("ascii")

    # Longest / most specific token first, then the rest.
    return (template
            .replace("{base64_full_page}", full_page_b64 or "")
            .replace("{base64}",            b64)
            .replace("{tag}",               tag)
            .replace("{event}",             event)
            .replace("{function}",          fn_name)
            .replace("{value}",             fn_value))


# --------------------------------------------------------------------------- #
# Full-payload encodings
# --------------------------------------------------------------------------- #
def apply_full_payload_encoding(payload, transform):
    if transform == "html_entity_decimal":
        return "".join(f"&#{ord(c)};" for c in payload)
    if transform == "html_entity_hex":
        return "".join(f"&#x{ord(c):x};" for c in payload)
    if transform == "url_encoded":
        return quote(payload, safe="")
    if transform == "double_url_encoded":
        return quote(quote(payload, safe=""), safe="")
    return payload


# --------------------------------------------------------------------------- #
# Core generation
# --------------------------------------------------------------------------- #
def generate_raw(cfg, event_pool):
    tags_cfg     = cfg.get("tags", {})
    ctx_bindings = cfg.get("context_bindings", {})
    functions    = cfg.get("functions", [{"name": "alert", "value": "1"}])
    opts         = cfg.get("generation_options", {})
    per_ctx_cap  = int(opts.get("max_payloads_per_context", 120))
    full_page_b64 = cfg.get("full_page_base64", "")

    raw = set()

    for context, cat_list in ctx_bindings.items():
        ctx_bucket = set()

        for cat_name in cat_list:
            cat = tags_cfg.get(cat_name)
            if not cat:
                continue

            templates = cat.get("templates", [])
            tag_list  = cat.get("list", [""])

            for tmpl in templates:
                tag_iter   = tag_list       if "{tag}"      in tmpl else [""]
                event_iter = event_pool     if "{event}"    in tmpl else [""]
                fn_iter    = functions      if "{function}" in tmpl else [functions[0]]

                for tag in tag_iter:
                    for ev in event_iter:
                        for fn in fn_iter:
                            p = substitute(
                                tmpl, tag, ev,
                                fn.get("name", ""),
                                fn.get("value", ""),
                                full_page_b64,
                            )
                            ctx_bucket.add(p)

        # Per-context cap via random sampling
        if len(ctx_bucket) > per_ctx_cap:
            ctx_bucket = set(random.sample(sorted(ctx_bucket), per_ctx_cap))

        raw.update(ctx_bucket)

    return raw


def apply_encodings(cfg, raw_payloads):
    """Return the extra payload variants produced by full_payload encodings."""
    encodings = cfg.get("encodings", {})
    out = set()

    for enc_name, enc_cfg in encodings.items():
        if enc_cfg.get("apply_to") != "full_payload":
            continue
        transform = enc_cfg.get("transform", "none")
        if transform == "none":
            continue
        for p in raw_payloads:
            out.add(apply_full_payload_encoding(p, transform))

    return out


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    here = os.path.dirname(os.path.abspath(__file__))

    cfg_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "xss.json")
    out_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(here, "payloads.txt")

    cfg = load_json(cfg_path)

    event_pool = build_event_pool(cfg)
    raw        = generate_raw(cfg, event_pool)
    allp       = set(raw)
    allp      |= apply_encodings(cfg, raw)

    sample_size = int(cfg.get("generation_options", {})
                         .get("random_sample_size", 1000))
    if sample_size > 0 and len(allp) > sample_size:
        allp = set(random.sample(sorted(allp), sample_size))

    payloads = sorted(allp)

    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    written = 0
    with open(out_path, "w", encoding="utf-8") as f:
        for p in payloads:
            if not p or "\n" in p or "\r" in p:
                continue                       # guard: one payload per line
            f.write(p + "\n")
            written += 1

    print(f"[+] {written} raw-context payloads generated")
    print(f"[+] Wrote {written} payloads to {out_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)