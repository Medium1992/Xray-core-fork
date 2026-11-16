#!/usr/bin/env python3
"""compare.py <reference-run> <xray-run>: does REALITY look like the target?

For each target and browser, the browser's connections straight to the
target (reference) against the Xray client's through REALITY (ours), on what
a censor sees and what the keylog adds:

  hello      ClientHello extensions: the set for Chrome, which shuffles them,
             the order for Firefox; with a ticket and without
  psk        length of the PSK identity
  full       server records of a full handshake: types and lengths, from
             ServerHello to the last ticket
  resumed    the same for a resumed handshake
  tickets    tickets after a full and after a resumed handshake

Lengths of CertificateVerify differ by a byte or two between handshakes
(ECDSA signatures), so they are compared within 2 bytes.
"""
import json
import os
import subprocess
import sys

S = os.environ.get("STAND_WORK") or os.path.expanduser("~/.cache/realitystand")
CODE = os.path.dirname(os.path.abspath(__file__))
GREASE = {0x0a0a + 0x1010 * i for i in range(16)}
HANDSHAKE_TAGS = {"SH", "CCS", "EE", "Cert", "CV", "Fin", "NST"}


def load(run, name):
    path = f"{run}/{name}/analysis.json"
    if not os.path.exists(path):
        subprocess.run([sys.executable, f"{CODE}/analyze.py", run, name], capture_output=True)
    with open(path) as f:
        return json.load(f)


def tag(r):
    # A compressed certificate goes where the certificate does: REALITY
    # sends its own in a record as long, which a censor cannot tell apart.
    return "+".join("Cert" if t == "CompCert" else t for t in r.get("hs", [])) or r["type"]


def server_shape(stream):
    """Server records from ServerHello through the last ticket."""
    recs = [r for r in stream["records"] if r["dir"] == "s>c"]
    shape = []
    for r in recs:
        t = tag(r)
        if not set(t.split("+")) <= HANDSHAKE_TAGS:
            if any(x == "NST" for s in shape for x in s[0].split("+")) or t == "App":
                # an App record ends the handshake once the flight is done
                if any("Fin" in s[0] for s in shape):
                    break
            continue
        shape.append((t, r["len"]))
    return shape


def tickets(shape):
    return sum(t.split("+").count("NST") for t, _ in shape)


def ext_key(exts, ordered):
    exts = [e for e in exts if e not in GREASE]
    return exts if ordered else sorted(exts)


def norm(v):
    """GREASE values compare equal to each other."""
    try:
        n = int(v, 0) if isinstance(v, str) else int(v)
    except ValueError:
        return v
    return "GREASE" if n in GREASE else n


# Extensions whose length a browser picks at random per connection: their
# lengths are compared as the sets seen over all connections instead.
RANDOM_LEN = {"chrome": {0xfe0d}, "edge": {0xfe0d}}
# The lengths Chromium picks its GREASE ECH from (BoringSSL, uniformly).
KNOWN_LENS = {0xfe0d: {186, 218, 250, 282}}


def hello_diff(ref, ours, skip=()):
    """Differences in content between two ClientHellos: each field value by
    value, in order, and the lengths of each extension type."""
    diffs = []
    for field, a in ref.get("detail", {}).items():
        b = ours.get("detail", {}).get(field, [])
        a, b = [norm(x) for x in a], [norm(x) for x in b]
        if a != b:
            diffs.append(f"{field}: ref {a} ours {b}")
    lens = []
    for ch in (ref, ours):
        d = {}
        for t, l in zip(ch["exts"], ch.get("ext_lens", [])):
            d.setdefault(norm(t), []).append(l)
        lens.append(d)
    for t in sorted(set(lens[0]) | set(lens[1]), key=str):
        if t in skip:
            continue
        if sorted(lens[0].get(t, [])) != sorted(lens[1].get(t, [])):
            diffs.append(f"ext {t} len: ref {lens[0].get(t)} ours {lens[1].get(t)}")
    return diffs


def same_shape(a, b):
    if len(a) != len(b):
        return False
    for (ta, la), (tb, lb) in zip(a, b):
        if ta != tb:
            return False
        if abs(la - lb) > (2 if "CV" in ta.split("+") else 0):
            return False
    return True


def split(streams):
    full = [s for s in streams if s["ch"] and not s["ch"]["psk_identities"]]
    resumed = [s for s in streams if s["ch"] and s["ch"]["psk_identities"]]
    return full, resumed


def fmt(shape):
    return " ".join(f"{t}:{l}" for t, l in shape)


def compare(ref_run, our_run, browser, target, ref_name=None):
    ref = load(ref_run, f"{ref_name or browser}-{target}")
    ours = load(our_run, f"xray-{browser}-{target}")
    rf, rr = split(ref)
    of, orr = split(ours)
    ordered = browser == "firefox"
    checks = []

    def check(name, ok, detail):
        checks.append((name, ok, detail))

    if rf and of:
        a, b = ext_key(rf[0]["ch"]["exts"], ordered), ext_key(of[0]["ch"]["exts"], ordered)
        check("hello full", a == b, f"ref {a}\n             ours {b}" if a != b else "")
        d = hello_diff(rf[0]["ch"], of[0]["ch"], RANDOM_LEN.get(browser, ()))
        check("hello content", not d, "\n             ".join(d))
        a, b = server_shape(rf[0]), server_shape(of[0])
        # the reference's first connection may end before its tickets came
        full_ref = max((server_shape(s) for s in rf), key=tickets)
        check("full", same_shape(full_ref, b), f"ref  {fmt(full_ref)}\n             ours {fmt(b)}")
    else:
        check("full", False, "no full handshake")
    for t in RANDOM_LEN.get(browser, ()):
        seen = []
        # all of the browser's connections in the reference run, any target
        every = [st for d in sorted(os.listdir(ref_run)) if d.startswith(f"{ref_name or browser}-")
                 for st in load(ref_run, d)]
        for streams in (every, ours):
            seen.append(sorted({l for s in streams if s["ch"] for e, l in zip(s["ch"]["exts"], s["ch"]["ext_lens"]) if e == t}))
        check(f"ext {t} lens", set(seen[1]) <= set(seen[0]) | KNOWN_LENS.get(t, set()),
              f"ref {seen[0]} ours {seen[1]}")
    # Time from the ServerHello to the client's Finished of full handshakes,
    # over that of resumed ones: the browser verifying the certificate.
    def verify_ms(streams):
        full = [s["timing"]["client_fin"] - s["timing"]["sh"] for s in streams
                if s["ch"] and not s["ch"]["psk_identities"] and "client_fin" in s.get("timing", {}) and "sh" in s["timing"]]
        res = sorted(s["timing"]["client_fin"] - s["timing"]["sh"] for s in streams
                     if s["ch"] and s["ch"]["psk_identities"] and "client_fin" in s.get("timing", {}) and "sh" in s["timing"])
        if not full or not res:
            return None
        base = res[len(res) // 2]
        return [round(f - base, 1) for f in full]
    a = [x for d in sorted(os.listdir(ref_run)) if d.startswith(f"{ref_name or browser}-")
         for x in (verify_ms(load(ref_run, d)) or [])]
    b = verify_ms(ours)
    if a and b:
        # A browser's first verification after it starts is slow (125 ms
        # for a real chain here), later ones are not: ours only has to fall
        # in the range.
        check("verify delay", min(a) - 10 <= min(b) and max(b) <= max(a) + 10, f"ref {a} ours {b} ms")
    if rr and orr:
        a, b = ext_key(rr[0]["ch"]["exts"], ordered), ext_key(orr[0]["ch"]["exts"], ordered)
        check("hello resumed", a == b, f"ref {a}\n             ours {b}" if a != b else "")
        d = hello_diff(rr[0]["ch"], orr[0]["ch"], RANDOM_LEN.get(browser, ()))
        check("hello res cont", not d, "\n             ".join(d))
        a, b = rr[0]["ch"]["psk_identities"], orr[0]["ch"]["psk_identities"]
        check("psk", a == b, f"ref {a} ours {b}")
        a, b = server_shape(rr[0]), server_shape(orr[0])
        check("resumed", same_shape(a, b), f"ref  {fmt(a)}\n             ours {fmt(b)}")
    else:
        check("resumed", False, f"reference resumed {len(rr)}, ours {len(orr)}")
    return checks


def main():
    ref_run, our_run = sys.argv[1], sys.argv[2]
    failed = 0
    targets = sorted({d[len("xray-chrome-"):] for d in os.listdir(our_run) if d.startswith("xray-chrome-")})
    for target in targets:
        for browser, ref_name in (("chrome", "chrome"), ("edge", "edge"), ("firefox", "firefox156"), ("firefox", "firefox160")):
            if not os.path.isdir(f"{ref_run}/{ref_name}-{target}"):
                continue
            print(f"== {browser} via {target}, reference {ref_name}")
            for name, ok, detail in compare(ref_run, our_run, browser, target, ref_name):
                failed += not ok
                print(f"  {'ok  ' if ok else 'DIFF'} {name:14s}" + (f" {detail}" if detail and not ok else ""))
    print(f"{failed} differences")


if __name__ == "__main__":
    main()
