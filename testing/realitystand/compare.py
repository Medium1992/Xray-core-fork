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
    return "+".join(r.get("hs", [])) or r["type"]


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


def same_shape(a, b):
    if len(a) != len(b):
        return False
    for (ta, la), (tb, lb) in zip(a, b):
        if ta != tb:
            return False
        if abs(la - lb) > (2 if ta == "CV" else 0):
            return False
    return True


def split(streams):
    full = [s for s in streams if s["ch"] and not s["ch"]["psk_identities"]]
    resumed = [s for s in streams if s["ch"] and s["ch"]["psk_identities"]]
    return full, resumed


def fmt(shape):
    return " ".join(f"{t}:{l}" for t, l in shape)


def compare(ref_run, our_run, browser, target):
    ref = load(ref_run, f"{browser}-{target}")
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
        a, b = server_shape(rf[0]), server_shape(of[0])
        # the reference's first connection may end before its tickets came
        full_ref = max((server_shape(s) for s in rf), key=tickets)
        check("full", same_shape(full_ref, b), f"ref  {fmt(full_ref)}\n             ours {fmt(b)}")
    else:
        check("full", False, "no full handshake")
    if rr and orr:
        a, b = ext_key(rr[0]["ch"]["exts"], ordered), ext_key(orr[0]["ch"]["exts"], ordered)
        check("hello resumed", a == b, f"ref {a}\n             ours {b}" if a != b else "")
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
    for target in ("nginx", "caddy", "haproxy"):
        for browser in ("chrome", "firefox"):
            print(f"== {browser} via {target}")
            for name, ok, detail in compare(ref_run, our_run, browser, target):
                failed += not ok
                print(f"  {'ok  ' if ok else 'DIFF'} {name:14s}" + (f" {detail}" if detail and not ok else ""))
    print(f"{failed} differences")


if __name__ == "__main__":
    main()
