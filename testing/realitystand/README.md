# REALITY session resumption stand

Checks that REALITY with `"browser": "auto"` looks, on the wire, like a
browser talking to the target: the ClientHello with and without a ticket,
and the server's records of full and resumed handshakes. Runs without root,
in user and network namespaces.

```
cli 10.9.0.1 --veth (netem, 60 ms RTT)-- srv
                                          .11 nginx (OpenSSL)   .12 Caddy (crypto/tls)   .13 HAProxy (OpenSSL)
                                          .14 nginx, tickets live 8 s
                                          .21-.24 REALITY, new build      .31-.33 REALITY, old build
                                          .40 HAProxy TCP round robin over .21 and .31
                                          .50 plain HTTP behind the proxies
```

The capture is taken on the client's side of the veth: what a censor sees.
The clients write their TLS secrets, so the captures decrypt.

## Setup

```sh
testing/realitystand/setup.sh . <new-ref> <old-ref>
```

Everything lands in `$STAND_WORK` (default `~/.cache/realitystand`):
Debian packages unpacked under `root/` (`install.sh`), Google Chrome stable,
Caddy checked against its release checksums, a copy of tcpdump (the system
one has an AppArmor profile that refuses signals and writes to hidden
directories), a test CA, and `xray-new`/`xray-old` built from the two refs.
Firefox comes from the system.

## Run

```sh
cd testing/realitystand
unshare -Urnm python3 stand.py browsers xray compat edge   # RTT_MS=60 by default
python3 analyze.py <run-dir>                                 # per connection
python3 compare.py <run-with-browsers> <run-with-xray>       # browsers vs REALITY
```

Each scenario leaves `capture.pcap`, `keylog`, `meta.json`, `analysis.json`
and the logs in `runs/<stamp>/<scenario>/`.

| group | scenarios |
|---|---|
| `browsers` | Chrome and Firefox straight to each target: a page that fetches again after the target closed the idle connection, so the later connections resume |
| `xray` | the new client through the new server, `chrome` and `firefox` fingerprints with `browser: auto`, and `chrome` without |
| `compat` | old client and new server, new client and old server, old with old |
| `edge` | ticket expiry; a new and an old server behind one address; a censor replaying a ClientHello that offers a ticket |

`compare.py` checks, per target and browser: ClientHello extensions (the set
for Chrome, which shuffles them, the order for Firefox), PSK identity length,
and the server records of full and resumed handshakes by type and length
(CertificateVerify within 2 bytes).

## Findings (2026-11-16)

References: Chrome 157, Edge 157, Firefox 156.0.1 and 160.0 (Firefox 153 ESR
of the system too), straight to each target. With the changes below,
`compare.py` finds no difference for chrome, edge and firefox through
REALITY: ClientHello content (every field and every extension's length;
GREASE ECH lengths as sets for Chromium, which picks them at random), PSK
identity length, the server's records of full and resumed handshakes, and
the time the client takes for its Finished.

- Firefox drops `session_ticket` when it offers a ticket and grows its
  GREASE ECH payload by the size of `pre_shared_key` rounded up to 32
  bytes; Chrome and Edge keep `session_ticket` and pick ECH lengths from
  {186, 218, 250, 282} regardless.
- Edge 157 is Chrome 155's ClientHello without `trust_anchors`; uTLS's
  `edge` was Edge 85, with no ML-KEM key share, which REALITY servers
  refuse. `ios` was iOS 14, also refused; it is now Safari 26.3's, which
  JA4 databases show for current macOS Safari and, at each version, the
  same for iOS.
- Safari's ClientHello (26.3) matches the most common Safari 27 JA4
  (`t13d2013h2_a09f3c656075_7f0f34a4126d`). No Safari JA4 seen in the wild
  is that ClientHello with `pre_shared_key`, so `safari` and `ios` do not
  resume.
- Browsers send their Finished later in full handshakes, verifying the
  certificate chain: Chrome 8-18 ms, Edge 7-10 ms, Firefox 1-5 ms over
  resumed ones (this 4-core machine). The client now waits as long after
  verifying REALITY's certificate.
- Old and new clients and servers work together in every combination.
- Behind one address with an old server, a ticket that reaches the old one
  ends in the target's certificate and a dropped connection; the client then
  offers no ticket there for 10 minutes.
- A replayed ClientHello with a ticket resumes on the REALITY server and
  gets a full handshake from the target: as a real server would resume its
  own ticket, but a censor who sends the ticket to the real site sees it
  refused. This adds to REALITY's known IP–SNI mismatch rather than opening
  a new hole.

## Not covered yet

- Real sites as targets (pasta is installed for that), and targets that
  send a whole flight in one record (BoringSSL), for which REALITY does not
  resume.
- XHTTP over REALITY; mihomo and sing-box clients.
- A target that restarts with a new ticket key (the server probes again
  hourly).
