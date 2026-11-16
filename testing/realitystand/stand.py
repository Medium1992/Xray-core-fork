#!/usr/bin/env python3
"""REALITY session resumption stand.

Run as `unshare -Urnm python3 stand.py <scenario>...` (root of a new user,
network and mount namespace, no real root needed). Two network namespaces:

  cli 10.9.0.1  --veth--  srv 10.9.0.2..
                                .11 nginx  .12 caddy  .13 haproxy      (targets)
                                .21-.23 REALITY, new build, target .11-.13
                                .31-.33 REALITY, old build, target .11-.13
                                .50 plain HTTP behind the proxies

Every scenario writes runs/<stamp>/<scenario>/: capture.pcap (taken on the
client's side of the veth: what a censor sees), keylog (TLS secrets of the
clients), meta.json, and logs. analyze.py reads them.
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import time

S = os.environ.get("STAND_WORK") or os.path.expanduser("~/.cache/realitystand")
CODE = os.path.dirname(os.path.abspath(__file__))
R = S + "/root"
ENV = dict(os.environ)
ENV["PATH"] = f"{S}/bin:{R}/usr/sbin:{R}/usr/bin:{R}/sbin:" + ENV.get("PATH", "")
ENV["LD_LIBRARY_PATH"] = f"{R}/usr/lib/x86_64-linux-gnu:{R}/lib/x86_64-linux-gnu:{R}/usr/lib"

TARGETS = {"nginx": "10.9.0.11", "caddy": "10.9.0.12", "haproxy": "10.9.0.13"}
# targets only REALITY uses, not the browser references
EXTRA_TARGETS = {"nginxshort": "10.9.0.14"}  # tickets live 8 s
NEW_SERVER = {"nginx": "10.9.0.21", "caddy": "10.9.0.22", "haproxy": "10.9.0.23", "nginxshort": "10.9.0.24"}
LB = "10.9.0.40"  # HAProxy in TCP mode, round robin over the new and the old server for nginx
OLD_SERVER = {"nginx": "10.9.0.31", "caddy": "10.9.0.32", "haproxy": "10.9.0.33"}
HTTP = "10.9.0.50"
UUID = "4594f501-ab51-49d1-b3da-01435d922c4c"
PRIVATE_KEY = "4OhcQP9U1nW0dPjI2RNQSOADXBdW0LLuvgBrYrLFy0A"
PUBLIC_KEY = "Mb8smvtzEq99MlGhrlulWKEWaC2JgU_pRsyNsCQFEF8"
SHORT_ID = "0123456789abcdef"

procs = []  # (name, Popen), stopped by pid, never by name: pkill sees the host
captures = []  # tcpdump processes


def sh(cmd, check=True, **kw):
    return subprocess.run(cmd, shell=True, check=check, env=ENV, **kw)


def start(name, cmd, log):
    p = subprocess.Popen(cmd, shell=True, env=ENV, stdout=open(log, "wb"),
                         stderr=subprocess.STDOUT, start_new_session=True)
    procs.append((name, p))
    return p


def stop(p, sig=signal.SIGTERM, wait=5):
    if p.poll() is None:
        try:
            os.killpg(p.pid, sig)
        except ProcessLookupError:
            return
        try:
            p.wait(wait)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()


def stop_all():
    for _, p in reversed(procs):
        stop(p)
    procs.clear()
    for p in captures:
        p.kill()
        p.wait()
    captures.clear()


def wait_port(ns, ip, port, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(f"ip netns exec {ns} python3 -c \"import socket;socket.create_connection(('{ip}',{port}),1)\"",
                           shell=True, env=ENV, capture_output=True)
        if r.returncode == 0:
            return
        time.sleep(0.2)
    raise RuntimeError(f"{ip}:{port} did not come up")


def topology():
    sh("mount -t tmpfs none /run && mkdir -p /run/netns")
    hosts = f"{S}/runs/hosts"
    with open(hosts, "w") as f:
        f.write("127.0.0.1 localhost\n")
        for name, ip in TARGETS.items():
            f.write(f"{ip} {name}.example.test\n")
    sh(f"mount --bind {hosts} /etc/hosts")
    sh("ip netns add cli && ip netns add srv")
    sh("ip link add vc type veth peer name vs && ip link set vc netns cli && ip link set vs netns srv")
    sh("ip -n cli addr add 10.9.0.1/24 dev vc && ip -n cli link set vc up && ip -n cli link set lo up")
    sh("ip -n srv addr add 10.9.0.2/24 dev vs && ip -n srv link set vs up && ip -n srv link set lo up")
    for ip in list(TARGETS.values()) + list(EXTRA_TARGETS.values()) + list(NEW_SERVER.values()) + list(OLD_SERVER.values()) + [HTTP, LB]:
        sh(f"ip -n srv addr add {ip}/32 dev vs")
    sh("ip -n cli route add 10.9.0.0/24 dev vc 2>/dev/null || true")
    rtt = int(os.environ.get("RTT_MS", "60"))
    if rtt:
        # half the round trip each way, on both ends of the veth
        sh(f"ip netns exec cli /usr/sbin/tc qdisc add dev vc root netem delay {rtt // 2}ms")
        sh(f"ip netns exec srv /usr/sbin/tc qdisc add dev vs root netem delay {rtt // 2}ms")


def start_targets(run):
    os.makedirs(f"{S}/runs/nginx-tmp", exist_ok=True)
    start("nginx", f"ip netns exec srv nginx -c {S}/conf/nginx.conf -g 'daemon off;'", f"{run}/nginx.log")
    start("caddy", f"ip netns exec srv env HOME={S}/runs XDG_DATA_HOME={S}/runs/caddy caddy run --config {S}/conf/Caddyfile --adapter caddyfile", f"{run}/caddy.log")
    start("haproxy", f"ip netns exec srv haproxy -f {S}/conf/haproxy.cfg", f"{run}/haproxy.log")
    start("http", f"ip netns exec srv python3 -m http.server --bind {HTTP} 80 --directory {S}/www", f"{run}/http.log")
    for ip in TARGETS.values():
        wait_port("srv", ip, 443)
    wait_port("srv", HTTP, 80)


def server_config(binary_servers):
    inbounds = []
    for name, ip in binary_servers.items():
        inbounds.append({
            "listen": ip, "port": 443, "protocol": "vless", "tag": f"in-{name}",
            "settings": {"clients": [{"id": UUID, "flow": "xtls-rprx-vision"}], "decryption": "none"},
            "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                "target": f"{ {**TARGETS, **EXTRA_TARGETS}[name]}:443", "serverNames": [f"{name}.example.test"],
                "privateKey": PRIVATE_KEY, "shortIds": [SHORT_ID]}},
        })
    return {"log": {"loglevel": "warning"}, "inbounds": inbounds,
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}


def start_servers(run, old=True):
    with open(f"{run}/server-new.json", "w") as f:
        json.dump(server_config(NEW_SERVER), f, indent=1)
    start("server-new", f"ip netns exec srv env SSL_CERT_FILE={S}/certs/ca.pem xray-new run -c {run}/server-new.json", f"{run}/server-new.log")
    if old:
        with open(f"{run}/server-old.json", "w") as f:
            json.dump(server_config(OLD_SERVER), f, indent=1)
        start("server-old", f"ip netns exec srv env SSL_CERT_FILE={S}/certs/ca.pem xray-old run -c {run}/server-old.json", f"{run}/server-old.log")
    for ip in NEW_SERVER.values():
        wait_port("srv", ip, 443)
    if old:
        for ip in OLD_SERVER.values():
            wait_port("srv", ip, 443)
    # REALITY probes the targets when it starts; let it finish.
    time.sleep(12)


def client_config(server_ip, target, fingerprint, browser, keylog, port=1080):
    reality = {"fingerprint": fingerprint, "serverName": f"{target}.example.test",
               "password": PUBLIC_KEY, "shortId": SHORT_ID, "masterKeyLog": keylog}
    if browser:
        reality["browser"] = browser
    return {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": server_ip, "port": 443,
                           "users": [{"id": UUID, "flow": "xtls-rprx-vision", "encryption": "none"}]}]},
                           "streamSettings": {"network": "raw", "security": "reality", "realitySettings": reality}}]}


class Capture:
    """tcpdump on the client's side of the veth. Started without a shell and
    stopped by its own pid, so that it really stops."""

    def __init__(self, path):
        self.p = subprocess.Popen(["ip", "netns", "exec", "cli", "tcpdump", "-Z", "root", "-i", "vc", "-U",
                                   "-w", "-", "tcp port 443"], env=ENV, stdout=open(path, "wb"),
                                  stderr=subprocess.DEVNULL)
        captures.append(self.p)
        time.sleep(1)

    def close(self):
        time.sleep(1)
        self.p.terminate()
        try:
            self.p.wait(5)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()
        captures.remove(self.p)


def scenario_dir(run, name):
    d = f"{run}/{name}"
    os.makedirs(d, exist_ok=True)
    return d


def xray_client(run, name, binary, server_ip, target, fingerprint, browser, dials, pause=1.0, pauses=None):
    """dials connections through an Xray client, each a new REALITY connection."""
    d = scenario_dir(run, name)
    keylog = f"{d}/keylog"
    with open(f"{d}/client.json", "w") as f:
        json.dump(client_config(server_ip, target, fingerprint, browser, keylog), f, indent=1)
    cap = Capture(f"{d}/capture.pcap")
    client = start(f"client-{name}", f"ip netns exec cli {binary} run -c {d}/client.json", f"{d}/client.log")
    wait_port("cli", "127.0.0.1", 1080)
    results = []
    for i in range(dials):
        r = subprocess.run(f"ip netns exec cli curl -s -o /dev/null -w '%{{http_code}}' --max-time 10 "
                           f"--socks5-hostname 127.0.0.1:1080 http://{HTTP}/index.html?{i}",
                           shell=True, env=ENV, capture_output=True, text=True)
        results.append(r.stdout)
        time.sleep(pauses[i] if pauses else pause)
    stop(client)
    procs.remove((f"client-{name}", client))
    cap.close()
    meta = {"kind": "xray", "binary": binary, "server": server_ip, "target": target,
            "fingerprint": fingerprint, "browser": browser, "http": results}
    with open(f"{d}/meta.json", "w") as f:
        json.dump(meta, f, indent=1)
    return meta


PAGE_HOSTS = {"nginx": "nginx.example.test", "caddy": "caddy.example.test", "haproxy": "haproxy.example.test"}


def chrome(run, name, target):
    d = scenario_dir(run, name)
    home = f"{d}/home"
    os.makedirs(f"{home}/.pki/nssdb", exist_ok=True)
    sh(f"certutil -d sql:{home}/.pki/nssdb -N --empty-password && "
       f"certutil -d sql:{home}/.pki/nssdb -A -t 'C,,' -n standca -i {S}/certs/ca.pem")
    cap = Capture(f"{d}/capture.pcap")
    p = start(f"chrome-{name}", f"ip netns exec cli env HOME={home} SSLKEYLOGFILE={d}/keylog "
              f"{R}/opt/google/chrome/chrome --headless=new --no-sandbox --disable-gpu --no-first-run "
              f"--disable-background-networking --disable-component-update --disable-sync "
              f"--user-data-dir={home}/profile https://{PAGE_HOSTS[target]}/page.html", f"{d}/chrome.log")
    time.sleep(12)
    stop(p)
    procs.remove((f"chrome-{name}", p))
    cap.close()
    with open(f"{d}/meta.json", "w") as f:
        json.dump({"kind": "chrome", "target": target}, f, indent=1)


def firefox(run, name, target):
    d = scenario_dir(run, name)
    profile = f"{d}/profile"
    os.makedirs(profile, exist_ok=True)
    sh(f"certutil -d sql:{profile} -N --empty-password && "
       f"certutil -d sql:{profile} -A -t 'C,,' -n standca -i {S}/certs/ca.pem")
    with open(f"{profile}/user.js", "w") as f:
        for k, v in {"browser.shell.checkDefaultBrowser": False, "datareporting.policy.dataSubmissionEnabled": False,
                     "toolkit.telemetry.enabled": False, "app.update.enabled": False,
                     "network.captive-portal-service.enabled": False, "network.connectivity-service.enabled": False,
                     "browser.safebrowsing.malware.enabled": False, "browser.safebrowsing.phishing.enabled": False,
                     "extensions.update.enabled": False, "browser.startup.homepage_override.mstone": "ignore"}.items():
            f.write(f"user_pref({json.dumps(k)}, {json.dumps(v)});\n")
    cap = Capture(f"{d}/capture.pcap")
    p = start(f"firefox-{name}", f"ip netns exec cli env HOME={d} SSLKEYLOGFILE={d}/keylog MOZ_DISABLE_CONTENT_SANDBOX=1 "
              f"firefox --headless --no-remote --profile {profile} https://{PAGE_HOSTS[target]}/page.html",
              f"{d}/firefox.log")
    time.sleep(14)
    stop(p)
    procs.remove((f"firefox-{name}", p))
    cap.close()
    with open(f"{d}/meta.json", "w") as f:
        json.dump({"kind": "firefox", "target": target}, f, indent=1)


REPLAY = r"""
import socket, struct, sys, json
def records(addr, hello):
    s = socket.create_connection((addr, 443), 5)
    s.sendall(hello)
    s.settimeout(2)
    data = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
    except Exception:
        pass
    s.close()
    out = []
    while len(data) >= 5:
        n = 5 + struct.unpack(">H", data[3:5])[0]
        out.append([data[0], n])
        data = data[n:]
    return out
hello = open(sys.argv[1], "rb").read()
print(json.dumps({a: records(a, hello) for a in sys.argv[2:]}))
"""


def replay_probe(run, name, source):
    """A censor replays a client's ClientHello that offers a ticket, to the
    REALITY server and to the target, and compares the answers."""
    d = scenario_dir(run, name)
    if source is None:
        source = f"{run}/edge-replay-source"
        xray_client(run, "edge-replay-source", "xray-new", NEW_SERVER["nginx"], "nginx", "chrome", "auto", 2)
    out = subprocess.run(f"tshark -r {source}/capture.pcap -Y 'tls.handshake.extensions.psk.identities.length' "
                         f"-T fields -e tcp.stream", shell=True, env=ENV, capture_output=True, text=True).stdout.split()
    if not out:
        with open(f"{d}/meta.json", "w") as f:
            json.dump({"kind": "replay", "error": "no ClientHello with a ticket"}, f)
        return
    raw = subprocess.run(f"tshark -r {source}/capture.pcap -q -z follow,tcp,raw,{out[0]}", shell=True, env=ENV,
                         capture_output=True, text=True).stdout
    client = b"".join(bytes.fromhex(l.strip()) for l in raw.splitlines()
                      if l and not l.startswith(("	", "=", "Follow", "Filter", "Node")) and all(c in "0123456789abcdef" for c in l.strip()))
    n = 5 + int.from_bytes(client[3:5], "big")
    with open(f"{d}/hello.bin", "wb") as f:
        f.write(client[:n])
    with open(f"{d}/replay.py", "w") as f:
        f.write(REPLAY)
    cap = Capture(f"{d}/capture.pcap")
    r = subprocess.run(f"ip netns exec cli python3 {d}/replay.py {d}/hello.bin {NEW_SERVER['nginx']} {TARGETS['nginx']}",
                       shell=True, env=ENV, capture_output=True, text=True)
    cap.close()
    with open(f"{d}/meta.json", "w") as f:
        json.dump({"kind": "replay", "answers": json.loads(r.stdout or "{}"), "stderr": r.stderr[-500:]}, f, indent=1)


def render():
    """Configs and the page, from the templates next to this script."""
    os.makedirs(f"{S}/conf", exist_ok=True)
    os.makedirs(f"{S}/www", exist_ok=True)
    for name in os.listdir(f"{CODE}/conf"):
        with open(f"{CODE}/conf/{name}") as f:
            text = f.read().replace("@WORK@", S)
        with open(f"{S}/conf/{name.removesuffix('.in')}", "w") as f:
            f.write(text)
    shutil.copy(f"{CODE}/www/page.html", f"{S}/www/page.html")


def main():
    render()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    run = f"{S}/runs/{stamp}"
    os.makedirs(run)
    with open(f"{run}/run.json", "w") as f:
        json.dump({"rtt_ms": int(os.environ.get("RTT_MS", "60")), "args": sys.argv[1:]}, f)
    wanted = sys.argv[1:] or ["browsers", "xray"]
    topology()
    try:
        start_targets(run)
        if "browsers" in wanted:
            for target in TARGETS:
                chrome(run, f"chrome-{target}", target)
                firefox(run, f"firefox-{target}", target)
        if "xray" in wanted or "compat" in wanted or "edge" in wanted:
            start_servers(run, old="compat" in wanted or "edge" in wanted)
        if "xray" in wanted:
            for target in TARGETS:
                for fp in ("chrome", "firefox"):
                    xray_client(run, f"xray-{fp}-{target}", "xray-new", NEW_SERVER[target], target, fp, "auto", 4)
                xray_client(run, f"xray-off-{target}", "xray-new", NEW_SERVER[target], target, "chrome", "", 3)
        if "edge" in wanted:
            # The ticket from the first connection expires during the pause.
            xray_client(run, "edge-expiry", "xray-new", NEW_SERVER["nginxshort"], "nginxshort", "chrome", "auto", 4,
                        pauses=[1, 10, 1, 1])
            lb = start("lb", f"ip netns exec srv haproxy -f {S}/conf/lb.cfg", f"{run}/lb.log")
            wait_port("srv", LB, 443)
            xray_client(run, "edge-mixed-cluster", "xray-new", LB, "nginx", "chrome", "auto", 8)
            stop(lb)
            procs.remove(("lb", lb))
            replay_probe(run, "edge-replay", f"{run}/xray-chrome-nginx" if os.path.isdir(f"{run}/xray-chrome-nginx") else None)
        if "compat" in wanted:
            t = "nginx"
            xray_client(run, "compat-old-client-new-server", "xray-old", NEW_SERVER[t], t, "chrome", "", 3)
            xray_client(run, "compat-new-client-old-server", "xray-new", OLD_SERVER[t], t, "chrome", "auto", 3)
            xray_client(run, "compat-old-client-old-server", "xray-old", OLD_SERVER[t], t, "chrome", "", 3)
    finally:
        stop_all()
    print(run)


if __name__ == "__main__":
    main()
