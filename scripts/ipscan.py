#!/usr/bin/env python3
"""
ipscan.py - subnet scanner for FPP (Falcon Player).

Command line follows Angry IP Scanner's, so the same habits work:

    ipscan.py -f:range 192.168.1.1 192.168.1.254 -s -q -o results.csv
    ipscan.py -f:cidr 192.168.1.0/24 -o results.csv
    ipscan.py -f:file hosts.txt -o results.csv

For every address it pings, tries a few TCP ports, reads the MAC from the
ARP table, does a reverse DNS lookup and, when a web port is open, asks the
device what it is (FPP, WLED, Falcon, ESPixelStick, Tasmota, ...).

Standard library only, so it runs on any FPP image without pip.
"""

import argparse
import concurrent.futures as cf
import csv
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

DEFAULT_PORTS = [22, 80, 443, 4048, 8080]

CSV_FIELDS = [
    "ip", "status", "ping_ms", "hostname", "mac", "vendor",
    "open_ports", "device_type", "device_name", "version", "details",
]
CSV_HEADERS = [
    "IP", "Status", "Ping (ms)", "Hostname", "MAC", "Vendor",
    "Open Ports", "Device Type", "Device Name", "Version", "Details",
]

# A few prefixes common on show networks, used when no OUI database is
# installed. /usr/share/ieee-data/oui.txt (package ieee-data) or nmap's
# mac-prefixes file is used instead when present.
BUILTIN_OUI = {
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "28CDC1": "Raspberry Pi", "D83ADD": "Raspberry Pi", "2CCF67": "Raspberry Pi",
    "240AC4": "Espressif", "30AEA4": "Espressif", "84F3EB": "Espressif",
    "A4CF12": "Espressif", "5CCF7F": "Espressif", "600194": "Espressif",
    "3C71BF": "Espressif", "246F28": "Espressif", "8CAAB5": "Espressif",
    "ECFABC": "Espressif", "C44F33": "Espressif", "18FE34": "Espressif",
    "BCDDC2": "Espressif", "98F4AB": "Espressif", "483FDA": "Espressif",
    "E8DB84": "Espressif", "7C9EBD": "Espressif",
}


# --------------------------------------------------------------------------
# Target lists
# --------------------------------------------------------------------------

def ip_range(start, end):
    a = int(ipaddress.IPv4Address(start))
    b = int(ipaddress.IPv4Address(end))
    if b < a:
        a, b = b, a
    return [str(ipaddress.IPv4Address(i)) for i in range(a, b + 1)]


def cidr_hosts(cidr):
    net = ipaddress.IPv4Network(cidr, strict=False)
    hosts = list(net.hosts()) or [net.network_address]
    return [str(h) for h in hosts]


def file_hosts(path):
    out = []
    with open(path) as f:
        for line in f:
            for tok in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?", line):
                out.extend(cidr_hosts(tok) if "/" in tok else [tok])
    return out


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

def ping(ip, timeout):
    """Return round-trip ms, or None if no reply."""
    try:
        r = subprocess.run(
            ["ping", "-n", "-c", "1", "-W", str(max(1, int(round(timeout)))), ip],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout + 2, text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    m = re.search(r"time[=<]([\d.]+)", r.stdout)
    return float(m.group(1)) if m else 0.0


def tcp_probe(ip, port, timeout):
    """'open', 'closed' (RST - host is up) or None (no answer)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return "open"
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        return None
    finally:
        s.close()


_dns_pool = cf.ThreadPoolExecutor(max_workers=16)


def reverse_dns(ip, timeout):
    fut = _dns_pool.submit(socket.gethostbyaddr, ip)
    try:
        return fut.result(timeout=timeout)[0]
    except Exception:
        return ""


def arp_table():
    table = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) >= 4 and p[3] != "00:00:00:00:00:00":
                    table[p[0]] = p[3].upper()
    except OSError:
        pass
    return table


def local_macs():
    """MACs of this box's own interfaces, which never show up in ARP."""
    out = {}
    try:
        r = subprocess.run(["ip", "-o", "-4", "addr"], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, text=True)
        for line in r.stdout.splitlines():
            m = re.match(r"\d+:\s+(\S+)\s+inet\s+([\d.]+)", line)
            if not m:
                continue
            iface, ip = m.group(1), m.group(2)
            try:
                with open(f"/sys/class/net/{iface}/address") as f:
                    out[ip] = f.read().strip().upper()
            except OSError:
                pass
    except OSError:
        pass
    return out


def load_oui():
    db = dict(BUILTIN_OUI)
    for path in ("/usr/share/ieee-data/oui.txt", "/usr/share/nmap/nmap-mac-prefixes"):
        try:
            with open(path, errors="ignore") as f:
                for line in f:
                    m = re.match(r"^([0-9A-Fa-f]{6})\s+(?:\(base 16\)\s+)?(.+)$", line.strip())
                    if m:
                        db[m.group(1).upper()] = m.group(2).strip()
        except OSError:
            continue
    return db


def http_get(url, timeout, limit=65536):
    req = urllib.request.Request(url, headers={"User-Agent": "fpp-ipscan/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, dict(r.headers), r.read(limit).decode("utf-8", "replace")


def http_json(url, timeout):
    try:
        status, _, body = http_get(url, timeout)
        if status == 200:
            return json.loads(body)
    except Exception:
        pass
    return None


def identify(ip, port, timeout):
    """Ask a web server what it is. Returns (type, name, version, details)."""
    base = f"http://{ip}" if port == 80 else f"http://{ip}:{port}"

    # FPP
    info = http_json(base + "/api/system/info", timeout)
    if isinstance(info, dict) and ("Platform" in info or "Variant" in info) and "Version" in info:
        details = " ".join(x for x in (info.get("Platform", ""), info.get("Variant", "")) if x)
        mode = info.get("Mode") or info.get("mode_name") or ""
        if mode:
            details += f" ({mode})"
        return "FPP", info.get("HostName", ""), info.get("Version", ""), details.strip()

    # WLED (and WLED forks that keep its JSON API)
    info = http_json(base + "/json/info", timeout)
    if isinstance(info, dict) and "ver" in info and "leds" in info:
        leds = info.get("leds", {})
        count = leds.get("count", "")
        details = f"{info.get('arch', '')} {count} LEDs".strip()
        return info.get("brand", "WLED") or "WLED", info.get("name", ""), info.get("ver", ""), details

    # Anything else: go by the page title / server header.
    try:
        _, headers, body = http_get(base + "/", timeout)
    except Exception:
        return "", "", "", ""
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()
    server = headers.get("Server", "") or headers.get("server", "")
    hay = f"{title} {server} {body[:4000]}".lower()

    known = [
        ("falcon player", "FPP"),
        ("falcon", "Falcon Controller"),
        ("espixelstick", "ESPixelStick"),
        ("tasmota", "Tasmota"),
        ("esphome", "ESPHome"),
        ("kulp", "Kulp Controller"),
        ("genius", "Genius Controller"),
        ("hinkspix", "HinksPix"),
        ("sandevices", "SanDevices"),
        ("e68", "SanDevices"),
        ("alphapix", "AlphaPix"),
        ("experience lights", "Experience Lights"),
        ("pixlite", "PixLite"),
        ("openhab", "openHAB"),
        ("home assistant", "Home Assistant"),
        ("octoprint", "OctoPrint"),
        ("mainsail", "Klipper (Mainsail)"),
        ("fluidd", "Klipper (Fluidd)"),
        ("unifi", "UniFi"),
        ("tp-link", "TP-Link"),
    ]
    dtype = next((label for key, label in known if key in hay), "")

    if dtype == "Tasmota":
        st = http_json(base + "/cm?cmnd=Status%200", timeout)
        if isinstance(st, dict):
            s = st.get("Status", {})
            fw = st.get("StatusFWR", {})
            name = s.get("DeviceName") or (s.get("FriendlyName") or [""])[0]
            return "Tasmota", name, fw.get("Version", ""), title

    details = title
    if server and server.lower() not in title.lower():
        details = f"{title} [{server}]" if title else server
    return dtype or "Web", title, "", details


def scan_host(ip, opts):
    start = time.time()
    rtt = ping(ip, opts.timeout)
    open_ports, alive = [], rtt is not None

    for port in opts.ports:
        r = tcp_probe(ip, port, opts.timeout)
        if r == "open":
            open_ports.append(port)
        if r is not None:
            alive = True

    if not alive:
        return {"ip": ip, "status": "dead"}

    res = {
        "ip": ip, "status": "alive",
        "ping_ms": "" if rtt is None else round(rtt, 1),
        "hostname": "", "mac": "", "vendor": "",
        "open_ports": " ".join(str(p) for p in open_ports),
        "device_type": "", "device_name": "", "version": "", "details": "",
        "scan_s": 0,
    }
    if opts.dns:
        res["hostname"] = reverse_dns(ip, opts.timeout)
    for port in (80, 8080, 443):
        if port in open_ports and port != 443:
            t, n, v, d = identify(ip, port, opts.timeout + 1)
            res.update(device_type=t, device_name=n, version=v, details=d)
            break
    if not res["device_type"] and 443 in open_ports:
        res["device_type"] = "Web (HTTPS)"
    if not res["device_type"] and 22 in open_ports:
        res["device_type"] = "SSH"
    res["scan_s"] = round(time.time() - start, 2)
    return res


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def write_atomic(path, text):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".ipscan-")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o664)
    os.replace(tmp, path)


def write_csv(path, rows, append=False):
    exists = append and os.path.exists(path)
    with open(path, "a" if append else "w", newline="") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(CSV_HEADERS)
        for r in rows:
            w.writerow([r.get(k, "") for k in CSV_FIELDS])


def parse_args(argv):
    # Angry IP Scanner writes the feeder as one token ("-f:range"); turn it
    # into a normal option so argparse can handle it.
    fixed = []
    for a in argv:
        m = re.match(r"^-f:(range|cidr|file)$", a)
        fixed.extend(["--feeder", m.group(1)] if m else [a])

    p = argparse.ArgumentParser(
        prog="ipscan",
        description="Scan a range of IPv4 addresses and report what answers.",
        epilog="Example: ipscan -f:range 192.168.1.1 192.168.1.254 -s -q -o results.csv",
    )
    p.add_argument("--feeder", choices=["range", "cidr", "file"], required=True,
                   help="-f:range START END | -f:cidr NET/BITS | -f:file PATH")
    p.add_argument("targets", nargs="+", help="feeder arguments")
    p.add_argument("-s", action="store_true", help="start immediately (accepted for compatibility)")
    p.add_argument("-q", action="store_true", help="quiet: no progress on the console")
    p.add_argument("-o", metavar="FILE", help="write results to FILE (.csv, .json or .txt)")
    p.add_argument("-a", action="store_true", help="append to the -o file instead of replacing it")
    p.add_argument("--all", action="store_true", help="include dead hosts in the output")
    p.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)),
                   help="TCP ports to try, comma separated (default %(default)s)")
    p.add_argument("--timeout", type=float, default=1.0, help="per-probe timeout in seconds")
    p.add_argument("--threads", type=int, default=64, help="hosts scanned at once")
    p.add_argument("--no-dns", dest="dns", action="store_false", help="skip reverse DNS")
    p.add_argument("--status", metavar="FILE", help="keep a JSON progress file (used by the FPP page)")
    p.add_argument("--max-hosts", type=int, default=65536)
    o = p.parse_args(fixed)

    try:
        if o.feeder == "range":
            if len(o.targets) != 2:
                p.error("-f:range needs START and END")
            o.hosts = ip_range(*o.targets)
        elif o.feeder == "cidr":
            o.hosts = [h for t in o.targets for h in cidr_hosts(t)]
        else:
            o.hosts = [h for t in o.targets for h in file_hosts(t)]
    except (ValueError, OSError) as e:
        p.error(str(e))
    if not o.hosts:
        p.error("no addresses to scan")
    if len(o.hosts) > o.max_hosts:
        p.error(f"{len(o.hosts)} addresses is more than --max-hosts {o.max_hosts}")
    try:
        o.ports = sorted({int(x) for x in o.ports.split(",") if x.strip()})
    except ValueError:
        p.error("--ports must be numbers separated by commas")
    o.threads = max(1, min(o.threads, 256))
    return o


def main(argv=None):
    opts = parse_args(sys.argv[1:] if argv is None else argv)
    total = len(opts.hosts)
    state = {
        "state": "running", "pid": os.getpid(),
        "started": time.time(), "finished": None,
        "range": f"{opts.hosts[0]} - {opts.hosts[-1]}",
        "total": total, "done": 0, "alive": 0, "hosts": [],
    }
    lock = threading.Lock()
    last_write = [0.0]
    stop = threading.Event()

    def save_status(force=False):
        if not opts.status:
            return
        now = time.time()
        if force or now - last_write[0] > 0.5:
            last_write[0] = now
            write_atomic(opts.status, json.dumps(state))

    import signal

    def on_term(*_):
        stop.set()
    signal.signal(signal.SIGTERM, on_term)

    save_status(force=True)
    results = []
    try:
        with cf.ThreadPoolExecutor(max_workers=opts.threads) as pool:
            futs = {pool.submit(scan_host, ip, opts): ip for ip in opts.hosts}
            for fut in cf.as_completed(futs):
                if stop.is_set():
                    for f in futs:
                        f.cancel()
                    break
                try:
                    r = fut.result()
                except Exception as e:
                    r = {"ip": futs[fut], "status": "error", "details": str(e)}
                with lock:
                    state["done"] += 1
                    results.append(r)
                    if r["status"] == "alive":
                        state["alive"] += 1
                        state["hosts"].append(r)
                    save_status()
                if not opts.q:
                    if r["status"] == "alive":
                        print("\r\033[K", end="", file=sys.stderr, flush=True)
                        print(f"\r{r['ip']:<16} {r.get('ping_ms', '')!s:>6}  "
                              f"{r.get('device_type', ''):<18} {r.get('device_name') or r.get('hostname', '')}")
                    print(f"\r  {state['done']}/{total} scanned, {state['alive']} alive",
                          end="", file=sys.stderr, flush=True)
    except KeyboardInterrupt:
        stop.set()

    # MACs come from the kernel's ARP cache, which the pings just filled.
    arp = arp_table()
    arp.update(local_macs())
    oui = load_oui()
    for r in results:
        if r["status"] == "alive":
            mac = arp.get(r["ip"], "")
            r["mac"] = mac
            r["vendor"] = oui.get(mac.replace(":", "")[:6], "") if mac else ""

    def ipkey(r):
        return int(ipaddress.IPv4Address(r["ip"]))
    results.sort(key=ipkey)
    state["hosts"].sort(key=ipkey)
    state["state"] = "stopped" if stop.is_set() else "finished"
    state["finished"] = time.time()
    save_status(force=True)

    out_rows = results if opts.all else [r for r in results if r["status"] == "alive"]
    if opts.o:
        ext = os.path.splitext(opts.o)[1].lower()
        if ext == ".json":
            write_atomic(opts.o, json.dumps(out_rows, indent=2))
        elif ext == ".txt":
            lines = [f"{r['ip']}\t{r.get('hostname', '')}\t{r.get('mac', '')}\t{r.get('device_type', '')}"
                     for r in out_rows]
            with open(opts.o, "a" if opts.a else "w") as f:
                f.write("\n".join(lines) + "\n")
        else:
            write_csv(opts.o, out_rows, append=opts.a)

    if not opts.q:
        secs = state["finished"] - state["started"]
        print(f"\r\033[K{total} addresses scanned in {secs:.1f}s, {state['alive']} alive"
              + (f", saved to {opts.o}" if opts.o else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
