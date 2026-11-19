# fpp-plugin-ipscan

An IP scanner for FPP 9.x and 10.x. It scans a range of addresses and lists everything that answers:

- ping time, hostname (reverse DNS), MAC address and vendor
- open TCP ports (default `22,80,443,4048,8080`)
- **device type, name and version** for FPP, WLED, Falcon, ESPixelStick, Tasmota, ESPHome, Kulp, Genius, HinksPix, SanDevices, AlphaPix, Experience Lights, PixLite, openHAB, Home Assistant, OctoPrint/Klipper and others (found from the web page)

Standard library Python 3 only: nothing to pip install and nothing to compile.

## Web page

**Status/Control → IP Scanner.** Pick one of the box's networks (or type a range), press **Scan**, and results fill in as they are found. You can sort by any column, filter, show only lighting controllers, click an IP to open its web page, and **Download CSV**.

## Command line

The flags follow Angry IP Scanner's:

```bash
ipscan -f:range 192.168.1.1 192.168.1.254 -s -q -o results.csv
ipscan -f:cidr 192.168.1.0/24 -o results.json
ipscan -f:file hosts.txt -o results.txt -a
```

| Option | Meaning |
|---|---|
| `-f:range START END` / `-f:cidr NET/BITS` / `-f:file PATH` | what to scan (the file can hold IPs and CIDRs) |
| `-o FILE` | save results; the extension sets the format: `.csv` (default), `.json`, `.txt` |
| `-a` | append to the `-o` file |
| `-q` | quiet, nothing printed |
| `-s` | accepted for compatibility (the scan always starts immediately) |
| `--all` | include dead hosts in the output |
| `--ports 22,80` | TCP ports to try |
| `--timeout 1.0` | seconds per probe |
| `--threads 64` | hosts scanned at once |
| `--no-dns` | skip hostname lookups |

The installer links `ipscan` into `/usr/local/bin`. Otherwise run it as
`/home/fpp/media/plugins/fpp-plugin-ipscan/scripts/ipscan.py`.

## API

Under `/api/plugin/fpp-plugin-ipscan/`:

| Method | Endpoint | |
|---|---|---|
| GET | `defaults` | suggested range for each network on the box |
| POST | `scan` | `{"start":"192.168.1.1","end":"192.168.1.254"}` or `{"cidr":"192.168.1.0/24"}`; optional `ports`, `timeout`, `dns` |
| GET | `status` | progress and the hosts found so far |
| POST | `stop` | stop the running scan |
| GET | `results.csv` / `results.json` | last scan |

```bash
curl -X POST -H 'Content-Type: application/json' \
     -d '{"start":"192.168.1.1","end":"192.168.1.254"}' \
     http://fpp.local/api/plugin/fpp-plugin-ipscan/scan
```

The web page and API allow up to 4096 addresses per scan; the command line has no such cap. Results are saved in `media/plugindata/fpp-plugin-ipscan/`.

## Notes

- A host counts as up if it answers ping **or** any of the TCP ports (accepted or refused), so devices that block ICMP still show up.
- MAC addresses come from the ARP table, so they only appear for hosts on the same subnet as the FPP box.
- To see full vendor names instead of the built-in short list (Raspberry Pi, Espressif), install `ieee-data` (`sudo apt install ieee-data`).
