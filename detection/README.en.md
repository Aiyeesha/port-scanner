# Detection side — spotting a port scan

🇫🇷 [Version française](README.md) · ⬅️ [Back to the project](../README.md)

`port-scanner` teaches how to **scan**; this folder teaches how to **detect a scan**. Port scanning maps
to MITRE ATT&CK **[T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/)**
(Discovery tactic, TA0007), often one of the first steps of an attacker moving laterally.

| Content | Purpose |
|---|---|
| `samples/scan-lab.pcap` | real capture of a `port-scanner` run (101 ports, loopback) |
| `samples/benign.pcap` | normal traffic: 20 web requests |
| `samples/busy.pcap` | very active legitimate client: 60 web requests to a single port |
| `suricata/port-scan.rules` | two Suricata (network IDS) rules |
| `sigma/port_scan_distinct_ports.yml` | Sigma correlation rule (SIEM) |
| `scripts/check_suricata.sh` | replays the captures and checks alerts (run in CI) |

Captures contain lab traffic on `127.0.0.1` only (fake services).

## 1. What the network sees

In `scan-lab.pcap`: **101 SYNs to 101 distinct ports** within milliseconds, **99 RST** replies (closed
ports), and for open ports a full handshake closed immediately by the scanner.

| Indicator | Strength |
|---|---|
| Burst of SYNs from one source | weak — busy clients do it too |
| Burst of RSTs sent back by one host | strong — legitimate clients target **open** services |
| Many **distinct** destination ports from one source | strong — the very definition of a scan |

## 2. Wireshark lab

Install Wireshark with **Npcap** and tick **"Support loopback traffic"**. Open
`samples/scan-lab.pcap` and try these display filters:

| Filter | Expected |
|---|---|
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | 101 packets |
| `tcp.flags.reset == 1` | 99 packets |
| `tcp.port == 2222` | 8 packets, SSH banner visible |

Then **Statistics → Conversations → TCP**. To capture your own scan, select **Adapter for loopback
traffic capture** and run `port-scanner 127.0.0.1 -t 3`.

```bash
# Distinct ports per source (expected: 101 127.0.0.1)
tshark -r scan-lab.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e ip.src -e tcp.dstport | sort -u | cut -f1 | uniq -c
```

## 3. Suricata rules

| SID | Indicator | Priority | Logic |
|---|---|---|---|
| `1000001` | SYN burst from one source | 3 (weak) | ≥ 30 SYN in 10 s, one alert per source and window |
| `1000002` | RST burst from an internal host | 2 | ≥ 30 RST in 10 s from the probed host |

Validated by replaying the captures (Suricata 7.0.3), re-checked in CI on every change:

| Capture | Alerts | Meaning |
|---|---|---|
| `scan-lab.pcap` | 1000001, 1000002 | scan detected |
| `benign.pcap` | none | normal traffic ignored |
| `busy.pcap` | 1000001 only | **known false positive** of rule 1; rule 2 stays silent |

Rule 1 counts SYNs, not **distinct** ports (a Suricata rule cannot), hence its "weak" rating.
Test locally on Linux/WSL: `sudo apt install suricata && bash detection/scripts/check_suricata.sh`.
When deploying, set `HOME_NET` and suppress authorised scanners in `threshold.config`.

## 4. Sigma rule

A non-alerting base rule (firewall event towards an RFC 1918 address) feeds a **`value_count`
correlation**: alert when one `src_ip` reaches **≥ 30 distinct `dst_port` values within one minute**.
Counting distinct ports removes the `busy.pcap` false positive.

```text
# sigma convert -t splunk --without-pipeline (verified with sigma-cli 4.0.0)
dst_ip="10.0.0.0/8" OR dst_ip="172.16.0.0/12" OR dst_ip="192.168.0.0/16"
| bin _time span=1m
| stats dc(dst_port) as value_count by _time src_ip
| search value_count >= 30
```

Field names follow the Sigma `firewall` taxonomy and must be mapped to your own logs (processing pipeline).

## 5. Limitations

Slow scans, distributed scans, short targeted port lists and firewalls that silently DROP all reduce
detection. Defence combines **several indicators** and **several sources** (network IDS, firewall,
host logs).
