# port-scanner

🇫🇷 [Version française](README.fr.md)

An **asynchronous**, **secure-by-default** TCP port scanner with a **detection side**
(Blue Team): learn how to scan, then how to spot a scan in network traffic.

> 🚧 **Work in progress** (v0.1.0 — scaffold). Scanning is not available yet.

## ⚖️ Legal notice — read before use

Only use this tool on machines and networks you own, or for which you hold the owner's
**written authorisation**.

Unauthorised scanning may be unlawful depending on your jurisdiction (in France, articles 323-1
and 323-3-1 of the Penal Code cover unauthorised access to information systems and possession of
tools designed for it without a legitimate reason) and usually breaches your ISP's or cloud
provider's terms of service.

This is why the tool will **refuse by default** any target that is neither private (RFC 1918)
nor loopback: an explicit option will be required to lift this safeguard.

## Roadmap

| Step | Content | Status |
|---|---|---|
| 1 | Repository, layout, continuous integration | ✅ |
| 2 | Target and port parsing, private-network safeguard | ✅ |
| 3 | Asynchronous TCP connect scan (asyncio), bounded concurrency | ✅ |
| 4 | Service identification, risk level, optional banner grabbing | ✅ |
| 5 | Full CLI, JSON/CSV output, exit codes | ✅ |
| 6 | Tests against local servers, docs, hardening → **v1.0.0** | ⏳ |
| 7 | Detection side: Wireshark capture, Suricata rule and Sigma rule | ⏳ |
| 8 | Local web UI (v1.1, optional) | ⏳ |

## Development

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest -v
port-scanner --version
```

## License

[MIT](LICENSE) © Aïcha Imène Dahoumane
