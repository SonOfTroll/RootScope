# RootScope

**Linux Privilege Escalation Enumeration Toolkit**

A modular, production-grade Bash toolkit for Linux privilege escalation enumeration with risk scoring, exploit suggestion, plugin extensibility, and multi-format reporting.

---

## Features

- **7 Enumeration Modules:** System, Filesystem, Services, Network, Credentials, Container, Software
- **Intelligence Databases:** GTFOBins mapping, kernel exploit suggestions, capability exploits, SUID whitelist
- **Risk Scoring Engine:** Weighted severity scoring with configurable thresholds
- **Exploit Suggestion Engine:** Cross-references findings against intelligence DBs with actionable hints
- **Multi-Format Reporting:** Text, JSON, and HTML dashboard reports
- **Plugin Architecture:** Auto-loading custom checks with simple API contract
- **Parallel Execution:** Configurable worker pool for faster scans
- **Stealth Mode:** Minimal forensic footprint for sensitive environments
- **Context-Aware:** Adapts checks based on detected environment (container, cloud, etc.)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/youruser/RootScope.git
cd RootScope

# Run a full scan
chmod +x main.sh
./main.sh

# Run specific modules
./main.sh --modules system,filesystem

# Stealth mode with JSON output only
./main.sh --stealth --quiet --format json
```

## Architecture

```
RootScope/
├── main.sh                  # Main controller
├── config/                  # Runtime settings & risk weights
├── modules/                 # 7 enumeration modules
│   ├── system/              # OS, kernel, users, sudo, cron
│   ├── filesystem/          # SUID, capabilities, permissions
│   ├── services/            # Systemd, init.d, running services
│   ├── network/             # Ports, firewall, NFS, DNS
│   ├── credentials/         # SSH keys, history, cloud tokens
│   ├── container/           # Docker, LXC, K8s, cgroup
│   └── software/            # Packages, compilers, CVE checks
├── intelligence/            # GTFOBins, kernel exploits, caps DB
├── engine/                  # Risk scoring, exploit suggestion, parser
├── plugins/                 # Auto-loading custom checks
├── utils/                   # Colors, logger, helpers
├── output/                  # Generated reports
├── tests/                   # Test environment scripts
└── docs/                    # Architecture & usage docs
```

## Severity Levels

| Level | Description |
|-------|-------------|
| **CRITICAL** | Immediate root shell possible |
| **HIGH** | Strong escalation vector |
| **MEDIUM** | Potential vector requiring conditions |
| **LOW** | Informational but noteworthy |
| **INFO** | Context information |

## Documentation

- [Architecture Guide](docs/architecture.md)
- [Usage Guide](docs/usage.md)

## Requirements

- Bash 4.0+
- Standard Linux coreutils
- Optional: `getcap`, `ss`/`netstat`, `systemctl`

## Disclaimer

> **This tool is designed for authorized security assessments and educational purposes only.**
> Always obtain proper authorization before running enumeration tools on any system.
> The authors are not responsible for misuse.

## License

MIT License — see [LICENSE](LICENSE) for details.
