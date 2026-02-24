# RootScope — Architecture

## Overview

RootScope is a modular Linux privilege escalation enumeration toolkit built in Bash. It follows a layered architecture with clear separation between enumeration modules, intelligence databases, scoring/analysis engines, and report generation.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     main.sh (Controller)                     │
│  CLI Parsing → Config Load → Module Orchestration → Reports │
└─────────┬───────────┬───────────┬───────────┬───────────────┘
          │           │           │           │
    ┌─────▼─────┐ ┌───▼───┐ ┌────▼────┐ ┌────▼────┐
    │  Modules  │ │Engine │ │ Plugins │ │  Utils  │
    │  (enum)   │ │(score)│ │ (ext)   │ │ (core)  │
    └─────┬─────┘ └───┬───┘ └─────────┘ └─────────┘
          │           │
    ┌─────▼───────────▼─────┐
    │  Intelligence DBs     │
    │  (GTFOBins, Kernel,   │
    │   Capabilities, SUID) │
    └───────────────────────┘
```

## Component Layers

### 1. Controller (`main.sh`)
- CLI argument parsing with `--modules`, `--stealth`, `--jobs`, etc.
- Config loading from `config/settings.conf` and `config/risk_weights.conf`
- Module discovery, resolution, and execution (parallel or sequential)
- Plugin auto-loading from `plugins/`
- Signal handling for graceful shutdown
- Output pipeline orchestration

### 2. Utility Layer (`utils/`)
| File | Purpose |
|------|---------|
| `colors.sh` | ANSI color codes, severity tags, structural print helpers |
| `logger.sh` | Timestamped leveled logging (DEBUG/INFO/WARN/ERROR) |
| `helpers.sh` | Command checks, OS fingerprinting, safe file reads, parallel engine, finding builders |

### 3. Engine Layer (`engine/`)
| File | Purpose |
|------|---------|
| `risk_engine.sh` | Weighted severity scoring, aggregation, risk classification |
| `exploit_suggester.sh` | Cross-references findings against intelligence DBs |
| `parser.sh` | Finding registration, report generation (TXT/JSON/HTML) |

### 4. Enumeration Modules (`modules/`)
Each module sources utilities and engine, then emits structured findings.

| Module | Entry Function | Checks |
|--------|---------------|--------|
| `system/sys_info.sh` | `run_system_enum` | OS, kernel, users, sudo, cron, env, PATH |
| `filesystem/fs_enum.sh` | `run_filesystem_enum` | SUID, SGID, capabilities, world-writable, sensitive perms |
| `services/svc_enum.sh` | `run_services_enum` | Running services, systemd units, init.d, config perms |
| `network/net_enum.sh` | `run_network_enum` | Ports, connections, firewall, DNS, NFS |
| `credentials/cred_enum.sh` | `run_credentials_enum` | SSH keys, history, .env, cloud tokens, config creds |
| `container/container_enum.sh` | `run_container_enum` | Docker, Podman, LXC, K8s, cgroup escapes |
| `software/sw_enum.sh` | `run_software_enum` | Packages, compilers, interpreters, vuln versions |

### 5. Intelligence Databases (`intelligence/`)
Pipe-delimited flat files for offline cross-referencing:
- `gtfobins.db` — Binary exploitation techniques (SUID, sudo, caps)
- `kernel_exploits.db` — Kernel version-to-CVE mapping
- `capability_exploits.db` — Linux capability abuse techniques
- `suid_whitelist.db` — Known-safe SUID binaries (noise filter)

### 6. Plugin System (`plugins/`)
- Plugins define `PLUGIN_NAME`, `PLUGIN_DESCRIPTION`, and `run_plugin()`
- Auto-loaded from `plugins/custom_checks/` when `AUTOLOAD_PLUGINS=1`
- Stealth plugin loaded first when `--stealth` flag is used

## Data Flow

```
Module Execution → emit_finding() → register_finding() → PARSED_FINDINGS[]
                                          ↓
                                   risk_record_finding()
                                          ↓
                               RISK_FINDING_COUNTS[] + RISK_TOTAL_SCORE
                                          ↓
                              generate_all_reports() → TXT / JSON / HTML
```

## Finding Record Format

```
FINDING|timestamp|severity|module|category|detail|hint
```

## Severity Levels

| Level | Weight | Color | Meaning |
|-------|--------|-------|---------|
| CRITICAL | 100 | White on Red | Immediate root shell possible |
| HIGH | 75 | Bright Red | Strong escalation vector |
| MEDIUM | 40 | Yellow | Potential vector requiring conditions |
| LOW | 15 | Cyan | Informational but noteworthy |
| INFO | 5 | Gray | Context information |
