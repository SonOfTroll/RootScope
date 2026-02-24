# RootScope — Usage Guide

## Installation

```bash
git clone https://github.com/youruser/RootScope.git
cd RootScope
chmod +x main.sh
```

No dependencies required beyond a standard Linux Bash 4+ environment.

## Quick Start

```bash
# Full scan with all modules (default)
./main.sh

# Run specific modules only
./main.sh --modules system,filesystem

# Stealth mode (no disk writes)
./main.sh --stealth --quiet --format json

# Verbose debug output
./main.sh --verbose

# Sequential execution with HIGH+ severity filter
./main.sh --jobs 0 --severity HIGH
```

## CLI Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--modules LIST` | `-m` | Comma-separated module names | `all` |
| `--output DIR` | `-o` | Output directory path | `output/` |
| `--format LIST` | `-f` | Report formats: `txt,json,html` | `txt,json,html` |
| `--jobs N` | `-j` | Parallel workers (0 = sequential) | `4` |
| `--stealth` | `-s` | Minimize disk I/O and artifacts | off |
| `--quiet` | `-q` | Suppress terminal findings | off |
| `--verbose` | `-v` | Enable debug logging | off |
| `--severity LVL` | `-S` | Min severity for reports | `INFO` |
| `--no-plugins` | | Disable plugin auto-loading | plugins on |
| `--help` | `-h` | Show help | |

## Available Modules

| Module | Description |
|--------|-------------|
| `system` | OS, kernel, users, sudo, cron, env vars, PATH |
| `filesystem` | SUID/SGID, capabilities, world-writable, sensitive files |
| `services` | Running processes, systemd units, init.d, configs |
| `network` | Ports, connections, firewall, DNS, NFS |
| `credentials` | SSH keys, history files, .env, cloud tokens |
| `container` | Docker, Podman, LXC, Kubernetes, cgroup escapes |
| `software` | Packages, compilers, interpreters, vulnerable versions |

## Configuration

### `config/settings.conf`
Runtime settings: output directory, verbosity, stealth mode, parallel workers, enabled modules, report formats, log level.

### `config/risk_weights.conf`
Severity weights (CRITICAL=100, HIGH=75, etc.) and per-check multipliers for tuning risk scores.

## Output

Reports are generated in `output/reports/`:

| Format | File | Description |
|--------|------|-------------|
| Text | `report.txt` | Human-readable findings by module |
| JSON | `report.json` | Machine-parseable structured data |
| HTML | `report.html` | Interactive dashboard with severity cards |

Raw module output: `output/raw/`
Parsed findings: `output/parsed/findings.dat`

## Writing Plugins

Create a `.sh` file in `plugins/custom_checks/`:

```bash
#!/usr/bin/env bash
PLUGIN_NAME="my_check"
PLUGIN_DESCRIPTION="My custom security check"
PLUGIN_AUTHOR="You"

run_plugin() {
    # Use emit_finding or register_finding
    if can_write /some/sensitive/file; then
        register_finding "CRITICAL" "plugin:${PLUGIN_NAME}" "my_category" \
            "Sensitive file is writable" "Exploitation hint here"
    fi
    return 0
}
```

Plugins are auto-loaded when `AUTOLOAD_PLUGINS=1` (default).

## Test Environment

```bash
# Create dummy vulnerable targets for testing
sudo bash tests/test_env.sh setup

# Run RootScope against test env
./main.sh -v

# Clean up
sudo bash tests/test_env.sh teardown
```
