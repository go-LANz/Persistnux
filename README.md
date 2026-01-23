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

## Persistence Mechanisms Detected

### 1. Systemd Services
- Service files in `/etc/systemd/system`, `/lib/systemd/system`, `/usr/lib/systemd/system`
- User-level systemd services
- Timer units
- Socket activation units
- Detects suspicious ExecStart commands

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

### 4. SSH Persistence
- SSH authorized_keys for all users
- User SSH configurations (`~/.ssh/config`)
- System SSH daemon configuration (`/etc/ssh/sshd_config`)
- Suspicious SSH forwarding and proxy configurations

### 5. Init Scripts & RC.local
- `/etc/rc.local` and variants
- SysV init scripts (`/etc/init.d`)
- Runlevel scripts (`/etc/rc*.d`)
- Detects suspicious download/execution commands

### 6. Kernel Modules & Library Preloading
- LD_PRELOAD configurations (`/etc/ld.so.preload`)
- Dynamic linker configurations
- Loaded kernel modules (enumeration)
- Kernel module auto-load configs (`/etc/modules`, `/etc/modules-load.d`)

### 7. Additional Mechanisms
- XDG autostart entries (`.config/autostart`, `/etc/xdg/autostart`)
- System environment files (`/etc/environment`)
- Sudoers configurations and drop-ins
- PAM (Pluggable Authentication Modules) configurations
- MOTD (Message of the Day) scripts

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
# Run with root privileges (recommended for complete analysis)
sudo ./persistnux.sh

# Run as regular user (limited scope)
./persistnux.sh
```

### Custom Output Directory

```bash
# Specify custom output directory
OUTPUT_DIR=/path/to/output sudo ./persistnux.sh
```

### Output Files

By default, Persistnux creates an output directory `./persistnux_output/` containing:

- `persistnux_<hostname>_<timestamp>.csv` - CSV format report
- `persistnux_<hostname>_<timestamp>.jsonl` - JSONL format report (one JSON object per line)

## Output Format

### CSV Format

```csv
timestamp,category,subcategory,persistence_type,location,description,confidence,sha256,metadata,additional_info
2026-01-23T10:30:00Z,Systemd,Service,systemd_service,/etc/systemd/system/example.service,"Service: example.service | Status: enabled | ExecStart: /usr/bin/example",HIGH,abc123...,mode:644|owner:root:root|size:256|...,enabled=enabled
```

### JSONL Format

```json
{"timestamp":"2026-01-23T10:30:00Z","hostname":"webserver01","category":"Systemd","subcategory":"Service","persistence_type":"systemd_service","location":"/etc/systemd/system/example.service","description":"Service: example.service | Status: enabled | ExecStart: /usr/bin/example","confidence":"HIGH","sha256":"abc123...","metadata":"mode:644|owner:root:root|size:256|...","additional_info":"enabled=enabled"}
```

## Confidence Scoring

- **LOW**: Standard system configuration, low suspicion
- **MEDIUM**: Potentially suspicious but could be legitimate
- **HIGH**: Suspicious patterns detected (e.g., curl/wget in cron, /tmp execution)
- **CRITICAL**: Highly suspicious, likely malicious (reserved for future advanced detection)

## Suspicious Indicators

Persistnux automatically flags items with higher confidence when it detects:

- Download tools: `curl`, `wget`
- Network tools: `nc`, `netcat`
- Execution from temporary directories: `/tmp`, `/dev/shm`
- Encoding/obfuscation: `base64`, `eval`
- Permission modifications: `chmod +x`
- Suspicious shell invocations: `bash -c`, `sh -c`

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
