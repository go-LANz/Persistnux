# False Positive Reduction Strategy for Persistnux

## Problem Statement
Current implementation treats ALL persistence mechanisms equally, resulting in:
- Hundreds of legitimate systemd services flagged as MEDIUM
- Standard cron jobs marked suspicious
- Default system configurations causing alert fatigue

## Solution Strategies

### 1. **Whitelist/Baseline Approach**

#### Known-Good Service Patterns
```bash
# Legitimate service prefixes (systemd)
KNOWN_GOOD_SERVICES=(
    "snap."              # Snap packages
    "systemd-"           # Core systemd services
    "dbus-"              # D-Bus services
    "NetworkManager"     # Network management
    "ssh"                # SSH daemon
    "cron"               # Cron daemon
    "rsyslog"            # Logging
    "accounts-daemon"    # User account management
    "upower"             # Power management
    "udisks2"            # Disk management
)

# Legitimate package names (cron.d)
KNOWN_GOOD_CRON=(
    "popularity-contest"
    "e2scrub_all"
    "dpkg"
    "apt-compat"
    "sysstat"
    "anacron"
)
```

#### Package-Installed Files
- Check if file is managed by package manager: `dpkg -S <file>` or `rpm -qf <file>`
- If managed by package → LOW confidence (unless content is suspicious)
- If NOT managed → Higher confidence (manually created)

### 2. **Temporal Anomaly Detection**

#### Installation Date Baseline
```bash
# Get system installation date
INSTALL_DATE=$(stat -c %W / 2>/dev/null || echo "0")

# Files created AFTER installation are more suspicious
# Especially if created recently (< 30 days)
```

#### Age-Based Scoring
- **File age > 1 year** → Likely legitimate (LOW confidence)
- **File age > 6 months** → Probably legitimate (MEDIUM confidence)
- **File age < 30 days** → Potentially suspicious (MEDIUM-HIGH)
- **File age < 7 days** → Very suspicious (HIGH)
- **File age < 24 hours** → Critically suspicious (HIGH-CRITICAL)

### 3. **Content-Based Fingerprinting**

#### Hash-Based Recognition
```bash
# Compare hashes against known-good database
# - Distro-specific package hashes
# - Vendor-signed systemd services
# - Common application services

# Example: systemd services from official packages
KNOWN_GOOD_HASHES=(
    "abc123...=snapd.service"
    "def456...=ssh.service"
)
```

#### Signature Patterns
```bash
# Legitimate patterns (lower suspicion)
LEGITIMATE_PATTERNS=(
    "ExecStart=/usr/bin/"        # Standard binary paths
    "ExecStart=/usr/sbin/"
    "ExecStart=/usr/lib/"
    "User=_"                     # System users (underscore prefix)
    "ProtectSystem=strict"       # Security hardening
    "PrivateTmp=true"
)

# Highly suspicious patterns (raise confidence)
MALICIOUS_PATTERNS=(
    "/tmp/"                      # Temp directory execution
    "/dev/shm/"                  # Shared memory (rootkit favorite)
    "/dev/tcp/"                  # Reverse shell
    "base64.*decode"             # Obfuscation
    "eval.*\$("                  # Dynamic execution
)
```

### 4. **Ownership and Permissions**

#### Suspicious Ownership
```bash
# Files owned by non-root in privileged locations
if [[ "$location" =~ ^/etc/ ]] || [[ "$location" =~ ^/usr/ ]]; then
    if [[ "$owner" != "root" ]]; then
        confidence="HIGH"  # Non-root owning system files = suspicious
    fi
fi
```

#### Suspicious Permissions
```bash
# World-writable files in sensitive locations
if [[ "$mode" =~ (777|666|002) ]]; then
    confidence="HIGH"
fi

# SUID/SGID on unusual binaries
if [[ "$mode" =~ ^[47] ]]; then
    # Check if binary is in known-good SUID list
    if ! is_known_suid "$file"; then
        confidence="HIGH"
    fi
fi
```

### 5. **Context-Aware Scoring**

#### Service Relationships
```bash
# Systemd service with no corresponding package
# More suspicious than service from installed package

# Check if service has .wants/ or .requires/ links
# Orphaned services with no dependencies = suspicious
```

#### User Context
```bash
# System user (UID < 1000) running interactive shells
if [[ $uid -lt 1000 ]] && [[ "$shell" =~ (bash|zsh|sh)$ ]]; then
    confidence="HIGH"
fi

# Root crontab executing as non-root user
# User crontab with root privileges
```

### 6. **Multi-Factor Scoring System**

Instead of binary LOW/MEDIUM/HIGH, use cumulative score:

```bash
score=0

# Base score from file type
[[ -f "/etc/systemd/system/$file" ]] && score+=10

# Age factors
[[ $days_old -lt 7 ]] && score+=30
[[ $days_old -lt 1 ]] && score+=50

# Content factors
check_suspicious_patterns && score+=40
[[ "$content" =~ /dev/tcp ]] && score+=60
[[ "$content" =~ base64 ]] && score+=20

# Package management
is_package_managed || score+=25

# Ownership
[[ "$owner" != "root" ]] && score+=15

# Final confidence
if [[ $score -ge 100 ]]; then
    confidence="CRITICAL"
elif [[ $score -ge 70 ]]; then
    confidence="HIGH"
elif [[ $score -ge 40 ]]; then
    confidence="MEDIUM"
else
    confidence="LOW"
fi
```

### 7. **Vendor/Distribution Signatures**

#### Signed Services
```bash
# Check systemd service for distribution markers
if grep -q "# Provided by:" "$service_file"; then
    confidence="LOW"  # Official service from distro
fi

# Check for Ubuntu/Debian/RHEL specific paths
if [[ "$exec_start" =~ /usr/lib/x86_64-linux-gnu/ ]]; then
    confidence="LOW"  # Standard Debian/Ubuntu path
fi
```

### 8. **Behavioral Anomalies**

#### Network Indicators
```bash
# Hardcoded IP addresses in configs
if [[ "$content" =~ [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} ]]; then
    # Extract IPs and check if:
    # - Private IPs (10.x, 172.16.x, 192.168.x) = less suspicious
    # - Public IPs = more suspicious
    # - Known C2 IPs from threat intel = CRITICAL
fi

# Suspicious domains
if [[ "$content" =~ (pastebin|ngrok|duckdns|no-ip) ]]; then
    score+=50  # Free services often used for C2
fi
```

### 9. **Machine Learning / Statistical Approach**

#### Frequency Analysis
```bash
# How common is this service across systems?
# - Seen on 90%+ of systems = legitimate
# - Seen on <5% of systems = suspicious
# - Unique to this system = very suspicious
```

## Implementation Priority

### Phase 1: Quick Wins (v1.2)
1. ✅ **Package manager checks** - `dpkg -S` / `rpm -qf`
2. ✅ **Known-good service whitelist** - Skip common services
3. ✅ **Enhanced time-based scoring** - Already partially implemented
4. ✅ **Improved pattern matching** - Already implemented

### Phase 2: Enhanced Detection (v1.3)
1. **Cumulative scoring system** - Replace simple confidence levels
2. **Ownership/permissions checks** - Flag unusual ownership
3. **Content fingerprinting** - Hash-based recognition
4. **Network indicator extraction** - Flag IPs/domains in configs

### Phase 3: Advanced (v2.0)
1. **Baseline mode** - Create system baseline for comparison
2. **Distribution signatures** - Vendor-specific validation
3. **Threat intelligence integration** - Check against known IOCs
4. **Machine learning scoring** - Statistical anomaly detection

## Output Improvements

### Add Filtering Options
```bash
# Command line options
--confidence-level=HIGH    # Only show HIGH+ findings
--exclude-packaged        # Skip package-managed files
--recent-only             # Only files modified in last N days
--show-scores             # Display numeric scores
```

### Enhanced Output Fields
```csv
timestamp,category,location,confidence,score,package_managed,age_days,reason
2026-01-23,Cron,/etc/cron.d/malicious,HIGH,95,false,2,"Recent creation + suspicious patterns"
2026-01-23,Systemd,/etc/systemd/system/ssh.service,LOW,15,true,365,"Package managed + old file"
```

## Recommended Immediate Actions

1. **Add package manager integration** (easy, high impact)
2. **Implement known-good whitelist** (easy, medium impact)
3. **Skip vendor services by pattern** (easy, high impact)
4. **Add --min-confidence flag** for filtering
5. **Document false positive patterns** for user tuning

