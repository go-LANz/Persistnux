# Persistnux Detection Logic

## Version 2.4.0

Complete detection and analysis logic for all 14 modules. This document covers: exact scan paths, artifact parsing, detection flows, confidence determination, and pattern architecture. For the matched_pattern reference, see `MATCHED_PATTERNS.md`. For the mechanism inventory, see `PERSISTENCE_MECHANISMS.md`.

---

## Execution Model

### Parallel Module Architecture

```
main()
 │
 ├─ Launch 14 background subshells simultaneously
 │    Each subshell:
 │      CSV_FILE  = temp per-module CSV
 │      JSONL_FILE = temp per-module JSONL
 │      MODULE_NAME = module name for diagnostics
 │      "$_mfn"   = module function call
 │    All stdout+stderr → per-module temp log file
 │
 └─ Wait loop (display order):
      for each module in order:
        wait $pid       ← blocks until module finishes
        cat $log        ← prints buffered output
        cat $csv >> master CSV
        cat $jsonl >> master JSONL
```

**Module display order:**
```
1: systemd    2: cron      3: shell_profiles  4: init_scripts  5: kernel_preload
6: additional 7: backdoors 8: ssh             9: binary_integrity
10: bootloader 11: polkit  12: dbus           13: udev         14: container
```

### Output Buffering

Every module's console output (`log_info`, `log_check`, `log_finding`) is captured in a temp log file and printed only after that module's background job completes. Users see module output in display order, not execution order. A hung module blocks all subsequent display — `wait` with `|| true` ensures a failed module does not abort the main process.

---

## Pattern Architecture

### Source Arrays

All detection patterns are defined as bash arrays in the script header. These are the single source of truth — all runtime regex is derived from them at startup. Adding a string to an array automatically includes it in all combined patterns with no other changes required.

**`NEVER_WHITELIST_PATTERNS`** — Patterns that are always malicious in any persistence context. Package-managed files matching these are still flagged HIGH (preventing package-status bypass). These are the highest-priority patterns.

```
/dev/tcp/                   # TCP redirect shell
/dev/udp/                   # UDP redirect shell
bash -i                     # Interactive bash
sh -i                       # Interactive sh
nc -e                       # Netcat exec
nc .*-e                     # Netcat exec variant
ncat -e / ncat .*-e         # Ncat exec
busybox nc.*-e              # Busybox netcat
busybox.*(sh|bash).*-[ice]  # Busybox shell
\| *nc                      # Pipe to netcat
\| *bash\b / \| *sh\b       # Pipe to shell
\| */bin/sh / \| */bin/bash # Pipe to path shell
>&[ ]*/dev/                 # Redirect to /dev
exec [0-9]*<>/dev/          # FD open to /dev
python.*socket\.socket      # Python socket creation
python.*socket.*connect     # Python socket connect
perl.*socket.*connect       # Perl socket connect
ruby.*TCPSocket             # Ruby TCP socket
ruby.*Socket\.new           # Ruby socket
socat.*exec:                # Socat shell
socat.*TCP:                 # Socat TCP
telnet.*\|.*(bash|sh)       # Telnet pipe shell
xterm -display              # Xterm display redirect
mknod.*backpipe             # Named pipe backconnect
mkfifo.*/tmp|/dev/shm...    # FIFO in temp dir
source .*/tmp|/dev/shm      # Source from temp dir
\. .*/tmp|/dev/shm          # Dot-source from temp dir
script.*-q.*/dev/null       # Script null output (TTY fix)
rev.*\|.*(bash|sh|exec)     # Rev encoding pipe
tr.*[A-Za-z].*\|.*(bash|sh) # Tr rotation pipe
eval.*\$\(.*curl            # Eval curl output
eval.*\$\(.*wget            # Eval wget output
LD_PRELOAD=.*/(tmp|dev/shm|var/tmp)/  # LD_PRELOAD from temp
LD_LIBRARY_PATH=.*/(tmp|...)          # LD_LIBRARY_PATH from temp
nsenter.*-t.*1              # Container namespace escape
```

**`SUSPICIOUS_COMMANDS`** — Common attack command patterns. Lower priority than NEVER_WHITELIST but still high-confidence indicators.

```
curl.*\|.*(bash|sh)         # Download-pipe-execute
wget.*\|.*(bash|sh)         # Download-pipe-execute
`curl.*/`wget.*\|...        # Backtick variants
curl.* sh -c / wget.* sh -c # Pipe to sh -c
curl.*-o.*/tmp|/dev/shm     # Download to temp
wget.*-O.*/tmp|/dev/shm     # Download to temp
chmod \+x.*/tmp|/dev/shm    # Make temp file executable
chmod 777                   # World-writable
base64 -d / base64 --decode # Base64 decode
eval.*\$.*base64            # Eval decoded base64
echo.*\|.*base64.*-d        # Pipe through base64 decode
python.*-c.*import (socket|subprocess|pty|ctypes|os.system|popen|base64|exec|eval)
python.*-c.*exec\(          # Python inline exec
perl -e / ruby -e / php -r  # Interpreter inline
php.*fsockopen              # PHP socket
openssl.*-d.*-base64        # OpenSSL decode
source/. from temp dirs     # Sourcing from writable dirs
nohup .*/tmp|/dev/shm       # Background from temp
nohup.*setsid               # Detached process
tftp.*-g                    # TFTP get (download)
dd if=/tmp|/dev/shm         # DD from temp
rev.*\|.*(bash|sh)          # Rev encoding
tr.*[A-Za-z].*\|.*(bash|sh) # ROT-style encoding
script.*-q.*/dev/null       # Script command TTY fix
```

**`SUSPICIOUS_NETWORK_PATTERNS`** — Network and shell indicator patterns for reverse shell detection.

```
bash -i >& /dev/tcp/        # Classic bash TCP shell
bash -i >& /dev/udp/        # Classic bash UDP shell
sh -i >$ /dev/tcp/          # sh variant
zsh -i >& /dev/tcp/         # zsh variant
ksh -i >& /dev/tcp/         # ksh variant
/bin/bash -c exec 5<>/dev/tcp/  # FD redirect
nc.*-e.*(sh|bash|dash|zsh)  # Netcat exec patterns
/bin/sh | nc                # Pipe to netcat
nc -k.*-l / ncat -k.*-l    # Persistent listen
mknod.*backpipe             # Named pipe
telnet.*\|.*(bash|sh)       # Telnet redirect
socat exec:                 # Socat exec shell
nsenter.*-t.*1              # Container escape
xterm -display              # X display redirect
```

**`SUSPICIOUS_LOCATIONS`** — Filesystem paths that are always suspicious as execution locations.

```
^/dev/shm/      # Shared memory (no persistent storage)
^/tmp/          # Temp (world-writable, cleared on reboot)
^/var/tmp/      # Persistent temp (world-writable)
/\.[a-z]        # Hidden directory
\.\./\.\.       # Directory traversal
^/run/user/     # User runtime dir
```

**`SUSPICIOUS_FILES`** — Sensitive file paths that should not appear in commands or script content.

```
/etc/shadow
/etc/passwd
/root/.ssh
id_rsa
authorized_keys
```

**`MULTILINE_SUSPICIOUS_PATTERNS`** — Patterns that span logical lines or require heredoc context.

```
cat.*<<.*EOF.*bash          # Heredoc to bash
cat.*<<.*EOF.*/dev/tcp      # Heredoc to /dev/tcp
cat.*<<.*EOF.*curl          # Heredoc download
base64.*-d.*<<.*EOF         # Base64 decode heredoc
eval.*<<.*EOF               # Eval heredoc
python.*-c.*<<.*EOF         # Python heredoc
perl.*-e.*<<.*EOF           # Perl heredoc
rev.*\|.*(bash|sh|exec)     # Rev pipe
tr.*['"'].*['"'].*\|...     # ROT cipher pipe
dd.*\|.*(bash|sh)           # DD pipe
openssl.*-d.*\|.*(bash|sh)  # OpenSSL pipe
base64.*-d.*\|.*(bash|sh)   # Base64 pipe
```

**`NETWORK_INDICATOR_PATTERNS`** — Detects IP addresses in tool invocations and suspicious TLDs.

```
(curl|wget|...)+IP_REGEX    # Tool calling raw IP address
(curl|wget|...)+SUSPICIOUS_TLD  # .ru, .cn, .onion, .tk, .xyz, .top, .pw, .cc, .biz
(curl|wget|...)+LONG_DOMAIN # Long random-looking domain (>16 chars before TLD)
(\\x[0-9a-fA-F]{2}){4}     # Hex-encoded IP address
```

---

### Pattern Compilation: `build_combined_patterns()`

At startup, each array is joined with `IFS='|'` into a pipe-delimited ERE string. Eight compiled patterns are produced:

```
COMBINED_NEVER_WHITELIST_PATTERN    ← from NEVER_WHITELIST_PATTERNS
COMBINED_COMMAND_PATTERN            ← from SUSPICIOUS_COMMANDS
COMBINED_NETWORK_PATTERN            ← from SUSPICIOUS_NETWORK_PATTERNS
COMBINED_LOCATION_PATTERN           ← from SUSPICIOUS_LOCATIONS
COMBINED_FILE_PATTERN               ← from SUSPICIOUS_FILES
COMBINED_KNOWN_GOOD_PATHS_PATTERN   ← from KNOWN_GOOD_EXECUTABLE_PATHS
COMBINED_MULTILINE_PATTERN          ← from MULTILINE_SUSPICIOUS_PATTERNS
COMBINED_NETWORK_INDICATOR_PATTERN  ← from NETWORK_INDICATOR_PATTERNS

UNIFIED_SUSPICIOUS_PATTERN = COMBINED_NEVER_WHITELIST | COMBINED_COMMAND |
                              COMBINED_NETWORK | COMBINED_NETWORK_INDICATOR
```

`UNIFIED_SUSPICIOUS_PATTERN` is used as the fast first-gate check before all deep analysis.

---

### Core Analysis Functions

#### `quick_suspicious_check(content)`

Fast first-gate. Runs a single `grep -qiE "$UNIFIED_SUSPICIOUS_PATTERN"` on the input string. If no match, the caller skips all deep analysis. Eliminates subprocess overhead for the vast majority of clean files.

#### `analyze_script_content(content, file_path)`

Deep multi-pass analysis of script content. Returns 0 (found) or 1 (clean). Sets `MATCHED_PATTERN` and `MATCHED_STRING` globals.

**Pass order:**
1. NEVER_WHITELIST — highest priority, sets CRITICAL signal
2. SUSPICIOUS_COMMANDS — command patterns
3. SUSPICIOUS_NETWORK_PATTERNS — network/shell patterns
4. MULTILINE_SUSPICIOUS_PATTERNS — cross-line patterns
5. NETWORK_INDICATOR_PATTERNS — IP/TLD indicators
6. SUSPICIOUS_FILES — sensitive file references
7. Encoding chain detection — `base64 -d | bash`, `openssl -d | sh`
8. High-entropy detection + exec pattern — random-looking strings with execution

#### `check_suspicious_patterns(content)`

Lighter version of analyze_script_content used for short strings (cron commands, env values). Checks NEVER_WHITELIST, SUSPICIOUS_COMMANDS, SUSPICIOUS_NETWORK_PATTERNS only.

#### `is_package_managed(file_path)` / `check_file_package(file_path)`

`is_package_managed()` returns the package status string via stdout and a return code:
- Return 0: managed and unmodified → echoes `"package_name:managed"` or `"snap:managed"`, etc.
- Return 1: unmanaged → echoes `"unmanaged"`
- Return 2: managed but modified → echoes `"package_name:MODIFIED"`

Uses `PKG_CACHE` associative array to avoid re-querying the same path within a scan.

Query chain (first match wins): snap paths → flatpak paths → runtime managers (npm, pip, cargo) → dpkg → rpm → pacman.

`check_file_package(file)` is a convenience wrapper that calls `is_package_managed` and stores the result in the global `PKG_STATUS` variable (instead of stdout capture), for use in contexts where direct assignment is cleaner.

#### `get_executable_from_command(command)`

Strips systemd exec prefixes (`@`, `-`, `!`, `+`, `:`), handles env variable wrappers (`/usr/bin/env`), and extracts the first real executable path from a command string.

#### `adjust_confidence_for_package(confidence, pkg_status, file_path)`

Applies package-based confidence adjustments:
- Package-verified file: HIGH → MEDIUM, MEDIUM → LOW
- Modified package file: any → CRITICAL
- Unmanaged file in standard path: no change
- File modified within 7 days: one tier up (LOW→MEDIUM, MEDIUM→HIGH)

---

## Module 1: Systemd Services

**Function:** `check_systemd()` | **Label:** `[1/14] Systemd Services`

### Scan Paths

Service files: `/etc/systemd/system`, `/usr/lib/systemd/system`, `/lib/systemd/system`, `/run/systemd/system`, `/etc/systemd/user`, `/usr/lib/systemd/user`. Per-user: `~/.config/systemd/user` for all users (root mode).

Generator directories: `/etc/systemd/system-generators`, `/usr/local/lib/systemd/system-generators`, `/usr/lib/systemd/system-generators`, `/lib/systemd/system-generators`.

### Pre-filter

Known-good service names are skipped without analysis (whitelist): `systemd-*`, `dbus-*`, `snap.*`, `NetworkManager*`, `ModemManager*`, `udisks*`, `colord*`, `accounts-daemon*`, and other vendor service patterns.

Disabled services are also skipped UNLESS a matching `.timer` file exists (timer activation keeps the service reachable even when disabled).

### ExecStart Analysis Flow

```
1. Extract ExecStart= value
2. Strip systemd modifiers (@, -, +, !, :)
3. Pre-check: grep COMBINED_NEVER_WHITELIST_PATTERN on raw ExecStart line
   → Match found before package check → flag HIGH (bypass prevention)
4. get_executable_from_command() → extracts binary/script path

   ┌─── Is executable an interpreter? ───────────────────────────────┐
   │ (python*, perl*, ruby*, bash, sh, dash, zsh, ksh*, php*, node,  │
   │  nodejs, java, lua*, awk, gawk, mawk, env)                       │
   └─────────────────────────────────────────────────────────────────┘
            YES                              NO
             │                               │
   ┌─────────▼──────────┐         ┌──────────▼──────────┐
   │ Check interpreter  │         │ Check binary pkg     │
   │ binary itself      │         │ MODIFIED → CRITICAL  │
   │ MODIFIED → CRITICAL│         │ UNMANAGED → analyze  │
   └─────────┬──────────┘         └──────────┬──────────┘
             │                               │
   Has script arg?                   Binary in known-good path?
      YES         NO                      YES      NO
       │           │                      │         │
   get_script   analyze              LOW/skip   analyze
   from args   inline_code()               location + content
       │
   Check script package status
     MODIFIED → CRITICAL
     VERIFIED + NEVER_WHITELIST → HIGH (bypass prevention)
     VERIFIED, no patterns → LOW, done
     UNMANAGED → analyze_script_content()
                   → patterns found: HIGH
                   → no patterns, suspicious location: MEDIUM→HIGH
                   → no patterns, standard path: MEDIUM
```

### ExecStartPre/Post Hook Analysis

Each hook command is extracted from semicolon-delimited list. For each:
1. Strip systemd modifiers
2. `get_executable_from_command()` → executable path
3. `is_package_managed()` → MODIFIED: CRITICAL (`modified_exec_hook`) / UNMANAGED: HIGH (`unmanaged_exec_hook`)
4. Pattern check on full hook string → `suspicious_exec_hook`

### OnFailure= Analysis

Each unit name in `OnFailure=` is resolved to a service file path. The service file is verified:
- Unmanaged → HIGH
- Modified → CRITICAL

### Environment= / EnvironmentFile= Analysis

`Environment=`: grep for `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PATH` in inline values → `env_directive_ld_inject` at HIGH.

`EnvironmentFile=`: strip leading `-` (optional marker), resolve path:
- File exists + unmanaged + LD_PRELOAD inside → `env_file_ld_inject` at HIGH
- File exists + MODIFIED → `modified_env_file` at CRITICAL
- File missing → `missing_env_file` at MEDIUM

### Systemd Timer Content

For `.timer` files associated with services already flagged:
- `OnBootSec=`, `OnCalendar=`, `OnUnitActiveSec=` values logged in finding description
- `Unit=` cross-checked — if timer activates a non-corresponding service name, flagged HIGH

### Generator Detection

Each binary in generator directories:
- `check_file_package()` → MODIFIED: CRITICAL (`modified_generator`)
- UNMANAGED in suspicious location → CRITICAL (`suspicious_location_generator`)
- UNMANAGED in standard location → MEDIUM→HIGH (`unmanaged_generator`)

---

## Module 2: Cron Jobs & Scheduled Tasks

**Function:** `check_cron()` | **Label:** `[2/14] Cron Jobs`

### Scan Paths and Parsing

**`/etc/crontab`** and **`/etc/cron.d/*`**: Each non-comment line with 7+ fields: `min hr dom mon dow user command`. Command starts at field 7. `@special` syntax: field 1=`@reboot` etc., field 2=user, field 3+=command.

**`/etc/cron.daily`, `.hourly`, `.weekly`, `.monthly`**: Each file is a script — no schedule fields. Analyzed as scripts, not crontab lines.

**`/var/spool/cron/` and `/var/spool/cron/crontabs/`**: Per-user crontabs. Format: no user field (5-field schedule + command).

**`/etc/anacrontab`**: `period delay job-id command`. Package status checked.

**`/var/spool/at/`**: Each file is an AT job. Hidden filenames (starting with `.`) flagged HIGH.

**`/etc/at.allow`, `/etc/at.deny`, `/etc/cron.allow`, `/etc/cron.deny`**: Each user listed cross-referenced against `/etc/passwd` — nonexistent users flagged MEDIUM (may indicate a deleted account left an access grant).

### Command Analysis (`analyze_cron_command()`)

1. NEVER_WHITELIST patterns checked first → HIGH
2. SUSPICIOUS_COMMANDS → HIGH
3. `SUSPICIOUS_NETWORK_PATTERNS` → HIGH
4. If command executes a file: `is_package_managed()` on the target → MODIFIED: CRITICAL, UNMANAGED: HIGH

---

## Module 3: Shell Profiles & RC Files

**Function:** `check_shell_profiles()` | **Label:** `[3/14] Shell Profiles`

### Scan Strategy

System profiles always scanned. Per-user profiles scanned when running as root — reads `/etc/passwd` to enumerate all home directories with UID >= 1000 (plus UID 0 for root's own files).

### Analysis per File

1. `quick_suspicious_check()` on first 500 lines — fast exit if clean
2. If passes: `analyze_script_content()` on full first 500 lines
3. `is_package_managed()` on the file itself
4. `adjust_confidence_for_package()` applied
5. Mtime check: modified within 7 days escalates one tier

Special cases: `.zshenv` is flagged as higher-impact in descriptions because it sources for ALL zsh invocations, including non-interactive scripts.

---

## Module 4: Init Scripts & RC.local

**Function:** `check_init_scripts()` | **Label:** `[4/14] Init Scripts`

### Analysis Flow

**rc.local files**: If exists and non-empty → `is_package_managed()` + `analyze_script_content()` on full content.

**`/etc/init.d/` files**: `is_package_managed()` first. VERIFIED with no patterns → LOW. MODIFIED → CRITICAL. UNMANAGED → analyze content.

**`/etc/rc*.d/`**: Two separate checks per entry:

1. **Regular files**: Any non-symlink file in rc*.d is flagged HIGH (`non_symlink_in_rcd`) — these directories should only contain symlinks.

2. **Symlinks**: `readlink -f` to get canonical target.
   - Target doesn't exist → MEDIUM (`broken_rcd_symlink`)
   - Target exists but is NOT under `/etc/init.d/` → HIGH (`suspicious_rcd_symlink`) + analyze target content if it's a file
   - Target is in `/tmp/`, `/dev/shm/`, `/var/tmp/` → CRITICAL (`suspicious_rcd_symlink_temp`)

---

## Module 5: Kernel Modules & Library Preloading

**Function:** `check_kernel_and_preload()` | **Label:** `[5/14] Kernel/Preload`

### `/etc/ld.so.preload`

Each non-comment line is a library path. For each:
1. Check location against `SUSPICIOUS_LOCATIONS` → CRITICAL if temp/hidden
2. `is_package_managed()` → VERIFIED: MEDIUM, MODIFIED: CRITICAL, UNMANAGED: HIGH
3. File existence check — missing library flagged at same confidence

### `/etc/ld.so.conf` and `/etc/ld.so.conf.d/`

1. `is_package_managed()` on the conf file → MODIFIED: CRITICAL, UNMANAGED: HIGH
2. Parse non-comment, non-include lines as library search paths
3. For unmanaged configs: grep paths for suspicious locations
4. Collect non-standard paths (not `/usr/lib*`, `/lib*`, `/usr/lib64`, `/lib64`)
5. For each non-standard path: scan all `.so*` files → `is_package_managed()` on each

### Loaded Kernel Modules (`lsmod`)

1. Parse module name from lsmod output
2. `modinfo -F filename "$module"` → get `.ko` file path
3. If modinfo returns no filename → built-in module, skip
4. If `.ko` path:
   - In `/lib/modules/` or `/usr/lib/modules/` → standard location
   - In other path → `module_nonstandard_location` HIGH
   - In temp path → `module_suspicious_location` CRITICAL
   - `is_package_managed()` on `.ko` path → MODIFIED: CRITICAL, UNMANAGED in standard: HIGH

### `/etc/modprobe.d/` Config Files

1. `is_package_managed()` on each `.conf` file → MODIFIED: CRITICAL, UNMANAGED: MEDIUM
2. Content check for `install` directives with suspicious command targets
3. Content check for `blacklist` of security modules (apparmor, selinux, seccomp) → HIGH

### `/etc/modules` and `/etc/modules-load.d/`

Each module name listed is resolved via `modinfo` and verified. Config file integrity checked.

---

## Module 6: Additional Persistence Mechanisms

**Function:** `check_additional_persistence()` | **Label:** `[6/14] Additional`

### CHECK 1 — XDG Autostart

For each `.desktop` file: extract `Exec=` field → `get_executable_from_command()` → analyze executable and any script argument. Same interpreter/direct-binary analysis flow as Module 1.

### CHECK 2 — /etc/environment LD_PRELOAD

Parse each line for `LD_PRELOAD=` or `LD_LIBRARY_PATH=`. For each library path found:
1. Flag file as HIGH (`ld_preload_env`)
2. `is_package_managed()` on the library → MODIFIED: CRITICAL, UNMANAGED: HIGH, missing: CRITICAL

### CHECK 3 — Sudoers

For each file in `/etc/sudoers` and `/etc/sudoers.d/`:
1. `visudo -c -f` syntax check where available
2. Grep for `NOPASSWD`, `ALL=(ALL) ALL`, `(ALL:ALL)` patterns → HIGH (`dangerous_sudoers_rule`)
3. `is_package_managed()` on file → MODIFIED: CRITICAL

### CHECK 4 — PAM Modules and Configuration

**PAM config parsing**: For each file in `/etc/pam.d/`:
1. Extract module names (lines matching `pam_*.so`)
2. Locate `.so` file in PAM library directories
3. `is_package_managed()` on `.so` file → UNMANAGED: CRITICAL, MODIFIED: CRITICAL

**pam_exec.so detection**: When `pam_exec.so` found in a PAM config:
1. Extract the script path from arguments
2. If script missing → CRITICAL (`pam_exec_missing_script`)
3. If script in temp dir → CRITICAL (`pam_exec_suspicious_location`)
4. `is_package_managed()` on script → MODIFIED: CRITICAL, UNMANAGED: `pam_exec_script`
5. `analyze_script_content()` on script content

**pam_env.so detection**: When `pam_env.so` found:
1. Read `/etc/security/pam_env.conf` for `LD_PRELOAD` or `LD_LIBRARY_PATH`
2. If found: extract library path, `is_package_managed()` → HIGH or MEDIUM

**pam_python.so / pam_perl.so / pam_script.so relay detection**: Extract script path argument, analyze content via `analyze_script_content()`.

**pam_env.conf per-user**: Scan `~/.pam_environment` for all users — same LD_PRELOAD detection.

**PAM config integrity**: `is_package_managed()` on each `/etc/pam.d/` file → MODIFIED: CRITICAL.

### CHECK 5 — MOTD Scripts

For each file in `/etc/update-motd.d/` and `/etc/motd.d/`:
1. `is_package_managed()` → MODIFIED: CRITICAL, UNMANAGED: MEDIUM
2. `analyze_script_content()` → HIGH/CRITICAL if patterns found

### CHECK 6 — Duplicate UID 0 Accounts

Parse `/etc/passwd`, check field 3 (UID). Any account with UID=0 where username is not `root` → CRITICAL finding.

### CHECK 7 — Shell Masking via Trailing Whitespace

Parse `/etc/passwd` field 7 (shell). For each entry:
1. Check if shell field ends with whitespace before EOL — HIGH (`shell_masking`)
2. Check if shell is not in `/etc/shells` and not `nologin`/`false`/`sync` — MEDIUM

---

## Module 7: Package Manager Backdoors & Common Locations

**Function:** `check_common_backdoors()` | **Label:** `[7/14] Backdoor Locations`

### CHECK 1 — APT/YUM Configuration Files

Enumerate files in `/etc/apt/apt.conf.d/`, `/usr/share/unattended-upgrades/`, `/etc/yum.repos.d/`, `/etc/yum.conf`. Run `check_suspicious_patterns()` on content. Flag on match.

### CHECK 2 — APT Hook Directives

Re-scan APT conf files specifically for `DPkg::Post-Invoke`, `DPkg::Pre-Invoke`, `APT::Update::Pre-Invoke`, `APT::Update::Post-Invoke` via `grep -iE`. For each match:
1. `check_file_package()` → `PKG_STATUS` (UNMANAGED → HIGH, MODIFIED → CRITICAL)
2. Extract hook command string: `grep -oiE '"[^"]+"[[:space:]]*;'` — content between first pair of quotes
3. `analyze_script_content()` on extracted command → CRITICAL if patterns found

### CHECK 3 — YUM/DNF Plugin Configurations

Enumerate plugin config files. Read `.py` script bodies. `analyze_script_content()` on each.

### CHECK 4 — DPKG Postinst Scripts

Bulk query: `timeout 10 dpkg-query -W -f='${Package}\t${Status}\n'` → builds `_dpkg_installed_pkgs` associative array (package → installed boolean).

For each `.postinst` file in `/var/lib/dpkg/info/`:
1. Extract package name from filename (strip `.postinst`)
2. Lookup in `_dpkg_installed_pkgs` — if NOT present: orphan (uninstalled package's postinst) → HIGH
3. `analyze_script_content()` on file content
4. Hex/octal obfuscation check: grep for `\x[0-9a-f]{2}` or `\0[0-7]{3}` sequences → HIGH

### RPM Scripts (Between CHECK 4 and CHECK 5)

`timeout 30 rpm -qa --scripts` → full list of all package scripts. Each script body analyzed via `analyze_script_content()`.

### CHECK 5 — at.allow / at.deny

For each user in `/etc/at.allow` and `/etc/at.deny`: cross-reference against `/etc/passwd`. User not found → MEDIUM (ghost access grant).

### CHECK 6 — doas.conf

Read `/etc/doas.conf`. Grep for `nopass` (passwordless), `permit` without `as` qualifier, or wildcard identity. → HIGH (`permissive_doas`).

### CHECK 7 — Git Configs (Credential Helpers and Hooks)

For each git config (`/etc/gitconfig`, per-user `~/.gitconfig`):
1. `[credential] helper = <command>` — extract helper command, check if it's an unmanaged path or matches suspicious patterns → MEDIUM/HIGH
2. `[core] pager = <command>` — check for suspicious commands → MEDIUM/HIGH

### CHECK 8 — Web Shell Scan

Five web directories: `/var/www/html/`, `/var/www/`, `/usr/share/nginx/html/`, `/srv/http/`, `/srv/www/`. For each, `find "$dir" -xdev -type f \( -name "*.php" -o -name "*.asp" -o -name "*.aspx" -o -name "*.jsp" \)`.

For each matched web file: grep for web shell signatures:
- PHP: `system(`, `exec(`, `passthru(`, `shell_exec(`, `popen(`, `_POST[`, `_GET[`, `eval(`, `base64_decode(`
- Generic: `<?php`, request/response output patterns

Positive match → HIGH (`webshell_pattern`).

---

## Module 8: SSH Persistence

**Function:** `check_ssh_persistence()` | **Label:** `[8/14] SSH`

### Regular Users (UID >= 1000)

For each user home with readable `.ssh/authorized_keys`:
1. Check mtime: modified within 7 days → MEDIUM baseline
2. For each key line: extract `command="..."` option via regex `command="([^"\\]|\\.){0,200}"`
3. `analyze_script_content()` on extracted command → HIGH/CRITICAL

For each `~/.ssh/rc`: presence → MEDIUM, content analysis → HIGH/CRITICAL.

### System Accounts (UID 1-999)

Parse `/etc/passwd` for entries with UID 1-999. For each with a readable home:
1. Check `$homedir/.ssh/authorized_keys` existence → HIGH (`system_account_ssh_key`)
2. Extract `command=` options → `analyze_script_content()` → CRITICAL if malicious

---

## Module 9: Binary Integrity

**Function:** `check_binary_integrity()` | **Label:** `[9/14] Binary Integrity`

### Package Integrity Verification

**Debian/Ubuntu (dpkg)**:
1. For each binary in `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`: `dpkg -S "$file"` to find owning package
2. Batch `dpkg --verify "$package"` — parse output for modified files
3. Skip lines with ` c ` (conffiles — expected to be user-modified)
4. Modified binary in critical path → CRITICAL (`modified_binary`)

PAM modules in architecture-specific security dirs also verified via `dpkg --verify`.

**RHEL/CentOS (rpm)**: `rpm -qf "$file"` to find owning package, `rpm -Va "$package"` to verify.

### SUID/SGID Active Scan

`find` with `-perm /4000` (SUID) and `-perm /2000` (SGID) across: `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/bin`, `/usr/local/sbin`, `/opt`, `/tmp`, `/dev/shm`, `/var/tmp`.

Result cap: 200 SUID, 100 SGID.

For each SUID file:
1. `check_file_package()` → if unmanaged: CRITICAL (`suid_unmanaged_binary`)
2. Location check: temp dirs → CRITICAL (`suid_suspicious_location`)
3. Script check (shebang): if shell script → `analyze_script_content()` → CRITICAL (`suid_script_malicious_content`)
4. Package-verified SUID → LOW (`suid_binary`)

For each SGID file: same flow, lower baseline.

### File Capabilities (`getcap`)

If `getcap` is available: `timeout 30 getcap -r /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin`.

For each capability entry:
1. Parse capability string (e.g., `cap_setuid+ep`)
2. `cap_sys_admin+ep` → CRITICAL (`cap_sys_admin`)
3. `cap_setuid+ep`:
   - Binary name in GTFOBins list → CRITICAL (`cap_setuid_gtfobin`)
   - Binary name not in GTFOBins → HIGH (`cap_setuid_unmanaged`)
4. `cap_net_raw+ep` on package-owned binary → LOW (`file_capability`)
5. Other capabilities → `check_file_package()` → confidence based on package status

**GTFOBins list:** `bash`, `sh`, `python`, `python2`, `python3`, `perl`, `ruby`, `find`, `vim`, `vi`, `nmap`, `awk`, `gawk`, `mawk`, `less`, `more`, `tee`, `cp`, `rsync`, `tar`

### Binary Hijacking — Renamed Originals

Scan dirs: `/bin`, `/usr/bin`, `/sbin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`.

`find "$dir" -maxdepth 1 -type f \( -name "*.original" -o -name "*.old" -o -name "*.bak" -o -name "*.real" \)`

For each renamed file:
1. Strip suffix to derive active name (e.g., `sshd.original` → `sshd`)
2. Check if `$dir/$active_name` exists
3. If active exists: is it a shell script (shebang check)?
   - Yes → `binary_hijack_wrapper` HIGH + `analyze_script_content()` → CRITICAL if malicious
   - No (both binaries exist) → `renamed_binary_active_present` HIGH
4. If active doesn't exist: `renamed_binary` MEDIUM (original moved, nothing replaced it yet)

---

## Module 10: Bootloader & Initramfs

**Function:** `check_bootloader_persistence()` | **Label:** `[10/14] Bootloader`

### GRUB Analysis

Files: `/etc/default/grub`, `/etc/default/grub.d/*.cfg`.

1. `check_file_package()` on each file
2. Extract `GRUB_CMDLINE_LINUX_DEFAULT=` and `GRUB_CMDLINE_LINUX=` values
3. Combine both values into one string
4. Bash regex match for `init=([^[:space:]"']+)`
5. Compare extracted path against standard inits: `/sbin/init`, `/lib/systemd/systemd`, `/usr/lib/systemd/systemd`, `/bin/busybox`, `/sbin/upstart`
   - Standard match → LOW (`grub_init_standard`)
   - Non-standard → HIGH (`grub_init_injection`)
   - Non-standard + `analyze_script_content()` on target → CRITICAL (`grub_init_malicious_content`)

### Root-level Dropped Scripts

`find / -xdev -maxdepth 2 -name "*.sh" -perm /111 -type f` excluding standard system dirs.

For each found script:
1. MEDIUM (`root_dropped_script`)
2. `analyze_script_content()` → HIGH/CRITICAL (`root_dropped_script_malicious`)

### Dracut Modules

For each `module-setup.sh` in `/usr/lib/dracut/modules.d/*/`:
1. `check_file_package()` → unmanaged: HIGH (`dracut_unmanaged_module`)
2. Grep for `inst_hook pre-pivot` → extract hook script path
3. If pre-pivot hook found:
   - HIGH (`dracut_pre_pivot_hook`)
   - Read hook script content
   - Grep for `/sysroot/etc/shadow` or `/sysroot/etc/passwd` writes → CRITICAL (`dracut_sysroot_shadow_write`)
   - `analyze_script_content()` on hook content → CRITICAL (`dracut_hook_malicious_content`)

### initramfs-tools (Ubuntu/Debian)

Scan executable files in `/etc/initramfs-tools/scripts/` and `/etc/initramfs-tools/hooks/`.

For each executable file:
1. `analyze_script_content()` on content
2. Specifically grep for writes to `$rootmnt/etc/shadow` or `$rootmnt/etc/passwd` → CRITICAL (`initramfs_rootmnt_shadow_write`)

### Initrd Modification Check

For each `/boot/initrd.img-*`: check mtime. Modified within 7 days → MEDIUM.

---

## Module 11: Polkit (PolicyKit)

**Function:** `check_polkit_persistence()` | **Label:** `[11/14] Polkit`

### .pkla Files (PolicyKit < 0.106)

Path: `/etc/polkit-1/localauthority/50-local.d/*.pkla`

For each file:
1. `check_file_package()` — unmanaged is the normal baseline for local policy (MEDIUM)
2. Parse KeyFile format: extract `Identity=`, `Action=`, `ResultAny=`, `ResultInactive=`, `ResultActive=`
3. Count how many Result fields are `yes`:
   - All three `yes` → CRITICAL (`polkit_pkla_all_result_yes`)
   - One or two `yes` → HIGH (`polkit_pkla_partial_yes`)
4. `Identity=` contains `unix-user:*` or `unix-group:*` (wildcard):
   - With all-yes → CRITICAL
   - Alone → HIGH

### .rules Files (PolicyKit >= 0.106)

Path: `/etc/polkit-1/rules.d/*.rules`

For each file:
1. `check_file_package()` — unmanaged is normal for local rules (MEDIUM)
2. Grep for `return polkit.Result.YES`
3. Check context: is the `return YES` inside an `if` block?
   - No surrounding `if` → CRITICAL (`polkit_rules_unconditional_yes`)
   - Inside `if` with minimal condition → HIGH
   - Inside `if` with meaningful condition → MEDIUM (`polkit_rules_conditioned_yes`)
4. `analyze_script_content()` on full file content for secondary patterns

---

## Module 12: D-Bus & NetworkManager

**Function:** `check_dbus_persistence()` | **Label:** `[12/14] D-Bus`

### D-Bus System Service Files

Path: `/usr/share/dbus-1/system-services/*.service`

For each service file:
1. Extract `Exec=` line → first word is executable path
2. Check if executable exists on disk:
   - Missing → HIGH (`dbus_dangling_exec`)
3. If exists: `check_file_package()`:
   - UNMANAGED → HIGH (`dbus_unmanaged_exec_target`)
4. Location check: temp dir → CRITICAL (`dbus_exec_suspicious_location`)
5. `analyze_script_content()` on executable if it's a script → CRITICAL (`dbus_malicious_exec_content`)
6. `check_file_package()` on the service file itself — unmanaged service file is always suspicious

### D-Bus Policy Files

Path: `/etc/dbus-1/system.d/*.conf`

For each XML policy file:
- Parse `<allow own="VALUE">` → flag if VALUE is `*` → HIGH (`dbus_wildcard_policy`)
- Parse `<allow send_destination="VALUE">` → flag if VALUE is `*` → HIGH (`dbus_wildcard_policy`)

### NetworkManager Dispatcher Scripts

Path: `/etc/NetworkManager/dispatcher.d/`

For each file:
1. Check executable bit (`-x`) — skip non-executable
2. `check_file_package()` → UNMANAGED: HIGH
3. `analyze_script_content()` on content → HIGH/CRITICAL

---

## Module 13: Udev Rules

**Function:** `check_udev_persistence()` | **Label:** `[13/14] Udev`

### Paths and Initial Classification

- `/run/udev/rules.d/` — ANY file here is HIGH (`udev_runtime_rule`) regardless of content
- `/etc/udev/rules.d/` — admin-managed
- `/lib/udev/rules.d/` — package-managed (checked via `check_file_package()`)

### RUN+= Extraction and Analysis

For each `.rules` file: grep for `RUN(\+?=|[[:space:]]*\+=[[:space:]]*)"[^"]+"` to extract all RUN+= directives.

For each extracted command string:
1. Grep for `at now` or `at +` or `crontab` → HIGH (`udev_run_at_delegation`)
2. Location check: temp dirs → CRITICAL (`udev_run_suspicious_location`)
3. `check_suspicious_patterns()` on command string → CRITICAL (`udev_run_malicious_command`)
4. If command is a file path: read file content, `analyze_script_content()` → CRITICAL (`udev_run_target_malicious`)

---

## Module 14: Container Escape Persistence

**Function:** `check_container_persistence()` | **Label:** `[14/14] Container`

Gracefully skips entire module if `docker` is not installed or not in PATH.

### Dockerfile Scan

`find /tmp /root /home /var/tmp -maxdepth 3 -name "Dockerfile" -type f`

For each found Dockerfile:
1. HIGH (`dockerfile_suspicious_location`)
2. Grep content for: `nsenter`, `socat exec:`, `--privileged` → CRITICAL (`dockerfile_escape_technique`)

### Docker Daemon Config

If `/etc/docker/daemon.json` exists:
1. Parse JSON (via grep on key-value patterns)
2. `userns-remap` is empty/null → HIGH (`docker_daemon_weakened_security`)
3. `no-new-privileges` is false → HIGH

### Container Inspection

`docker ps -aq` → list of all container IDs.
Result cap: first 50 containers.

For each container ID: `docker inspect "$id"` (with `timeout 10`).

Parse JSON output:
- `HostConfig.Privileged: true` → HIGH (`container_privileged`)
- `HostConfig.Privileged: true` AND `HostConfig.PidMode: host` → CRITICAL (`container_privileged_pid_host`)
- Any mount path containing `/var/run/docker.sock` → CRITICAL (`container_docker_sock_mount`)
- `Config.Entrypoint` or `Config.Cmd` contains `nsenter` → CRITICAL (`container_nsenter_entrypoint`)

---

## Confidence Scoring Reference

| Level | Trigger Examples |
|---|---|
| **LOW** | Package-verified file, standard location, no patterns |
| **MEDIUM** | Unmanaged file, no patterns; or broken/missing reference; or file modified 7-30 days ago |
| **HIGH** | Unmanaged file with location risk; NEVER_WHITELIST match in monitored content; single strong structural indicator (SUID unmanaged, system account SSH key) |
| **CRITICAL** | Package integrity failure; execution from temp dirs with SUID; PAM module unmanaged/modified; initrd/dracut shadow write; container escape primitives |

**Time escalation:** File modified within 7 days advances confidence one tier (LOW→MEDIUM, MEDIUM→HIGH). Applied after package-based adjustment.

**SUID/SGID escalation:** Any HIGH finding on a file with SUID or SGID bit → CRITICAL. Pattern string appended with `+suid_sgid`.

---

## Output Format

Each finding written as one line to both CSV and JSONL. Fields:

```
timestamp       ISO 8601 UTC
hostname        system hostname
category        module category (e.g., "Systemd Service", "Cron Job")
confidence      LOW | MEDIUM | HIGH | CRITICAL
file_path       path of the artifact (service file, script, key, etc.)
file_hash       SHA-256 of file_path (or "N/A" for non-file artifacts)
file_owner      user:group
file_permissions octal permissions
file_age_days   days since last modification
package_status  package manager status string from is_package_managed()
command         the executable or command involved
description     human-readable description
matched_pattern pattern ID (see MATCHED_PATTERNS.md)
matched_string  the specific content that triggered the finding
```

---

*Last Updated: 2026-03-16 | Version: 2.4.0*
