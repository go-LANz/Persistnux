# Changelog

All notable changes to Persistnux will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
