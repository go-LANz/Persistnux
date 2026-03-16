#!/bin/bash
################################################################################
# Persistnux - Linux Persistence Detection Tool
# A comprehensive DFIR tool to detect known Linux persistence mechanisms
# Author: DFIR Community Project
# License: MIT
# Version: 2.4.0
################################################################################

# Require bash 4.0+ for associative arrays (declare -A)
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
    echo "ERROR: persistnux requires bash 4.0 or later. Detected: $BASH_VERSION" >&2
    echo "       On macOS, install bash via: brew install bash" >&2
    exit 1
fi

set -eo pipefail

# Cleanup temp data on any exit (normal, interrupt, signal)
# Prevents /tmp/persistnux_* files from accumulating on Ctrl+C or error
trap 'rm -rf "${TEMP_DATA:-}" 2>/dev/null' EXIT INT TERM HUP

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-./persistnux_output}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HOSTNAME=$(hostname)
CSV_FILE="${OUTPUT_DIR}/persistnux_${HOSTNAME}_${TIMESTAMP}.csv"
JSONL_FILE="${OUTPUT_DIR}/persistnux_${HOSTNAME}_${TIMESTAMP}.jsonl"
TEMP_DATA="/tmp/persistnux_${TIMESTAMP}"
FINDINGS_COUNT=0
CHECK_NUM=0

# Filter mode: "suspicious_only" (default) or "all"
FILTER_MODE="${FILTER_MODE:-suspicious_only}"
MIN_CONFIDENCE="${MIN_CONFIDENCE:-}"

# Check if running as root
EUID_CHECK=$(id -u)

# Performance: Package manager cache to avoid repeated lookups
# Format: PKG_CACHE["/path/to/file"]="status:package_name" or "unmanaged"
# NOTE: PKG_CACHE is per-subshell -- each of the 14 parallel modules has its own
# copy after fork. Cross-module cache sharing requires a file-based implementation
# with flock, which is a planned v2.5.0 enhancement. Cache still eliminates
# duplicate calls WITHIN a single module's run.
declare -A PKG_CACHE

# Performance: File hash + metadata caches to avoid repeated sha256sum/stat calls
# The same binary/script path can appear in systemd, cron, and autostart checks
declare -A FILE_HASH_CACHE
declare -A FILE_METADATA_CACHE

# Performance: Systemctl enabled status cache to avoid repeated calls
# Format: SYSTEMCTL_CACHE["service_name"]="enabled" or "disabled"
declare -A SYSTEMCTL_CACHE
SYSTEMCTL_CACHE_INITIALIZED=false

################################################################################
# Suspicious Pattern Definitions
################################################################################

# Enhanced suspicious patterns based on research from multiple sources
# Includes patterns from Crackdown and community DFIR knowledge
declare -a SUSPICIOUS_NETWORK_PATTERNS=(
    "bash -i >& /dev/tcp/"
    "bash -i >& /dev/udp/"
    "sh -i >& /dev/tcp/"
    "sh -i >& /dev/udp/"
    "zsh -i >& /dev/tcp/"             # zsh reverse shell variant
    "ksh -i >& /dev/tcp/"             # ksh reverse shell variant
    "/bin/bash -c exec 5<>/dev/tcp/"
    "/bin/bash -c exec 5<>/dev/udp/"
    "nc.*-e.*(sh|bash|dash|zsh)"      # Netcat with any shell execute flag
    "/bin/sh | nc"
    "nc -k.*-l"                       # Netcat bind shell listener (persistent)
    "ncat -k.*-l"                     # Ncat bind shell listener (persistent)
    "mknod.*backpipe"
    "telnet.*\|.*(bash|sh)"           # Telnet piped to any shell
    "socat exec:"
    "nsenter.*-t.*1"              # Container escape (enter host PID namespace)
    "xterm -display"
)

declare -a SUSPICIOUS_COMMANDS=(
    "curl.*\|.*bash"              # Download and execute via curl
    "curl.*\|.*sh"                # Download and execute via curl
    "wget.*\|.*bash"              # Download and execute via wget
    "wget.*\|.*sh"                # Download and execute via wget
    "\`curl.*\|.*bash"            # Backtick curl piped to bash
    "\`curl.*\|.*sh"              # Backtick curl piped to sh
    "\`wget.*\|.*bash"            # Backtick wget piped to bash
    "\`wget.*\|.*sh"              # Backtick wget piped to sh
    "curl.* sh -c"                # Download and execute via curl
    "wget.* sh -c"                # Download and execute via wget
    "curl.*-o.*/tmp"              # Download to /tmp via curl
    "curl.*-o.*/dev/shm"          # Download to /dev/shm via curl
    "wget.*-O.*/tmp"              # Download to /tmp via wget
    "wget.*-O.*/dev/shm"          # Download to /dev/shm via wget
    "chmod \+x.*/tmp"             # Making /tmp files executable
    "chmod \+x.*/dev/shm"         # Making /dev/shm files executable
    "chmod 777[[:space:]]"        # Overly permissive permissions (fixed: was trailing-space anchored)
    "base64 -d"                   # Base64 decode (common obfuscation)
    "base64 --decode"             # Base64 decode (long form)
    "eval.*\\\$.*base64"          # Eval with base64 decoded content
    "echo.*\|.*base64.*-d"        # Echo piped to base64 decode
    "python.*-c.*import.*(socket|subprocess|pty|ctypes|os\.system|popen|base64|exec\b|eval\b)"  # Python inline dangerous imports only
    "python.*-c.*exec\("           # Python inline exec() without import
    "perl -e"                     # Perl inline code
    "ruby -e"                     # Ruby inline code
    "php -r"                      # PHP inline code
    "php.*fsockopen"              # PHP socket connection
    "openssl.*-d.*-base64"        # OpenSSL base64 decode
    "source .*/tmp/"              # Dot-source script from /tmp staging area
    "source .*/dev/shm/"          # Dot-source script from /dev/shm
    "\. .*/tmp/"                  # POSIX dot-source from /tmp
    "\. .*/dev/shm/"              # POSIX dot-source from /dev/shm
    "nohup .*/tmp/"               # Background execution of /tmp payload
    "nohup .*/dev/shm/"           # Background execution of /dev/shm payload
    "nohup.*setsid"               # Process detachment chain (survives logout, any path)
    "tftp.*-g"                    # TFTP get (worm propagation)
    "dd if=/tmp/"                 # dd reading from /tmp staging area
    "dd if=/dev/shm/"             # dd reading from /dev/shm
    "rev.*\|.*(bash|sh)"          # String reversal decode to shell
    "tr.*[A-Za-z].*\|.*(bash|sh)" # tr-based cipher decode to shell (ROT13/ROT47)
    "script.*-q.*/dev/null"       # TTY upgrade technique (post-exploitation)
)

# Suspicious execution locations - these patterns are checked against file paths
# and ExecStart commands to identify potential staging/hiding locations
declare -a SUSPICIOUS_LOCATIONS=(
    "^/dev/shm/"                  # Execution from shared memory
    "^/tmp/"                      # Execution from temp directory
    "^/var/tmp/"                  # Execution from persistent temp
    "/\.[[:alpha:]]"              # Hidden file/directory (starts with dot)
    "\.\./\.\."                   # Multiple parent traversals (path escape attempt)
    "^/run/user/"                 # User runtime directory (volatile, world-accessible)
)

declare -a SUSPICIOUS_FILES=(
    "/etc/shadow"
    "/etc/passwd"
    "/root/.ssh"
    "id_rsa"
    "authorized_keys"
)

################################################################################
# False Positive Reduction - Known-Good Executable Paths
################################################################################

# Known legitimate executable paths (system binaries)
# These are trusted because they're in system directories and package-managed
declare -a KNOWN_GOOD_EXECUTABLE_PATHS=(
    "^/usr/bin/"
    "^/usr/sbin/"
    "^/bin/"
    "^/sbin/"
    "^/usr/lib/"
    "^/lib/"
    "^/lib/systemd/"
    "^/usr/lib/systemd/"
)

# Known interpreter patterns (regex-based for version flexibility)
# CRITICAL: When these are the executable, we must analyze the script argument, not the interpreter
# Using regex patterns instead of hardcoded versions for forward compatibility
declare -a KNOWN_INTERPRETER_PATTERNS=(
    "^python[0-9.]*$"      # python, python2, python3, python3.11, python3.13, pypy, pypy3
    "^pypy[0-9]*$"         # pypy, pypy3
    "^perl[0-9.]*$"        # perl, perl5, perl5.32
    "^ruby[0-9.]*$"        # ruby, ruby2.7, ruby3.0
    "^bash$"
    "^sh$"
    "^dash$"
    "^zsh$"
    "^ksh$"
    "^ksh[0-9]*$"          # ksh93, ksh88
    "^php[0-9.]*$"         # php, php7, php8
    "^node$"
    "^nodejs$"
    "^java$"
    "^lua[0-9.]*$"         # lua, lua5.1, lua5.4
    "^awk$"
    "^gawk$"
    "^mawk$"
    "^env$"            # /usr/bin/env /tmp/evil.sh - env is a relay, check what it runs
)

# Known legitimate command patterns (safe operations)
# These patterns indicate normal system operations
declare -a KNOWN_GOOD_COMMAND_PATTERNS=(
    "^/usr/bin/test "              # Test command
    "^/usr/bin/\\["                # Test command (bracket form)
    "^/bin/true$"                  # No-op command
    "^/bin/false$"                 # No-op command
    "^@"                           # systemd special prefix
    "^-"                           # systemd special prefix (ignore failures)
    "^:"                           # systemd special prefix (always succeed)
    "^\\+"                         # systemd special prefix
    "^!"                           # systemd special prefix
)

# Dangerous command patterns that should NEVER be whitelisted
# These override any known-good path checks
# NOTE: Patterns are designed to detect actual malicious usage, not just keywords
declare -a NEVER_WHITELIST_PATTERNS=(
    "/dev/tcp/"                  # Bash network redirection (reverse shells)
    "/dev/udp/"                  # Bash network redirection (reverse shells)
    "bash -i"                    # Interactive bash (common in reverse shells)
    "sh -i"                      # Interactive shell (common in reverse shells)
    "nc -e"                      # Netcat with execute flag (reverse shell)
    "nc .*-e"                    # Netcat with execute flag (alternate syntax)
    "ncat -e"                    # Ncat with execute flag
    "ncat .*-e"                  # Ncat with execute flag (alternate syntax)
    "busybox nc.*-e"             # Busybox netcat reverse shell
    "busybox.*(sh|bash).*-[ice]" # Busybox shell inline execution
    "\| *nc "                    # Piping to netcat
    "\| *bash\b"                 # Piping to bash (fixed: word boundary, was trailing-space)
    "\| *sh\b"                   # Piping to sh (fixed: word boundary, was trailing-space)
    "\| */bin/sh"                # Piping to /bin/sh
    "\| */bin/bash"              # Piping to /bin/bash
    ">&[ ]*/dev/"                # Redirecting to /dev/ (reverse shell pattern)
    "exec [0-9]*<>/dev/"         # Bash exec fd+bidirectional dev redirect (fixed: was dead pattern)
    "python.*socket\.socket"     # Python socket creation
    "python.*socket.*connect"    # Python socket connect (removed spurious space requirement)
    "perl.*socket.*connect"      # Perl socket connect
    "ruby.*TCPSocket"            # Ruby TCP socket
    "ruby.*Socket\.new"          # Ruby socket creation
    "socat.*exec:"               # Socat with exec (reverse shell)
    "telnet.*\|.*(bash|sh)"      # Telnet piped to any shell (fixed: was two separate patterns)
    "xterm -display"             # Xterm display redirection (reverse shell)
    "mknod.*backpipe"            # Named pipe for reverse shell
    "mkfifo.*/(tmp|dev/shm|var/tmp)"  # Named pipe in staging dirs (fixed: added /dev/shm /var/tmp)
    "source .*/tmp/"             # Sourcing script from /tmp staging area
    "source .*/dev/shm/"         # Sourcing script from /dev/shm
    "\. .*/tmp/"                 # POSIX dot-source from /tmp
    "\. .*/dev/shm/"             # POSIX dot-source from /dev/shm
    "script.*-q.*/dev/null"      # TTY upgrade (post-exploitation technique)
    "rev.*\|.*(bash|sh|exec)"    # String reversal decode to shell
    "tr.*[A-Za-z].*\|.*(bash|sh)" # tr-based cipher decode to shell (ROT13/ROT47)
    "eval.*\$\(.*curl"           # eval with curl command substitution (download+exec)
    "eval.*\$\(.*wget"           # eval with wget command substitution (download+exec)
    "LD_PRELOAD=.*(/(tmp|dev/shm|var/tmp|home|opt|srv)/|=\.)"     # LD_PRELOAD pointing to staging/user dirs or relative path
    "LD_LIBRARY_PATH=.*(/(tmp|dev/shm|var/tmp|home|opt|srv)/|=\.)" # LD_LIBRARY_PATH pointing to staging/user dirs or relative path
)

# Multi-line suspicious patterns (for heredocs, split commands, etc.)
# These patterns detect obfuscation techniques that span multiple lines
declare -a MULTILINE_SUSPICIOUS_PATTERNS=(
    "cat.*<<.*EOF.*bash"          # Heredoc to bash
    "cat.*<<.*EOF.*/dev/tcp"      # Heredoc with reverse shell
    "cat.*<<.*EOF.*curl"          # Heredoc with download
    "base64.*-d.*<<.*EOF"         # Base64 decode heredoc
    "eval.*<<.*EOF"               # Eval heredoc
    "python.*-c.*<<.*EOF"         # Python heredoc execution
    "perl.*-e.*<<.*EOF"           # Perl heredoc execution
    "rev.*\|.*(bash|sh|exec)"     # String reversal decode piped to shell
    "tr.*['\"].*['\"].*\|.*(bash|sh)"  # tr cipher decode piped to shell (ROT13/ROT47)
    "dd.*\|.*(bash|sh)"           # dd piped to shell
    "openssl.*-d.*\|.*(bash|sh)"  # OpenSSL decrypt piped to shell
    "base64.*-d.*\|.*(bash|sh)"   # Base64 decoded cross-line piped to shell
)

# Network indicators — hardcoded C2 destinations (IPs, suspicious TLDs, DGA, hex-encoded)
# These complement SUSPICIOUS_NETWORK_PATTERNS (which cover shell redirect techniques).
# Focus: destination indicators that appear in download/connect contexts in ANY file type.
declare -a NETWORK_INDICATOR_PATTERNS=(
    # Non-RFC1918 IP in download/connect context — RFC1918 exclusion is handled in
    # check_network_indicators() with bash arithmetic; this catches the broad pattern.
    "(curl|wget|fetch|ncat|nc|python|perl|ruby)[[:space:]]+['\"]?[a-zA-Z]*://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    # Suspicious TLD in download URL
    "(curl|wget|fetch)[^\"'[:space:]]{0,100}\.(ru|cn|onion|tk|xyz|top|pw|cc|biz)([/\"' )]|$)"
    # DGA-like: 16+ char single label subdomain in download context (CDN names are typically shorter)
    "(curl|wget|fetch)[^\"'[:space:]]{0,60}[a-z0-9-]{16,}\.(com|net|org|io|co)([/\"' )]|$)"
    # Hex-encoded IP: 4+ consecutive hex byte escapes (e.g. \x31\x39\x32\x2e)
    "(\\\\x[0-9a-fA-F]{2}){4}"
)

# Unified quick suspicious content check pattern (used by all modules).
# ISC-C1: Auto-derived in build_combined_patterns() from NEVER_WHITELIST + SUSPICIOUS_COMMANDS + SUSPICIOUS_NETWORK arrays.
# DO NOT hardcode this string here — it is set at startup from the authoritative arrays above.
UNIFIED_SUSPICIOUS_PATTERN=""

# Check if content matches suspicious patterns
# Returns: 0 if match found, 1 if no match
# Sets global MATCHED_PATTERN with the pattern that matched
# Sets global MATCHED_CATEGORY with the category (network, command, location, file)
# Sets global MATCHED_STRING with the actual string that matched from content
MATCHED_PATTERN=""
MATCHED_CATEGORY=""
MATCHED_STRING=""

# Pre-built combined regex patterns for fast initial detection (built once at startup)
# These are populated by build_combined_patterns() called in main()
COMBINED_NETWORK_PATTERN=""
COMBINED_COMMAND_PATTERN=""
COMBINED_LOCATION_PATTERN=""
COMBINED_FILE_PATTERN=""
COMBINED_NEVER_WHITELIST_PATTERN=""
COMBINED_KNOWN_GOOD_PATHS_PATTERN=""
COMBINED_MULTILINE_PATTERN=""
COMBINED_NETWORK_INDICATOR_PATTERN=""

# Performance: Package verify cache to avoid re-running dpkg/rpm --verify per package
# Format: PKG_VERIFY_CACHE["package_name"]="full verify output (may be empty if clean)"
declare -A PKG_VERIFY_CACHE

# Scan epoch captured once in main() — avoids date +%s subprocess inside per-file loops
SCAN_EPOCH=0

# Build combined regex patterns for faster matching
build_combined_patterns() {
    # Join array elements with | for regex alternation
    local IFS='|'
    COMBINED_NETWORK_PATTERN="(${SUSPICIOUS_NETWORK_PATTERNS[*]})"
    COMBINED_COMMAND_PATTERN="(${SUSPICIOUS_COMMANDS[*]})"
    COMBINED_LOCATION_PATTERN="(${SUSPICIOUS_LOCATIONS[*]})"
    COMBINED_FILE_PATTERN="(${SUSPICIOUS_FILES[*]})"
    COMBINED_NEVER_WHITELIST_PATTERN="(${NEVER_WHITELIST_PATTERNS[*]})"
    COMBINED_KNOWN_GOOD_PATHS_PATTERN="(${KNOWN_GOOD_EXECUTABLE_PATHS[*]})"
    COMBINED_MULTILINE_PATTERN="(${MULTILINE_SUSPICIOUS_PATTERNS[*]})"
    COMBINED_NETWORK_INDICATOR_PATTERN="(${NETWORK_INDICATOR_PATTERNS[*]})"

    # ISC-C1 FIX: Auto-derive UNIFIED_SUSPICIOUS_PATTERN from the authoritative arrays.
    # Previously this was a manually maintained string that diverged silently whenever
    # new patterns were added to SUSPICIOUS_COMMANDS or NEVER_WHITELIST_PATTERNS.
    # Now it is built from those combined patterns — zero drift guaranteed.
    UNIFIED_SUSPICIOUS_PATTERN="${COMBINED_NEVER_WHITELIST_PATTERN}|${COMBINED_COMMAND_PATTERN}|${COMBINED_NETWORK_PATTERN}|${COMBINED_NETWORK_INDICATOR_PATTERN}"
}

# Helper: Check single category and set match info
_check_category() {
    local content="$1"
    local category="$2"
    local combined_pattern="$3"
    shift 3
    local -a patterns=("$@")

    # Fast initial check with combined pattern (<<< avoids echo subshell fork)
    if ! grep -qE "$combined_pattern" <<< "$content" 2>/dev/null; then
        return 1  # No match in this category
    fi

    # Found something - now identify which specific pattern matched
    for pattern in "${patterns[@]}"; do
        local match
        match=$(grep -oE "$pattern" <<< "$content" 2>/dev/null | head -1) || true
        if [[ -n "$match" ]]; then
            MATCHED_PATTERN="$pattern"
            MATCHED_CATEGORY="$category"
            MATCHED_STRING="$match"
            return 0
        fi
    done

    return 1
}

# Network indicator check — detects hardcoded C2 destinations in any content type.
# Covers: non-RFC1918 IPs, suspicious TLDs, DGA-like long subdomains, hex-encoded IPs.
# Returns: 0 on match (sets MATCHED_PATTERN / MATCHED_STRING), 1 if clean.
check_network_indicators() {
    local content="$1"
    [[ -z "$content" ]] && return 1

    # Fast pre-filter: skip if combined pattern doesn't match at all
    grep -qE "$COMBINED_NETWORK_INDICATOR_PATTERN" <<< "$content" 2>/dev/null || return 1

    # ── Check 1: non-RFC1918 IP in network tool context ───────────────────────
    local _ni_line
    _ni_line=$(grep -oE "(curl|wget|fetch|ncat|nc|python|perl|ruby)[[:space:]]+['\"]?[a-zA-Z]*://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" \
        <<< "$content" 2>/dev/null | head -1) || true
    if [[ -n "$_ni_line" ]]; then
        # Extract the dotted-quad IP
        local _ip
        _ip=$(grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" <<< "$_ni_line" | head -1) || true
        if [[ -n "$_ip" ]]; then
            local _o1 _o2 _o3
            IFS=. read -r _o1 _o2 _o3 _ <<< "$_ip"
            local _is_private=false
            # 10.0.0.0/8
            [[ $_o1 -eq 10 ]] && _is_private=true
            # 127.0.0.0/8
            [[ $_o1 -eq 127 ]] && _is_private=true
            # 172.16.0.0/12
            [[ $_o1 -eq 172 && $_o2 -ge 16 && $_o2 -le 31 ]] && _is_private=true
            # 192.168.0.0/16
            [[ $_o1 -eq 192 && $_o2 -eq 168 ]] && _is_private=true
            # 169.254.0.0/16 (link-local)
            [[ $_o1 -eq 169 && $_o2 -eq 254 ]] && _is_private=true

            if [[ "$_is_private" == false ]]; then
                MATCHED_PATTERN="network_indicator_routable_ip"
                MATCHED_CATEGORY="indicator"
                MATCHED_STRING="${_ni_line:0:200}"
                return 0
            fi
        fi
    fi

    # ── Check 2: suspicious TLD in download URL ───────────────────────────────
    local _tld_line
    _tld_line=$(grep -oiE "(curl|wget|fetch)[^\"'[:space:]]{0,100}\.(ru|cn|onion|tk|xyz|top|pw|cc|biz)([/\"' )]|$)" \
        <<< "$content" 2>/dev/null | head -1) || true
    if [[ -n "$_tld_line" ]]; then
        MATCHED_PATTERN="network_indicator_suspicious_tld"
        MATCHED_CATEGORY="indicator"
        MATCHED_STRING="${_tld_line:0:200}"
        return 0
    fi

    # ── Check 3: DGA-like long subdomain in download URL ─────────────────────
    local _dga_line
    _dga_line=$(grep -oiE "(curl|wget|fetch)[^\"'[:space:]]{0,60}[a-z0-9-]{16,}\.(com|net|org|io|co)([/\"' )]|$)" \
        <<< "$content" 2>/dev/null | head -1) || true
    if [[ -n "$_dga_line" ]]; then
        MATCHED_PATTERN="network_indicator_dga_domain"
        MATCHED_CATEGORY="indicator"
        MATCHED_STRING="${_dga_line:0:200}"
        return 0
    fi

    # ── Check 4: hex-encoded IP bytes (4+ consecutive \xNN sequences) ─────────
    local _hex_line
    _hex_line=$(grep -oE "(\\\\x[0-9a-fA-F]{2}){4}" <<< "$content" 2>/dev/null | head -1) || true
    if [[ -n "$_hex_line" ]]; then
        MATCHED_PATTERN="network_indicator_hex_encoded"
        MATCHED_CATEGORY="indicator"
        MATCHED_STRING="${_hex_line:0:200}"
        return 0
    fi

    return 1
}

check_suspicious_patterns() {
    local content="$1"
    local pattern_type="${2:-all}"  # all, network, command, location, file

    # Reset globals
    MATCHED_PATTERN=""
    MATCHED_CATEGORY=""
    MATCHED_STRING=""

    # Skip empty content
    [[ -z "$content" ]] && return 1

    # Network-based patterns
    if [[ "$pattern_type" == "all" ]] || [[ "$pattern_type" == "network" ]]; then
        if _check_category "$content" "network" "$COMBINED_NETWORK_PATTERN" "${SUSPICIOUS_NETWORK_PATTERNS[@]}"; then
            return 0
        fi
    fi

    # Command-based patterns
    if [[ "$pattern_type" == "all" ]] || [[ "$pattern_type" == "command" ]]; then
        if _check_category "$content" "command" "$COMBINED_COMMAND_PATTERN" "${SUSPICIOUS_COMMANDS[@]}"; then
            return 0
        fi
    fi

    # Location-based patterns
    if [[ "$pattern_type" == "all" ]] || [[ "$pattern_type" == "location" ]]; then
        if _check_category "$content" "location" "$COMBINED_LOCATION_PATTERN" "${SUSPICIOUS_LOCATIONS[@]}"; then
            return 0
        fi
    fi

    # File-based patterns
    if [[ "$pattern_type" == "all" ]] || [[ "$pattern_type" == "file" ]]; then
        if _check_category "$content" "file" "$COMBINED_FILE_PATTERN" "${SUSPICIOUS_FILES[@]}"; then
            return 0
        fi
    fi

    # Network indicator patterns (C2 IPs, suspicious TLDs, DGA domains, hex IPs)
    if [[ "$pattern_type" == "all" ]] || [[ "$pattern_type" == "indicator" ]]; then
        if check_network_indicators "$content"; then
            return 0
        fi
    fi

    return 1  # No suspicious patterns found
}

# Quick suspicious content check using unified pattern
# Returns: 0 if suspicious content found, 1 if clean
# Faster than full check_suspicious_patterns for initial screening
quick_suspicious_check() {
    local content="$1"
    [[ -z "$content" ]] && return 1

    # <<< here-string avoids forking an echo subshell; grep is the only subprocess
    local full_line
    full_line=$(grep -iE "$UNIFIED_SUSPICIOUS_PATTERN" <<< "$content" | head -1) || true
    if [[ -n "$full_line" ]]; then
        MATCHED_PATTERN="unified_suspicious"
        # Bash-native trim (no sed/echo fork): strip leading spaces, trailing spaces, cap at 200
        full_line="${full_line#"${full_line%%[! ]*}"}"
        full_line="${full_line%"${full_line##*[! ]}"}"
        MATCHED_STRING="${full_line:0:200}"
        return 0
    fi
    return 1
}

################################################################################
# Utility Functions
################################################################################

show_usage() {
    cat << EOF
Usage: sudo ./persistnux.sh [OPTIONS]

Persistnux - Linux Persistence Detection Tool v2.4.0
Comprehensive DFIR tool to detect Linux persistence mechanisms

OPTIONS:
  -h, --help              Show this help message
  -a, --all               Show all findings (default: suspicious only)
  -m, --min-confidence    Minimum confidence level (LOW|MEDIUM|HIGH|CRITICAL)

ENVIRONMENT VARIABLES:
  OUTPUT_DIR              Custom output directory (default: ./persistnux_output)
  FILTER_MODE             Filter mode: "suspicious_only" or "all" (default: suspicious_only)
  MIN_CONFIDENCE          Minimum confidence filter (LOW|MEDIUM|HIGH|CRITICAL)

EXAMPLES:
  # Show only suspicious findings (MEDIUM, HIGH, CRITICAL)
  sudo ./persistnux.sh

  # Show all findings including baseline (LOW confidence)
  sudo ./persistnux.sh --all
  # OR
  sudo FILTER_MODE=all ./persistnux.sh

  # Show only HIGH and CRITICAL confidence findings
  sudo MIN_CONFIDENCE=HIGH ./persistnux.sh

  # Custom output directory
  sudo OUTPUT_DIR=/tmp/evidence ./persistnux.sh

CONFIDENCE LEVELS:
  LOW       - Baseline system configuration, package-managed files
  MEDIUM    - Potentially suspicious, requires review
  HIGH      - Suspicious patterns detected (reverse shells, download/execute)
  CRITICAL  - Highly suspicious, likely malicious

FALSE POSITIVE REDUCTION:
  - Package-managed files (dpkg/rpm) receive lower confidence scores
  - Known-good vendor services (systemd-*, dbus-*, snap.*) are skipped
  - Time-based analysis: recent modifications (<7 days) increase confidence

OUTPUT:
  - CSV format: persistnux_<hostname>_<timestamp>.csv
  - JSONL format: persistnux_<hostname>_<timestamp>.jsonl

EXIT CODES:
  0 - No CRITICAL findings
  1 - CRITICAL findings detected (for CI/CD integration)

For more information, see README.md and DFIR_GUIDE.md
EOF
}

print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
    ____                  _       __
   / __ \___  __________(_)____/ /___  __  ___  __
  / /_/ / _ \/ ___/ ___/ / ___/ __/ / / / |/_/ |/_/
 / ____/  __/ /  (__  ) (__  ) /_/ /_/ />  <_>  <
/_/    \___/_/  /____/_/____/\__/\__,_/_/|_/_/|_|

    Linux Persistence Detection Tool v2.4.0
    For DFIR Investigations
EOF
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

log_check() {
    (( CHECK_NUM++ )) || true
    log_info "[CHECK ${CHECK_NUM}] $1"
    # Write immediately to terminal so parallel-module progress is visible even before buffered output prints
    echo "[$(date '+%H:%M:%S')] [${MODULE_NAME:-?}] CHECK ${CHECK_NUM}: $1" >> /dev/tty 2>/dev/null || true
}

log_finding() {
    echo -e "${RED}[FINDING]${NC} $1"
    FINDINGS_COUNT=$((FINDINGS_COUNT + 1))
}

# Calculate file hash
get_file_hash() {
    local file="$1"
    # Return cached result if available (same file may be checked by multiple modules)
    if [[ -n "${FILE_HASH_CACHE[$file]+isset}" ]]; then
        echo "${FILE_HASH_CACHE[$file]}"
        return
    fi
    local result="N/A"
    if [[ -f "$file" ]] && [[ -r "$file" ]]; then
        local hash _
        read -r hash _ < <(sha256sum "$file" 2>/dev/null) || true
        result="${hash:-N/A}"
    fi
    FILE_HASH_CACHE["$file"]="$result"
    echo "$result"
}

# Get file metadata
get_file_metadata() {
    local file="$1"
    # Return cached result if available (stat is called once per file across all modules)
    if [[ -n "${FILE_METADATA_CACHE[$file]+isset}" ]]; then
        echo "${FILE_METADATA_CACHE[$file]}"
        return
    fi
    local result="N/A"
    if [[ -e "$file" ]]; then
        result=$(stat -c "mode:%a|owner:%U:%G|size:%s|modified:%Y|accessed:%X|changed:%Z" "$file" 2>/dev/null || echo "N/A")
    fi
    FILE_METADATA_CACHE["$file"]="$result"
    echo "$result"
}

# Initialize systemctl enabled status cache (called once at startup)
# Populates SYSTEMCTL_CACHE with all unit enabled states in single call
init_systemctl_cache() {
    if [[ "$SYSTEMCTL_CACHE_INITIALIZED" == "true" ]]; then
        return 0
    fi

    if ! command -v systemctl &> /dev/null; then
        SYSTEMCTL_CACHE_INITIALIZED=true
        return 0
    fi

    # Get all unit files and their states in one call
    # read -r splits columns without spawning awk subshells (unit state [vendor-preset])
    while read -r unit_name state _; do
        [[ -z "$unit_name" ]] && continue

        # Only cache service units
        if [[ "$unit_name" == *.service ]]; then
            if [[ "$state" == "enabled" ]] || [[ "$state" == "enabled-runtime" ]]; then
                SYSTEMCTL_CACHE["$unit_name"]="enabled"
            else
                SYSTEMCTL_CACHE["$unit_name"]="disabled"
            fi
        fi
    done < <(systemctl list-unit-files --type=service --no-pager --no-legend 2>/dev/null)

    SYSTEMCTL_CACHE_INITIALIZED=true
}

# Get systemctl enabled status from cache (avoids repeated systemctl calls)
get_systemctl_enabled_status() {
    local service_name="$1"

    # Ensure cache is initialized
    if [[ "$SYSTEMCTL_CACHE_INITIALIZED" != "true" ]]; then
        init_systemctl_cache
    fi

    # Return cached status or check directly if not in cache
    if [[ -n "${SYSTEMCTL_CACHE[$service_name]+isset}" ]]; then
        echo "${SYSTEMCTL_CACHE[$service_name]}"
    else
        # Not in cache - do single check and cache it
        if systemctl is-enabled "$service_name" &>/dev/null; then
            SYSTEMCTL_CACHE["$service_name"]="enabled"
            echo "enabled"
        else
            SYSTEMCTL_CACHE["$service_name"]="disabled"
            echo "disabled"
        fi
    fi
}

# Check if file is managed by package manager (reduces false positives)
# Uses PKG_CACHE for performance optimization
is_package_managed() {
    local file="$1"
    local original_file="$1"

    # Canonicalize path (resolve symlinks like /lib -> /usr/lib)
    # Some packages store canonical paths, others store symlink paths (e.g., kernel modules)
    # NOTE: only update file if realpath succeeds; a failed realpath with no output
    # would otherwise zero $file, causing dpkg -S "" to find nothing → false "unmanaged"
    if [[ -e "$file" ]]; then
        local canonical
        canonical=$(realpath "$file" 2>/dev/null) && file="$canonical" || true
    fi

    # Check cache first (performance optimization)
    if [[ -n "${PKG_CACHE[$file]+isset}" ]]; then
        local cached="${PKG_CACHE[$file]}"
        echo "$cached"
        if [[ "$cached" == *":MODIFIED" ]]; then
            return 2
        elif [[ "$cached" == "unmanaged" ]]; then
            return 1
        else
            return 0
        fi
    fi

    local result=""
    local ret_code=1

    # Check snap packages - files under /snap/ or /var/lib/snapd/ are snap-managed.
    # ISC-C9 FIX: Also cover ~/snap/ user installs. Previous check anchored to ^/snap/,
    # missing /home/user/snap/ and /root/snap/ (user-installed snaps).
    # Unanchored /snap/ match covers all snap paths without over-matching (snap is a
    # very specific directory name that doesn't appear in false contexts).
    if [[ "$file" =~ /snap/ ]] || [[ "$file" =~ ^/var/lib/snapd/ ]]; then
        result="snap:managed"
        PKG_CACHE["$file"]="$result"
        echo "$result"
        return 0
    fi

    # Check flatpak packages - files under flatpak dirs are flatpak-managed
    if [[ "$file" =~ ^/var/lib/flatpak/ ]] || [[ "$file" =~ ^/run/host/usr/ ]]; then
        result="flatpak:managed"
        PKG_CACHE["$file"]="$result"
        echo "$result"
        return 0
    fi

    # ISC-C11 FIX: Runtime package managers (npm, pip, cargo) install to paths that
    # dpkg/rpm don't own. Treat these as "runtime-managed" to reduce FP floods on
    # developer machines. adjust_confidence_for_package() downgrades these the same
    # way it handles dpkg-managed files (HIGH→MEDIUM, MEDIUM→LOW).
    if [[ "$file" =~ /node_modules/ ]] || \
       [[ "$file" =~ /site-packages/ ]] || \
       [[ "$file" =~ /dist-packages/ ]] || \
       [[ "$file" =~ /.cargo/registry/ ]] || \
       [[ "$file" =~ /.cargo/bin/ ]] || \
       [[ "$file" =~ /go/pkg/mod/ ]] || \
       [[ "$file" =~ /gems/gems/ ]] || \
       [[ "$file" =~ /.local/lib/python ]] || \
       [[ "$file" =~ /.local/share/virtualenvs/ ]]; then
        result="runtime-managed"
        PKG_CACHE["$file"]="$result"
        echo "$result"
        return 0
    fi

    # Check dpkg (Debian/Ubuntu) - guarded cascade: each fallback dpkg -S only runs
    # if the previous attempt returned empty (PERF-1: avoids redundant dpkg calls)
    if command -v dpkg &> /dev/null; then
        local dpkg_output
        dpkg_output=$(timeout 5 dpkg -S "$file" 2>/dev/null) || true

        # If canonical path lookup fails, try original path (kernel modules use /lib/modules not /usr/lib/modules)
        if [[ -z "$dpkg_output" ]] && [[ "$file" != "$original_file" ]]; then
            dpkg_output=$(timeout 5 dpkg -S "$original_file" 2>/dev/null) || true
            # Use original path for subsequent checks if it matched
            [[ -n "$dpkg_output" ]] && file="$original_file"
        fi

        # dpkg does NOT resolve symlinks in -S queries. On merged-/usr systems
        # (Ubuntu 22.04+) /lib -> usr/lib, so dpkg stores /usr/lib/... paths.
        # On pre-merge systems, dpkg stores /lib/... paths.
        # Try the alternate form so both generations of Ubuntu work correctly.
        if [[ -z "$dpkg_output" ]]; then
            local alt_path=""
            if [[ "$file" == /usr/lib/* ]]; then
                alt_path="/lib/${file#/usr/lib/}"
            elif [[ "$file" == /usr/bin/* ]]; then
                alt_path="/bin/${file#/usr/bin/}"
            elif [[ "$file" == /usr/sbin/* ]]; then
                alt_path="/sbin/${file#/usr/sbin/}"
            elif [[ "$file" == /lib/* ]]; then
                alt_path="/usr/lib/${file#/lib/}"
            elif [[ "$file" == /bin/* ]]; then
                alt_path="/usr/bin/${file#/bin/}"
            elif [[ "$file" == /sbin/* ]]; then
                alt_path="/usr/sbin/${file#/sbin/}"
            fi
            if [[ -n "$alt_path" ]]; then
                dpkg_output=$(timeout 5 dpkg -S "$alt_path" 2>/dev/null) || true
                [[ -n "$dpkg_output" ]] && file="$alt_path"
            fi
        fi

        if [[ -n "$dpkg_output" ]]; then
            local package=$(echo "$dpkg_output" | cut -d':' -f1 | head -n1)

            # Verify file hasn't been tampered with
            # PKG_VERIFY_CACHE: dpkg --verify scans ALL files in a package — cache by package
            # name so multiple files from the same package share one verification run
            # Use " $file" (space prefix) to prevent substring false-match on short paths
            # e.g. /usr/bin/py would otherwise match /usr/bin/python3 in verify output
            local full_verify
            if [[ -n "${PKG_VERIFY_CACHE[$package]+isset}" ]]; then
                full_verify="${PKG_VERIFY_CACHE[$package]}"
            else
                full_verify=$(timeout 15 dpkg --verify "$package" 2>/dev/null) || true
                PKG_VERIFY_CACHE["$package"]="$full_verify"
            fi
            local verify_output
            verify_output=$(echo "$full_verify" | grep -F " $file")
            if [[ -n "$verify_output" ]]; then
                # File has been modified - flag as compromised
                result="dpkg:$package:MODIFIED"
                ret_code=2
            else
                result="dpkg:$package"
                ret_code=0
            fi

            # Cache the result
            PKG_CACHE["$file"]="$result"
            echo "$result"
            return $ret_code
        fi
    fi

    # Check rpm (RedHat/CentOS/Fedora) - single call to avoid duplicate lookups
    if command -v rpm &> /dev/null; then
        local rpm_output
        rpm_output=$(rpm -qf "$file" 2>/dev/null) || true

        # If canonical path lookup fails, try original path
        if { [[ -z "$rpm_output" ]] || [[ "$rpm_output" == *"not owned"* ]]; } && [[ "$file" != "$original_file" ]]; then
            rpm_output=$(rpm -qf "$original_file" 2>/dev/null) || true
            # Use original path for subsequent checks if it matched
            [[ -n "$rpm_output" ]] && [[ "$rpm_output" != *"not owned"* ]] && file="$original_file"
        fi

        if [[ -n "$rpm_output" ]] && [[ "$rpm_output" != *"not owned"* ]]; then
            local package=$(echo "$rpm_output" | head -n1)

            # Verify file integrity using rpm -V
            # PKG_VERIFY_CACHE: rpm -V scans ALL files in a package — cache by package name
            # Use " $file" (space prefix) to prevent substring false-match on short paths
            local full_verify
            if [[ -n "${PKG_VERIFY_CACHE[$package]+isset}" ]]; then
                full_verify="${PKG_VERIFY_CACHE[$package]}"
            else
                full_verify=$(rpm -V "$package" 2>/dev/null) || true
                PKG_VERIFY_CACHE["$package"]="$full_verify"
            fi
            local verify_output
            verify_output=$(echo "$full_verify" | grep -F " $file")
            if [[ -n "$verify_output" ]]; then
                # File has been modified
                result="rpm:$package:MODIFIED"
                ret_code=2
            else
                result="rpm:$package"
                ret_code=0
            fi

            # Cache the result
            PKG_CACHE["$file"]="$result"
            echo "$result"
            return $ret_code
        fi
    fi

    # Check pacman (Arch Linux / Manjaro / EndeavourOS)
    if command -v pacman &> /dev/null; then
        local pacman_output
        pacman_output=$(pacman -Qo "$file" 2>/dev/null) || true

        if [[ -n "$pacman_output" ]] && [[ "$pacman_output" != *"No package"* ]]; then
            local package
            package=$(echo "$pacman_output" | awk '{print $(NF-1)}')

            # Verify with pacman -Qkk (check file integrity for package)
            # PKG_VERIFY_CACHE: pacman -Qkk scans the whole package — cache by package name
            local full_verify
            if [[ -n "${PKG_VERIFY_CACHE[$package]+isset}" ]]; then
                full_verify="${PKG_VERIFY_CACHE[$package]}"
            else
                full_verify=$(pacman -Qkk "$package" 2>/dev/null | grep -v "^warning") || true
                PKG_VERIFY_CACHE["$package"]="$full_verify"
            fi
            local verify_output
            verify_output=$(echo "$full_verify" | grep -F " $file")
            if [[ -n "$verify_output" ]]; then
                result="pacman:$package:MODIFIED"
                ret_code=2
            else
                result="pacman:$package"
                ret_code=0
            fi

            PKG_CACHE["$file"]="$result"
            echo "$result"
            return $ret_code
        fi
    fi

    # Check apk (Alpine Linux)
    if command -v apk &>/dev/null; then
        if apk info --who-owns "$file" 2>/dev/null | grep -q "is owned by"; then
            result="apk:managed"
            PKG_CACHE["$file"]="$result"
            echo "$result"
            return 0
        fi
    fi

    # Not managed by package manager - cache and return
    PKG_CACHE["$file"]="unmanaged"
    echo "unmanaged"
    return 1
}

# Convenience wrapper: calls is_package_managed and stores result in global PKG_STATUS.
# Used by new v2.4.0 modules (bootloader, polkit, dbus, udev, container, binary_integrity)
# so callers don't need to capture stdout — they just read $PKG_STATUS after the call.
# Uses || pattern to prevent set -eo pipefail from aborting on return 1 (unmanaged)
# or return 2 (modified), both of which are expected non-zero return codes.
check_file_package() {
    PKG_STATUS=$(is_package_managed "$1" 2>/dev/null) || PKG_STATUS="${PKG_STATUS:-unmanaged}"
}

# Extract the first executable path from a command
get_executable_from_command() {
    local command="$1"

    # Remove ALL systemd prefixes (@, -, :, +, !) - can be multiple like !!
    while [[ "$command" =~ ^[@:+!\-] ]]; do
        command="${command#?}"
    done

    # Strip leading KEY=VALUE environment variable assignments
    # e.g. "LD_PRELOAD=/tmp/evil.so /usr/bin/sshd -D" -> "/usr/bin/sshd -D"
    while [[ "$command" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; do
        command="${command#* }"
        # If no space found (only one token), stop
        [[ "$command" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || break
    done

    # Extract first word (the executable)
    local executable; read -r executable _ <<< "$command"

    # Remove quotes if present
    executable="${executable//\"/}"
    executable="${executable//\'/}"

    # If it's not an absolute path, try to resolve it using PATH
    if [[ -n "$executable" ]] && [[ "$executable" != /* ]]; then
        local resolved
        resolved=$(command -v "$executable" 2>/dev/null) || true
        if [[ -n "$resolved" ]]; then
            executable="$resolved"
        fi
    fi

    echo "$executable"
}

# Check if executable is a known interpreter (python, perl, bash, etc.)
# Uses regex patterns for version flexibility (e.g., python3.13, pypy3)
is_interpreter() {
    local executable="$1"
    local basename=$(basename "$executable")

    for pattern in "${KNOWN_INTERPRETER_PATTERNS[@]}"; do
        if [[ "$basename" =~ $pattern ]]; then
            return 0  # Is an interpreter
        fi
    done

    return 1  # Not an interpreter
}

# Extract the script file path from an interpreter command
# Example: "/usr/bin/python3 /opt/app/malware.py --daemon" -> "/opt/app/malware.py"
get_script_from_interpreter_command() {
    local command="$1"

    # Remove systemd prefixes
    command="${command#[@\-:+!]}"

    # Parse command into array of arguments safely (avoid eval)
    # Use read with IFS to split, handling the command safely
    local -a args

    # Simple word splitting - handles most cases without eval dangers
    # First, normalize whitespace
    command=$(echo "$command" | tr -s '[:space:]' ' ')

    # Read into array using simple word splitting
    read -ra args <<< "$command" 2>/dev/null || {
        # If read fails, try basic splitting
        IFS=' ' read -ra args <<< "$command"
    }

    # If no args parsed, return failure
    if [[ ${#args[@]} -eq 0 ]]; then
        echo ""
        return 1
    fi

    # First arg is the interpreter
    local interpreter="${args[0]}"

    # Look through remaining arguments for the script file
    for ((i=1; i<${#args[@]}; i++)); do
        local arg="${args[i]}"

        # Special case: -c flag means inline code, not a file
        if [[ "$arg" == "-c" ]]; then
            # Next arg is inline code, not a file path
            echo ""
            return 1
        fi

        # Special case: -m flag for Python modules
        if [[ "$arg" == "-m" ]]; then
            # Next arg is a module name, not a file
            i=$((i+1))
            continue
        fi

        # Skip other interpreter flags (start with -)
        if [[ "$arg" =~ ^- ]]; then
            continue
        fi

        # This looks like a file path (not a flag)
        # Clean up quotes first
        arg="${arg#\"}"
        arg="${arg#\'}"
        arg="${arg%\"}"
        arg="${arg%\'}"

        # Check if it's an absolute path or relative path
        if [[ "$arg" =~ ^/ ]] || [[ "$arg" =~ ^\./ ]] || [[ "$arg" =~ ^\.\. ]] || [[ -f "$arg" ]]; then
            echo "$arg"
            return 0
        fi
    done

    # No script file found
    echo ""
    return 1
}

# Resolve the actual execution target from a command string for the 'command' output field.
# - interpreter + /path/to/script  → returns /path/to/script
# - interpreter + -c 'code'        → returns the inline code string
# - interpreter + -e 'code'        → returns the inline code string (perl)
# - direct executable / empty      → returns the input unchanged
resolve_command_target() {
    local cmd="$1"
    [[ -z "$cmd" ]] && return 0

    # Strip leading systemd exec modifiers (@, :, +, !, -)
    while [[ "$cmd" =~ ^[@:+!\-] ]]; do cmd="${cmd#?}"; done
    cmd=$(echo "$cmd" | tr -s '[:space:]' ' ')
    cmd="${cmd## }"; cmd="${cmd%% }"

    # Get first token to check if it's a known interpreter
    local first_token
    read -r first_token _ <<< "$cmd"
    if ! is_interpreter "$first_token" 2>/dev/null; then
        echo "$cmd"
        return 0
    fi

    # It's an interpreter — parse arguments
    local -a args
    read -ra args <<< "$cmd" 2>/dev/null || IFS=' ' read -ra args <<< "$cmd"

    local i
    for ((i=1; i<${#args[@]}; i++)); do
        local arg="${args[i]}"
        # -c (bash/python/ruby/node) or -e (perl) — next token(s) are inline code
        if [[ "$arg" == "-c" ]] || [[ "$arg" == "-e" ]]; then
            # Join everything after this flag as the inline code
            local inline="${args[*]:$((i+1))}"
            # Strip surrounding quotes if present
            inline="${inline#\'}" ; inline="${inline%\'}"
            inline="${inline#\"}" ; inline="${inline%\"}"
            echo "$inline"
            return 0
        fi
        # Skip other flags
        [[ "$arg" =~ ^- ]] && continue
        # First non-flag argument is the script path — strip quotes and return
        arg="${arg#\"}" ; arg="${arg%\"}"
        arg="${arg#\'}" ; arg="${arg%\'}"
        echo "$arg"
        return 0
    done

    # Interpreter with no resolvable target — return full command
    echo "$cmd"
}

# Check if a file is a script (not binary/ELF)
is_script() {
    local file="$1"

    # Check if file exists and is readable
    if [[ ! -f "$file" ]] || [[ ! -r "$file" ]]; then
        return 1  # Not a script
    fi

    # First check: look for shebang (most reliable for scripts)
    # Read first line and check for #! without using command substitution on binary files
    if head -n 1 "$file" 2>/dev/null | grep -qm1 "^#!"; then
        return 0  # Has shebang, it's a script
    fi

    # Second check: Use file command mime type (cleaner, no descriptive text with potential nulls)
    # Check MIME type instead of description to avoid null bytes in output
    local mime_type=$(file -b --mime-type "$file" 2>/dev/null)
    if [[ "$mime_type" == text/* ]] || [[ "$mime_type" == application/x-shellscript ]] || [[ "$mime_type" == application/x-*script ]]; then
        return 0  # It's a text/script file
    fi

    return 1  # Not a script (likely binary)
}

# Calculate entropy using hybrid approach:
# - Strings < 30 chars: Skip (too short)
# - Strings 30-199 chars: Use AWK Shannon entropy (accurate for medium strings)
# - Strings 200+ chars: Use gzip compression ratio (efficient for long strings)
# High entropy (>4.5) indicates random/encrypted/obfuscated data
# Returns entropy as float (0.0-8.0)
calculate_entropy() {
    local data="$1"
    local length=${#data}

    # Return 0 for empty or very short strings (not enough data)
    if [[ $length -lt 30 ]]; then
        echo "0"
        return
    fi

    # For very long strings (200+), use gzip compression ratio
    # Extended Shannon range (30-199) for better accuracy on medium-length strings
    if [[ $length -ge 200 ]]; then
        # Check if gzip is available
        if ! command -v gzip &> /dev/null; then
            # Fallback: single awk pass (1 subprocess vs fold|sort|uniq|awk = 4)
            local entropy
            entropy=$(printf '%s' "$data" | awk -v len="$length" '
                {
                    n = length($0)
                    for (i = 1; i <= n; i++) freq[substr($0, i, 1)]++
                }
                END {
                    entropy = 0
                    for (c in freq) {
                        p = freq[c] / len
                        if (p > 0) entropy -= p * log(p) / log(2)
                    }
                    printf "%.2f", entropy
                }
            ')
            echo "$entropy"
            return
        fi

        local compressed_size=$(echo -n "$data" | gzip -c 2>/dev/null | wc -c)

        # Handle gzip failure - fallback: single awk pass
        if [[ -z "$compressed_size" ]] || [[ "$compressed_size" -eq 0 ]]; then
            local entropy
            entropy=$(printf '%s' "$data" | awk -v len="$length" '
                {
                    n = length($0)
                    for (i = 1; i <= n; i++) freq[substr($0, i, 1)]++
                }
                END {
                    entropy = 0
                    for (c in freq) {
                        p = freq[c] / len
                        if (p > 0) entropy -= p * log(p) / log(2)
                    }
                    printf "%.2f", entropy
                }
            ')
            echo "$entropy"
            return
        fi

        # Subtract gzip header overhead (~18 bytes)
        local adjusted_compressed=$((compressed_size - 18))
        [[ $adjusted_compressed -lt 0 ]] && adjusted_compressed=0

        # Calculate compression ratio
        local ratio=$(awk "BEGIN {printf \"%.2f\", $adjusted_compressed / $length}")

        # Convert ratio to approximate entropy
        # Ratio 0.0-0.4 (highly compressible) → Entropy ~2.0-3.5 (low)
        # Ratio 0.4-0.7 (normal text)        → Entropy ~3.5-4.5 (medium)
        # Ratio 0.7-0.9 (base64/encoded)     → Entropy ~4.5-6.0 (high)
        # Ratio 0.9-1.0+ (random/encrypted)  → Entropy ~6.0-8.0 (very high)
        local entropy=$(awk "BEGIN {
            ratio = $ratio
            if (ratio < 0.4) entropy = 2.0 + (ratio / 0.4) * 1.5
            else if (ratio < 0.7) entropy = 3.5 + ((ratio - 0.4) / 0.3) * 1.0
            else if (ratio < 0.9) entropy = 4.5 + ((ratio - 0.7) / 0.2) * 1.5
            else entropy = 6.0 + ((ratio - 0.9) / 0.1) * 2.0
            printf \"%.2f\", entropy
        }")

        echo "$entropy"
    else
        # For medium strings (30-199): single awk pass replaces fold|sort|uniq|awk (4→1 subprocess)
        local entropy
        entropy=$(printf '%s' "$data" | awk -v len="$length" '
            {
                n = length($0)
                for (i = 1; i <= n; i++) freq[substr($0, i, 1)]++
            }
            END {
                entropy = 0
                for (c in freq) {
                    p = freq[c] / len
                    if (p > 0) entropy -= p * log(p) / log(2)
                }
                printf "%.2f", entropy
            }
        ')

        echo "$entropy"
    fi
}

# Check if a line/string has suspiciously high entropy
# Returns 0 if high entropy detected, 1 if normal
is_high_entropy() {
    local string="$1"
    local threshold="${2:-4.5}"  # Default threshold 4.5 (base64 is ~6.0, random is ~7.9)
    local length=${#string}

    # Skip very short strings (not enough data)
    if [[ $length -lt 30 ]]; then
        return 1
    fi

    if [[ $length -ge 200 ]]; then
        # Long strings: use gzip-compression path in calculate_entropy (complex to inline)
        local entropy
        entropy=$(calculate_entropy "$string")
        # Single awk for float comparison only (calculate_entropy already did the heavy work)
        awk -v e="$entropy" -v t="$threshold" 'BEGIN { exit (e > t) ? 0 : 1 }'
        return $?
    else
        # Short/medium strings (30-199 chars): single awk does entropy + comparison
        # Saves one subprocess vs the two-step calculate_entropy → compare pattern
        printf '%s' "$string" | awk -v len="$length" -v t="$threshold" '
            {
                n = length($0)
                for (i = 1; i <= n; i++) freq[substr($0, i, 1)]++
            }
            END {
                entropy = 0
                for (c in freq) {
                    p = freq[c] / len
                    if (p > 0) entropy -= p * log(p) / log(2)
                }
                exit (entropy > t) ? 0 : 1
            }
        '
        return $?
    fi
}

# Analyze script content for suspicious patterns
# Returns 0 if suspicious content found, 1 if clean
# Optimized: Uses combined regex patterns for single-pass matching
analyze_script_content() {
    local script_file="$1"

    # Check if file exists and is readable
    if [[ ! -f "$script_file" ]] || [[ ! -r "$script_file" ]]; then
        return 1  # Cannot analyze, treat as clean
    fi

    # Read first 1000 lines of script (to avoid huge files)
    # Strip null bytes to prevent bash warnings with binary content
    local script_content
    script_content=$(head -n 1000 "$script_file" 2>/dev/null | tr -d '\0') || true

    # ISC-C3 FIX: Also scan mid-zone and tail for large files.
    # Previous: head-1000 + tail-200 left lines 1001-to-(N-200) as a blind spot.
    # Attackers can pad with 800 benign lines, insert payload at 801, then add 600 more.
    # Solution: add a 200-line mid-zone sample so any zone evasion requires 3x padding.
    local line_count
    line_count=$(wc -l < "$script_file" 2>/dev/null || echo 0)
    if [[ $line_count -gt 1000 ]]; then
        local tail_content
        tail_content=$(tail -n 200 "$script_file" 2>/dev/null | tr -d '\0') || true
        script_content="${script_content}"$'\n'"${tail_content}"
    fi
    if [[ $line_count -gt 1200 ]]; then
        local mid=$((line_count / 2))
        local mid_start=$(( mid - 100 ))
        [[ $mid_start -lt 1 ]] && mid_start=1
        local mid_content
        mid_content=$(sed -n "${mid_start},$((mid_start + 199))p" "$script_file" 2>/dev/null | tr -d '\0') || true
        script_content="${script_content}"$'\n'"${mid_content}"
    fi

    # ISC-C4 FIX: Strip comment lines before pattern matching.
    # Comment lines (# example: curl http://evil.com | bash) in educational/historical scripts
    # caused false positives. The entropy loop keeps using raw content (variable assignments
    # inside comments are noise anyway). All grep pattern checks use script_content_clean.
    local script_content_clean
    script_content_clean=$(echo "$script_content" | grep -Ev '^[[:space:]]*#') || true

    # Check dangerous patterns using pre-built combined pattern (built once at startup)
    # Uses script_content_clean (comments stripped) to avoid FP on educational examples
    if [[ -n "$COMBINED_NEVER_WHITELIST_PATTERN" ]]; then
        local full_line
        full_line=$(grep -iE "$COMBINED_NEVER_WHITELIST_PATTERN" <<< "$script_content_clean" | head -1) || true
        if [[ -n "$full_line" ]]; then
            MATCHED_PATTERN="never_whitelist"
            full_line="${full_line#"${full_line%%[! ]*}"}"
            full_line="${full_line%"${full_line##*[! ]}"}"
            MATCHED_STRING="${full_line:0:200}"
            return 0  # SUSPICIOUS - found dangerous pattern
        fi
    fi

    # ISC-C2 FIX: Use COMBINED_COMMAND_PATTERN (auto-built from SUSPICIOUS_COMMANDS array)
    # instead of the orphan hand-maintained script_pattern_combined string.
    # This ensures analyze_script_content() is always in sync with SUSPICIOUS_COMMANDS.
    if [[ -n "$COMBINED_COMMAND_PATTERN" ]]; then
        local full_line
        full_line=$(grep -iE "$COMBINED_COMMAND_PATTERN" <<< "$script_content_clean" | head -1) || true
        if [[ -n "$full_line" ]]; then
            MATCHED_PATTERN="script_suspicious"
            full_line="${full_line#"${full_line%%[! ]*}"}"
            full_line="${full_line%"${full_line##*[! ]}"}"
            MATCHED_STRING="${full_line:0:200}"

            # ISC-C6 FIX: If the matched line contains an interpreter -c/-e flag, extract
            # and deeply analyze the inline code argument. analyze_cron_command() already does
            # this; now analyze_script_content() does too, catching obfuscated payloads inside
            # bash -c '...', python -c '...', perl -e '...' etc. embedded in script files.
            if echo "$full_line" | grep -qiE '(bash|sh|dash|zsh|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*)[[:space:]].*-[ce][[:space:]]'; then
                if analyze_inline_code "$full_line"; then
                    MATCHED_PATTERN="script_suspicious+inline:${INLINE_CODE_REASON}"
                fi
            fi

            return 0  # SUSPICIOUS - found dangerous script pattern
        fi
    fi

    # Check for multi-line suspicious patterns using pre-built combined pattern (1 grep vs N)
    # Uses tr to convert newlines to spaces for cross-line matching
    # Uses script_content_clean (comments stripped) to avoid FP on commented examples
    local content_single_line
    content_single_line=$(echo "$script_content_clean" | tr '\n' ' ')
    if [[ -n "$COMBINED_MULTILINE_PATTERN" ]]; then
        local full_line
        full_line=$(grep -iE "$COMBINED_MULTILINE_PATTERN" <<< "$content_single_line" | head -1) || true
        if [[ -n "$full_line" ]]; then
            MATCHED_PATTERN="multiline_suspicious"
            MATCHED_STRING="${full_line:0:200}"
            return 0  # SUSPICIOUS - found multi-line dangerous pattern
        fi
    fi

    # Check for encoding-based obfuscation (hex/octal/ANSI-C encoding)
    # Legitimate scripts have no reason to encode strings this way.
    # 4+ consecutive hex/octal = intentional encoding. 2+ ANSI-C sequences = intentional.

    # Hex escape sequences: \x41\x42\x43 (shell/perl/python style)
    local hex_line
    hex_line=$(grep -E '(\\x[0-9a-fA-F]{2}){4,}' <<< "$script_content_clean" | head -1) || true
    if [[ -n "$hex_line" ]]; then
        MATCHED_PATTERN="hex_encoding"
        hex_line="${hex_line#"${hex_line%%[! ]*}"}"
        hex_line="${hex_line%"${hex_line##*[! ]}"}"
        MATCHED_STRING="${hex_line:0:200}"
        return 0  # SUSPICIOUS - hex-encoded payload
    fi

    # Octal escape sequences: \101\102\060 (shell/perl style)
    local octal_line
    octal_line=$(grep -E '(\\[0-7]{3}){4,}' <<< "$script_content_clean" | head -1) || true
    if [[ -n "$octal_line" ]]; then
        MATCHED_PATTERN="octal_encoding"
        octal_line="${octal_line#"${octal_line%%[! ]*}"}"
        octal_line="${octal_line%"${octal_line##*[! ]}"}"
        MATCHED_STRING="${octal_line:0:200}"
        return 0  # SUSPICIOUS - octal-encoded payload
    fi

    # ANSI-C quoting: $'\x41\x62\x63' (bash-specific hex encoding in strings)
    # Threshold lowered from {3,} to {2,}: 2 encoded chars is already intentional
    # Short payloads like $'\x62\x61\x73\x68' ("bash") were previously missed at {3,}
    local ansi_line
    ansi_line=$(grep -E "\\\$'(\\\\x[0-9a-fA-F]{2}|\\\\[0-7]{3}){2,}'" <<< "$script_content_clean" | head -1) || true
    if [[ -n "$ansi_line" ]]; then
        MATCHED_PATTERN="ansi_c_encoding"
        ansi_line="${ansi_line#"${ansi_line%%[! ]*}"}"
        ansi_line="${ansi_line%"${ansi_line##*[! ]}"}"
        MATCHED_STRING="${ansi_line:0:200}"
        return 0  # SUSPICIOUS - ANSI-C encoded payload
    fi

    # tr-based character substitution piped to execution (ROT13, ROT47, custom ciphers)
    # Pattern: tr '...' '...' | bash/sh  — obfuscation via character rotation
    local tr_exec_line
    tr_exec_line=$(grep -iE "tr[[:space:]]+['\"].+['\"].*\|[[:space:]]*(bash|sh|dash|zsh|exec)" <<< "$script_content_clean" | head -1) || true
    if [[ -n "$tr_exec_line" ]]; then
        MATCHED_PATTERN="tr_cipher_obfuscation"
        tr_exec_line="${tr_exec_line#"${tr_exec_line%%[! ]*}"}"
        tr_exec_line="${tr_exec_line%"${tr_exec_line##*[! ]}"}"
        MATCHED_STRING="${tr_exec_line:0:200}"
        return 0  # SUSPICIOUS - tr cipher obfuscation piped to shell
    fi

    # rev-based string reversal piped to execution
    local rev_exec_line
    rev_exec_line=$(grep -iE "rev[[:space:]]*\|[[:space:]]*(bash|sh|dash|zsh)" <<< "$script_content_clean" | head -1) || true
    if [[ -n "$rev_exec_line" ]]; then
        MATCHED_PATTERN="rev_obfuscation"
        rev_exec_line="${rev_exec_line#"${rev_exec_line%%[! ]*}"}"
        rev_exec_line="${rev_exec_line%"${rev_exec_line##*[! ]}"}"
        MATCHED_STRING="${rev_exec_line:0:200}"
        return 0  # SUSPICIOUS - string reversal piped to shell
    fi

    # Language-specific network/exec patterns (Python, Perl, Ruby)
    # These appear in scripts that use language stdlib instead of shell commands,
    # making them invisible to shell-command pattern checks.
    local lang_exec_line
    lang_exec_line=$(grep -oE \
        "socket\.connect\(|pty\.spawn\(|subprocess\.Popen[^)]{0,60}shell[[:space:]]*=[[:space:]]*True|os\.(system|popen|exec[vl]p?)\(|TCPSocket\.new\(" \
        <<< "$script_content_clean" | head -1) || true
    if [[ -n "$lang_exec_line" ]]; then
        MATCHED_PATTERN="language_network_exec"
        MATCHED_STRING="${lang_exec_line:0:200}"
        return 0  # SUSPICIOUS - language-specific network or shell-execution pattern
    fi

    # High-entropy string detection -- single awk pass (avoids per-line subprocess cost)
    local _entropy_hit
    _entropy_hit=$(awk '
        /^[[:space:]]*#/ { next }
        /=/ {
            # POSIX awk: 2-arg match() + RSTART/RLENGTH (no gawk-only 3-arg match)
            val = ""
            if (match($0, /="[^"]{30,}"/)) {
                val = substr($0, RSTART+2, RLENGTH-3)
            } else if (match($0, /='"'"'[^'"'"']{30,}'"'"'/)) {
                val = substr($0, RSTART+2, RLENGTH-3)
            } else if (match($0, /=[^[:space:]"'"'"']{30,}/)) {
                val = substr($0, RSTART+1, RLENGTH-1)
            }
            if (val == "") next
            # Compute Shannon entropy
            n = length(val)
            if (n < 30) next
            delete freq
            for (i=1; i<=n; i++) freq[substr(val,i,1)]++
            ent = 0
            for (c in freq) { p = freq[c]/n; ent -= p * log(p)/log(2) }
            if (ent >= 4.5) {
                # Only flag if execution context present on same line
                if ($0 ~ /eval|exec[[:space:]]|base64.*-d|bash[[:space:]]|sh -c|openssl.*-d/) {
                    print substr(val, 1, 50)
                    exit
                }
            }
        }
    ' <<< "$script_content_clean") || true

    if [[ -n "$_entropy_hit" ]]; then
        MATCHED_PATTERN="high_entropy_exec"
        MATCHED_STRING="${_entropy_hit}..."
        return 0
    fi

    return 1  # Clean - no suspicious patterns found
}

# Analyze a content string (not a file path) for suspicious patterns.
# Writes content to a temp file, calls analyze_script_content(), cleans up.
# Use this at all call sites that have content in a variable, not a file path.
analyze_content_string() {
    local content="$1"
    local context_label="${2:-}"   # for logging only

    [[ -z "$content" ]] && return 1

    local _tmp_file
    _tmp_file=$(mktemp /tmp/persistnux_content_XXXXXX) || return 1
    printf '%s' "$content" > "$_tmp_file"

    local _result=1
    analyze_script_content "$_tmp_file" && _result=0
    rm -f "$_tmp_file"
    return $_result
}

# Analyze inline code content for suspicious patterns and obfuscation
# Used for: interpreter -c "code" or interpreter -e "code"
# Returns: 0 if suspicious, 1 if clean
# Sets INLINE_CODE_REASON with detection details
INLINE_CODE_REASON=""
analyze_inline_code() {
    local full_command="$1"
    INLINE_CODE_REASON=""

    # Extract the inline code from -c "..." or -e "..." patterns
    local inline_code=""

    # BUG-5 fix: match same-type quotes to avoid greedy cross-section capture.
    # Old pattern [\"\'](.+)[\"\'] was greedy and would match from the first quote
    # to the LAST quote anywhere in the string, capturing unrelated trailing args.
    # e.g. python3 -c 'code' "argv0" → old captured: code' "argv0  (wrong)
    #
    # BUG-6 fix: unquoted fallback now captures to end-of-string, not just one word.
    # Old pattern ([^\ ]+) captured only the first word.
    # e.g. bash -c echo foo → old captured: echo  (wrong, missed: foo)

    # Store quote-containing patterns in variables to avoid bash parser misinterpretation
    local _sq_pat="[[:space:]]-[ce][[:space:]]+'([^']+)'"
    local _dq_pat='[[:space:]]-[ce][[:space:]]+"([^"]+)"'

    # Try single-quoted form: -c 'code content here'
    if [[ "$full_command" =~ $_sq_pat ]]; then
        inline_code="${BASH_REMATCH[1]}"
    # Try double-quoted form: -c "code content here"
    elif [[ "$full_command" =~ $_dq_pat ]]; then
        inline_code="${BASH_REMATCH[1]}"
    # Unquoted fallback: capture everything to end of string after -c/-e
    elif [[ "$full_command" =~ [[:space:]]-[ce][[:space:]]+(.+)$ ]]; then
        inline_code="${BASH_REMATCH[1]}"
        # Strip any leading/trailing quotes that might have been included
        inline_code="${inline_code#[\"\']}"
        inline_code="${inline_code%[\"\']}"
    fi

    # Also try env -S/--split-string evasion: the quoted argument is the split-string payload
    if [[ -z "$inline_code" ]]; then
        local _env_sq_pat
        _env_sq_pat="[[:space:]](-S|--split-string)[[:space:]]+'([^']+)'"
        local _env_dq_pat='[[:space:]](-S|--split-string)[[:space:]]+"([^"]+)"'
        if [[ "$full_command" =~ $_env_sq_pat ]]; then
            inline_code="${BASH_REMATCH[2]}"
        elif [[ "$full_command" =~ $_env_dq_pat ]]; then
            inline_code="${BASH_REMATCH[2]}"
        elif [[ "$full_command" =~ [[:space:]](-S|--split-string)[[:space:]]+(.+)$ ]]; then
            inline_code="${BASH_REMATCH[2]}"
        fi
    fi

    [[ -z "$inline_code" ]] && return 1  # No inline code found

    # ─────────────────────────────────────────────────────────────────
    # CHECK 1: Suspicious patterns in inline code
    # ─────────────────────────────────────────────────────────────────
    if quick_suspicious_check "$inline_code"; then
        INLINE_CODE_REASON="suspicious_pattern"
        return 0
    fi

    # Check NEVER_WHITELIST patterns using pre-built combined pattern
    if [[ -n "$COMBINED_NEVER_WHITELIST_PATTERN" ]]; then
        if echo "$inline_code" | grep -qiE "$COMBINED_NEVER_WHITELIST_PATTERN"; then
            INLINE_CODE_REASON="dangerous_pattern"
            return 0
        fi
    fi

    # ─────────────────────────────────────────────────────────────────
    # CHECK 2: High-entropy strings (obfuscation detection)
    # Look for base64, hex, or other encoded payloads
    # ─────────────────────────────────────────────────────────────────

    # Extract potential encoded strings (quoted values, variable assignments)
    # Pattern: strings of 20+ chars that look like encoded data
    local encoded_patterns
    encoded_patterns=$(echo "$inline_code" | grep -oE "[A-Za-z0-9+/=]{20,}" | head -5) || true

    while IFS= read -r potential_encoded; do
        [[ -z "$potential_encoded" ]] && continue

        if is_high_entropy "$potential_encoded" 4.5; then
            INLINE_CODE_REASON="high_entropy_string:${potential_encoded:0:30}..."
            return 0
        fi
    done <<< "$encoded_patterns"

    # Also check for hex-encoded strings (common in perl/python obfuscation)
    local hex_patterns
    hex_patterns=$(echo "$inline_code" | grep -oE "[0-9a-fA-F]{20,}" | head -5) || true

    while IFS= read -r potential_hex; do
        [[ -z "$potential_hex" ]] && continue

        # Hex strings have moderate entropy (~3.7-4.0) but are suspicious if long
        if [[ ${#potential_hex} -ge 30 ]]; then
            INLINE_CODE_REASON="hex_encoded_string:${potential_hex:0:30}..."
            return 0
        fi
    done <<< "$hex_patterns"

    # Check variable assignments with high entropy values
    if [[ "$inline_code" =~ [\"\']([A-Za-z0-9+/=]{30,})[\"\'] ]]; then
        local value="${BASH_REMATCH[1]}"
        if is_high_entropy "$value" 4.5; then
            INLINE_CODE_REASON="obfuscated_variable:${value:0:30}..."
            return 0
        fi
    fi

    return 1  # Clean
}


# Adjust confidence based on package management status
adjust_confidence_for_package() {
    local current_confidence="$1"
    local package_status="$2"

    # CRITICAL: If package file was MODIFIED, upgrade to CRITICAL confidence
    # This indicates potential rootkit/compromise of system packages
    if [[ "$package_status" == *":MODIFIED"* ]]; then
        echo "CRITICAL"
        return
    fi

    # If file is package-managed and current confidence is HIGH, downgrade to MEDIUM
    if [[ "$package_status" != "unmanaged" ]] && [[ "$current_confidence" == "HIGH" ]]; then
        echo "MEDIUM"
        return
    fi

    # If file is package-managed and current confidence is MEDIUM, downgrade to LOW
    if [[ "$package_status" != "unmanaged" ]] && [[ "$current_confidence" == "MEDIUM" ]]; then
        echo "LOW"
        return
    fi

    # Otherwise keep original confidence
    echo "$current_confidence"
}

# Check if finding should be included based on filter settings
should_include_finding() {
    local confidence="$1"
    local has_suspicious_pattern="$2"  # "true" or "false"

    # If MIN_CONFIDENCE is set, filter by confidence level
    if [[ -n "$MIN_CONFIDENCE" ]]; then
        case "$MIN_CONFIDENCE" in
            "CRITICAL")
                if [[ "$confidence" != "CRITICAL" ]]; then
                    return 1  # Exclude
                fi
                ;;
            "HIGH")
                if [[ "$confidence" != "HIGH" ]] && [[ "$confidence" != "CRITICAL" ]]; then
                    return 1  # Exclude
                fi
                ;;
            "MEDIUM")
                if [[ "$confidence" == "LOW" ]]; then
                    return 1  # Exclude
                fi
                ;;
            "LOW")
                # Include all
                ;;
        esac
    fi

    # Apply suspicious_only filter
    if [[ "$FILTER_MODE" == "suspicious_only" ]]; then
        # Only include MEDIUM, HIGH, or CRITICAL confidence
        # LOW confidence is considered baseline/non-suspicious
        if [[ "$confidence" == "LOW" ]]; then
            return 1  # Exclude
        fi
    fi

    return 0  # Include
}

# Escape CSV fields
escape_csv() {
    local field="$1"
    # Wrap in quotes if field contains comma, quote, newline, carriage return,
    # or Unicode line/paragraph separators (U+2028, U+2029) that break CSV parsers
    local ls=$'\xe2\x80\xa8'   # U+2028 LINE SEPARATOR (UTF-8)
    local ps=$'\xe2\x80\xa9'   # U+2029 PARAGRAPH SEPARATOR (UTF-8)
    if [[ "$field" == *","* ]] || [[ "$field" == *'"'* ]] || \
       [[ "$field" == *$'\n'* ]] || [[ "$field" == *$'\r'* ]] || \
       [[ "$field" == *"$ls"* ]] || [[ "$field" == *"$ps"* ]]; then
        echo "\"${field//\"/\"\"}\""
    else
        echo "$field"
    fi
}

# Escape JSON strings
escape_json() {
    local str="$1"
    # Escape backslashes, quotes, newlines, tabs, carriage returns
    str="${str//\\/\\\\}"      # \ -> \\
    str="${str//\"/\\\"}"      # " -> \"
    str="${str//$'\n'/\\n}"    # newline -> \n
    str="${str//$'\t'/\\t}"    # tab -> \t
    str="${str//$'\r'/\\r}"    # carriage return -> \r
    # Strip remaining ASCII control characters (0x00-0x1F) not already handled above.
    # These produce invalid JSON and can break downstream parsers (jq, Splunk, Elastic).
    # \001-\010 = 0x01-0x08, \013 = 0x0B (VT), \014 = 0x0C (FF), \016-\037 = 0x0E-0x1F
    str=$(printf '%s' "$str" | tr -d '\000-\010\013\014\016-\037')
    echo "$str"
}

# Extract owner from metadata string
# Metadata format: mode:xxx|owner:user:group|size:xxx|...
get_owner_from_metadata() {
    local metadata="$1"
    local tmp="${metadata#*owner:}"
    # If pattern not found (e.g. metadata="N/A"), tmp == metadata — return N/A
    [[ "$tmp" == "$metadata" ]] && echo "N/A" && return
    echo "${tmp%%|*}"
}

# Extract permissions from metadata string
get_permissions_from_metadata() {
    local metadata="$1"
    local tmp="${metadata#*mode:}"
    [[ "$tmp" == "$metadata" ]] && echo "N/A" && return
    echo "${tmp%%|*}"
}

# Add finding to output (new structured format)
# NOTE: file_hash can be "DEFER" to delay hash calculation until filtering
add_finding_new() {
    local category="$1"
    local confidence="$2"
    local file_path="$3"
    local file_hash="$4"
    local file_owner="$5"
    local file_permissions="$6"
    local file_age_days="$7"
    local package_status="$8"
    local command="${9:-}"
    local enabled_status="${10:-}"
    local description="${11:-}"
    local matched_pattern="${12:-}"    # The pattern that triggered detection
    local matched_string="${13:-}"     # The actual string that matched

    # Truncate matched_string to avoid oversized CSV/JSONL fields
    matched_string="${matched_string:0:500}"

    # Resolve command to actual execution target (script path or inline code)
    if [[ -n "$command" ]]; then
        command=$(resolve_command_target "$command")
    fi

    # ISC-C8 FIX: Escalate HIGH → CRITICAL for SUID/SGID files with suspicious content.
    # SUID/SGID + suspicious patterns is the most dangerous persistence combination:
    # an attacker-controlled setuid binary that spawns a shell or downloads a payload.
    # Permissions field format: "rwsr-xr-x" or "rws--x--x" etc. (s in user/group position).
    # Escalate HIGH -> CRITICAL for SUID/SGID files (permission bits 04000/02000)
    # file_permissions is octal from stat -c "%a" (e.g. "4755", "2755", "6755")
    # Extract leading digit(s): if value >= 4000 octal, SUID bit is set;
    # if value >= 2000 (mod 4000), SGID bit is set.
    if [[ "$confidence" == "HIGH" ]] && [[ "$file_permissions" =~ ^[0-9]+$ ]]; then
        local _perm_oct
        _perm_oct=$(( 8#${file_permissions} )) 2>/dev/null || _perm_oct=0
        if (( (_perm_oct & 04000) || (_perm_oct & 02000) )); then
            confidence="CRITICAL"
            matched_pattern="${matched_pattern}+suid_sgid"
        fi
    fi

    # Check if this finding should be included based on filter settings
    local has_suspicious="false"
    if [[ "$confidence" == "HIGH" ]] || [[ "$confidence" == "CRITICAL" ]]; then
        has_suspicious="true"
    fi

    if ! should_include_finding "$confidence" "$has_suspicious"; then
        return 0  # Skip this finding
    fi

    # Compute hash only if needed (optimization: skip for filtered-out findings)
    if [[ "$file_hash" == "DEFER" ]]; then
        file_hash=$(get_file_hash "$file_path")
    fi

    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # CSV output (new structure with matched_pattern and matched_string)
    echo "$(escape_csv "$timestamp"),$(escape_csv "$HOSTNAME"),$(escape_csv "$category"),$(escape_csv "$confidence"),$(escape_csv "$file_path"),$(escape_csv "$file_hash"),$(escape_csv "$file_owner"),$(escape_csv "$file_permissions"),$(escape_csv "$file_age_days"),$(escape_csv "$package_status"),$(escape_csv "$command"),$(escape_csv "$description"),$(escape_csv "$matched_pattern"),$(escape_csv "$matched_string")" >> "$CSV_FILE"

    # JSONL output (new structure with proper escaping)
    cat >> "$JSONL_FILE" << EOF
{"timestamp":"$(escape_json "$timestamp")","hostname":"$(escape_json "$HOSTNAME")","category":"$(escape_json "$category")","confidence":"$confidence","file_path":"$(escape_json "$file_path")","file_hash":"$(escape_json "$file_hash")","file_owner":"$(escape_json "$file_owner")","file_permissions":"$(escape_json "$file_permissions")","file_age_days":"$(escape_json "$file_age_days")","package_status":"$(escape_json "$package_status")","command":"$(escape_json "$command")","description":"$(escape_json "$description")","matched_pattern":"$(escape_json "$matched_pattern")","matched_string":"$(escape_json "$matched_string")"}
EOF
}

# Wrapper function for backward compatibility (converts old format to new)
add_finding() {
    local category="$1"
    local subcategory="$2"
    local persistence_type="$3"
    local location="$4"
    local description="$5"
    local confidence="$6"
    local hash="$7"
    local metadata="$8"
    local additional_info="${9:-}"
    local matched_pattern="${10:-}"    # The pattern that triggered detection
    local matched_string="${11:-}"     # The actual string that matched

    # Extract structured fields using bash parameter expansion (faster than grep -oP)
    # Metadata format: mode:xxx|owner:user:group|size:xxx|modified:xxx|...
    local owner="N/A" permissions="N/A" days_old="N/A" package_status="unmanaged" enabled=""

    # Parse metadata with single read
    if [[ "$metadata" =~ owner:([^|]+) ]]; then owner="${BASH_REMATCH[1]}"; fi
    if [[ "$metadata" =~ mode:([^|]+) ]]; then permissions="${BASH_REMATCH[1]}"; fi

    # Parse additional_info with single read
    if [[ "$additional_info" =~ days_old=([0-9]+) ]]; then days_old="${BASH_REMATCH[1]}"; fi
    if [[ "$additional_info" =~ package=([^|]+) ]]; then package_status="${BASH_REMATCH[1]}"; fi
    if [[ "$additional_info" =~ enabled=([^|]+) ]]; then enabled="${BASH_REMATCH[1]}"; fi

    # Try to extract command from description (ExecStart: or preview= patterns)
    local command=""
    if [[ "$description" =~ ExecStart:\ (.+)$ ]]; then
        command="${BASH_REMATCH[1]}"
    elif [[ "$additional_info" =~ preview=(.+)$ ]]; then
        command="${BASH_REMATCH[1]}"
    elif [[ "$additional_info" =~ content_preview=(.+)$ ]]; then
        command="${BASH_REMATCH[1]}"
    fi

    # Build clean category name
    local clean_category="$category $subcategory"

    # Call new structured function with matched_pattern and matched_string
    add_finding_new "$clean_category" "$confidence" "$location" "$hash" "$owner" "$permissions" "$days_old" "$package_status" "$command" "$enabled" "$persistence_type" "$matched_pattern" "$matched_string"
}

# Initialize output files
init_output() {
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$TEMP_DATA"

    # CSV header (new structured format with matched_pattern and matched_string)
    echo "timestamp,hostname,category,confidence,file_path,file_hash,file_owner,file_permissions,file_age_days,package_status,command,description,matched_pattern,matched_string" > "$CSV_FILE"

    # Clear JSONL file
    > "$JSONL_FILE"

    log_info "Output directory: $OUTPUT_DIR"
    log_info "CSV output: $CSV_FILE"
    log_info "JSONL output: $JSONL_FILE"
}

################################################################################
# Detection Modules
################################################################################

check_bootloader_persistence() {
    log_info "[NEW] Checking bootloader and initramfs persistence..."

    # ─── GRUB bootloader ────────────────────────────────────────────────────
    log_check "GRUB bootloader configuration (init= injection)"

    local _grub_files=()
    [[ -f /etc/default/grub ]] && _grub_files+=("/etc/default/grub")
    while IFS= read -r -d '' _cfg; do
        _grub_files+=("$_cfg")
    done < <(find /etc/default/grub.d -maxdepth 1 -name "*.cfg" -type f -print0 2>/dev/null)

    local _standard_inits=("/sbin/init" "/lib/systemd/systemd" "/usr/lib/systemd/systemd" "/bin/busybox" "/sbin/upstart")

    for _gf in "${_grub_files[@]}"; do
        local _hash; _hash=$(get_file_hash "$_gf")
        local _meta; _meta=$(get_file_metadata "$_gf")
        check_file_package "$_gf"
        local _pkg_status="$PKG_STATUS"

        local _confidence="LOW"
        local _matched_pattern=""
        local _matched_string=""

        # Parse both GRUB_CMDLINE_LINUX_DEFAULT and GRUB_CMDLINE_LINUX
        local _cmdline=""
        _cmdline=$(grep -E "^GRUB_CMDLINE_LINUX(_DEFAULT)?=" "$_gf" 2>/dev/null | tr '\n' ' ') || true

        if [[ -n "$_cmdline" ]]; then
            # Extract init= value using bash parameter expansion
            if [[ "$_cmdline" =~ (^|[[:space:]])init=([^[:space:]\"\']+) ]]; then
                local _init_target="${BASH_REMATCH[2]}"
                # Strip leading and trailing quotes if captured
                _init_target="${_init_target#[\"\']}"
                _init_target="${_init_target%[\"\']}"

                local _is_standard=false
                for _si in "${_standard_inits[@]}"; do
                    [[ "$_init_target" == "$_si" ]] && _is_standard=true && break
                done

                if [[ "$_is_standard" == "true" ]]; then
                    _confidence="LOW"
                    _matched_pattern="grub_init_standard"
                    _matched_string="init=$_init_target"
                else
                    _confidence="HIGH"
                    _matched_pattern="grub_init_injection"
                    _matched_string="init=$_init_target"
                    log_finding "GRUB init= injection detected in $_gf: init=$_init_target"

                    # Analyze the init= target script if it exists
                    if [[ -f "$_init_target" ]]; then
                        local _init_content
                        _init_content=$(head -n 200 "$_init_target" 2>/dev/null | tr -d '\0') || true
                        if [[ -n "$_init_content" ]] && analyze_content_string "$_init_content" "$_init_target"; then
                            _confidence="CRITICAL"
                            _matched_pattern="grub_init_malicious_content"
                            _matched_string="$MATCHED_STRING"
                            log_finding "GRUB init= target has malicious content: $_init_target"
                        fi
                    fi
                fi
            fi
        fi

        [[ "$_pkg_status" == "unmanaged" && "$_confidence" == "LOW" ]] && _confidence="MEDIUM"

        add_finding "Bootloader" "GRUB" "grub_config" "$_gf" "GRUB config: $(basename "$_gf")" "$_confidence" "$_hash" "$_meta" "package=$_pkg_status" "$_matched_pattern" "$_matched_string"
    done

    # Scan root-level dropped init scripts (attacker drops e.g. /grub-panix.sh)
    log_check "Root-level dropped init scripts"
    while IFS= read -r -d '' _root_sh; do
        local _hash; _hash=$(get_file_hash "$_root_sh")
        local _meta; _meta=$(get_file_metadata "$_root_sh")
        check_file_package "$_root_sh"
        local _confidence="HIGH"
        local _matched_pattern="root_dropped_script"
        local _matched_string="$(basename "$_root_sh")"
        local _content
        _content=$(head -n 200 "$_root_sh" 2>/dev/null | tr -d '\0') || true
        if [[ -n "$_content" ]] && analyze_content_string "$_content" "$_root_sh"; then
            _confidence="CRITICAL"
            _matched_pattern="root_dropped_script_malicious"
            _matched_string="$MATCHED_STRING"
        fi
        log_finding "Root-level dropped script: $_root_sh"
        add_finding "Bootloader" "DroppedScript" "root_dropped_script" "$_root_sh" "Root-level script: $(basename "$_root_sh")" "$_confidence" "$_hash" "$_meta" "package=$PKG_STATUS" "$_matched_pattern" "$_matched_string"
    done < <(find / -xdev -maxdepth 2 -type f -name "*.sh" -perm /111 -not -path "/etc/*" -not -path "/usr/*" -not -path "/bin/*" -not -path "/sbin/*" -not -path "/lib/*" -not -path "/lib64/*" -not -path "/opt/*" -not -path "/home/*" -not -path "/root/*" -not -path "/tmp/*" -not -path "/var/*" -not -path "/snap/*" 2>/dev/null)

    # ─── Initramfs / Dracut ─────────────────────────────────────────────────
    log_check "Dracut initramfs modules (pre-pivot hooks)"

    local _dracut_base="/usr/lib/dracut/modules.d"
    if [[ -d "$_dracut_base" ]]; then
        while IFS= read -r -d '' _setup; do
            local _mod_dir; _mod_dir=$(dirname "$_setup")
            local _hash; _hash=$(get_file_hash "$_setup")
            local _meta; _meta=$(get_file_metadata "$_setup")
            check_file_package "$_setup"
            local _pkg="$PKG_STATUS"

            local _confidence="LOW"
            local _matched_pattern=""
            local _matched_string=""

            local _content
            _content=$(cat "$_setup" 2>/dev/null | tr -d '\0') || true

            # Look for pre-pivot hook installation
            if grep -qiE "inst_hook[[:space:]]+pre-pivot" <<< "$_content" 2>/dev/null; then
                _confidence="HIGH"
                _matched_pattern="dracut_pre_pivot_hook"
                _matched_string=$(grep -iE "inst_hook[[:space:]]+pre-pivot" <<< "$_content" | head -1) || true
                log_finding "Dracut pre-pivot hook found: $_setup"

                # Find and analyze the hook script
                local _hook_script
                _hook_script=$(grep -oiE "inst_hook[[:space:]]+pre-pivot[[:space:]]+[0-9]+[[:space:]]+\S+" <<< "$_content" | awk '{print $NF}' | head -1) || true
                if [[ -n "$_hook_script" ]]; then
                    local _hook_path="$_mod_dir/$_hook_script"
                    if [[ -f "$_hook_path" ]]; then
                        local _hook_content
                        _hook_content=$(cat "$_hook_path" 2>/dev/null | tr -d '\0') || true
                        # Check for /sysroot/etc/shadow writes — CRITICAL backdoor user injection
                        if grep -qiE "(>|>>)[[:space:]]*/sysroot/etc/shadow" <<< "$_hook_content" 2>/dev/null; then
                            _confidence="CRITICAL"
                            _matched_pattern="dracut_sysroot_shadow_write"
                            _matched_string=$(grep -iE "(>|>>)[[:space:]]*/sysroot/etc/shadow" <<< "$_hook_content" | head -1) || true
                            log_finding "Dracut hook writes to /sysroot/etc/shadow: $_hook_path"
                        elif analyze_content_string "$_hook_content" "$_hook_path"; then
                            _confidence="CRITICAL"
                            _matched_pattern="dracut_hook_malicious_content"
                            _matched_string="$MATCHED_STRING"
                        fi
                    fi
                fi
            elif [[ "$_pkg" == "unmanaged" ]]; then
                _confidence="HIGH"
                _matched_pattern="dracut_unmanaged_module"
                _matched_string="$(basename "$_mod_dir")"
                log_finding "Unmanaged dracut module: $_mod_dir"
            fi

            add_finding "Bootloader" "Dracut" "dracut_module" "$_setup" "Dracut module: $(basename "$_mod_dir")" "$_confidence" "$_hash" "$_meta" "package=$_pkg" "$_matched_pattern" "$_matched_string"
        done < <(find "$_dracut_base" -maxdepth 6 -name "module-setup.sh" -type f -print0 2>/dev/null)
    fi

    # Ubuntu/Debian: initramfs-tools hook scripts
    log_check "initramfs-tools hook scripts (Ubuntu/Debian)"
    local _initramfs_scripts_dirs=(
        "/etc/initramfs-tools/scripts"
        "/etc/initramfs-tools/hooks"
    )
    for _ird in "${_initramfs_scripts_dirs[@]}"; do
        [[ -d "$_ird" ]] || continue
        while IFS= read -r -d '' _hook; do
            local _hash; _hash=$(get_file_hash "$_hook")
            local _meta; _meta=$(get_file_metadata "$_hook")
            check_file_package "$_hook"
            local _pkg="$PKG_STATUS"
            local _confidence="LOW"
            local _matched_pattern=""
            local _matched_string=""

            [[ "$_pkg" == "unmanaged" ]] && _confidence="MEDIUM"

            local _content
            _content=$(head -n 300 "$_hook" 2>/dev/null | tr -d '\0') || true
            if [[ -n "$_content" ]] && analyze_content_string "$_content" "$_hook"; then
                _confidence="CRITICAL"
                _matched_pattern="$MATCHED_PATTERN"
                _matched_string="$MATCHED_STRING"
                log_finding "Suspicious initramfs-tools hook: $_hook"
            elif grep -qiE "\\\$rootmnt/etc/(shadow|passwd)" <<< "$_content" 2>/dev/null; then
                _confidence="CRITICAL"
                _matched_pattern="initramfs_rootmnt_shadow_write"
                _matched_string=$(grep -iE "\\\$rootmnt/etc/(shadow|passwd)" <<< "$_content" | head -1) || true
                log_finding "initramfs hook writes to \$rootmnt/etc/shadow or passwd: $_hook"
            fi

            add_finding "Bootloader" "InitramfsTools" "initramfs_hook" "$_hook" "initramfs-tools hook: $(basename "$_hook")" "$_confidence" "$_hash" "$_meta" "package=$_pkg" "$_matched_pattern" "$_matched_string"
        done < <(find "$_ird" -maxdepth 6 -type f -perm /111 -print0 2>/dev/null)
    done

    # FIM for /boot/initrd.img-* — mtime-based (no baseline available on live systems)
    log_check "/boot/initrd.img-* recent modification"
    while IFS= read -r -d '' _initrd; do
        local _meta; _meta=$(get_file_metadata "$_initrd")
        local _days_old="9999"
        if [[ "$_meta" =~ days_old:([0-9]+) ]]; then _days_old="${BASH_REMATCH[1]}"; fi
        if [[ "$_days_old" -le 7 ]]; then
            local _hash; _hash=$(get_file_hash "$_initrd")
            add_finding "Bootloader" "InitrdImage" "initrd_recent_modification" "$_initrd" "initrd image recently modified (${_days_old}d ago)" "MEDIUM" "$_hash" "$_meta" "" "initrd_recent_modification" "days_old=$_days_old"
            log_finding "initrd image recently modified: $_initrd (${_days_old} days ago)"
        fi
    done < <(find /boot -maxdepth 1 -name "initrd.img-*" -type f -print0 2>/dev/null)
}

# Check systemd services
check_systemd() {
    log_info "[1/9] Checking systemd services..."

    if ! command -v systemctl &> /dev/null; then
        log_warn "systemctl not found, skipping systemd checks"
        return
    fi

    # Initialize systemctl cache for faster enabled status lookups
    init_systemctl_cache

    local systemd_paths=(
        "/etc/systemd/system"
        "/usr/lib/systemd/system"
        "/lib/systemd/system"
        "/run/systemd/system"
        "/etc/systemd/user"
        "/usr/lib/systemd/user"
        "$HOME/.config/systemd/user"
    )

    # When running as root, also scan all users' user-level systemd service directories
    # User-level systemd services run as the user without root, used by attackers after
    # compromising non-privileged accounts (www-data, service accounts, etc.)
    if [[ $EUID_CHECK -eq 0 ]]; then
        while IFS=: read -r username _ uid _ _ homedir _; do
            if [[ $uid -ge 1000 ]] || [[ $uid -eq 0 ]]; then
                local user_systemd_dir="$homedir/.config/systemd/user"
                if [[ -d "$user_systemd_dir" ]] && [[ "$user_systemd_dir" != "$HOME/.config/systemd/user" ]]; then
                    systemd_paths+=("$user_systemd_dir")
                fi
            fi
        done < /etc/passwd
    fi

    log_check "Systemd service files (.service)"

    # Track scanned real paths to avoid double-scanning /lib/ and /usr/lib/ on merged-/usr
    local scanned_systemd_paths=()

    for path in "${systemd_paths[@]}"; do
        if [[ -d "$path" ]]; then
            local real_path
            real_path=$(realpath "$path" 2>/dev/null) || real_path="$path"
            local _already=false
            local _prev
            for _prev in "${scanned_systemd_paths[@]}"; do
                [[ "$_prev" == "$real_path" ]] && _already=true && break
            done
            "$_already" && continue
            scanned_systemd_paths+=("$real_path")

            while IFS= read -r -d '' service_file; do
                local metadata=$(get_file_metadata "$service_file")
                local service_name=$(basename "$service_file")

                # Extract exec directives from service file
                local exec_start="" exec_pre="" exec_post=""
                local on_failure=""
                local env_inline="" env_file=""
                if [[ -f "$service_file" ]]; then
                    # Join backslash-continued lines, then extract all ExecStart= values
                    exec_start=$(awk '/^ExecStart=/{
                        line = substr($0, index($0,"=")+1)
                        while (sub(/\\$/, "", line)) {
                            if ((getline nextline) > 0) line = line " " nextline
                            else break
                        }
                        print line
                    }' "$service_file" 2>/dev/null | tr '\n' ';' | sed 's/;$//' || echo "")
                    exec_pre=$(grep -E "^ExecStartPre=" "$service_file" 2>/dev/null | cut -d'=' -f2- | tr '\n' ';' || echo "")
                    exec_post=$(grep -E "^ExecStartPost=" "$service_file" 2>/dev/null | cut -d'=' -f2- | tr '\n' ';' || echo "")
                    on_failure=$(grep -E "^OnFailure=" "$service_file" 2>/dev/null | cut -d'=' -f2- | tr '\n' ',' | sed 's/,$//' || echo "")
                    env_inline=$(grep -E "^Environment=" "$service_file" 2>/dev/null | cut -d'=' -f2- | tr '\n' ';' || echo "")
                    env_file=$(grep -E "^EnvironmentFile=" "$service_file" 2>/dev/null | cut -d'=' -f2- | tr '\n' ';' || echo "")
                fi

                # Skip services with no ExecStart - nothing to analyse
                [[ -z "$exec_start" ]] && [[ -z "$exec_pre" ]] && [[ -z "$exec_post" ]] && continue

                # If only pre/post hooks exist with no ExecStart, still analyze them
                if [[ -z "$exec_start" ]]; then
                    exec_start="${exec_pre:-${exec_post}}"
                    exec_pre=""
                fi

                # Check if service is enabled (using cache for performance)
                local enabled_status
                enabled_status=$(get_systemctl_enabled_status "$service_name")

                # Skip disabled services - not active, not a persistence risk
                # Exception: timer-activated services appear "disabled" but run on schedule
                # If a matching .timer file exists in any systemd path, analyze the service anyway
                local _timer_schedule=""
                if [[ "$enabled_status" == "disabled" ]]; then
                    local _timer_basename="${service_name%.service}.timer"
                    local _timer_found=false
                    local _tdir
                    for _tdir in "$(dirname "$service_file")" /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /run/systemd/system /etc/systemd/user /usr/lib/systemd/user; do
                        if [[ -f "${_tdir}/${_timer_basename}" ]]; then
                            _timer_found=true
                            # Analyze timer content for schedule values and Unit= cross-reference
                            local _timer_file="${_tdir}/${_timer_basename}"
                            local _timer_on_boot; _timer_on_boot=$(grep -iE "^OnBootSec[[:space:]]*=" "$_timer_file" 2>/dev/null | head -1 | cut -d'=' -f2- | tr -d ' ') || true
                            local _timer_on_cal; _timer_on_cal=$(grep -iE "^OnCalendar[[:space:]]*=" "$_timer_file" 2>/dev/null | head -1 | cut -d'=' -f2- | tr -d ' ') || true
                            local _timer_on_unit; _timer_on_unit=$(grep -iE "^OnUnitActiveSec[[:space:]]*=" "$_timer_file" 2>/dev/null | head -1 | cut -d'=' -f2- | tr -d ' ') || true
                            local _timer_unit_ref; _timer_unit_ref=$(grep -iE "^Unit[[:space:]]*=" "$_timer_file" 2>/dev/null | head -1 | cut -d'=' -f2- | tr -d ' ') || true
                            [[ -n "$_timer_on_boot" ]] && _timer_schedule="OnBootSec=$_timer_on_boot"
                            [[ -n "$_timer_on_cal" ]] && _timer_schedule="${_timer_schedule:+$_timer_schedule|}OnCalendar=$_timer_on_cal"
                            [[ -n "$_timer_on_unit" ]] && _timer_schedule="${_timer_schedule:+$_timer_schedule|}OnUnitActiveSec=$_timer_on_unit"
                            # Flag if timer activates a DIFFERENT service than expected
                            if [[ -n "$_timer_unit_ref" ]] && [[ "$_timer_unit_ref" != "${service_name}" ]]; then
                                log_finding "Timer activates non-corresponding service: $_timer_file -> $_timer_unit_ref (expected: $service_name)"
                            fi
                            break
                        fi
                    done
                    [[ "$_timer_found" == "false" ]] && continue
                fi

                local confidence="MEDIUM"
                local finding_matched_pattern=""
                local finding_matched_string=""
                local package_status="unmanaged"
                local skip_pattern_analysis=false

                # Check modification time — extract from already-fetched metadata (no extra stat fork)
                local mod_time=0
                [[ "$metadata" =~ modified:([0-9]+) ]] && mod_time="${BASH_REMATCH[1]}"
                local current_time=$SCAN_EPOCH
                local days_old=$(( (current_time - mod_time) / 86400 ))

                # Only analyze ExecStart if it exists
                local executable=""
                local script_to_analyze=""

                if [[ -n "$exec_start" ]]; then
                    # ═══════════════════════════════════════════════════════════
                    # FOCUS: Only check the ExecStart target (binary/script)
                    # The .service file is just config - the forensic artifact
                    # is what actually gets executed
                    # ═══════════════════════════════════════════════════════════

                    # Pre-check: NEVER_WHITELIST patterns on the full ExecStart line.
                    # This prevents the package-verification bypass: a verified system binary
                    # (e.g. /usr/bin/curl) executing with a pipe-to-shell pattern would
                    # otherwise set skip_pattern_analysis=true and get confidence=LOW.
                    local exec_never_wl_match=""
                    exec_never_wl_match=$(echo "$exec_start" | grep -oE "$COMBINED_NEVER_WHITELIST_PATTERN" | head -1) || true

                    executable=$(get_executable_from_command "$exec_start")

                    if [[ -n "$executable" ]] && [[ -f "$executable" ]]; then

                        # BRANCH 1: Is it an interpreter? (python, perl, bash, etc.)
                        if is_interpreter "$executable"; then
                            # For interpreters, analyze the SCRIPT, not the interpreter binary
                            # Extract and analyze the SCRIPT (this is the key forensic artifact)
                            script_to_analyze=$(get_script_from_interpreter_command "$exec_start") || true

                            if [[ -n "$script_to_analyze" ]] && [[ -f "$script_to_analyze" ]]; then
                                # Check script's package status
                                local script_pkg_status
                                script_pkg_status=$(is_package_managed "$script_to_analyze") || true
                                package_status="$script_pkg_status"

                                if [[ "$script_pkg_status" == *":MODIFIED" ]]; then
                                    # Script file was MODIFIED - CRITICAL
                                    confidence="CRITICAL"
                                    finding_matched_pattern="modified_script"
                                    finding_matched_string="$script_to_analyze"
                                    log_finding "Interpreter script is modified package file: $script_to_analyze"
                                elif [[ "$script_pkg_status" != "unmanaged" ]]; then
                                    # Script is package-managed and verified
                                    if [[ -n "$exec_never_wl_match" ]]; then
                                        # ExecStart contains a NEVER_WHITELIST pattern — always flag
                                        # regardless of the script's package status
                                        confidence="HIGH"
                                        finding_matched_pattern="never_whitelist"
                                        finding_matched_string="$exec_never_wl_match"
                                        log_finding "Systemd service: package-verified script with never-whitelist pattern: $exec_never_wl_match"
                                    else
                                        confidence="LOW"
                                        skip_pattern_analysis=true
                                    fi
                                else
                                    # Script is UNMANAGED - analyze content
                                    if is_script "$script_to_analyze"; then
                                        if analyze_script_content "$script_to_analyze"; then
                                            confidence="HIGH"
                                            finding_matched_pattern="suspicious_script_content"
                                            finding_matched_string="$script_to_analyze"
                                            log_finding "Interpreter script contains suspicious content: $script_to_analyze"
                                        fi
                                    fi

                                    # Check location-based suspicion
                                    # BUG-8 fix: only set finding_matched_pattern if not already set
                                    # by the content analysis above (preserve the more specific finding)
                                    if [[ "$script_to_analyze" =~ ^/(tmp|dev/shm|var/tmp) ]]; then
                                        confidence="HIGH"
                                        if [[ -z "$finding_matched_pattern" ]]; then
                                            finding_matched_pattern="suspicious_location"
                                            finding_matched_string="$script_to_analyze"
                                        fi
                                        log_finding "Interpreter executing script from suspicious location: $script_to_analyze"
                                    elif [[ "$script_to_analyze" =~ ^/(opt|usr/local|home) ]]; then
                                        # Common but unmanaged locations
                                        [[ "$confidence" == "LOW" ]] && confidence="MEDIUM"
                                    fi

                                    # Default reason if no specific pattern found
                                    if [[ -z "$finding_matched_pattern" ]]; then
                                        finding_matched_pattern="unmanaged_script"
                                        finding_matched_string="$script_to_analyze"
                                    fi
                                fi
                            else
                                # Interpreter with no file argument - check for inline code
                                if [[ "$exec_start" =~ \ -[ce]\  ]] || [[ "$exec_start" =~ \ -[ce]$ ]] || [[ "$exec_start" =~ [[:space:]](-S|--split-string)([[:space:]]|$) ]]; then
                                    # Analyze the inline code content for patterns and obfuscation
                                    if analyze_inline_code "$exec_start"; then
                                        confidence="CRITICAL"
                                        finding_matched_pattern="inline_code_suspicious"
                                        finding_matched_string="$INLINE_CODE_REASON"
                                        log_finding "Systemd service has suspicious inline code ($INLINE_CODE_REASON): $service_file"
                                    else
                                        confidence="HIGH"
                                        finding_matched_pattern="inline_code"
                                        finding_matched_string="-c/-e flag"
                                        log_finding "Systemd service uses interpreter with inline code: $service_file"
                                    fi
                                else
                                    # Interactive shell or command without script
                                    # Verify the interpreter binary itself (e.g., ExecStart=/usr/bin/bash)
                                    local interp_pkg_status
                                    interp_pkg_status=$(is_package_managed "$executable") || true
                                    package_status="$interp_pkg_status"
                                    if [[ "$interp_pkg_status" == *":MODIFIED" ]]; then
                                        confidence="CRITICAL"
                                        finding_matched_pattern="modified_interpreter"
                                        finding_matched_string="$executable"
                                        log_finding "Systemd service uses MODIFIED interpreter: $executable"
                                    elif [[ "$interp_pkg_status" != "unmanaged" ]]; then
                                        # Managed interpreter - LOW risk
                                        confidence="LOW"
                                    fi
                                    if [[ -z "$finding_matched_pattern" ]]; then
                                        finding_matched_pattern="interpreter_interactive"
                                        finding_matched_string="$executable"
                                    fi
                                fi
                            fi

                        else
                            # BRANCH 2: Not an interpreter - direct binary execution
                            # Only check the ExecStart target (binary), not the .service file

                            local exec_pkg_status
                            exec_pkg_status=$(is_package_managed "$executable") || true

                            if [[ "$exec_pkg_status" == *":MODIFIED" ]]; then
                                # Executable was MODIFIED - CRITICAL
                                confidence="CRITICAL"
                                finding_matched_pattern="modified_binary"
                                finding_matched_string="$executable"
                                package_status="$exec_pkg_status"
                                log_finding "Systemd service executes modified package file: $executable"

                            elif [[ "$exec_pkg_status" != "unmanaged" ]]; then
                                # Binary is package-managed and verified
                                if [[ -n "$exec_never_wl_match" ]]; then
                                    # ExecStart contains a NEVER_WHITELIST pattern — always flag
                                    # regardless of the binary's package status
                                    confidence="HIGH"
                                    finding_matched_pattern="never_whitelist"
                                    finding_matched_string="$exec_never_wl_match"
                                    log_finding "Systemd service: package-verified binary with never-whitelist pattern: $exec_never_wl_match"
                                else
                                    confidence="LOW"
                                    skip_pattern_analysis=true
                                    package_status="$exec_pkg_status"
                                fi

                            else
                                # UNMANAGED binary - need pattern analysis
                                # Check location first
                                if [[ "$executable" =~ ^/(tmp|dev/shm|var/tmp) ]]; then
                                    confidence="HIGH"
                                    finding_matched_pattern="suspicious_location"
                                    finding_matched_string="$executable"
                                    log_finding "Systemd service executes file from suspicious location: $executable"
                                fi

                                # If it's a script file, analyze content
                                if is_script "$executable"; then
                                    if analyze_script_content "$executable"; then
                                        confidence="HIGH"
                                        finding_matched_pattern="suspicious_script_content"
                                        # Use the actual suspicious content found
                                        finding_matched_string="$MATCHED_STRING"
                                        log_finding "Systemd service script contains suspicious content: $executable"
                                    fi
                                fi

                                # Pattern analysis on ExecStart command
                                if [[ "$skip_pattern_analysis" != true ]] && [[ "$confidence" != "HIGH" ]]; then
                                    # Get full line containing dangerous command, not just the match
                                    local dangerous_line
                                    dangerous_line=$(echo "$exec_start" | grep -iE "(curl.*\||wget.*\||nc -e|/dev/tcp/|/dev/udp/|bash -i|sh -i)" | head -1) || true
                                    if [[ -n "$dangerous_line" ]]; then
                                        confidence="HIGH"
                                        finding_matched_pattern="dangerous_command"
                                        finding_matched_string="$dangerous_line"
                                        log_finding "Dangerous command in systemd service: $service_file"
                                    elif check_suspicious_patterns "$exec_start"; then
                                        confidence="HIGH"
                                        finding_matched_pattern="$MATCHED_PATTERN"
                                        finding_matched_string="$MATCHED_STRING"
                                        log_finding "Suspicious pattern in ExecStart: $service_file [matched: $MATCHED_STRING]"
                                    fi
                                fi

                                # (time-based elevation removed — no baseline context)

                                # Default reason if no specific pattern found - show ExecStart content
                                if [[ -z "$finding_matched_pattern" ]]; then
                                    finding_matched_pattern="unmanaged_binary"
                                    # Show the exec_start command instead of just the path
                                    finding_matched_string="${exec_start:0:200}"
                                fi
                            fi
                        fi

                    else
                        # Executable doesn't exist or isn't a file
                        # Can't verify - keep default MEDIUM confidence
                        package_status="unmanaged"
                        finding_matched_pattern="unresolved_executable"
                        finding_matched_string="$executable"
                    fi

                fi

                # Check ExecStartPre and ExecStartPost hooks for suspicious content
                # These run before/after the main service and are a common injection point:
                # attackers leave ExecStart clean but add malicious hooks to tampered services
                for exec_hook_str in "$exec_pre" "$exec_post"; do
                    [[ -z "$exec_hook_str" ]] && continue

                    # Check the full hook string for suspicious patterns (covers all commands)
                    if check_suspicious_patterns "$exec_hook_str" || quick_suspicious_check "$exec_hook_str"; then
                        if [[ "$confidence" != "CRITICAL" ]]; then
                            confidence="HIGH"
                            finding_matched_pattern="suspicious_exec_hook"
                            finding_matched_string="$exec_hook_str"
                            log_finding "Suspicious pattern in exec hook: $service_file [$exec_hook_str]"
                        fi
                    fi

                    # Process each individual hook command for binary verification.
                    # exec_pre/exec_post are joined by tr '\n' ';' so we split on ';'
                    # to get each hook command independently (avoids trailing-semicolon
                    # corrupting the executable path when using awk '{print $1}').
                    local hook_cmd
                    while IFS= read -r hook_cmd; do
                        # Trim leading/trailing whitespace
                        hook_cmd="${hook_cmd## }"
                        hook_cmd="${hook_cmd%% }"
                        [[ -z "$hook_cmd" ]] && continue

                        # Strip systemd exec modifiers (-, @, +, !, :)
                        local hook_clean="$hook_cmd"
                        while [[ "$hook_clean" =~ ^[@:+!-] ]]; do hook_clean="${hook_clean#?}"; done

                        local hook_executable
                        hook_executable=$(get_executable_from_command "$hook_clean") || true

                        # Check if hook executable is unmanaged or modified
                        if [[ -n "$hook_executable" ]]; then
                            local hook_pkg_status hook_pkg_return=0
                            hook_pkg_status=$(is_package_managed "$hook_executable") || hook_pkg_return=$?

                            if [[ $hook_pkg_return -eq 2 ]]; then
                                # Hook runs a MODIFIED binary - CRITICAL regardless of ExecStart
                                confidence="CRITICAL"
                                finding_matched_pattern="modified_exec_hook"
                                finding_matched_string="$hook_cmd"
                                log_finding "Service has MODIFIED binary in exec hook: $service_file [$hook_cmd]"
                            elif [[ $hook_pkg_return -eq 1 ]]; then
                                # Unmanaged binary in hook - suspicious, upgrade if not already HIGH+
                                if [[ "$confidence" == "LOW" ]] || [[ "$confidence" == "MEDIUM" ]]; then
                                    confidence="HIGH"
                                    finding_matched_pattern="unmanaged_exec_hook"
                                    finding_matched_string="$hook_cmd"
                                    log_finding "Service has unmanaged binary in exec hook: $service_file [$hook_cmd]"
                                fi
                            fi
                        fi
                    done < <(echo "$exec_hook_str" | tr ';' '\n')
                done

                # ── Environment= / EnvironmentFile= : check for LD_PRELOAD / PATH injection ──
                if [[ -n "$env_inline" ]]; then
                    local _env_ld_match
                    _env_ld_match=$(echo "$env_inline" | grep -oiE "(LD_PRELOAD|LD_LIBRARY_PATH|PATH)[[:space:]]*=[[:space:]]*[^;]+" | head -1) || true
                    if [[ -n "$_env_ld_match" ]]; then
                        if [[ "$confidence" != "CRITICAL" ]]; then
                            confidence="HIGH"
                            finding_matched_pattern="env_directive_ld_inject"
                            finding_matched_string="$_env_ld_match"
                            log_finding "Systemd service has suspicious Environment= directive: $service_file [$_env_ld_match]"
                        fi
                    fi
                fi
                if [[ -n "$env_file" ]]; then
                    local _env_file_path
                    _env_file_path=$(echo "$env_file" | grep -oE '[^;]+' | head -1 | sed 's/^[[:space:]]*//;s/[[:space:]]*;//') || true
                    _env_file_path="${_env_file_path#-}"  # strip leading - (optional env file marker)
                    _env_file_path="${_env_file_path## }"
                    if [[ -n "$_env_file_path" ]] && [[ -f "$_env_file_path" ]]; then
                        local _ef_pkg_status _ef_pkg_return=0
                        _ef_pkg_status=$(is_package_managed "$_env_file_path") || _ef_pkg_return=$?
                        if [[ $_ef_pkg_return -eq 2 ]]; then
                            confidence="CRITICAL"
                            finding_matched_pattern="modified_env_file"
                            finding_matched_string="$_env_file_path"
                            log_finding "Systemd service EnvironmentFile is MODIFIED: $_env_file_path ($service_file)"
                        elif [[ $_ef_pkg_return -eq 1 ]]; then
                            local _ef_ld_match
                            _ef_ld_match=$(grep -oiE "(LD_PRELOAD|LD_LIBRARY_PATH|PATH)[[:space:]]*=[[:space:]]*[^[:space:]]+" "$_env_file_path" 2>/dev/null | head -1) || true
                            if [[ -n "$_ef_ld_match" ]]; then
                                if [[ "$confidence" != "CRITICAL" ]]; then
                                    confidence="HIGH"
                                    finding_matched_pattern="env_file_ld_inject"
                                    finding_matched_string="$_ef_ld_match"
                                    log_finding "Systemd service EnvironmentFile contains LD injection: $_env_file_path [$_ef_ld_match]"
                                fi
                            fi
                        fi
                    elif [[ -n "$_env_file_path" ]] && [[ "$_env_file_path" != -* ]]; then
                        if [[ "$confidence" == "LOW" ]] || [[ "$confidence" == "MEDIUM" ]]; then
                            confidence="MEDIUM"
                            if [[ -z "$finding_matched_pattern" ]]; then
                                finding_matched_pattern="missing_env_file"
                                finding_matched_string="$_env_file_path"
                            fi
                        fi
                    fi
                fi

                # ── OnFailure= directive: runs a service when this one fails ─────
                # Attackers can add OnFailure= to a trusted service pointing to a
                # malicious service that triggers on first crash/stop.
                if [[ -n "$on_failure" ]]; then
                    IFS=',' read -ra _on_failure_units <<< "$on_failure"
                    for _of_unit in "${_on_failure_units[@]}"; do
                        _of_unit="${_of_unit## }"
                        _of_unit="${_of_unit%% }"
                        [[ -z "$_of_unit" ]] && continue
                        local _of_found=false _of_pkg_return=0
                        local _of_path=""
                        for _of_dir in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
                            if [[ -f "$_of_dir/$_of_unit" ]]; then
                                _of_path="$_of_dir/$_of_unit"
                                _of_found=true
                                break
                            fi
                        done
                        local _of_confidence="MEDIUM"
                        local _of_pattern="on_failure_service"
                        local _of_string="$_of_unit"
                        if [[ "$_of_found" == "false" ]]; then
                            # OnFailure references a non-existent service - suspicious
                            _of_confidence="HIGH"
                            _of_pattern="on_failure_missing_service"
                            _of_string="$_of_unit (not found)"
                            log_finding "Systemd service OnFailure= references missing service: $_of_unit ($service_file)"
                        else
                            local _of_pkg_status
                            _of_pkg_status=$(is_package_managed "$_of_path") || _of_pkg_return=$?
                            if [[ $_of_pkg_return -eq 2 ]]; then
                                _of_confidence="CRITICAL"
                                _of_pattern="on_failure_modified_service"
                                _of_string="$_of_path"
                                log_finding "Systemd OnFailure= target is MODIFIED package service: $_of_path ($service_file)"
                            elif [[ $_of_pkg_return -eq 1 ]]; then
                                _of_confidence="HIGH"
                                _of_pattern="on_failure_unmanaged_service"
                                _of_string="$_of_path"
                                log_finding "Systemd OnFailure= target is unmanaged service: $_of_unit ($service_file)"
                            fi
                        fi
                        if should_include_finding "$_of_confidence" "false"; then
                            add_finding_new "Systemd OnFailure" "$_of_confidence" "$service_file" "DEFER" \
                                "$(get_owner_from_metadata "$metadata")" "$(get_permissions_from_metadata "$metadata")" \
                                "$days_old" "${_of_pkg_status:-unmanaged}" "$on_failure" "$enabled_status" \
                                "$service_name" "$_of_pattern" "$_of_string"
                        fi
                    done
                fi

                # Extract owner and permissions from metadata
                local owner=$(get_owner_from_metadata "$metadata")
                local permissions=$(get_permissions_from_metadata "$metadata")

                # Use new structured format directly (DEFER hash until filtering)
                # Include matched pattern and string for forensic analysis
                # Append timer schedule info to matched_string if timer-activated
                local _final_matched_string="$finding_matched_string"
                [[ -n "$_timer_schedule" ]] && _final_matched_string="${_final_matched_string:+${_final_matched_string}|}timer:${_timer_schedule}"
                add_finding_new "Systemd Service" "$confidence" "$service_file" "DEFER" "$owner" "$permissions" "$days_old" "$package_status" "$exec_start" "$enabled_status" "$service_name" "$finding_matched_pattern" "$_final_matched_string"

            # NOTE: Only scan .service files for persistence detection
            # .socket and .timer files don't contain ExecStart commands - they only
            # define socket/timer activation and reference other .service files.
            # From a forensics perspective, only .service files contain the actual
            # persistence mechanism (the executable/script being run).
            done < <(find "$path" -maxdepth 1 -type f -name "*.service" -print0 2>/dev/null)
        fi
    done

    log_check "Systemd generator scripts"

    # ═══════════════════════════════════════════════════════════════════════════
    # Systemd Generator Scripts
    # Generators run at boot BEFORE any units load, as root, with no restrictions.
    # They can dynamically create service unit files, making them a powerful and
    # stealthy persistence vector - the actual generated units are ephemeral.
    # ═══════════════════════════════════════════════════════════════════════════
    local generator_dirs=(
        "/etc/systemd/system-generators"
        "/usr/lib/systemd/system-generators"
        "/lib/systemd/system-generators"
        "/run/systemd/system-generators"
        "/etc/systemd/user-generators"
        "/usr/lib/systemd/user-generators"
    )

    # Track scanned real paths to avoid double-scanning /lib/ and /usr/lib/ on merged-/usr
    local scanned_gen_dirs=()

    for gen_dir in "${generator_dirs[@]}"; do
        if [[ -d "$gen_dir" ]]; then
            local real_gen_dir
            real_gen_dir=$(realpath "$gen_dir" 2>/dev/null) || real_gen_dir="$gen_dir"
            local _already=false
            local _prev
            for _prev in "${scanned_gen_dirs[@]}"; do
                [[ "$_prev" == "$real_gen_dir" ]] && _already=true && break
            done
            "$_already" && continue
            scanned_gen_dirs+=("$real_gen_dir")

            while IFS= read -r -d '' gen_file; do
                local pkg_status pkg_return=0
                pkg_status=$(is_package_managed "$gen_file") || pkg_return=$?

                # Skip verified package-managed generators (expected on all systemd systems)
                [[ $pkg_return -eq 0 ]] && continue

                local metadata
                metadata=$(get_file_metadata "$gen_file") || true
                local confidence="HIGH"
                local finding_matched_pattern="unmanaged_generator"
                local finding_matched_string="$gen_file"

                if [[ $pkg_return -eq 2 ]]; then
                    # Modified generator - CRITICAL (runs as root before all units)
                    confidence="CRITICAL"
                    finding_matched_pattern="modified_generator"
                    finding_matched_string="$gen_file"
                    log_finding "Systemd generator is MODIFIED package file: $gen_file"
                elif [[ "$gen_file" =~ ^/(tmp|dev/shm|var/tmp|home) ]] || [[ "$gen_dir" =~ ^/(run) ]]; then
                    # Generator in suspicious/ephemeral location
                    confidence="CRITICAL"
                    finding_matched_pattern="suspicious_location_generator"
                    log_finding "Systemd generator in suspicious location: $gen_file"
                else
                    log_finding "Unmanaged systemd generator: $gen_file"
                fi

                # Analyze script content if accessible
                if is_script "$gen_file"; then
                    if analyze_script_content "$gen_file"; then
                        confidence="CRITICAL"
                        finding_matched_pattern="$MATCHED_PATTERN"
                        finding_matched_string="$MATCHED_STRING"
                        log_finding "Generator contains suspicious content: $gen_file"
                    fi
                fi

                add_finding "Systemd" "Generator" "systemd_generator" "$gen_file" "Systemd generator: $(basename "$gen_file")" "$confidence" "DEFER" "$metadata" "dir=$(basename "$gen_dir")|package=$pkg_status" "$finding_matched_pattern" "$finding_matched_string"

            done < <(find "$gen_dir" -maxdepth 1 -type f -print0 2>/dev/null)
        fi
    done

    log_check "Systemd .path units"

    # ═══════════════════════════════════════════════════════════════════════════
    # Systemd Path Units
    # .path units trigger service activation on filesystem events (file creation,
    # modification, etc.) — a stealthy persistence vector that bypasses .timer.
    # ═══════════════════════════════════════════════════════════════════════════
    local path_unit_dirs=(
        "/etc/systemd/system"
        "/usr/lib/systemd/system"
        "/lib/systemd/system"
        "/run/systemd/system"
    )

    local scanned_path_dirs=()
    for _pu_dir in "${path_unit_dirs[@]}"; do
        [[ -d "$_pu_dir" ]] || continue
        local _pu_real
        _pu_real=$(realpath "$_pu_dir" 2>/dev/null) || _pu_real="$_pu_dir"
        local _pu_already=false _pu_prev
        for _pu_prev in "${scanned_path_dirs[@]}"; do
            [[ "$_pu_prev" == "$_pu_real" ]] && _pu_already=true && break
        done
        "$_pu_already" && continue
        scanned_path_dirs+=("$_pu_real")

        while IFS= read -r -d '' path_unit_file; do
            local pu_pkg_status pu_pkg_return=0
            pu_pkg_status=$(is_package_managed "$path_unit_file") || pu_pkg_return=$?
            [[ $pu_pkg_return -eq 0 ]] && continue  # Verified package .path unit — skip

            local pu_metadata
            pu_metadata=$(get_file_metadata "$path_unit_file") || true
            local pu_mod_time=0
            [[ "$pu_metadata" =~ modified:([0-9]+) ]] && pu_mod_time="${BASH_REMATCH[1]}"
            local pu_days_old=$(( (SCAN_EPOCH - pu_mod_time) / 86400 ))

            local pu_confidence="HIGH"
            local pu_pattern="unmanaged_path_unit"
            local pu_string="$path_unit_file"
            local pu_activated_unit=""
            pu_activated_unit=$(grep -E "^Unit=" "$path_unit_file" 2>/dev/null | cut -d'=' -f2- | head -1) || true

            if [[ $pu_pkg_return -eq 2 ]]; then
                pu_confidence="CRITICAL"
                pu_pattern="modified_path_unit"
                log_finding "Systemd .path unit is MODIFIED package file: $path_unit_file"
            elif [[ "$path_unit_file" =~ ^/(tmp|run/|dev/shm|var/tmp) ]]; then
                pu_confidence="CRITICAL"
                pu_pattern="suspicious_location_path_unit"
                log_finding "Systemd .path unit in suspicious location: $path_unit_file"
            else
                log_finding "Unmanaged systemd .path unit: $path_unit_file (activates: ${pu_activated_unit:-unknown})"
            fi

            add_finding_new "Systemd PathUnit" "$pu_confidence" "$path_unit_file" "DEFER" \
                "$(get_owner_from_metadata "$pu_metadata")" "$(get_permissions_from_metadata "$pu_metadata")" \
                "$pu_days_old" "$pu_pkg_status" "${pu_activated_unit}" "" \
                "$(basename "$path_unit_file")" "$pu_pattern" "$pu_string"

        done < <(find "$_pu_dir" -maxdepth 1 -type f -name "*.path" -print0 2>/dev/null)
    done
}

# Analyze a cron command for suspicious patterns and unmanaged executables
# Follows same detection logic as systemd:
# - Package verification FIRST (verified = skip, move on)
# - Interpreter detection (check script, not interpreter binary)
# - Inline code detection (-c/-e flags)
# - Unmanaged script content analysis
# Returns: 0 if suspicious/unmanaged found, 1 if verified/clean (skip)
# Sets CRON_ANALYSIS_REASON with the reason for detection
CRON_ANALYSIS_REASON=""
analyze_cron_command() {
    local cron_command="$1"
    local source_file="$2"
    CRON_ANALYSIS_REASON=""

    [[ -z "$cron_command" ]] && return 1

    # DEFLOW-2 fix: check the raw command for suspicious patterns BEFORE checking executable
    # existence. Catches: "curl http://evil | bash", pipe-to-shell patterns, NEVER_WHITELIST
    # hits that would otherwise be silently skipped when the executable is a package-managed
    # binary like /usr/bin/curl or /usr/bin/wget.
    if [[ -n "$COMBINED_NEVER_WHITELIST_PATTERN" ]]; then
        if echo "$cron_command" | grep -qiE "$COMBINED_NEVER_WHITELIST_PATTERN"; then
            CRON_ANALYSIS_REASON="dangerous_pattern:$(echo "$cron_command" | grep -oiE "$COMBINED_NEVER_WHITELIST_PATTERN" | head -1)"
            return 0
        fi
    fi
    if quick_suspicious_check "$cron_command"; then
        CRON_ANALYSIS_REASON="suspicious_pattern:$MATCHED_STRING"
        return 0
    fi

    local executable
    executable=$(get_executable_from_command "$cron_command")

    # Check if executable exists
    if [[ -z "$executable" ]] || [[ ! -f "$executable" ]]; then
        return 1  # Cannot analyze, skip
    fi

    # ═══════════════════════════════════════════════════════════════════
    # BRANCH 1: Is it an interpreter? (python, perl, bash, etc.)
    # For interpreters, analyze the SCRIPT, not the interpreter binary
    # ═══════════════════════════════════════════════════════════════════
    if is_interpreter "$executable"; then
        local script_file
        script_file=$(get_script_from_interpreter_command "$cron_command") || true

        if [[ -n "$script_file" ]] && [[ -f "$script_file" ]]; then
            # ─────────────────────────────────────────────────────────
            # FIRST CHECK: Script package verification (most efficient)
            # ─────────────────────────────────────────────────────────
            local script_pkg_status script_pkg_return=0
            script_pkg_status=$(is_package_managed "$script_file") || script_pkg_return=$?

            if [[ $script_pkg_return -eq 0 ]]; then
                # Script is package-managed and VERIFIED - SKIP, move on
                return 1
            elif [[ $script_pkg_return -eq 2 ]]; then
                # Script was MODIFIED - CRITICAL
                CRON_ANALYSIS_REASON="modified_script:$script_file"
                return 0
            fi

            # Script is UNMANAGED - analyze content and location
            # Check suspicious location first
            if [[ "$script_file" =~ ^/(tmp|dev/shm|var/tmp|run/user/) ]] || [[ "$script_file" =~ /\.[a-zA-Z] ]]; then
                CRON_ANALYSIS_REASON="suspicious_location:$script_file"
                return 0
            fi

            # Analyze script content for suspicious patterns
            if is_script "$script_file"; then
                if analyze_script_content "$script_file"; then
                    # Include the actual suspicious content found
                    CRON_ANALYSIS_REASON="suspicious_script_content:$MATCHED_STRING"
                    return 0
                fi
            fi

            # Unmanaged but no suspicious content - show preview of file content
            local preview
            preview=$(grep -Ev "^#|^$" "$script_file" 2>/dev/null | head -3 | tr '\n' ' ' | head -c 150) || true
            CRON_ANALYSIS_REASON="unmanaged_script:${preview:-$script_file}"
            return 0

        else
            # No script file - check for INLINE CODE (-c/-e flags or env -S)
            if [[ "$cron_command" =~ \ -[ce]\  ]] || [[ "$cron_command" =~ \ -[ce]$ ]] || [[ "$cron_command" =~ [[:space:]](-S|--split-string)([[:space:]]|$) ]]; then
                # FLOW-3 fix: check if the interpreter ITSELF is in a suspicious location
                # (e.g. /tmp/bash -c 'code' should flag the interpreter, not just the code)
                if [[ "$executable" =~ ^/(tmp|dev/shm|var/tmp) ]] || [[ "$executable" =~ /\.[[:alpha:]] ]]; then
                    CRON_ANALYSIS_REASON="suspicious_interpreter_location:$executable"
                    return 0
                fi

                # Analyze the inline code content for patterns and obfuscation
                if analyze_inline_code "$cron_command"; then
                    CRON_ANALYSIS_REASON="inline_code_suspicious:$INLINE_CODE_REASON"
                else
                    CRON_ANALYSIS_REASON="inline_code:-c/-e flag"
                fi
                return 0
            fi

            # Check raw command for suspicious patterns (reverse shells use -i with /dev/tcp, etc.)
            if quick_suspicious_check "$cron_command"; then
                CRON_ANALYSIS_REASON="suspicious_command:$cron_command"
                return 0
            fi
            if [[ -n "$COMBINED_NEVER_WHITELIST_PATTERN" ]]; then
                if echo "$cron_command" | grep -qiE "$COMBINED_NEVER_WHITELIST_PATTERN"; then
                    CRON_ANALYSIS_REASON="dangerous_command:$cron_command"
                    return 0
                fi
            fi

            # Interactive interpreter without script and no suspicious patterns - skip
            return 1
        fi
    fi

    # ═══════════════════════════════════════════════════════════════════
    # BRANCH 2: Not an interpreter - direct binary execution
    # ═══════════════════════════════════════════════════════════════════

    # ─────────────────────────────────────────────────────────────────
    # FIRST CHECK: Binary package verification (most efficient)
    # ─────────────────────────────────────────────────────────────────
    local pkg_status pkg_return=0
    pkg_status=$(is_package_managed "$executable") || pkg_return=$?

    if [[ $pkg_return -eq 0 ]]; then
        # Binary is package-managed and VERIFIED - SKIP, move on
        return 1
    elif [[ $pkg_return -eq 2 ]]; then
        # Binary was MODIFIED - CRITICAL
        CRON_ANALYSIS_REASON="modified_binary:$executable"
        return 0
    fi

    # Binary is UNMANAGED - analyze location and content
    # Check suspicious location
    if [[ "$executable" =~ ^/(tmp|dev/shm|var/tmp|run/user/) ]] || [[ "$executable" =~ /\.[a-zA-Z] ]]; then
        CRON_ANALYSIS_REASON="suspicious_location:$executable"
        return 0
    fi

    # If it's a script file, analyze content
    # BUG-7 fix: cache is_script() result to avoid calling it twice (2 subprocesses each time)
    local _is_script=false
    is_script "$executable" && _is_script=true

    if $_is_script; then
        if analyze_script_content "$executable"; then
            # Include the actual suspicious content found
            CRON_ANALYSIS_REASON="suspicious_script_content:$MATCHED_STRING"
            return 0
        fi
    fi

    # Unmanaged binary but no suspicious content - show preview if script
    local preview=""
    if $_is_script; then
        preview=$(grep -Ev "^#|^$" "$executable" 2>/dev/null | head -3 | tr '\n' ' ' | head -c 150) || true
    fi
    CRON_ANALYSIS_REASON="unmanaged_binary:${preview:-$executable}"
    return 0
}

# Check cron jobs
check_cron() {
    log_info "[2/9] Checking cron jobs and scheduled tasks..."

    # ═══════════════════════════════════════════════════════════════════════════
    # ALL CRON FILES: Same detection logic
    # - Package verified → SKIP (file untouched, no malicious entries possible)
    # - Package modified → CRITICAL (file tampered)
    # - Unmanaged → Analyze entries
    # ═══════════════════════════════════════════════════════════════════════════

    # Individual crontab files
    local crontab_files=(
        "/etc/crontab"
    )

    # Crontab directories (files with time specifications)
    local crontab_dirs=(
        "/etc/cron.d"
        "/var/spool/cron"
        "/var/spool/cron/crontabs"
    )

    # Cron script directories (standalone scripts, NO time specs)
    local cron_script_dirs=(
        "/etc/cron.daily"
        "/etc/cron.hourly"
        "/etc/cron.weekly"
        "/etc/cron.monthly"
    )

    log_check "/etc/crontab"

    # ─────────────────────────────────────────────────────────────────────────
    # Process /etc/crontab
    # ─────────────────────────────────────────────────────────────────────────
    for cron_path in "${crontab_files[@]}"; do
        if [[ -f "$cron_path" ]]; then
            # FIRST CHECK: Package verification
            # Use || true pattern to prevent set -e from exiting on non-zero return
            local package_status
            local pkg_return=0
            package_status=$(is_package_managed "$cron_path") || pkg_return=$?

            if [[ $pkg_return -eq 0 ]]; then
                # Package-managed and VERIFIED - skip entirely
                continue
            fi

            # File is MODIFIED or UNMANAGED - analyze it
            local hash
            hash=$(get_file_hash "$cron_path") || true
            local metadata
            metadata=$(get_file_metadata "$cron_path") || true
            local content
            content=$(grep -Ev "^#|^$" "$cron_path" 2>/dev/null | head -200) || true
            local confidence="MEDIUM"
            local finding_matched_pattern=""
            local finding_matched_string=""

            if [[ $pkg_return -eq 2 ]]; then
                # Package file was MODIFIED - CRITICAL
                confidence="CRITICAL"
                finding_matched_pattern="modified_package"
                finding_matched_string="$cron_path"
                log_finding "Crontab is MODIFIED package file: $cron_path"
            fi

            # Analyze crontab entries for suspicious commands
            while IFS= read -r cron_line; do
                [[ -z "$cron_line" ]] && continue
                local cron_command
                # @special entries: "@reboot username command..." — command starts at field 3
                # timed entries:    "* * * * * username command..." — command starts at field 7
                local _cf; read -ra _cf <<< "$cron_line"
                if [[ "$cron_line" =~ ^@ ]]; then
                    cron_command="${_cf[*]:2}"
                else
                    cron_command="${_cf[*]:6}"
                fi
                cron_command="${cron_command%"${cron_command##*[![:space:]]}"}"
                if analyze_cron_command "$cron_command" "$cron_path"; then
                    [[ "$confidence" != "CRITICAL" ]] && confidence="HIGH"
                    # Extract pattern and string from CRON_ANALYSIS_REASON (format: pattern:value)
                    finding_matched_pattern="${CRON_ANALYSIS_REASON%%:*}"
                    finding_matched_string="${CRON_ANALYSIS_REASON#*:}"
                    log_finding "Crontab entry suspicious ($CRON_ANALYSIS_REASON): $cron_path"
                fi
            done <<< "$content"

            add_finding "Cron" "System" "crontab_file" "$cron_path" "System crontab" "$confidence" "$hash" "$metadata" "entries=$(echo "$content" | wc -l)|package=$package_status" "$finding_matched_pattern" "$finding_matched_string"
        fi
    done

    log_check "Crontab directories (cron.d, spool)"

    # ─────────────────────────────────────────────────────────────────────────
    # Process crontab directories (/etc/cron.d, /var/spool/cron/*)
    # ─────────────────────────────────────────────────────────────────────────
    for cron_dir in "${crontab_dirs[@]}"; do
        if [[ -d "$cron_dir" ]]; then
            while IFS= read -r -d '' cron_file; do
                # FIRST CHECK: Package verification
                # Use || pkg_return=$? pattern to capture return code with set -e
                local package_status
                local pkg_return=0
                package_status=$(is_package_managed "$cron_file") || pkg_return=$?

                if [[ $pkg_return -eq 0 ]]; then
                    # Package-managed and VERIFIED - skip entirely
                    continue
                fi

                # File is MODIFIED or UNMANAGED - analyze it
                local hash="DEFER"
                local metadata
                metadata=$(get_file_metadata "$cron_file") || true
                local content
                content=$(grep -Ev "^#|^$" "$cron_file" 2>/dev/null | head -200) || true
                local confidence="MEDIUM"
                local finding_matched_pattern=""
                local finding_matched_string=""

                if [[ $pkg_return -eq 2 ]]; then
                    # Package file was MODIFIED - CRITICAL
                    confidence="CRITICAL"
                    finding_matched_pattern="modified_package"
                    finding_matched_string="$cron_file"
                    log_finding "Crontab is MODIFIED package file: $cron_file"
                fi

                # Analyze crontab entries for suspicious commands
                while IFS= read -r cron_line; do
                    [[ -z "$cron_line" ]] && continue
                    local cron_command
                    # @special entries: "@reboot username command..." — command starts at field 3
                    # timed entries:    "* * * * * username command..." — command starts at field 7
                    local _cf; read -ra _cf <<< "$cron_line"
                    if [[ "$cron_line" =~ ^@ ]]; then
                        cron_command="${_cf[*]:2}"
                    else
                        cron_command="${_cf[*]:6}"
                    fi
                    cron_command="${cron_command%"${cron_command##*[![:space:]]}"}"
                    if analyze_cron_command "$cron_command" "$cron_file"; then
                        [[ "$confidence" != "CRITICAL" ]] && confidence="HIGH"
                        finding_matched_pattern="${CRON_ANALYSIS_REASON%%:*}"
                        finding_matched_string="${CRON_ANALYSIS_REASON#*:}"
                        log_finding "Crontab entry suspicious ($CRON_ANALYSIS_REASON): $cron_file"
                    fi
                done <<< "$content"

                add_finding "Cron" "System" "crontab_file" "$cron_file" "Crontab: $(basename "$cron_file")" "$confidence" "$hash" "$metadata" "package=$package_status" "$finding_matched_pattern" "$finding_matched_string"

            done < <(find "$cron_dir" \( -type f -o -type l \) -print0 2>/dev/null)
        fi
    done

    log_check "Periodic cron directories (daily/hourly/weekly/monthly)"

    # ─────────────────────────────────────────────────────────────────────────
    # Process cron script directories (/etc/cron.daily, hourly, weekly, monthly)
    # These are standalone scripts - same logic applies
    # ─────────────────────────────────────────────────────────────────────────
    for cron_dir in "${cron_script_dirs[@]}"; do
        if [[ -d "$cron_dir" ]]; then
            while IFS= read -r -d '' cron_script; do
                # FIRST CHECK: Package verification
                # Use || pkg_return=$? pattern to capture return code with set -e
                local package_status
                local pkg_return=0
                package_status=$(is_package_managed "$cron_script") || pkg_return=$?

                if [[ $pkg_return -eq 0 ]]; then
                    # Package-managed and VERIFIED - skip entirely
                    continue
                fi

                # File is MODIFIED or UNMANAGED - analyze it
                local hash="DEFER"
                local metadata
                metadata=$(get_file_metadata "$cron_script") || true
                local confidence="MEDIUM"
                local finding_matched_pattern=""
                local finding_matched_string=""

                if [[ $pkg_return -eq 2 ]]; then
                    # Package file was MODIFIED - CRITICAL
                    confidence="CRITICAL"
                    finding_matched_pattern="modified_package"
                    finding_matched_string="$cron_script"
                    log_finding "Cron script is MODIFIED package file: $cron_script"
                else
                    # UNMANAGED script - analyze content
                    # Extract mod_time from already-fetched metadata (no extra stat fork)
                    local mod_time=0
                    [[ "$metadata" =~ modified:([0-9]+) ]] && mod_time="${BASH_REMATCH[1]}"
                    local current_time=$SCAN_EPOCH
                    local days_old=$(( (current_time - mod_time) / 86400 ))

                    # (time-based elevation removed — no baseline context)

                    if [[ "$cron_script" =~ \.(tmp|bak|old)$ ]] || [[ "$(basename "$cron_script")" =~ ^\. ]]; then
                        confidence="HIGH"
                        finding_matched_pattern="suspicious_name"
                        finding_matched_string="$(basename "$cron_script")"
                        log_finding "Cron script with suspicious name: $cron_script"
                    fi

                    if analyze_script_content "$cron_script"; then
                        confidence="HIGH"
                        finding_matched_pattern="$MATCHED_PATTERN"
                        finding_matched_string="$MATCHED_STRING"
                        log_finding "Cron script contains suspicious content: $cron_script"
                    fi
                fi

                add_finding "Cron" "Script" "cron_script" "$cron_script" "Cron script: $(basename "$cron_script")" "$confidence" "$hash" "$metadata" "dir=$(basename "$(dirname "$cron_script")")|package=$package_status" "$finding_matched_pattern" "$finding_matched_string"

            done < <(find "$cron_dir" -type f -print0 2>/dev/null)
        fi
    done

    log_check "User crontabs"

    # User crontabs
    # Analyze each entry with the full execution chain (same flow as /etc/crontab and /etc/cron.d)
    if [[ $EUID_CHECK -eq 0 ]]; then
        while IFS=: read -r username _ uid _; do
            if [[ $uid -ge 1000 ]] || [[ $uid -eq 0 ]]; then
                local user_cron
                user_cron=$(crontab -u "$username" -l 2>/dev/null || echo "")
                if [[ -n "$user_cron" ]]; then
                    local confidence="MEDIUM"
                    local finding_matched_pattern=""
                    local finding_matched_string=""

                    while IFS= read -r cron_line; do
                        # Skip comments, empty lines, and variable assignments
                        [[ "$cron_line" =~ ^[[:space:]]*# ]] && continue
                        [[ -z "${cron_line//[[:space:]]/}" ]] && continue
                        [[ "$cron_line" =~ ^[A-Z_]+= ]] && continue

                        # Extract command column: @special uses field 2+, timed entries field 6+
                        local cron_command
                        local _cf; read -ra _cf <<< "$cron_line"
                        if [[ "$cron_line" =~ ^@ ]]; then
                            cron_command="${_cf[*]:1}"
                        else
                            cron_command="${_cf[*]:5}"
                        fi
                        cron_command="${cron_command%"${cron_command##*[![:space:]]}"}"  # rtrim

                        if analyze_cron_command "$cron_command" "/var/spool/cron/crontabs/$username"; then
                            [[ "$confidence" != "CRITICAL" ]] && confidence="HIGH"
                            finding_matched_pattern="${CRON_ANALYSIS_REASON%%:*}"
                            finding_matched_string="${CRON_ANALYSIS_REASON#*:}"
                            log_finding "User crontab entry suspicious ($CRON_ANALYSIS_REASON): $username"
                        fi
                    done <<< "$user_cron"

                    add_finding "Cron" "User" "user_crontab" "/var/spool/cron/crontabs/$username" "User $username crontab entries" "$confidence" "N/A" "user=$username" "preview=${user_cron:0:100}" "$finding_matched_pattern" "$finding_matched_string"
                fi
            fi
        done < /etc/passwd
    else
        # Non-root: check only current user
        local user_cron
        user_cron=$(crontab -l 2>/dev/null || echo "")
        if [[ -n "$user_cron" ]]; then
            local confidence="MEDIUM"
            local finding_matched_pattern=""
            local finding_matched_string=""

            while IFS= read -r cron_line; do
                [[ "$cron_line" =~ ^[[:space:]]*# ]] && continue
                [[ -z "${cron_line//[[:space:]]/}" ]] && continue
                [[ "$cron_line" =~ ^[A-Z_]+= ]] && continue

                local cron_command
                local _cf; read -ra _cf <<< "$cron_line"
                if [[ "$cron_line" =~ ^@ ]]; then
                    cron_command="${_cf[*]:1}"
                else
                    cron_command="${_cf[*]:5}"
                fi
                cron_command="${cron_command%"${cron_command##*[![:space:]]}"}"

                if analyze_cron_command "$cron_command" "~/.crontab"; then
                    [[ "$confidence" != "CRITICAL" ]] && confidence="HIGH"
                    finding_matched_pattern="${CRON_ANALYSIS_REASON%%:*}"
                    finding_matched_string="${CRON_ANALYSIS_REASON#*:}"
                    log_finding "User crontab entry suspicious ($CRON_ANALYSIS_REASON): $(whoami)"
                fi
            done <<< "$user_cron"

            add_finding "Cron" "User" "user_crontab" "~/.crontab" "Current user crontab" "$confidence" "N/A" "user=$(whoami)" "preview=${user_cron:0:100}" "$finding_matched_pattern" "$finding_matched_string"
        fi
    fi

    log_check "At jobs (atq + spool)"

    # Check at jobs - two methods:
    # 1. atq + at -c: standard, but atq can be tampered on compromised systems
    # 2. Direct spool scan: forensically reliable, catches hidden jobs not shown by atq
    local atq_job_ids=()

    if command -v atq &> /dev/null; then
        local at_jobs
        at_jobs=$(atq 2>/dev/null || echo "")
        if [[ -n "$at_jobs" ]]; then
            log_info "Found at jobs via atq"
            while read -r job_line; do
                local job_id
                job_id=$(echo "$job_line" | awk '{print $1}')
                atq_job_ids+=("$job_id")
                local job_details
                job_details=$(at -c "$job_id" 2>/dev/null | tail -20 | tr -d '\0' || echo "")

                local confidence="LOW"
                local finding_matched_pattern=""
                local finding_matched_string=""

                # Analyze each command line with full execution chain
                while IFS= read -r at_line; do
                    [[ -z "${at_line//[[:space:]]/}" ]] && continue
                    [[ "$at_line" =~ ^[[:space:]]*# ]] && continue
                    # Skip shell environment preamble lines from at -c output
                    [[ "$at_line" =~ ^(export |umask |cd |eval |typeset ) ]] && continue

                    if analyze_cron_command "$at_line" "/var/spool/at/$job_id"; then
                        [[ "$confidence" != "HIGH" ]] && confidence="HIGH"
                        finding_matched_pattern="${CRON_ANALYSIS_REASON%%:*}"
                        finding_matched_string="${CRON_ANALYSIS_REASON#*:}"
                        log_finding "Suspicious at job $job_id ($CRON_ANALYSIS_REASON)"
                    fi
                done <<< "$job_details"

                add_finding "Scheduled" "At" "at_job" "/var/spool/at/$job_id" "At job $job_id" "$confidence" "N/A" "$job_line" "job_id=$job_id" "$finding_matched_pattern" "$finding_matched_string"
            done <<< "$at_jobs"
        fi
    fi

    # Direct at spool scan - catches hidden jobs not visible via atq
    # On compromised systems, atq may be tampered but spool files remain
    local at_spool_dirs=(
        "/var/spool/at"
        "/var/spool/cron/atjobs"
    )
    for spool_dir in "${at_spool_dirs[@]}"; do
        if [[ -d "$spool_dir" ]] && [[ $EUID_CHECK -eq 0 ]]; then
            while IFS= read -r -d '' spool_file; do
                local spool_name
                spool_name=$(basename "$spool_file")

                # at spool files are named with job ID (numeric) - skip non-job files like .SEQ
                [[ "$spool_name" =~ ^\. ]] && continue
                [[ ! "$spool_name" =~ ^[a-zA-Z0-9=+_-]+$ ]] && continue

                local metadata
                metadata=$(get_file_metadata "$spool_file") || true
                local content
                # at spool files start with env setup then the actual job commands
                # Skip the env header (lines starting with export/cd etc) and read the job payload
                content=$(grep -v "^export\|^cd \|^umask\|^#!/" "$spool_file" 2>/dev/null | tr -d '\0' | head -50) || true

                local confidence="LOW"
                local finding_matched_pattern=""
                local finding_matched_string=""
                local hidden_flag=""

                # Check if this job was NOT visible in atq (hidden job)
                # Note: If atq_job_ids is empty, atd might not be running - skip hidden check
                local in_atq=false
                if [[ ${#atq_job_ids[@]} -gt 0 ]]; then
                    for known_id in "${atq_job_ids[@]}"; do
                        # At spool files embed the job ID (format varies: "a0000001", "=a01", etc.)
                        # Use boundary-aware regex: match zero-padded job ID bounded by non-digits
                        # to prevent "1" matching "10", "12", "21", etc. (substring false positive)
                        if echo "$spool_name" | grep -qE "(^|[^0-9])0*${known_id}([^0-9]|$)"; then
                            in_atq=true
                            break
                        fi
                    done

                    if [[ "$in_atq" == "false" ]]; then
                        # Job exists in spool but NOT in atq - suspicious but could be timing/format issue
                        confidence="MEDIUM"  # MEDIUM not HIGH - could be false positive
                        finding_matched_pattern="hidden_at_job"
                        finding_matched_string="$spool_name (not in atq output)"
                        hidden_flag="hidden=true"
                        log_finding "At job in spool not visible in atq (possible hidden job): $spool_file"
                    fi
                fi

                # Analyze each command line with full execution chain
                while IFS= read -r spool_line; do
                    [[ -z "${spool_line//[[:space:]]/}" ]] && continue
                    [[ "$spool_line" =~ ^[[:space:]]*# ]] && continue
                    [[ "$spool_line" =~ ^(export |umask |cd |eval |typeset ) ]] && continue

                    if analyze_cron_command "$spool_line" "$spool_file"; then
                        [[ "$confidence" != "HIGH" ]] && confidence="HIGH"
                        if [[ -z "$finding_matched_pattern" ]] || [[ "$in_atq" == "true" ]]; then
                            finding_matched_pattern="${CRON_ANALYSIS_REASON%%:*}"
                            finding_matched_string="${CRON_ANALYSIS_REASON#*:}"
                        fi
                        log_finding "Suspicious content in at spool file: $spool_file"
                    fi
                done <<< "$content"

                # Only report if not already reported via atq (avoid duplicates for visible jobs)
                if [[ "$in_atq" == "false" ]]; then
                    add_finding "Scheduled" "At" "at_spool" "$spool_file" "At spool job: $spool_name" "$confidence" "DEFER" "$metadata" "spool=$spool_dir|${hidden_flag}" "$finding_matched_pattern" "$finding_matched_string"
                fi

            done < <(find "$spool_dir" -maxdepth 1 -type f -print0 2>/dev/null)
        fi
    done

    log_check "Anacron (/etc/anacrontab)"

    # Check anacron (/etc/anacrontab) - persistent jobs for machines that may be powered off
    # Anacron guarantees job execution even after missed runs - a stealth persistence vector
    if [[ -f "/etc/anacrontab" ]]; then
        local pkg_status pkg_return=0
        pkg_status=$(is_package_managed "/etc/anacrontab") || pkg_return=$?

        if [[ $pkg_return -ne 0 ]]; then
            # Unmanaged or modified anacrontab
            local metadata
            metadata=$(get_file_metadata "/etc/anacrontab") || true
            local content
            content=$(grep -Ev "^#|^$|^SHELL|^PATH|^MAILTO|^RANDOM_DELAY|^START_HOURS_RANGE" "/etc/anacrontab" 2>/dev/null | head -20) || true
            local confidence="MEDIUM"
            local finding_matched_pattern="unmanaged_anacrontab"
            local finding_matched_string="/etc/anacrontab"

            if [[ $pkg_return -eq 2 ]]; then
                confidence="CRITICAL"
                finding_matched_pattern="modified_anacrontab"
                log_finding "anacrontab is MODIFIED package file: /etc/anacrontab"
            elif [[ -n "$content" ]]; then
                if quick_suspicious_check "$content"; then
                    confidence="HIGH"
                    finding_matched_pattern="$MATCHED_PATTERN"
                    finding_matched_string="$MATCHED_STRING"
                    log_finding "Suspicious anacrontab content: /etc/anacrontab"
                else
                    log_finding "Unmanaged anacrontab with entries: /etc/anacrontab"
                fi
            fi

            add_finding "Cron" "Anacron" "anacrontab" "/etc/anacrontab" "Anacron scheduled jobs" "$confidence" "DEFER" "$metadata" "package=$pkg_status" "$finding_matched_pattern" "$finding_matched_string"
        fi
    fi

    log_check "cron.allow / cron.deny ACL files"

    # ─────────────────────────────────────────────────────────────────────────
    # cron.allow / cron.deny — ACL files controlling who may use cron.
    # Tampered to allow unauthorized accounts = privilege escalation path.
    # ─────────────────────────────────────────────────────────────────────────
    local cron_acl_files=( "/etc/cron.allow" "/etc/cron.deny" )
    for _ca_file in "${cron_acl_files[@]}"; do
        [[ -f "$_ca_file" ]] || continue
        local _ca_hash _ca_meta _ca_pkg_status _ca_pkg_return=0
        _ca_hash=$(get_file_hash "$_ca_file") || true
        _ca_meta=$(get_file_metadata "$_ca_file") || true
        _ca_pkg_status=$(is_package_managed "$_ca_file") || _ca_pkg_return=$?

        local _ca_confidence="MEDIUM"
        local _ca_pattern="cron_acl_file"
        local _ca_string="$_ca_file"

        if [[ $_ca_pkg_return -eq 2 ]]; then
            _ca_confidence="CRITICAL"
            _ca_pattern="modified_cron_acl"
            _ca_string="$_ca_file"
            log_finding "Cron ACL file is MODIFIED package file: $_ca_file"
        elif [[ $_ca_pkg_return -eq 0 ]]; then
            _ca_confidence="LOW"
            _ca_pattern="verified_cron_acl"
        else
            log_finding "Unmanaged cron ACL file: $_ca_file"
        fi

        add_finding "Cron" "ACL" "cron_acl" "$_ca_file" "Cron access control: $(basename "$_ca_file")" \
            "$_ca_confidence" "$_ca_hash" "$_ca_meta" "package=$_ca_pkg_status" "$_ca_pattern" "$_ca_string"
    done
}

# Check shell profiles and RC files
check_shell_profiles() {
    log_info "[3/9] Checking shell profiles and RC files..."

    local profile_files=(
        "/etc/profile"
        "/etc/profile.d"
        "/etc/bash.bashrc"
        "/etc/bashrc"
        "/etc/zsh/zshrc"
        "/etc/zshrc"
        "/etc/zsh/zshenv"      # Sourced for ALL zsh invocations (interactive, non-interactive, login, scripts)
        "/etc/zsh/zprofile"    # Zsh login profile (equivalent to bash_profile)
        "/etc/zsh/zlogin"      # Zsh login shell post-zshrc
        "/etc/fish/config.fish"
    )

    log_check "System-wide shell profiles"

    # System-wide profiles
    for profile in "${profile_files[@]}"; do
        if [[ -e "$profile" ]]; then
            if [[ -f "$profile" ]]; then
                local hash=$(get_file_hash "$profile")
                local metadata=$(get_file_metadata "$profile")
                local content=$(head -n 500 "$profile" 2>/dev/null || echo "")

                local confidence="LOW"
                local finding_matched_pattern=""
                local finding_matched_string=""
                if quick_suspicious_check "$content"; then
                    confidence="HIGH"
                    finding_matched_pattern="$MATCHED_PATTERN"
                    finding_matched_string="$MATCHED_STRING"
                    log_finding "Suspicious content in profile: $profile"
                elif analyze_script_content "$profile"; then
                    confidence="HIGH"
                    finding_matched_pattern="$MATCHED_PATTERN"
                    finding_matched_string="$MATCHED_STRING"
                    log_finding "Profile contains suspicious script patterns: $profile"
                fi

                # Check if file is package-managed and adjust confidence
                local package_status
                package_status=$(is_package_managed "$profile") || true
                confidence=$(adjust_confidence_for_package "$confidence" "$package_status")

                # (time-based elevation removed — no baseline context)
                local mod_time=0
                [[ "$metadata" =~ modified:([0-9]+) ]] && mod_time="${BASH_REMATCH[1]}"
                local days_old=$(( (SCAN_EPOCH - mod_time) / 86400 ))

                add_finding "ShellProfile" "System" "profile_file" "$profile" "System shell profile" "$confidence" "$hash" "$metadata" "days_old=${days_old};package=$package_status" "$finding_matched_pattern" "$finding_matched_string"

            elif [[ -d "$profile" ]]; then
                while IFS= read -r -d '' profile_file; do
                    local hash="DEFER"  # Defer hash calculation until filtering
                    local metadata=$(get_file_metadata "$profile_file")
                    local content=$(head -n 500 "$profile_file" 2>/dev/null || echo "")

                    local confidence="LOW"
                    local finding_matched_pattern=""
                    local finding_matched_string=""
                    if quick_suspicious_check "$content"; then
                        confidence="HIGH"
                        finding_matched_pattern="$MATCHED_PATTERN"
                        finding_matched_string="$MATCHED_STRING"
                        log_finding "Suspicious profile script: $profile_file"
                    elif analyze_script_content "$profile_file"; then
                        confidence="HIGH"
                        finding_matched_pattern="$MATCHED_PATTERN"
                        finding_matched_string="$MATCHED_STRING"
                        log_finding "Profile.d script contains suspicious patterns: $profile_file"
                    fi

                    # Check if file is package-managed and adjust confidence
                    local package_status
                    package_status=$(is_package_managed "$profile_file") || true
                    confidence=$(adjust_confidence_for_package "$confidence" "$package_status")

                    # (time-based elevation removed — no baseline context)
                    local mod_time=0
                    [[ "$metadata" =~ modified:([0-9]+) ]] && mod_time="${BASH_REMATCH[1]}"
                    local days_old=$(( (SCAN_EPOCH - mod_time) / 86400 ))

                    add_finding "ShellProfile" "System" "profile_script" "$profile_file" "Profile.d script: $(basename "$profile_file")" "$confidence" "$hash" "$metadata" "days_old=${days_old};package=$package_status" "$finding_matched_pattern" "$finding_matched_string"

                done < <(find "$profile" -type f -print0 2>/dev/null)
            fi
        fi
    done

    log_check "User shell profiles"

    # User profiles
    local user_profiles=(
        ".bashrc"
        ".bash_profile"
        ".bash_login"
        ".profile"
        ".zshrc"
        ".zprofile"
        ".zlogin"
        ".zshenv"              # Most powerful zsh config - sourced for ALL invocations including non-interactive
        ".bash_logout"         # Executed on logout — can persist cleanup scripts or beacons
        ".config/fish/config.fish"
    )

    # Check for all users if root
    if [[ $EUID_CHECK -eq 0 ]]; then
        while IFS=: read -r username _ uid _ _ homedir _; do
            if [[ $uid -ge 1000 ]] || [[ $uid -eq 0 ]]; then
                for user_profile in "${user_profiles[@]}"; do
                    local profile_path="$homedir/$user_profile"
                    if [[ -f "$profile_path" ]]; then
                        local hash=$(get_file_hash "$profile_path")
                        local metadata=$(get_file_metadata "$profile_path")
                        local content=$(head -n 500 "$profile_path" 2>/dev/null || echo "")

                        local confidence="LOW"
                        local finding_matched_pattern=""
                        local finding_matched_string=""
                        if quick_suspicious_check "$content"; then
                            confidence="HIGH"
                            finding_matched_pattern="$MATCHED_PATTERN"
                            finding_matched_string="$MATCHED_STRING"
                            log_finding "Suspicious user profile: $profile_path (user: $username)"
                        elif analyze_script_content "$profile_path"; then
                            confidence="HIGH"
                            finding_matched_pattern="$MATCHED_PATTERN"
                            finding_matched_string="$MATCHED_STRING"
                            log_finding "User profile contains suspicious patterns: $profile_path (user: $username)"
                        fi

                        # DEFLOW-3: Check package status — catches modified system-managed dotfiles (e.g., /root/.bashrc)
                        local package_status
                        package_status=$(is_package_managed "$profile_path") || true
                        confidence=$(adjust_confidence_for_package "$confidence" "$package_status")

                        # (time-based elevation removed — no baseline context)
                        local mod_time=0
                        [[ "$metadata" =~ modified:([0-9]+) ]] && mod_time="${BASH_REMATCH[1]}"
                        local days_old=$(( (SCAN_EPOCH - mod_time) / 86400 ))

                        add_finding "ShellProfile" "User" "user_profile" "$profile_path" "User profile for $username" "$confidence" "$hash" "$metadata" "days_old=${days_old};user=$username;package=$package_status" "$finding_matched_pattern" "$finding_matched_string"
                    fi
                done
            fi
        done < /etc/passwd
    else
        # Non-root: check only current user
        for user_profile in "${user_profiles[@]}"; do
            local profile_path="$HOME/$user_profile"
            if [[ -f "$profile_path" ]]; then
                local hash=$(get_file_hash "$profile_path")
                local metadata=$(get_file_metadata "$profile_path")
                local content=$(head -n 500 "$profile_path" 2>/dev/null || echo "")

                local confidence="LOW"
                local finding_matched_pattern=""
                local finding_matched_string=""
                if quick_suspicious_check "$content"; then
                    confidence="HIGH"
                    finding_matched_pattern="$MATCHED_PATTERN"
                    finding_matched_string="$MATCHED_STRING"
                elif analyze_script_content "$profile_path"; then
                    confidence="HIGH"
                    finding_matched_pattern="$MATCHED_PATTERN"
                    finding_matched_string="$MATCHED_STRING"
                fi

                # DEFLOW-3: Check package status — catches modified system-managed dotfiles
                local package_status
                package_status=$(is_package_managed "$profile_path") || true
                confidence=$(adjust_confidence_for_package "$confidence" "$package_status")

                # (time-based elevation removed — no baseline context)
                local mod_time=0
                [[ "$metadata" =~ modified:([0-9]+) ]] && mod_time="${BASH_REMATCH[1]}"
                local days_old=$(( (SCAN_EPOCH - mod_time) / 86400 ))

                add_finding "ShellProfile" "User" "user_profile" "$profile_path" "Current user profile" "$confidence" "$hash" "$metadata" "days_old=${days_old};user=$(whoami);package=$package_status" "$finding_matched_pattern" "$finding_matched_string"
            fi
        done
    fi
}

# Check init scripts and rc.local
check_init_scripts() {
    log_info "[4/9] Checking init scripts and rc.local..."

    log_check "rc.local startup scripts"

    # ═══════════════════════════════════════════════════════════════════════════
    # TYPE 1: rc.local files (typically NOT package-managed, always analyze)
    # These are user-customization files that run at boot
    # ═══════════════════════════════════════════════════════════════════════════
    local rc_local_files=(
        "/etc/rc.local"
        "/etc/rc.d/rc.local"
    )

    for rc_local in "${rc_local_files[@]}"; do
        if [[ -f "$rc_local" ]]; then
            # rc.local is typically not package-managed - always analyze
            local hash=$(get_file_hash "$rc_local")
            local metadata=$(get_file_metadata "$rc_local")
            local content=$(grep -Ev "^#|^$" "$rc_local" 2>/dev/null | head -20 || echo "")
            local package_status pkg_return=0
            package_status=$(is_package_managed "$rc_local") || pkg_return=$?

            local confidence="MEDIUM"
            local finding_matched_pattern=""
            local finding_matched_string=""

            # If it's package-managed and verified, still flag but lower confidence
            # (rc.local having content is unusual even if from a package)
            if [[ -n "$content" ]]; then
                if quick_suspicious_check "$content"; then
                    confidence="HIGH"
                    finding_matched_pattern="$MATCHED_PATTERN"
                    finding_matched_string="$MATCHED_STRING"
                    log_finding "Suspicious rc.local: $rc_local"
                elif analyze_script_content "$rc_local"; then
                    confidence="HIGH"
                    finding_matched_pattern="$MATCHED_PATTERN"
                    finding_matched_string="$MATCHED_STRING"
                    log_finding "rc.local contains suspicious patterns: $rc_local"
                fi
            fi

            # Adjust confidence based on package status
            confidence=$(adjust_confidence_for_package "$confidence" "$package_status")

            add_finding "Init" "RcLocal" "rc_local" "$rc_local" "rc.local startup script" "$confidence" "$hash" "$metadata" "package=$package_status" "$finding_matched_pattern" "$finding_matched_string"
        fi
    done

    log_check "SysV init.d scripts"

    # ═══════════════════════════════════════════════════════════════════════════
    # TYPE 2: /etc/init.d scripts (often package-managed)
    # Check package status FIRST, skip if verified (like systemd/cron)
    # ═══════════════════════════════════════════════════════════════════════════
    if [[ -d "/etc/init.d" ]]; then
        while IFS= read -r -d '' init_file; do
            # Skip if it's a symbolic link to /dev/null
            if [[ -L "$init_file" ]]; then
                local link_target=$(readlink -f "$init_file")
                if [[ "$link_target" == "/dev/null" ]]; then
                    continue
                fi
            fi

            # ─────────────────────────────────────────────────────────────
            # FIRST CHECK: Package verification (like systemd/cron)
            # If verified, skip entirely - no need to analyze
            # ─────────────────────────────────────────────────────────────
            local package_status pkg_return=0
            package_status=$(is_package_managed "$init_file") || pkg_return=$?

            if [[ $pkg_return -eq 0 ]]; then
                # Package-managed and VERIFIED - skip this file entirely
                continue
            fi

            # File is either MODIFIED or UNMANAGED - analyze it
            local hash="DEFER"
            local metadata=$(get_file_metadata "$init_file")
            local confidence="MEDIUM"
            local finding_matched_pattern=""
            local finding_matched_string=""

            if [[ $pkg_return -eq 2 ]]; then
                # Package file was MODIFIED - CRITICAL
                confidence="CRITICAL"
                finding_matched_pattern="modified_package"
                finding_matched_string="$init_file"
                log_finding "Init script is MODIFIED package file: $init_file"
            else
                # UNMANAGED script - analyze content
                if quick_suspicious_check "$(head -n 50 "$init_file" 2>/dev/null)"; then
                    confidence="HIGH"
                    finding_matched_pattern="$MATCHED_PATTERN"
                    finding_matched_string="$MATCHED_STRING"
                    log_finding "Suspicious init script: $init_file"
                elif analyze_script_content "$init_file"; then
                    confidence="HIGH"
                    finding_matched_pattern="$MATCHED_PATTERN"
                    finding_matched_string="$MATCHED_STRING"
                    log_finding "Init script contains suspicious patterns: $init_file"
                fi
            fi

            add_finding "Init" "Script" "init_script" "$init_file" "Init script: $(basename "$init_file")" "$confidence" "$hash" "$metadata" "package=$package_status" "$finding_matched_pattern" "$finding_matched_string"

        done < <(find "/etc/init.d" -maxdepth 1 \( -type f -o -type l \) -print0 2>/dev/null)
    fi

    log_check "Runlevel scripts (rc*.d symlinks)"

    # ═══════════════════════════════════════════════════════════════════════════
    # TYPE 3: /etc/rc*.d directories (runlevel symlinks)
    # These are typically symlinks to /etc/init.d - check for non-symlink files
    # which would be suspicious (scripts shouldn't be directly in rc*.d)
    # ═══════════════════════════════════════════════════════════════════════════
    for rc_dir in /etc/rc*.d; do
        if [[ -d "$rc_dir" ]]; then
            # Check 1: Non-symlink files in rc*.d (always suspicious - these dirs should only have symlinks)
            while IFS= read -r -d '' rc_file; do
                if [[ -f "$rc_file" ]] && [[ ! -L "$rc_file" ]]; then
                    local hash="DEFER"
                    local metadata=$(get_file_metadata "$rc_file")
                    local confidence="HIGH"
                    local finding_matched_pattern="non_symlink_in_rcd"
                    local finding_matched_string="$rc_file"

                    log_finding "Non-symlink file in rc directory (unusual): $rc_file"

                    if analyze_script_content "$rc_file"; then
                        confidence="CRITICAL"
                        finding_matched_pattern="$MATCHED_PATTERN"
                        finding_matched_string="$MATCHED_STRING"
                        log_finding "Suspicious script in rc directory: $rc_file"
                    fi

                    add_finding "Init" "RcDir" "rc_script" "$rc_file" "Script in rc directory: $(basename "$rc_file")" "$confidence" "$hash" "$metadata" "dir=$(basename "$rc_dir")" "$finding_matched_pattern" "$finding_matched_string"
                fi
            done < <(find "$rc_dir" -maxdepth 1 -type f -print0 2>/dev/null)

            # Check 2: Symlinks pointing OUTSIDE /etc/init.d/ (should always point there)
            # Legitimate runlevel links: /etc/rc2.d/S20ssh -> /etc/init.d/ssh
            # Malicious example:        /etc/rc2.d/S99backdoor -> /tmp/backdoor.sh
            while IFS= read -r -d '' rc_link; do
                local link_target
                link_target=$(readlink -f "$rc_link" 2>/dev/null) || true

                # Normal: symlinks pointing to /etc/init.d/ - skip
                [[ "$link_target" == /etc/init.d/* ]] && continue

                # Suspicious: symlink pointing outside /etc/init.d/
                local metadata
                metadata=$(get_file_metadata "$rc_link") || true
                local confidence="HIGH"
                local finding_matched_pattern="suspicious_rcd_symlink"
                local finding_matched_string="${link_target:-broken link}"

                if [[ -z "$link_target" ]] || [[ ! -e "$link_target" ]]; then
                    # Broken symlink - possibly cleaned up but rc entry left, or temp evasion
                    confidence="MEDIUM"
                    finding_matched_pattern="broken_rcd_symlink"
                    finding_matched_string="$(readlink "$rc_link" 2>/dev/null || echo "unknown")"
                    log_finding "Broken rc*.d symlink: $rc_link"
                elif [[ "$link_target" =~ ^/(tmp|dev/shm|var/tmp) ]]; then
                    # Points to temp directory - CRITICAL
                    confidence="CRITICAL"
                    finding_matched_pattern="suspicious_rcd_symlink_temp"
                    log_finding "rc*.d symlink points to temp directory: $rc_link -> $link_target"
                else
                    log_finding "rc*.d symlink points outside /etc/init.d/: $rc_link -> $link_target"
                fi

                # Analyze the symlink target if it's a script
                if [[ -f "$link_target" ]] && is_script "$link_target"; then
                    if analyze_script_content "$link_target"; then
                        confidence="CRITICAL"
                        finding_matched_pattern="$MATCHED_PATTERN"
                        finding_matched_string="$MATCHED_STRING"
                        log_finding "rc*.d symlink target contains suspicious content: $link_target"
                    fi
                fi

                add_finding "Init" "RcLink" "rc_symlink" "$rc_link" "Suspicious rc symlink: $(basename "$rc_link")" "$confidence" "DEFER" "$metadata" "target=$link_target|dir=$(basename "$rc_dir")" "$finding_matched_pattern" "$finding_matched_string"

            done < <(find "$rc_dir" -maxdepth 1 -type l -print0 2>/dev/null)
        fi
    done
}

# Check kernel modules and library preloading
check_kernel_and_preload() {
    log_info "[5/9] Checking kernel modules and library preloading..."

    # ═══════════════════════════════════════════════════════════════════════════
    # Suspicious locations for libraries/modules - these should NEVER contain
    # legitimate system libraries or kernel modules
    # ═══════════════════════════════════════════════════════════════════════════
    local suspicious_locations_pattern="^/(tmp|dev/shm|var/tmp|home|root)/|/\."

    log_check "ld.so.preload library injection"

    # ═══════════════════════════════════════════════════════════════════════════
    # TYPE 1: /etc/ld.so.preload - Libraries loaded into ALL processes
    # This file is almost NEVER used legitimately - any content is suspicious
    # ═══════════════════════════════════════════════════════════════════════════
    if [[ -f "/etc/ld.so.preload" ]]; then
        local preload_content
        preload_content=$(grep -v "^#" "/etc/ld.so.preload" 2>/dev/null | grep -v "^$") || true

        if [[ -n "$preload_content" ]]; then
            # Parse each library path and verify
            while IFS= read -r lib_path; do
                [[ -z "$lib_path" ]] && continue

                local confidence="HIGH"
                local finding_matched_pattern="ld_preload_entry"
                local finding_matched_string="$lib_path"

                # Check if library file exists
                if [[ -f "$lib_path" ]]; then
                    local lib_hash=$(get_file_hash "$lib_path")
                    local lib_metadata=$(get_file_metadata "$lib_path")

                    # Check for suspicious location FIRST
                    if [[ "$lib_path" =~ $suspicious_locations_pattern ]]; then
                        confidence="CRITICAL"
                        finding_matched_pattern="preload_suspicious_location"
                        log_finding "LD_PRELOAD library in suspicious location: $lib_path"
                    else
                        # Check package status
                        local pkg_status pkg_return=0
                        pkg_status=$(is_package_managed "$lib_path") || pkg_return=$?

                        if [[ $pkg_return -eq 0 ]]; then
                            # Package-managed and verified - still suspicious in ld.so.preload!
                            # Even legitimate libraries in ld.so.preload is unusual
                            confidence="MEDIUM"
                            finding_matched_pattern="preload_verified_lib"
                            log_finding "LD_PRELOAD with package-managed library (unusual): $lib_path"
                        elif [[ $pkg_return -eq 2 ]]; then
                            # MODIFIED package file - CRITICAL
                            confidence="CRITICAL"
                            finding_matched_pattern="preload_modified_lib"
                            log_finding "LD_PRELOAD with MODIFIED library: $lib_path"
                        else
                            # Unmanaged library in ld.so.preload - HIGH
                            confidence="HIGH"
                            finding_matched_pattern="preload_unmanaged_lib"
                            log_finding "LD_PRELOAD with unmanaged library: $lib_path"
                        fi
                    fi

                    add_finding "Preload" "LDPreload" "ld_preload_lib" "$lib_path" "Preloaded library: $lib_path" "$confidence" "$lib_hash" "$lib_metadata" "package=$pkg_status" "$finding_matched_pattern" "$finding_matched_string"
                else
                    # Library doesn't exist - still flag the config entry
                    log_finding "LD_PRELOAD references non-existent library: $lib_path"
                    add_finding "Preload" "LDPreload" "ld_preload_missing" "/etc/ld.so.preload" "Preload references missing library: $lib_path" "MEDIUM" "N/A" "N/A" "" "preload_missing_lib" "$lib_path"
                fi
            done <<< "$preload_content"
        fi
    fi

    log_check "ld.so.conf dynamic linker configuration"

    # ═══════════════════════════════════════════════════════════════════════════
    # TYPE 2: /etc/ld.so.conf and /etc/ld.so.conf.d/* - Library search paths
    # Check for suspicious paths being added to library search
    # ═══════════════════════════════════════════════════════════════════════════
    local ld_conf_files=()
    [[ -f "/etc/ld.so.conf" ]] && ld_conf_files+=("/etc/ld.so.conf")
    if [[ -d "/etc/ld.so.conf.d" ]]; then
        while IFS= read -r -d '' conf_file; do
            ld_conf_files+=("$conf_file")
        done < <(find "/etc/ld.so.conf.d" -type f -name "*.conf" -print0 2>/dev/null)
    fi

    for conf_file in "${ld_conf_files[@]}"; do
        local hash=$(get_file_hash "$conf_file")
        local metadata=$(get_file_metadata "$conf_file")
        local confidence="LOW"
        local finding_matched_pattern=""
        local finding_matched_string=""

        # Check package status of config file
        local pkg_status pkg_return=0
        pkg_status=$(is_package_managed "$conf_file") || pkg_return=$?

        if [[ $pkg_return -eq 2 ]]; then
            # Config file was MODIFIED
            confidence="CRITICAL"
            finding_matched_pattern="modified_ld_config"
            finding_matched_string="$conf_file"
            log_finding "LD config is MODIFIED package file: $conf_file"
        elif [[ $pkg_return -eq 1 ]]; then
            # Unmanaged config - check for suspicious paths
            local suspicious_paths
            suspicious_paths=$(grep -vE "^#|^$|^include" "$conf_file" 2>/dev/null | grep -E "$suspicious_locations_pattern" | head -1) || true

            if [[ -n "$suspicious_paths" ]]; then
                confidence="HIGH"
                finding_matched_pattern="suspicious_lib_path"
                finding_matched_string="$suspicious_paths"
                log_finding "LD config contains suspicious path: $suspicious_paths"
            else
                confidence="MEDIUM"
                finding_matched_pattern="unmanaged_ld_config"
                finding_matched_string="$conf_file"
            fi
        fi
        # If pkg_return -eq 0 (verified), confidence stays LOW

        add_finding "Preload" "LDConfig" "ld_config" "$conf_file" "LD configuration: $(basename "$conf_file")" "$confidence" "$hash" "$metadata" "package=$pkg_status" "$finding_matched_pattern" "$finding_matched_string"
    done

    # ═══════════════════════════════════════════════════════════════════════════
    # TYPE 2b: Shared objects at non-standard paths listed in ld.so.conf.d
    # The conf-file integrity check above catches tampered config files, but an
    # attacker can add a NEW unmanaged conf pointing to /opt/lib/ or similar,
    # drop a malicious libssl.so.1.1 there, and the conf gets MEDIUM confidence
    # (deprioritized). We must also scan the actual .so files at those paths.
    # Standard dirs (/usr/lib, /lib, /usr/lib64, /lib64) are already covered by
    # package verification elsewhere — we only scan non-standard additions.
    # ═══════════════════════════════════════════════════════════════════════════
    # Standard lib dirs to skip (already covered by package manager checks)
    local _std_lib_dirs_pattern="^(/usr/lib|/lib|/usr/lib64|/lib64)(/|$)"

    # Collect all non-standard paths from all ld conf files
    local _ld_extra_paths=()
    declare -A _ld_seen_paths=()
    for _ldcf in "${ld_conf_files[@]}"; do
        while IFS= read -r _ldpath; do
            [[ -z "$_ldpath" ]] && continue
            # Skip comment and include lines
            [[ "$_ldpath" =~ ^# ]] && continue
            [[ "$_ldpath" =~ ^include ]] && continue
            # Skip standard dirs — already covered
            [[ "$_ldpath" =~ $_std_lib_dirs_pattern ]] && continue
            # O(1) dedup via associative array
            [[ -n "${_ld_seen_paths[$_ldpath]+set}" ]] && continue
            _ld_seen_paths[$_ldpath]=1
            _ld_extra_paths+=("$_ldpath")
        done < <(grep -v "^#" "$_ldcf" 2>/dev/null)
    done

    for _lddir in "${_ld_extra_paths[@]}"; do
        [[ -d "$_lddir" ]] || continue
        while IFS= read -r -d '' _so_file; do
            local so_pkg_status so_pkg_return=0
            so_pkg_status=$(is_package_managed "$_so_file") || so_pkg_return=$?
            [[ $so_pkg_return -eq 0 ]] && continue  # Verified package .so — fine

            local so_hash so_metadata
            so_hash=$(get_file_hash "$_so_file") || true
            so_metadata=$(get_file_metadata "$_so_file") || true
            local so_confidence so_pattern

            if [[ $so_pkg_return -eq 2 ]]; then
                so_confidence="CRITICAL"
                so_pattern="modified_lib_at_ld_path"
                log_finding "MODIFIED package .so at non-standard ld path: $_so_file"
            else
                so_confidence="HIGH"
                so_pattern="unmanaged_lib_at_ld_path"
                log_finding "Unmanaged .so at non-standard ld path: $_so_file"
            fi

            add_finding "Preload" "LDPath" "so_at_ld_path" "$_so_file" \
                "Unverified .so at non-standard ld path: $_lddir" "$so_confidence" \
                "$so_hash" "$so_metadata" "package=$so_pkg_status" \
                "$so_pattern" "$_so_file"
        done < <(find "$_lddir" -maxdepth 1 -name "*.so*" \( -type f -o -type l \) -print0 2>/dev/null)
    done

    log_check "Loaded kernel modules (lsmod)"

    # ═══════════════════════════════════════════════════════════════════════════
    # TYPE 3: Loaded kernel modules - verify each module file
    # ═══════════════════════════════════════════════════════════════════════════
    if [[ $EUID_CHECK -eq 0 ]] && command -v lsmod &>/dev/null; then
        log_info "Enumerating loaded kernel modules..."

        while read -r module_line; do
            [[ -z "$module_line" ]] && continue

            local module_name=$(echo "$module_line" | awk '{print $1}')
            local module_size=$(echo "$module_line" | awk '{print $2}')
            local module_used=$(echo "$module_line" | awk '{print $3}')

            # Find module file path
            local module_path
            module_path=$(modinfo -F filename "$module_name" 2>/dev/null) || true

            # Skip built-in modules (no file path)
            if [[ -z "$module_path" ]] || [[ "$module_path" == "(builtin)" ]]; then
                continue
            fi

            local hash="N/A"
            local metadata="N/A"
            local confidence="LOW"
            local finding_matched_pattern=""
            local finding_matched_string=""
            local pkg_status="N/A"

            if [[ -f "$module_path" ]]; then
                hash=$(get_file_hash "$module_path")
                metadata=$(get_file_metadata "$module_path")

                # Check for suspicious location FIRST
                if [[ "$module_path" =~ $suspicious_locations_pattern ]]; then
                    confidence="CRITICAL"
                    finding_matched_pattern="module_suspicious_location"
                    finding_matched_string="$module_path"
                    log_finding "Kernel module loaded from suspicious location: $module_path"
                else
                    # Check if module is from standard kernel module paths
                    # Normal paths: /lib/modules/$(uname -r)/, /usr/lib/modules/
                    if [[ ! "$module_path" =~ ^/(lib|usr/lib)/modules/ ]]; then
                        confidence="HIGH"
                        finding_matched_pattern="module_nonstandard_location"
                        finding_matched_string="$module_path"
                        log_finding "Kernel module from non-standard location: $module_path"
                    else
                        # Check package status
                        local pkg_return=0
                        pkg_status=$(is_package_managed "$module_path") || pkg_return=$?

                        if [[ $pkg_return -eq 0 ]]; then
                            # Package-managed and verified - skip
                            continue
                        elif [[ $pkg_return -eq 2 ]]; then
                            # MODIFIED package file - CRITICAL
                            confidence="CRITICAL"
                            finding_matched_pattern="modified_kernel_module"
                            finding_matched_string="$module_path"
                            log_finding "Kernel module is MODIFIED package file: $module_path"
                        else
                            # Unmanaged module in standard location
                            confidence="MEDIUM"
                            finding_matched_pattern="unmanaged_kernel_module"
                            finding_matched_string="$module_path"
                        fi
                    fi
                fi
            else
                # Module file doesn't exist (shouldn't happen for loaded modules)
                confidence="HIGH"
                finding_matched_pattern="module_file_missing"
                finding_matched_string="$module_name"
            fi

            add_finding "Kernel" "Module" "kernel_module" "$module_path" "Loaded module: $module_name (size: $module_size)" "$confidence" "$hash" "$metadata" "module=$module_name|package=$pkg_status" "$finding_matched_pattern" "$finding_matched_string"

        done < <(lsmod 2>/dev/null | tail -n +2)
    fi

    log_check "/etc/modules and modules-load.d auto-load configs"

    # ═══════════════════════════════════════════════════════════════════════════
    # TYPE 4: Kernel module auto-loading configs
    # Check /etc/modules and /etc/modules-load.d/* for suspicious entries
    # ═══════════════════════════════════════════════════════════════════════════
    local module_configs=(
        "/etc/modules"
    )

    # Add files from /etc/modules-load.d/
    if [[ -d "/etc/modules-load.d" ]]; then
        while IFS= read -r -d '' conf_file; do
            module_configs+=("$conf_file")
        done < <(find "/etc/modules-load.d" -type f -print0 2>/dev/null)
    fi

    # Track resolved module names across all configs to avoid duplicate modinfo calls
    declare -A _seen_ko_modules=()

    for mod_config in "${module_configs[@]}"; do
        [[ ! -f "$mod_config" ]] && continue

        local hash=$(get_file_hash "$mod_config")
        local metadata=$(get_file_metadata "$mod_config")
        local confidence="LOW"
        local finding_matched_pattern=""
        local finding_matched_string=""

        # Check package status
        local pkg_status pkg_return=0
        pkg_status=$(is_package_managed "$mod_config") || pkg_return=$?

        if [[ $pkg_return -eq 0 ]]; then
            # Package-managed and verified - skip
            continue
        elif [[ $pkg_return -eq 2 ]]; then
            # MODIFIED package file
            confidence="CRITICAL"
            finding_matched_pattern="modified_module_config"
            finding_matched_string="$mod_config"
            log_finding "Module config is MODIFIED package file: $mod_config"
        else
            # Unmanaged config - analyze content
            confidence="MEDIUM"
            finding_matched_pattern="unmanaged_module_config"

            # Check for suspicious module names (modules that shouldn't be auto-loaded)
            local suspicious_modules
            suspicious_modules=$(grep -vE "^#|^$" "$mod_config" 2>/dev/null | head -5 | tr '\n' ' ') || true
            finding_matched_string="${suspicious_modules:-$mod_config}"
        fi

        add_finding "Kernel" "ModuleConfig" "module_config" "$mod_config" "Module auto-load config: $(basename "$mod_config")" "$confidence" "$hash" "$metadata" "package=$pkg_status" "$finding_matched_pattern" "$finding_matched_string"

        # ISC-21/D: Extract module names from this config and verify their .ko files.
        # The config-file integrity check only confirms the LIST hasn't changed;
        # it doesn't verify the actual kernel module binaries referenced by name.
        while IFS= read -r _modname; do
            [[ -z "$_modname" ]] && continue
            # Skip module names already resolved from a previous config file
            [[ -n "${_seen_ko_modules[$_modname]+set}" ]] && continue
            _seen_ko_modules[$_modname]=1
            local _ko_path
            _ko_path=$(modinfo -F filename "$_modname" 2>/dev/null) || true
            # Skip builtins and unresolvable names
            { [[ -z "$_ko_path" ]] || [[ "$_ko_path" == "(builtin)" ]]; } && continue
            # Strip compression suffix for existence check (module may be .ko.zst, .ko.xz)
            # Use %.ko.* (not %%.*) to strip only the compression part, not the version dirs
            local _ko_base="${_ko_path%.ko.*}.ko"
            local _ko_exists=""
            [[ -f "$_ko_path" ]] && _ko_exists="$_ko_path"
            [[ -z "$_ko_exists" ]] && [[ -f "$_ko_base" ]] && _ko_exists="$_ko_base"

            if [[ -z "$_ko_exists" ]]; then
                add_finding "Kernel" "Module" "module_missing_ko" "$_ko_path" \
                    "Module listed in config has no .ko file: $_modname" "MEDIUM" \
                    "N/A" "N/A" "" "module_missing_ko" "$_modname"
                continue
            fi

            # Location check before package check
            if [[ ! "$_ko_exists" =~ ^/(lib|usr/lib)/modules/ ]]; then
                local _ko_hash _ko_meta
                _ko_hash=$(get_file_hash "$_ko_exists") || true
                _ko_meta=$(get_file_metadata "$_ko_exists") || true
                log_finding "Module .ko outside standard path: $_ko_exists"
                add_finding "Kernel" "Module" "module_nonstandard_ko" "$_ko_exists" \
                    "Module .ko at non-standard path: $_modname" "HIGH" \
                    "$_ko_hash" "$_ko_meta" "" "module_nonstandard_location" "$_ko_exists"
                continue
            fi

            local _ko_pkg_status _ko_pkg_return=0
            _ko_pkg_status=$(is_package_managed "$_ko_exists") || _ko_pkg_return=$?
            [[ $_ko_pkg_return -eq 0 ]] && continue  # Verified — fine

            local _ko_hash _ko_meta
            _ko_hash=$(get_file_hash "$_ko_exists") || true
            _ko_meta=$(get_file_metadata "$_ko_exists") || true

            if [[ $_ko_pkg_return -eq 2 ]]; then
                log_finding "Module .ko is MODIFIED package file: $_ko_exists"
                add_finding "Kernel" "Module" "modified_ko_file" "$_ko_exists" \
                    "Module .ko MODIFIED (config: $(basename "$mod_config")): $_modname" "CRITICAL" \
                    "$_ko_hash" "$_ko_meta" "package=$_ko_pkg_status" \
                    "modified_kernel_module" "$_ko_exists"
            else
                add_finding "Kernel" "Module" "unmanaged_ko_file" "$_ko_exists" \
                    "Module .ko unmanaged (config: $(basename "$mod_config")): $_modname" "MEDIUM" \
                    "$_ko_hash" "$_ko_meta" "package=$_ko_pkg_status" \
                    "unmanaged_kernel_module" "$_ko_exists"
            fi
        done < <(grep -vE "^#|^$" "$mod_config" 2>/dev/null)
    done

    log_check "modprobe.d kernel module parameters"

    # ═══════════════════════════════════════════════════════════════════════════
    # TYPE 5: /etc/modprobe.d/ and /etc/modprobe.conf — kernel module parameters
    # This directory is the primary attack surface for kernel-level persistence:
    # - `install` directives execute arbitrary commands instead of loading a module
    #   (e.g., `install kvm /usr/local/bin/backdoor.sh` runs on every `modprobe kvm`)
    # - `blacklist` directives can silence security modules (apparmor, seccomp, lockdown)
    # - The files themselves may be modified package files (integrity check needed)
    # ═══════════════════════════════════════════════════════════════════════════
    local modprobe_configs=()
    [[ -f "/etc/modprobe.conf" ]] && modprobe_configs+=("/etc/modprobe.conf")
    if [[ -d "/etc/modprobe.d" ]]; then
        while IFS= read -r -d '' _mpf; do
            modprobe_configs+=("$_mpf")
        done < <(find /etc/modprobe.d -type f -print0 2>/dev/null)
    fi

    # Security modules whose blacklisting is always suspicious
    local _security_modules_pattern="apparmor|selinux|seccomp|lockdown|integrity|ima|evm|audit"

    for mp_config in "${modprobe_configs[@]}"; do
        local mp_hash mp_metadata
        mp_hash=$(get_file_hash "$mp_config") || true
        mp_metadata=$(get_file_metadata "$mp_config") || true
        local mp_pkg_status mp_pkg_return=0
        mp_pkg_status=$(is_package_managed "$mp_config") || mp_pkg_return=$?

        local mp_confidence="LOW"
        local mp_pattern="" mp_matched=""

        if [[ $mp_pkg_return -eq 2 ]]; then
            mp_confidence="CRITICAL"
            mp_pattern="modified_modprobe_config"
            mp_matched="$mp_config"
            log_finding "modprobe config is MODIFIED package file: $mp_config"
        elif [[ $mp_pkg_return -eq 1 ]]; then
            mp_confidence="MEDIUM"
            mp_pattern="unmanaged_modprobe_config"
            mp_matched="$mp_config"
        else
            # Verified — still scan content for dangerous directives below
            :
        fi

        add_finding "Kernel" "ModprobeConfig" "modprobe_config" "$mp_config" \
            "modprobe config: $(basename "$mp_config")" "$mp_confidence" \
            "$mp_hash" "$mp_metadata" "package=$mp_pkg_status" \
            "$mp_pattern" "$mp_matched"

        # ── Single pass: collect install + blacklist lines from this config ────
        # One grep covers both directive types, avoiding two separate file reads.
        local _mp_install_lines=() _mp_blacklist_lines=()
        while IFS= read -r _mp_line; do
            local _mp_verb
            _mp_verb=$(echo "$_mp_line" | awk '{print tolower($1)}') || true
            case "$_mp_verb" in
                install)   _mp_install_lines+=("$_mp_line") ;;
                blacklist) _mp_blacklist_lines+=("$_mp_line") ;;
            esac
        done < <(grep -iE "^[[:space:]]*(install|blacklist)[[:space:]]+" "$mp_config" 2>/dev/null)

        # ── install directives: arbitrary command execution on module load ───────
        for _install_line in "${_mp_install_lines[@]}"; do
            # Format: install <module_name> <command> [args...]
            # Extract the command (3rd token); awk handles leading whitespace correctly
            local _install_cmd
            _install_cmd=$(echo "$_install_line" | awk '{print $3}') || true
            [[ -z "$_install_cmd" ]] && continue
            # Skip legitimate no-op installs (/bin/true, :, /bin/false)
            [[ "$_install_cmd" == ":" ]] && continue
            [[ "$_install_cmd" =~ ^/(bin|usr/bin)/(true|false)$ ]] && continue
            # Must be an absolute path to be actionable
            [[ "$_install_cmd" =~ ^/ ]] || continue

            local ic_confidence="CRITICAL"
            local ic_pattern="modprobe_install_directive"
            local ic_matched="$_install_cmd"

            if [[ ! -e "$_install_cmd" ]]; then
                ic_pattern="modprobe_install_missing_cmd"
                log_finding "modprobe install directive references missing command: $_install_cmd ($mp_config)"
            elif [[ "$_install_cmd" =~ $suspicious_locations_pattern ]]; then
                ic_pattern="modprobe_install_suspicious_location"
                log_finding "modprobe install directive in suspicious location: $_install_cmd ($mp_config)"
            else
                local ic_pkg_status ic_pkg_return=0
                ic_pkg_status=$(is_package_managed "$_install_cmd") || ic_pkg_return=$?
                if [[ $ic_pkg_return -eq 0 ]]; then
                    ic_confidence="LOW"
                    ic_pattern="modprobe_install_verified_cmd"
                elif [[ $ic_pkg_return -eq 2 ]]; then
                    ic_pattern="modprobe_install_modified_cmd"
                    log_finding "modprobe install uses MODIFIED package binary: $_install_cmd ($mp_config)"
                else
                    ic_pattern="modprobe_install_unmanaged_cmd"
                    log_finding "modprobe install uses unmanaged command: $_install_cmd ($mp_config)"
                fi
            fi

            local ic_hash="N/A" ic_meta="N/A"
            if [[ -e "$_install_cmd" ]]; then
                ic_hash=$(get_file_hash "$_install_cmd") || true
                ic_meta=$(get_file_metadata "$_install_cmd") || true
            fi

            add_finding "Kernel" "ModprobeInstall" "modprobe_install" "$_install_cmd" \
                "modprobe install hook in $(basename "$mp_config")" "$ic_confidence" \
                "$ic_hash" "$ic_meta" "" "$ic_pattern" "$ic_matched"
        done

        # ── blacklist of security modules ─────────────────────────────────────
        local _bl_security=""
        for _bl_line in "${_mp_blacklist_lines[@]}"; do
            local _bl_mod
            _bl_mod=$(echo "$_bl_line" | awk '{print $2}') || true
            [[ "$_bl_mod" =~ ^($_security_modules_pattern)$ ]] && _bl_security="$_bl_line" && break
        done
        if [[ -n "$_bl_security" ]]; then
            local _bl_module
            _bl_module=$(echo "$_bl_security" | awk '{print $2}' | head -1)
            log_finding "Security module blacklisted in modprobe config: $_bl_module ($mp_config)"
            add_finding "Kernel" "ModprobeBlacklist" "modprobe_security_blacklist" "$mp_config" \
                "Security module blacklisted: $_bl_module" "HIGH" \
                "$mp_hash" "$mp_metadata" "package=$mp_pkg_status" \
                "security_module_blacklist" "$_bl_security"
        fi
    done
}

# Check additional persistence locations
check_additional_persistence() {
    log_info "[6/9] Checking additional persistence mechanisms..."

    log_check "XDG autostart entries"

    # XDG autostart
    local autostart_dirs=(
        "/etc/xdg/autostart"
        "$HOME/.config/autostart"
    )

    # When running as root, scan all users' XDG autostart directories
    if [[ $EUID_CHECK -eq 0 ]]; then
        while IFS=: read -r _ _ xdg_uid _ _ homedir _; do
            if [[ $xdg_uid -ge 1000 ]] || [[ $xdg_uid -eq 0 ]]; then
                local _user_autostart="$homedir/.config/autostart"
                if [[ "$_user_autostart" != "$HOME/.config/autostart" ]] && [[ -d "$_user_autostart" ]]; then
                    autostart_dirs+=("$_user_autostart")
                fi
            fi
        done < /etc/passwd
    fi

    for autostart_dir in "${autostart_dirs[@]}"; do
        if [[ -d "$autostart_dir" ]]; then
            while IFS= read -r -d '' desktop_file; do
                local hash=$(get_file_hash "$desktop_file")
                local metadata=$(get_file_metadata "$desktop_file")
                local exec_line=$(grep "^Exec=" "$desktop_file" 2>/dev/null | cut -d'=' -f2- || echo "")

                local confidence="LOW"
                local finding_matched_pattern=""
                local finding_matched_string=""
                local skip_pattern_analysis=false

                if [[ -n "$exec_line" ]]; then
                    # Pre-check: NEVER_WHITELIST patterns on the full Exec= line.
                    # Prevents package-verification bypass (same logic as check_systemd).
                    local xdg_never_wl_match=""
                    xdg_never_wl_match=$(echo "$exec_line" | grep -oE "$COMBINED_NEVER_WHITELIST_PATTERN" | head -1) || true

                    local xdg_executable
                    xdg_executable=$(get_executable_from_command "$exec_line") || true

                    if [[ -n "$xdg_executable" ]] && [[ -f "$xdg_executable" ]]; then

                        if is_interpreter "$xdg_executable"; then
                            # BRANCH 1: Interpreter — analyze the script target, not the interpreter
                            local xdg_script
                            xdg_script=$(get_script_from_interpreter_command "$exec_line") || true

                            if [[ -n "$xdg_script" ]] && [[ -f "$xdg_script" ]]; then
                                local script_pkg_status
                                script_pkg_status=$(is_package_managed "$xdg_script") || true

                                if [[ "$script_pkg_status" == *":MODIFIED" ]]; then
                                    confidence="CRITICAL"
                                    finding_matched_pattern="modified_script"
                                    finding_matched_string="$xdg_script"
                                    log_finding "XDG autostart interpreter script is modified package file: $xdg_script"
                                elif [[ "$script_pkg_status" != "unmanaged" ]]; then
                                    if [[ -n "$xdg_never_wl_match" ]]; then
                                        confidence="HIGH"
                                        finding_matched_pattern="never_whitelist"
                                        finding_matched_string="$xdg_never_wl_match"
                                        log_finding "XDG autostart: package-verified script with never-whitelist pattern: $xdg_never_wl_match"
                                    else
                                        confidence="LOW"
                                        skip_pattern_analysis=true
                                    fi
                                else
                                    if [[ "$xdg_script" =~ ^/(tmp|dev/shm|var/tmp) ]]; then
                                        confidence="HIGH"
                                        finding_matched_pattern="suspicious_location"
                                        finding_matched_string="$xdg_script"
                                        log_finding "XDG autostart script in suspicious location: $xdg_script"
                                    elif is_script "$xdg_script" && analyze_script_content "$xdg_script"; then
                                        confidence="HIGH"
                                        finding_matched_pattern="suspicious_script_content"
                                        finding_matched_string="$MATCHED_STRING"
                                        log_finding "XDG autostart script contains suspicious content: $xdg_script"
                                    else
                                        confidence="MEDIUM"
                                    fi
                                    if [[ -z "$finding_matched_pattern" ]]; then
                                        finding_matched_pattern="unmanaged_script"
                                        finding_matched_string="$xdg_script"
                                    fi
                                fi
                            else
                                # Interpreter with no script arg — check for inline code
                                if [[ "$exec_line" =~ \ -[ce]\  ]] || [[ "$exec_line" =~ \ -[ce]$ ]] || [[ "$exec_line" =~ [[:space:]](-S|--split-string)([[:space:]]|$) ]]; then
                                    if analyze_inline_code "$exec_line"; then
                                        confidence="CRITICAL"
                                        finding_matched_pattern="inline_code_suspicious"
                                        finding_matched_string="$INLINE_CODE_REASON"
                                        log_finding "XDG autostart has suspicious inline code: $desktop_file"
                                    else
                                        confidence="HIGH"
                                        finding_matched_pattern="inline_code"
                                        finding_matched_string="-c/-e flag"
                                        log_finding "XDG autostart uses interpreter with inline code: $desktop_file"
                                    fi
                                fi
                            fi

                        else
                            # BRANCH 2: Direct binary execution
                            local exec_pkg_status
                            exec_pkg_status=$(is_package_managed "$xdg_executable") || true

                            if [[ "$exec_pkg_status" == *":MODIFIED" ]]; then
                                confidence="CRITICAL"
                                finding_matched_pattern="modified_binary"
                                finding_matched_string="$xdg_executable"
                                log_finding "XDG autostart executes modified package binary: $xdg_executable"
                            elif [[ "$exec_pkg_status" != "unmanaged" ]]; then
                                if [[ -n "$xdg_never_wl_match" ]]; then
                                    confidence="HIGH"
                                    finding_matched_pattern="never_whitelist"
                                    finding_matched_string="$xdg_never_wl_match"
                                    log_finding "XDG autostart: package-verified binary with never-whitelist pattern: $xdg_never_wl_match"
                                else
                                    confidence="LOW"
                                    skip_pattern_analysis=true
                                fi
                            else
                                if [[ "$xdg_executable" =~ ^/(tmp|dev/shm|var/tmp) ]]; then
                                    confidence="HIGH"
                                    finding_matched_pattern="suspicious_location"
                                    finding_matched_string="$xdg_executable"
                                    log_finding "XDG autostart executes binary from suspicious location: $xdg_executable"
                                elif is_script "$xdg_executable" && analyze_script_content "$xdg_executable"; then
                                    confidence="HIGH"
                                    finding_matched_pattern="suspicious_script_content"
                                    finding_matched_string="$MATCHED_STRING"
                                    log_finding "XDG autostart script has suspicious content: $xdg_executable"
                                fi
                                if [[ -z "$finding_matched_pattern" ]]; then
                                    finding_matched_pattern="unmanaged_binary"
                                    finding_matched_string="${exec_line:0:200}"
                                fi
                            fi
                        fi

                    else
                        # Executable not found — fall back to pattern check on the Exec= line
                        if quick_suspicious_check "$exec_line"; then
                            confidence="HIGH"
                            finding_matched_pattern="$MATCHED_PATTERN"
                            finding_matched_string="$MATCHED_STRING"
                            log_finding "Suspicious XDG autostart pattern: $desktop_file"
                        else
                            finding_matched_pattern="unresolved_executable"
                            finding_matched_string="${xdg_executable:-$exec_line}"
                        fi
                    fi

                    # Final pattern sweep on the raw Exec= line if not already flagged
                    if [[ "$skip_pattern_analysis" != true ]] && [[ "$confidence" != "HIGH" ]] && [[ "$confidence" != "CRITICAL" ]]; then
                        if quick_suspicious_check "$exec_line"; then
                            confidence="HIGH"
                            finding_matched_pattern="$MATCHED_PATTERN"
                            finding_matched_string="$MATCHED_STRING"
                            log_finding "Suspicious XDG autostart pattern: $desktop_file"
                        fi
                    fi
                fi

                add_finding "Autostart" "XDG" "xdg_autostart" "$desktop_file" "XDG autostart: $(basename "$desktop_file") | Exec: $exec_line" "$confidence" "$hash" "$metadata" "" "$finding_matched_pattern" "$finding_matched_string"
            done < <(find "$autostart_dir" -type f -name "*.desktop" -print0 2>/dev/null)
        fi
    done

    log_check "/etc/environment LD_PRELOAD / LD_LIBRARY_PATH"

    # Check /etc/environment
    if [[ -f "/etc/environment" ]]; then
        local hash=$(get_file_hash "/etc/environment")
        local metadata=$(get_file_metadata "/etc/environment")
        local suspicious_env=$(grep -iE "(LD_PRELOAD|LD_LIBRARY_PATH)" /etc/environment 2>/dev/null || echo "")

        local confidence="LOW"
        local finding_matched_pattern=""
        local finding_matched_string=""
        if [[ -n "$suspicious_env" ]]; then
            confidence="HIGH"
            finding_matched_pattern="ld_preload_env"
            finding_matched_string="$suspicious_env"
            log_finding "Suspicious environment variables in /etc/environment"
        fi

        add_finding "Environment" "System" "environment_file" "/etc/environment" "System environment file" "$confidence" "$hash" "$metadata" "" "$finding_matched_pattern" "$finding_matched_string"

        # ── Extract and verify the actual LD_PRELOAD library path ────────────
        # The finding above flags the environment file itself. This block extracts
        # the library path from LD_PRELOAD and verifies it independently — the
        # library file is the actual payload and needs its own integrity check.
        local _env_ld_paths
        _env_ld_paths=$(grep -iE "^LD_PRELOAD[[:space:]]*=" /etc/environment 2>/dev/null | \
            grep -oE '/[^[:space:]"'"'"']+') || true

        for _env_lib in $_env_ld_paths; do
            [[ -z "$_env_lib" ]] && continue

            local env_lib_pkg env_lib_return=0
            env_lib_pkg=$(is_package_managed "$_env_lib") || env_lib_return=$?

            local env_lib_confidence env_lib_pattern
            if [[ $env_lib_return -eq 0 ]]; then
                env_lib_confidence="LOW"
                env_lib_pattern="env_ld_preload_verified"
            elif [[ $env_lib_return -eq 2 ]]; then
                env_lib_confidence="CRITICAL"
                env_lib_pattern="env_ld_preload_modified"
                log_finding "/etc/environment LD_PRELOAD is MODIFIED package library: $_env_lib"
            else
                env_lib_confidence="CRITICAL"
                env_lib_pattern="env_ld_preload_unmanaged"
                log_finding "/etc/environment LD_PRELOAD unmanaged library: $_env_lib"
            fi

            local env_lib_hash env_lib_meta
            env_lib_hash=$(get_file_hash "$_env_lib") || true
            env_lib_meta=$(get_file_metadata "$_env_lib") || true

            add_finding "Environment" "LDPreload" "env_ld_preload_lib" "$_env_lib" \
                "/etc/environment LD_PRELOAD library" "$env_lib_confidence" \
                "$env_lib_hash" "$env_lib_meta" "package=$env_lib_pkg" \
                "$env_lib_pattern" "$_env_lib"
        done
    fi

    log_check "Sudoers configuration"

    # Check sudoers for persistence
    if [[ $EUID_CHECK -eq 0 ]]; then
        if [[ -f "/etc/sudoers" ]]; then
            local hash=$(get_file_hash "/etc/sudoers")
            local metadata=$(get_file_metadata "/etc/sudoers")
            local content=$(cat "/etc/sudoers" 2>/dev/null || echo "")

            local confidence="LOW"
            local finding_matched_pattern=""
            local finding_matched_string=""
            local danger_match=$(echo "$content" | grep -v "^#" | grep -iE "(NOPASSWD|ALL=\(ALL\)|ALL:ALL)" | head -1) || true
            if [[ -n "$danger_match" ]]; then
                confidence="HIGH"
                finding_matched_pattern="dangerous_sudoers_rule"
                finding_matched_string="$danger_match"
                log_finding "Dangerous sudoers rule: /etc/sudoers"
            fi

            add_finding "Privilege" "Sudoers" "sudoers_file" "/etc/sudoers" "Sudoers configuration" "$confidence" "$hash" "$metadata" "" "$finding_matched_pattern" "$finding_matched_string"
        fi

        if [[ -d "/etc/sudoers.d" ]]; then
            while IFS= read -r -d '' sudoers_file; do
                local hash=$(get_file_hash "$sudoers_file")
                local metadata=$(get_file_metadata "$sudoers_file")
                local content=$(cat "$sudoers_file" 2>/dev/null || echo "")

                local confidence="MEDIUM"
                local finding_matched_pattern=""
                local finding_matched_string=""
                local danger_match=$(echo "$content" | grep -v "^#" | grep -iE "(NOPASSWD|ALL=\(ALL\)|ALL:ALL)" | head -1) || true
                if [[ -n "$danger_match" ]]; then
                    confidence="HIGH"
                    finding_matched_pattern="dangerous_sudoers_rule"
                    finding_matched_string="$danger_match"
                    log_finding "Dangerous sudoers rule: $sudoers_file"
                fi

                add_finding "Privilege" "Sudoers" "sudoers_drop_in" "$sudoers_file" "Sudoers drop-in: $(basename "$sudoers_file")" "$confidence" "$hash" "$metadata" "" "$finding_matched_pattern" "$finding_matched_string"
            done < <(find /etc/sudoers.d -type f -print0 2>/dev/null)
        fi
    fi

    log_check "PAM modules and configuration"

    # Check for PAM backdoors
    # Verify actual PAM module .so files, not just config references
    if [[ -d "/etc/pam.d" ]] || [[ -f "/etc/pam.conf" ]]; then
        # Common PAM module directories - checked in order, first match wins (break below)
        # /usr/lib listed before /lib so merged-/usr systems pick the canonical path
        local pam_lib_dirs=(
            "/usr/lib/x86_64-linux-gnu/security"
            "/usr/lib/aarch64-linux-gnu/security"
            "/usr/lib/security"
            "/usr/lib64/security"
            "/lib/x86_64-linux-gnu/security"
            "/lib/aarch64-linux-gnu/security"
            "/lib/security"
            "/lib64/security"
        )

        # Find the actual PAM lib directory on this system
        local pam_lib_dir=""
        for dir in "${pam_lib_dirs[@]}"; do
            if [[ -d "$dir" ]]; then
                pam_lib_dir="$dir"
                break
            fi
        done

        # Track which modules we've already checked (avoid duplicates)
        declare -A checked_modules

        # ─────────────────────────────────────────────────────────────────────
        # ISC-9/ISC-10 FIX: Build complete list of PAM config files to analyze.
        # Includes /etc/pam.conf (legacy single-file format) and follows
        # @include directives pointing outside /etc/pam.d/.
        # ─────────────────────────────────────────────────────────────────────
        local _all_pam_files=()
        if [[ -d "/etc/pam.d" ]]; then
            while IFS= read -r -d '' _pf; do
                _all_pam_files+=("$_pf")
            done < <(find /etc/pam.d -type f -print0 2>/dev/null)
        fi
        [[ -f "/etc/pam.conf" ]] && _all_pam_files+=("/etc/pam.conf")

        # Follow @include directives one level deep (with cycle detection)
        local _include_queue=() _include_path
        for _pf in "${_all_pam_files[@]}"; do
            while IFS= read -r _include_path; do
                [[ -f "$_include_path" ]] || continue
                local _dup=0
                for _ef in "${_all_pam_files[@]}" "${_include_queue[@]}"; do
                    [[ "$_ef" == "$_include_path" ]] && _dup=1 && break
                done
                [[ $_dup -eq 0 ]] && _include_queue+=("$_include_path")
            done < <(grep -oE "@include[[:space:]]+(/[^[:space:]]+)" "$_pf" 2>/dev/null | grep -oE "(/[^[:space:]]+)$")
        done
        _all_pam_files+=("${_include_queue[@]}")

        # _pam_cfg_content: unified content from all PAM files (strips service-name
        # column from /etc/pam.conf lines; used by pam_exec and relay detection).
        # Built inline in the module loop below to avoid reading each file twice.
        local _pam_cfg_content=""
        local _pam_script_used=0

        for pam_file in "${_all_pam_files[@]}"; do
            # Read file once; strip comments and pam.conf service column in one pass
            local _pam_file_content
            if [[ "$pam_file" == "/etc/pam.conf" ]]; then
                _pam_file_content=$(grep -v "^#" "$pam_file" 2>/dev/null | awk '{$1=""; print}') || true
            else
                _pam_file_content=$(grep -v "^#" "$pam_file" 2>/dev/null) || true
            fi
            _pam_cfg_content+=$'\n'"$_pam_file_content"

            # Extract named PAM modules (pam_*.so)
            local modules
            modules=$(echo "$_pam_file_content" | grep -oE "pam_[a-zA-Z0-9_]+\.so" | sort -u) || true

            # ISC-3 FIX: Also extract absolute-path .so references (e.g. /usr/lib/custom/auth.so)
            local abs_modules
            abs_modules=$(echo "$_pam_file_content" | grep -oE "(/[a-zA-Z0-9/_.-]+\.so)" | grep -vE "/pam_[a-zA-Z0-9_]+\.so$" | sort -u) || true

            for module in $modules; do
                # ISC-6 FIX: Track if pam_script.so is referenced (hook files checked after loop)
                [[ "$module" == "pam_script.so" ]] && _pam_script_used=1

                # Find the actual .so file
                local module_path=""
                if [[ -n "$pam_lib_dir" ]] && [[ -f "$pam_lib_dir/$module" ]]; then
                    module_path="$pam_lib_dir/$module"
                else
                    # Try to find it
                    for dir in "${pam_lib_dirs[@]}"; do
                        if [[ -f "$dir/$module" ]]; then
                            module_path="$dir/$module"
                            break
                        fi
                    done
                fi

                # If module file doesn't exist, skip (might be optional/conditional)
                [[ -z "$module_path" ]] && continue

                # ISC-13 FIX: Dedup by full resolved path, not module name
                [[ -n "${checked_modules[$module_path]}" ]] && continue
                checked_modules[$module_path]=1

                # Check package status of the actual .so file
                local pkg_status pkg_return=0
                pkg_status=$(is_package_managed "$module_path") || pkg_return=$?

                if [[ $pkg_return -eq 0 ]]; then
                    # Package-managed and VERIFIED - skip
                    continue
                fi

                local hash=$(get_file_hash "$module_path")
                local metadata=$(get_file_metadata "$module_path")
                local confidence="MEDIUM"
                local finding_matched_pattern=""
                local finding_matched_string=""

                if [[ $pkg_return -eq 2 ]]; then
                    # Module was MODIFIED - CRITICAL (potential backdoor)
                    confidence="CRITICAL"
                    finding_matched_pattern="modified_pam_module"
                    finding_matched_string="$module_path"
                    log_finding "PAM module is MODIFIED package file: $module_path"
                else
                    # UNMANAGED module - suspicious
                    confidence="HIGH"
                    finding_matched_pattern="unmanaged_pam_module"
                    finding_matched_string="$module_path"
                    log_finding "Unmanaged PAM module: $module_path"
                fi

                add_finding "PAM" "Module" "pam_module" "$module_path" "PAM module: $module" "$confidence" "$hash" "$metadata" "package=$pkg_status" "$finding_matched_pattern" "$finding_matched_string"
            done

            # ISC-3 FIX: Check absolute-path .so module references
            for abs_module in $abs_modules; do
                [[ -f "$abs_module" ]] || continue
                [[ -n "${checked_modules[$abs_module]}" ]] && continue
                checked_modules[$abs_module]=1

                local pkg_status pkg_return=0
                pkg_status=$(is_package_managed "$abs_module") || pkg_return=$?
                [[ $pkg_return -eq 0 ]] && continue

                local hash=$(get_file_hash "$abs_module")
                local metadata=$(get_file_metadata "$abs_module")
                local confidence="MEDIUM"
                local finding_matched_pattern=""
                local finding_matched_string=""

                if [[ $pkg_return -eq 2 ]]; then
                    confidence="CRITICAL"
                    finding_matched_pattern="modified_pam_module"
                    finding_matched_string="$abs_module"
                    log_finding "PAM module is MODIFIED package file: $abs_module"
                else
                    confidence="HIGH"
                    finding_matched_pattern="unmanaged_pam_module"
                    finding_matched_string="$abs_module"
                    log_finding "Unmanaged PAM module (absolute path): $abs_module"
                fi

                add_finding "PAM" "Module" "pam_module" "$abs_module" \
                    "PAM module: $(basename "$abs_module")" "$confidence" \
                    "$hash" "$metadata" "package=$pkg_status" \
                    "$finding_matched_pattern" "$finding_matched_string"
            done
        done

        # ─────────────────────────────────────────────────────────────────────
        # ISC-6 FIX: pam_script.so hook file detection.
        # pam_script.so executes fixed-path scripts in /etc/security/ on every
        # auth event. Unlike pam_exec.so, the script path is not in the config
        # line — it reads from well-known hook file paths directly.
        # ─────────────────────────────────────────────────────────────────────
        if [[ $_pam_script_used -eq 1 ]]; then
            local _pam_script_hooks=(
                "/etc/security/pam_script_auth"
                "/etc/security/pam_script_acct"
                "/etc/security/pam_script_ses"
                "/etc/security/pam_script_passwd"
                "/etc/security/pam_script_session"
            )
            for hook_file in "${_pam_script_hooks[@]}"; do
                [[ -f "$hook_file" ]] || continue

                local hook_pkg_status hook_pkg_return=0
                hook_pkg_status=$(is_package_managed "$hook_file") || hook_pkg_return=$?

                local confidence="HIGH"
                local finding_matched_pattern="pam_script_hook"
                local finding_matched_string="$hook_file"

                if [[ $hook_pkg_return -eq 0 ]]; then
                    confidence="LOW"
                    finding_matched_pattern="pam_script_hook_verified"
                elif [[ $hook_pkg_return -eq 2 ]]; then
                    confidence="CRITICAL"
                    finding_matched_pattern="pam_script_hook_modified"
                    log_finding "pam_script.so hook file is MODIFIED package file: $hook_file"
                elif analyze_script_content "$hook_file"; then
                    confidence="CRITICAL"
                    finding_matched_pattern="$MATCHED_PATTERN"
                    finding_matched_string="$MATCHED_STRING"
                    log_finding "pam_script.so hook contains suspicious content: $hook_file"
                else
                    log_finding "pam_script.so hook file present (unmanaged): $hook_file"
                fi

                local hook_hash="DEFER"
                local hook_metadata
                hook_metadata=$(get_file_metadata "$hook_file") || true

                add_finding "PAM" "Exec" "pam_script_hook" "$hook_file" \
                    "pam_script.so hook script" "$confidence" \
                    "$hook_hash" "$hook_metadata" "package=$hook_pkg_status" \
                    "$finding_matched_pattern" "$finding_matched_string"
            done
        fi

        # ─────────────────────────────────────────────────────────────────────
        # ISC-11/ISC-19 FIX: PAM config file integrity check.
        # The .so module check above only verifies module binaries. The config
        # files themselves (/etc/pam.d/common-auth, sshd, sudo, etc.) are
        # package-owned on Debian/Ubuntu/RHEL. An attacker who adds a pam_exec
        # line to common-auth modifies a package file — dpkg -V catches it, but
        # only if we call is_package_managed() on the config file itself.
        # ─────────────────────────────────────────────────────────────────────
        # Note: unmanaged (return 1) files are intentionally NOT reported here.
        # Many /etc/pam.d/ files (common-auth, common-session, etc.) are generated
        # by pam-auth-update and are not tracked by dpkg, so they show as "unmanaged"
        # on every clean system — reporting them would produce constant false positives.
        # Only package-owned files that have been MODIFIED are meaningful findings.
        for pam_cfg_file in "${_all_pam_files[@]}"; do
            local cfg_pkg_status cfg_pkg_return=0
            cfg_pkg_status=$(is_package_managed "$pam_cfg_file") || cfg_pkg_return=$?
            [[ $cfg_pkg_return -eq 2 ]] || continue

            # Package-owned config was MODIFIED — attacker may have inserted a line
            local cfg_hash cfg_metadata
            cfg_hash=$(get_file_hash "$pam_cfg_file") || true
            cfg_metadata=$(get_file_metadata "$pam_cfg_file") || true

            log_finding "PAM config file is MODIFIED package file: $pam_cfg_file"
            add_finding "PAM" "Config" "pam_config_modified" "$pam_cfg_file" \
                "PAM config file modified (package tamper)" "CRITICAL" \
                "$cfg_hash" "$cfg_metadata" "package=$cfg_pkg_status" \
                "modified_pam_config" "$pam_cfg_file"
        done

        # ─────────────────────────────────────────────────────────────────────
        # Special case: pam_exec.so is a relay module - its .so file is always
        # package-managed and verified, BUT it executes an external script given
        # as an argument in the PAM config. We must analyze THAT script, not the .so.
        # Example: "auth optional pam_exec.so /tmp/credential_logger.sh"
        #           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        #           verified package file (we skip)  ACTUAL PAYLOAD (we were missing this)
        # ─────────────────────────────────────────────────────────────────────
        if [[ ${#_all_pam_files[@]} -gt 0 ]]; then
            # Extract all script paths passed to pam_exec.so from all PAM config files
            # Uses _pam_cfg_content which includes /etc/pam.conf and @include targets (ISC-9/10)
            local pam_exec_scripts
            pam_exec_scripts=$(echo "$_pam_cfg_content" | \
                grep "pam_exec\.so" | \
                grep -oE 'pam_exec\.so([[:space:]]+[^/[:space:]][^[:space:]]*)*[[:space:]]+(/[^[:space:]]+)' | \
                grep -oE '(/[^[:space:]]+)$' | \
                sort -u) || true

            for exec_script in $pam_exec_scripts; do
                [[ -z "$exec_script" ]] && continue

                local exec_pkg_status exec_pkg_return=0
                exec_pkg_status=$(is_package_managed "$exec_script") || exec_pkg_return=$?

                local confidence="CRITICAL"
                local finding_matched_pattern="pam_exec_script"
                local finding_matched_string="$exec_script"

                if [[ $exec_pkg_return -eq 0 ]]; then
                    # Script is package-managed and verified - LOW confidence
                    confidence="LOW"
                    finding_matched_pattern="pam_exec_verified_script"
                elif [[ $exec_pkg_return -eq 2 ]]; then
                    # Script is MODIFIED - CRITICAL
                    confidence="CRITICAL"
                    finding_matched_pattern="pam_exec_modified_script"
                    log_finding "pam_exec.so executes MODIFIED package script: $exec_script"
                else
                    # UNMANAGED script - check existence, location, and content
                    if [[ ! -e "$exec_script" ]]; then
                        confidence="CRITICAL"
                        finding_matched_pattern="pam_exec_missing_script"
                        finding_matched_string="$exec_script"
                        log_finding "pam_exec.so references non-existent script (post-compromise cleanup?): $exec_script"
                    elif [[ "$exec_script" =~ ^/(tmp|dev/shm|var/tmp|run/user/) ]] || [[ "$exec_script" =~ /\.[a-zA-Z] ]]; then
                        confidence="CRITICAL"
                        finding_matched_pattern="pam_exec_suspicious_location"
                        log_finding "pam_exec.so executes script from suspicious location: $exec_script"
                    elif [[ -f "$exec_script" ]] && analyze_script_content "$exec_script"; then
                        confidence="CRITICAL"
                        finding_matched_pattern="$MATCHED_PATTERN"
                        finding_matched_string="$MATCHED_STRING"
                        log_finding "pam_exec.so script contains suspicious content: $exec_script"
                    else
                        log_finding "pam_exec.so executes unmanaged script: $exec_script"
                    fi
                fi

                local exec_hash="DEFER"
                local exec_metadata
                exec_metadata=$(get_file_metadata "$exec_script") || true

                add_finding "PAM" "Exec" "pam_exec_script" "$exec_script" "pam_exec.so target script" "$confidence" "$exec_hash" "$exec_metadata" "package=$exec_pkg_status" "$finding_matched_pattern" "$finding_matched_string"
            done
        fi

        # ─────────────────────────────────────────────────────────────────────
        # ISC-4/ISC-5 FIX: pam_python.so and pam_perl.so relay detection.
        # Like pam_exec.so, these modules execute external scripts on every auth
        # event. Their .so files are package-managed (verified → skipped above).
        # We must extract and analyze the script path argument instead.
        # ─────────────────────────────────────────────────────────────────────
        for relay_module in pam_python pam_perl; do
            local relay_scripts
            relay_scripts=$(echo "$_pam_cfg_content" | \
                grep "${relay_module}\.so" | \
                grep -oE "${relay_module}\.so[[:space:]]+(/[^[:space:]]+)" | \
                grep -oE '(/[^[:space:]]+)$' | \
                sort -u) || true

            for relay_script in $relay_scripts; do
                [[ -z "$relay_script" ]] && continue

                local relay_pkg_status relay_pkg_return=0
                relay_pkg_status=$(is_package_managed "$relay_script") || relay_pkg_return=$?

                local confidence="CRITICAL"
                local finding_matched_pattern="${relay_module}_script"
                local finding_matched_string="$relay_script"

                if [[ $relay_pkg_return -eq 0 ]]; then
                    confidence="LOW"
                    finding_matched_pattern="${relay_module}_verified_script"
                elif [[ $relay_pkg_return -eq 2 ]]; then
                    confidence="CRITICAL"
                    finding_matched_pattern="${relay_module}_modified_script"
                    log_finding "${relay_module}.so executes MODIFIED package script: $relay_script"
                else
                    if [[ ! -e "$relay_script" ]]; then
                        confidence="CRITICAL"
                        finding_matched_pattern="${relay_module}_missing_script"
                        finding_matched_string="$relay_script"
                        log_finding "${relay_module}.so references non-existent script (post-compromise cleanup?): $relay_script"
                    elif [[ "$relay_script" =~ ^/(tmp|dev/shm|var/tmp|run/user/) ]] || [[ "$relay_script" =~ /\.[a-zA-Z] ]]; then
                        confidence="CRITICAL"
                        finding_matched_pattern="${relay_module}_suspicious_location"
                        log_finding "${relay_module}.so executes script from suspicious location: $relay_script"
                    elif [[ -f "$relay_script" ]] && analyze_script_content "$relay_script"; then
                        confidence="CRITICAL"
                        finding_matched_pattern="$MATCHED_PATTERN"
                        finding_matched_string="$MATCHED_STRING"
                        log_finding "${relay_module}.so script contains suspicious content: $relay_script"
                    else
                        log_finding "${relay_module}.so executes unmanaged script: $relay_script"
                    fi
                fi

                local relay_hash="DEFER"
                local relay_metadata
                relay_metadata=$(get_file_metadata "$relay_script") || true

                add_finding "PAM" "Exec" "${relay_module}_script" "$relay_script" \
                    "${relay_module}.so target script" "$confidence" \
                    "$relay_hash" "$relay_metadata" "package=$relay_pkg_status" \
                    "$finding_matched_pattern" "$finding_matched_string"
            done
        done

        # ─────────────────────────────────────────────────────────────────────
        # ISC-7 FIX: /etc/security/pam_env.conf LD_PRELOAD injection detection.
        # pam_env.so reads this file and sets session environment variables for
        # every PAM-authenticated process. An attacker can inject LD_PRELOAD
        # pointing to a malicious shared library, preloaded into every auth process.
        # Format: LD_PRELOAD   DEFAULT=/path/to/lib.so
        # ─────────────────────────────────────────────────────────────────────
        if [[ -f "/etc/security/pam_env.conf" ]]; then
            local ld_preload_paths
            ld_preload_paths=$(grep -v "^#" /etc/security/pam_env.conf 2>/dev/null | \
                grep -i "^LD_PRELOAD" | \
                grep -oE '/[^[:space:]]+' | \
                sort -u) || true

            for ld_lib in $ld_preload_paths; do
                [[ -z "$ld_lib" ]] && continue

                local ld_pkg_status ld_pkg_return=0
                ld_pkg_status=$(is_package_managed "$ld_lib") || ld_pkg_return=$?

                local confidence="CRITICAL"
                local finding_matched_pattern="pam_env_ld_preload"
                local finding_matched_string="$ld_lib"

                if [[ $ld_pkg_return -eq 0 ]]; then
                    confidence="LOW"
                    finding_matched_pattern="pam_env_ld_preload_verified"
                elif [[ $ld_pkg_return -eq 2 ]]; then
                    log_finding "pam_env.conf LD_PRELOAD points to MODIFIED package library: $ld_lib"
                else
                    log_finding "pam_env.conf LD_PRELOAD points to unmanaged library: $ld_lib"
                fi

                local ld_hash="DEFER"
                local ld_metadata
                ld_metadata=$(get_file_metadata "$ld_lib") || true

                add_finding "PAM" "Env" "pam_env_ld_preload" "$ld_lib" \
                    "pam_env.conf LD_PRELOAD library" "$confidence" \
                    "$ld_hash" "$ld_metadata" "package=$ld_pkg_status" \
                    "$finding_matched_pattern" "$finding_matched_string"
            done
        fi

        # ─────────────────────────────────────────────────────────────────────
        # ISC-8 FIX: Per-user ~/.pam_environment LD_PRELOAD injection detection.
        # pam_env.so also reads ~/.pam_environment for each authenticating user.
        # An attacker with access to any account can inject LD_PRELOAD there,
        # preloading a malicious library into every process in that user's session.
        # ─────────────────────────────────────────────────────────────────────
        if [[ $EUID_CHECK -eq 0 ]]; then
            while IFS=: read -r _uname _ _uid _ _ _home _; do
                { [[ -z "$_home" ]] || [[ "$_home" == "/" ]]; } && continue
                local _user_pam_env="$_home/.pam_environment"
                [[ -f "$_user_pam_env" ]] || continue

                local _user_ld_paths
                _user_ld_paths=$(grep -v "^#" "$_user_pam_env" 2>/dev/null | \
                    grep -i "^LD_PRELOAD" | \
                    grep -oE '/[^[:space:]]+' | \
                    sort -u) || true

                for ld_lib in $_user_ld_paths; do
                    [[ -z "$ld_lib" ]] && continue

                    local ld_pkg_status ld_pkg_return=0
                    ld_pkg_status=$(is_package_managed "$ld_lib") || ld_pkg_return=$?

                    local confidence="CRITICAL"
                    local finding_matched_pattern="pam_env_user_ld_preload"
                    local finding_matched_string="$ld_lib"

                    if [[ $ld_pkg_return -eq 0 ]]; then
                        confidence="LOW"
                        finding_matched_pattern="pam_env_user_ld_preload_verified"
                    elif [[ $ld_pkg_return -eq 2 ]]; then
                        log_finding "~/.pam_environment LD_PRELOAD points to MODIFIED library ($_uname): $ld_lib"
                    else
                        log_finding "~/.pam_environment LD_PRELOAD points to unmanaged library ($_uname): $ld_lib"
                    fi

                    local ld_hash="DEFER"
                    local ld_metadata
                    ld_metadata=$(get_file_metadata "$ld_lib") || true

                    add_finding "PAM" "Env" "pam_env_user_ld_preload" "$ld_lib" \
                        "~/.pam_environment LD_PRELOAD ($_uname)" "$confidence" \
                        "$ld_hash" "$ld_metadata" "package=$ld_pkg_status" \
                        "$finding_matched_pattern" "$finding_matched_string"
                done
            done < /etc/passwd
        fi

        # ─────────────────────────────────────────────────────────────────────
        # ISC-12 FIX: /etc/security/ directory scan.
        # This directory contains PAM support files — pam_env.conf (covered by
        # ISC-7), pam_script_* hooks (covered by ISC-6), plus access.conf,
        # limits.conf, and others. Modified package-owned files or unmanaged
        # executables here are suspicious.
        # ─────────────────────────────────────────────────────────────────────
        if [[ -d "/etc/security" ]]; then
            while IFS= read -r -d '' sec_file; do
                local sec_pkg_status sec_pkg_return=0
                sec_pkg_status=$(is_package_managed "$sec_file") || sec_pkg_return=$?

                if [[ $sec_pkg_return -eq 2 ]]; then
                    local sec_hash sec_metadata
                    sec_hash=$(get_file_hash "$sec_file") || true
                    sec_metadata=$(get_file_metadata "$sec_file") || true
                    log_finding "/etc/security/ file is MODIFIED package file: $sec_file"
                    add_finding "PAM" "Security" "pam_security_modified" "$sec_file" \
                        "/etc/security/ file modified (package tamper)" "CRITICAL" \
                        "$sec_hash" "$sec_metadata" "package=$sec_pkg_status" \
                        "modified_pam_security" "$sec_file"
                elif [[ $sec_pkg_return -eq 1 ]] && [[ -x "$sec_file" ]]; then
                    # Unmanaged executable in /etc/security/ — suspicious
                    local sec_hash sec_metadata
                    sec_hash=$(get_file_hash "$sec_file") || true
                    sec_metadata=$(get_file_metadata "$sec_file") || true
                    local confidence="HIGH"
                    local finding_matched_pattern="pam_security_unmanaged_exec"
                    local finding_matched_string="$sec_file"
                    if analyze_script_content "$sec_file"; then
                        confidence="CRITICAL"
                        finding_matched_pattern="$MATCHED_PATTERN"
                        finding_matched_string="$MATCHED_STRING"
                    fi
                    log_finding "Unmanaged executable in /etc/security/: $sec_file"
                    add_finding "PAM" "Security" "pam_security_unmanaged_exec" "$sec_file" \
                        "Unmanaged executable in /etc/security/" "$confidence" \
                        "$sec_hash" "$sec_metadata" "package=$sec_pkg_status" \
                        "$finding_matched_pattern" "$finding_matched_string"
                fi
            done < <(find /etc/security -type f -print0 2>/dev/null)
        fi
    fi

    log_check "MOTD update scripts"

    # Check MOTD scripts
    local motd_dirs=(
        "/etc/update-motd.d"
        "/usr/lib/update-notifier"
    )

    for motd_dir in "${motd_dirs[@]}"; do
        if [[ -d "$motd_dir" ]]; then
            while IFS= read -r -d '' motd_script; do
                local hash=$(get_file_hash "$motd_script")
                local metadata=$(get_file_metadata "$motd_script")

                local confidence="LOW"
                local finding_matched_pattern=""
                local finding_matched_string=""

                # Package verification: skip verified, escalate modified to CRITICAL
                local motd_pkg_status
                local motd_pkg_return=0
                motd_pkg_status=$(is_package_managed "$motd_script") || motd_pkg_return=$?
                if [[ $motd_pkg_return -eq 0 ]]; then
                    continue
                elif [[ $motd_pkg_return -eq 2 ]]; then
                    confidence="CRITICAL"
                    finding_matched_pattern="modified_package"
                    finding_matched_string="$motd_script"
                    log_finding "MOTD script is MODIFIED package file: $motd_script"
                fi

                # Content analysis for UNMANAGED or MODIFIED scripts
                if [[ "$confidence" != "CRITICAL" ]]; then
                    # Strip null bytes to prevent bash warnings with binary content
                    local content=$(head -n 100 "$motd_script" 2>/dev/null | tr -d '\0' || echo "")
                    if quick_suspicious_check "$content"; then
                        confidence="HIGH"
                        finding_matched_pattern="$MATCHED_PATTERN"
                        finding_matched_string="$MATCHED_STRING"
                        log_finding "Suspicious MOTD script: $motd_script"
                    elif analyze_script_content "$motd_script"; then
                        confidence="HIGH"
                        finding_matched_pattern="$MATCHED_PATTERN"
                        finding_matched_string="$MATCHED_STRING"
                        log_finding "MOTD script contains suspicious patterns: $motd_script"
                    fi
                fi

                add_finding "MOTD" "Script" "motd_script" "$motd_script" "MOTD script: $(basename "$motd_script")" "$confidence" "$hash" "$metadata" "" "$finding_matched_pattern" "$finding_matched_string"
            done < <(find "$motd_dir" -type f -print0 2>/dev/null)
        fi
    done

    # ─── Passwd: UID 0 duplicate accounts ────────────────────────────────────
    log_check "Duplicate UID 0 accounts in /etc/passwd"

    if [[ -r /etc/passwd ]]; then
        while IFS=: read -r _pw_user _ _pw_uid _ _ _pw_home _pw_shell; do
            if [[ "$_pw_uid" -eq 0 ]] && [[ "$_pw_user" != "root" ]]; then
                local _hash; _hash=$(get_file_hash /etc/passwd)
                local _meta; _meta=$(get_file_metadata /etc/passwd)
                add_finding "UserAccount" "Passwd" "non_root_uid_zero" "/etc/passwd" "Non-root UID 0 account: $_pw_user" "CRITICAL" "$_hash" "$_meta" "uid=$_pw_uid|home=$_pw_home" "non_root_uid_zero" "user=$_pw_user;uid=0"
                log_finding "Non-root account with UID 0: $_pw_user (home: $_pw_home)"
            fi
        done < /etc/passwd
    fi

    # ─── Passwd: Shell masking (trailing space) ────────────────────────────
    log_check "Shell masking via trailing space in /etc/passwd"

    if [[ -r /etc/passwd ]]; then
        local _shells_list=()
        if [[ -r /etc/shells ]]; then
            while IFS= read -r _sl; do
                [[ "$_sl" =~ ^# ]] && continue
                [[ -z "$_sl" ]] && continue
                _shells_list+=("$_sl")
            done < /etc/shells
        fi

        while IFS=: read -r _sm_user _ _sm_uid _ _ _sm_home _sm_shell; do
            # Check for trailing whitespace in shell field
            if [[ "$_sm_shell" =~ [[:space:]]$ ]]; then
                local _hash; _hash=$(get_file_hash /etc/passwd)
                local _meta; _meta=$(get_file_metadata /etc/passwd)
                add_finding "UserAccount" "Passwd" "shell_masking_trailing_space" "/etc/passwd" "Shell masking (trailing space): $_sm_user" "HIGH" "$_hash" "$_meta" "uid=$_sm_uid|shell='${_sm_shell}'" "shell_trailing_space" "user=$_sm_user;shell_raw='${_sm_shell}'"
                log_finding "Shell masking via trailing space: user=$_sm_user shell='${_sm_shell}'"
            fi

            # Check for non-standard shell (not in /etc/shells, not nologin/false)
            if [[ ${#_shells_list[@]} -gt 0 ]]; then
                local _shell_trimmed="${_sm_shell%"${_sm_shell##*[! ]}"}"
                local _is_valid=false
                for _valid_shell in "${_shells_list[@]}"; do
                    [[ "$_shell_trimmed" == "$_valid_shell" ]] && _is_valid=true && break
                done
                if [[ "$_is_valid" == "false" ]] && [[ "$_shell_trimmed" != "/bin/false" ]] && [[ "$_shell_trimmed" != "/usr/sbin/nologin" ]] && [[ "$_shell_trimmed" != "/sbin/nologin" ]] && [[ -n "$_shell_trimmed" ]]; then
                    local _hash; _hash=$(get_file_hash /etc/passwd)
                    local _meta; _meta=$(get_file_metadata /etc/passwd)
                    add_finding "UserAccount" "Passwd" "nonstandard_shell" "/etc/passwd" "Non-standard shell: $_sm_user" "MEDIUM" "$_hash" "$_meta" "uid=$_sm_uid|shell=$_shell_trimmed" "nonstandard_shell" "user=$_sm_user;shell=$_shell_trimmed"
                fi
            fi
        done < /etc/passwd
    fi

}

# Check common backdoor locations (inspired by Crackdown and DFIR research)
check_common_backdoors() {
    log_info "[7/9] Checking common backdoor locations..."

    # APT/YUM configuration files that can be abused
    log_check "APT/YUM package manager configuration files"
    local pkg_mgr_configs=(
        "/etc/apt/apt.conf.d"
        "/usr/share/unattended-upgrades"
        "/etc/yum.repos.d"
        "/etc/yum.conf"
    )

    for config_dir in "${pkg_mgr_configs[@]}"; do
        if [[ -e "$config_dir" ]]; then
            if [[ -f "$config_dir" ]]; then
                local hash=$(get_file_hash "$config_dir")
                local metadata=$(get_file_metadata "$config_dir")
                local content=$(cat "$config_dir" 2>/dev/null || echo "")

                local confidence="LOW"
                local finding_matched_pattern=""
                local finding_matched_string=""
                if check_suspicious_patterns "$content"; then
                    confidence="HIGH"
                    finding_matched_pattern="$MATCHED_PATTERN"
                    finding_matched_string="$MATCHED_STRING"
                    log_finding "Suspicious package manager config: $config_dir"
                fi

                add_finding "PackageManager" "Config" "pkg_config" "$config_dir" "Package manager configuration: $(basename "$config_dir")" "$confidence" "$hash" "$metadata" "" "$finding_matched_pattern" "$finding_matched_string"

            elif [[ -d "$config_dir" ]]; then
                while IFS= read -r -d '' config_file; do
                    local hash=$(get_file_hash "$config_file")
                    local metadata=$(get_file_metadata "$config_file")
                    local content=$(head -50 "$config_file" 2>/dev/null || echo "")

                    local confidence="LOW"
                    local finding_matched_pattern=""
                    local finding_matched_string=""
                    if check_suspicious_patterns "$content"; then
                        confidence="HIGH"
                        finding_matched_pattern="$MATCHED_PATTERN"
                        finding_matched_string="$MATCHED_STRING"
                        log_finding "Suspicious package manager config: $config_file"
                    fi

                    add_finding "PackageManager" "Config" "pkg_config" "$config_file" "Package manager config: $(basename "$config_file")" "$confidence" "$hash" "$metadata" "" "$finding_matched_pattern" "$finding_matched_string"
                done < <(find "$config_dir" -type f -print0 2>/dev/null)
            fi
        fi
    done

    # ─── APT Post-Invoke / Pre-Invoke hook directives ─────────────────────────
    log_check "APT DPkg::Post-Invoke and APT::Update hook directives"

    if [[ -d "/etc/apt/apt.conf.d" ]]; then
        while IFS= read -r -d '' _apt_conf; do
            local _content
            _content=$(cat "$_apt_conf" 2>/dev/null | tr -d '\0') || true

            # Parse DPkg::Post-Invoke and APT::Update::Pre-Invoke / Post-Invoke
            local _hook_hit
            _hook_hit=$(grep -iE '(DPkg::(Post|Pre)-Invoke|APT::Update::(Pre|Post)-Invoke)' <<< "$_content" | grep -v "^[[:space:]]*#" | head -3) || true

            [[ -z "$_hook_hit" ]] && continue

            local _hash; _hash=$(get_file_hash "$_apt_conf")
            local _meta; _meta=$(get_file_metadata "$_apt_conf")
            check_file_package "$_apt_conf"
            local _pkg="$PKG_STATUS"

            local _confidence="MEDIUM"
            local _matched_pattern="apt_hook_directive"
            local _matched_string="${_hook_hit:0:200}"

            [[ "$_pkg" == "unmanaged" ]] && _confidence="HIGH"

            # Extract and analyze the hook command string
            local _hook_cmd
            _hook_cmd=$(grep -oiE '"[^"]+"[[:space:]]*;' <<< "$_hook_hit" | tr -d '"' | tr -d ';' | head -1) || true
            if [[ -n "$_hook_cmd" ]] && analyze_content_string "$_hook_cmd" "$_apt_conf"; then
                _confidence="CRITICAL"
                _matched_pattern="apt_hook_malicious_command"
                _matched_string="$MATCHED_STRING"
                log_finding "APT hook directive with malicious command: $_apt_conf"
            else
                log_finding "APT hook directive found: $_apt_conf"
            fi

            add_finding "PackageManager" "AptHook" "apt_hook_directive" "$_apt_conf" "APT hook: $(basename "$_apt_conf")" "$_confidence" "$_hash" "$_meta" "package=$_pkg" "$_matched_pattern" "$_matched_string"
        done < <(find /etc/apt/apt.conf.d -maxdepth 1 -type f -print0 2>/dev/null)
    fi

    log_check "YUM/DNF plugin configurations and scripts"

    # ═══════════════════════════════════════════════════════════════════════════
    # YUM / DNF Plugin persistence
    # Plugins are Python scripts that run inside the package manager process.
    # An attacker can drop a plugin .py with an `execute` hook that fires on
    # every `yum`/`dnf` invocation — extremely stealthy on RPM-based systems.
    # ═══════════════════════════════════════════════════════════════════════════
    local yum_plugin_conf_dirs=(
        "/etc/yum/pluginconf.d"
        "/etc/dnf/pluginconf.d"
    )
    local yum_plugin_lib_dirs=(
        "/usr/lib/yum-plugins"
        "/usr/lib/python"          # glob-expanded below
    )

    for _ypcd in "${yum_plugin_conf_dirs[@]}"; do
        [[ -d "$_ypcd" ]] || continue
        while IFS= read -r -d '' _conf; do
            local _conf_hash _conf_meta _conf_content _conf_pkg _conf_pkg_return=0
            _conf_hash=$(get_file_hash "$_conf")
            _conf_meta=$(get_file_metadata "$_conf")
            _conf_content=$(cat "$_conf" 2>/dev/null || echo "")
            _conf_pkg=$(is_package_managed "$_conf") || _conf_pkg_return=$?

            local _yp_confidence="LOW"
            local _yp_pattern="" _yp_string=""

            # Flag plugins explicitly enabled in an unmanaged config
            if [[ $_conf_pkg_return -eq 2 ]]; then
                _yp_confidence="CRITICAL"
                _yp_pattern="modified_plugin_conf"
                _yp_string="$_conf"
                log_finding "YUM/DNF plugin config is MODIFIED package file: $_conf"
            elif [[ $_conf_pkg_return -eq 1 ]]; then
                # Unmanaged — check if enabled and if the plugin .py has suspicious content
                local _enabled
                _enabled=$(grep -iE "^enabled[[:space:]]*=[[:space:]]*1" "$_conf" 2>/dev/null || echo "")
                if [[ -n "$_enabled" ]]; then
                    _yp_confidence="MEDIUM"
                    _yp_pattern="unmanaged_plugin_enabled"
                    _yp_string="enabled=1"
                    log_finding "Unmanaged YUM/DNF plugin enabled: $_conf"

                    # Try to find and scan the corresponding Python plugin script
                    local _plugin_name
                    _plugin_name=$(basename "$_conf" .conf)
                    local _py_script=""
                    # Check standard yum-plugins location
                    [[ -f "/usr/lib/yum-plugins/${_plugin_name}.py" ]] && _py_script="/usr/lib/yum-plugins/${_plugin_name}.py"
                    # Check dnf-plugins under any python version
                    if [[ -z "$_py_script" ]]; then
                        _py_script=$(find /usr/lib/python* /usr/lib64/python* -path "*/dnf-plugins/${_plugin_name}.py" 2>/dev/null | head -1 || true)
                    fi
                    if [[ -n "$_py_script" ]] && [[ -f "$_py_script" ]]; then
                        local _py_hash _py_meta _py_pkg _py_pkg_return=0
                        _py_hash=$(get_file_hash "$_py_script")
                        _py_meta=$(get_file_metadata "$_py_script")
                        _py_pkg=$(is_package_managed "$_py_script") || _py_pkg_return=$?
                        local _py_confidence="MEDIUM"
                        local _py_pattern="unmanaged_plugin_py" _py_string="$_py_script"
                        if [[ $_py_pkg_return -eq 2 ]]; then
                            _py_confidence="CRITICAL"
                            _py_pattern="modified_plugin_py"
                            log_finding "YUM/DNF plugin Python script is MODIFIED package file: $_py_script"
                        elif [[ $_py_pkg_return -eq 1 ]]; then
                            if check_suspicious_patterns "$( cat "$_py_script" 2>/dev/null || echo "" )"; then
                                _py_confidence="HIGH"
                                _py_pattern="$MATCHED_PATTERN"
                                _py_string="$MATCHED_STRING"
                                log_finding "YUM/DNF plugin script contains suspicious content: $_py_script"
                            fi
                        fi
                        add_finding "PackageManager" "Plugin" "yum_plugin_py" "$_py_script" \
                            "YUM/DNF plugin script: $(basename "$_py_script")" "$_py_confidence" \
                            "$_py_hash" "$_py_meta" "package=$_py_pkg" "$_py_pattern" "$_py_string"
                    fi
                fi
            fi

            add_finding "PackageManager" "Plugin" "yum_plugin_conf" "$_conf" \
                "YUM/DNF plugin config: $(basename "$_conf")" "$_yp_confidence" \
                "$_conf_hash" "$_conf_meta" "package=$_conf_pkg" "$_yp_pattern" "$_yp_string"
        done < <(find "$_ypcd" -type f -name "*.conf" -print0 2>/dev/null)
    done

    log_check "DPKG postinst scripts (/var/lib/dpkg/info/*.postinst)"

    # ═══════════════════════════════════════════════════════════════════════════
    # DPKG postinst scripts  (/var/lib/dpkg/info/*.postinst)
    # Every installed Debian package can ship a post-install shell script that
    # runs as root after apt install/upgrade. dpkg -S does NOT track these files
    # (they are dpkg's internal metadata, not package-owned installed files), so
    # is_package_managed() always returns "unmanaged" — useless here.
    #
    # WHY analyze_script_content() is NOT used here:
    #   SUSPICIOUS_COMMANDS includes wget, curl, base64, chmod +x /tmp, etc.
    #   Every legitimate package installer uses these — calling the full analyzer
    #   produces hundreds of FPs. Postinst scripts are installation code, not
    #   runtime persistence, so only a narrow set of patterns is meaningful.
    #
    # Detection uses two focused signals:
    #   1. Postinst-specific content checks — only patterns that are never
    #      legitimate in an installation script:
    #        • NEVER_WHITELIST  : reverse shells, /dev/tcp/, nc -e, bash -i
    #        • Download+execute : curl/wget piped directly to a shell
    #        • Encoding obfusc. : hex/octal/ANSI-C sequences (no legit use)
    #        • Process detach   : nohup+setsid (installers never detach)
    #   2. Orphan postinst — script exists for a package that is NOT currently
    #      installed. Classic TTP: `apt install evil && apt remove evil` —
    #      payload survives in /var/lib/dpkg/info/ without purge.
    # ═══════════════════════════════════════════════════════════════════════════
    local dpkg_info_dir="/var/lib/dpkg/info"
    if [[ -d "$dpkg_info_dir" ]]; then
        # Pre-build installed package set with ONE bulk dpkg-query call (timeout 10).
        # Avoids 400-800 sequential dpkg-query forks that block if apt holds the dpkg lock.
        local -A _dpkg_installed_pkgs=()
        if command -v dpkg-query &>/dev/null; then
            while IFS=$'\t' read -r _dp _ds; do
                [[ "$_ds" == *"install ok installed"* ]] && _dpkg_installed_pkgs["$_dp"]=1
            done < <(timeout 10 dpkg-query -W -f='${Package}\t${Status}\n' 2>/dev/null)
        fi

        if [[ ${#_dpkg_installed_pkgs[@]} -eq 0 ]] && command -v dpkg-query &>/dev/null; then
            log_warn "dpkg-query returned no packages (apt lock held or timeout) — skipping postinst orphan check"
        fi

        while IFS= read -r -d '' _postinst; do
            local _pi_confidence="LOW"
            local _pi_pattern="" _pi_string=""
            local _pi_is_orphan=false

            # ── Signal 1: Orphan check ─────────────────────────────────────
            local _pi_pkgname
            _pi_pkgname=$(basename "$_postinst" .postinst)
            _pi_pkgname="${_pi_pkgname%%:*}"   # strip :arch suffix (e.g. bash:amd64 → bash)

            if [[ ${#_dpkg_installed_pkgs[@]} -gt 0 ]] && [[ -z "${_dpkg_installed_pkgs[$_pi_pkgname]+isset}" ]]; then
                _pi_is_orphan=true
                _pi_confidence="MEDIUM"
                _pi_pattern="orphan_postinst"
                _pi_string="package $_pi_pkgname not installed"
            fi

            # ── Signal 2: Focused content analysis ────────────────────────
            # Read content and strip comment lines to avoid FP on docs/examples
            local _pi_content _pi_clean
            _pi_content=$(head -n 500 "$_postinst" 2>/dev/null | tr -d '\0') || true
            _pi_clean=$(echo "$_pi_content" | grep -Ev '^[[:space:]]*#') || true

            local _pi_hit=""

            # Check A: NEVER_WHITELIST — absolute red flags in any context
            if [[ -n "$COMBINED_NEVER_WHITELIST_PATTERN" ]]; then
                _pi_hit=$(echo "$_pi_clean" | grep -iE "$COMBINED_NEVER_WHITELIST_PATTERN" | head -1) || true
                if [[ -n "$_pi_hit" ]]; then
                    _pi_confidence="HIGH"
                    _pi_pattern="never_whitelist"
                    _pi_string=$(echo "$_pi_hit" | sed 's/^[[:space:]]*//' | head -c 200)
                fi
            fi

            # Check B: Download-and-execute — curl/wget piped to a shell
            # (legitimate postinst scripts download files but never pipe them straight to bash)
            if [[ -z "$_pi_hit" ]]; then
                _pi_hit=$(echo "$_pi_clean" | grep -iE \
                    "(curl|wget)[^|]*\|[[:space:]]*(bash|sh|dash|zsh|exec)|eval[[:space:]]*\$\((curl|wget)" \
                    | head -1) || true
                if [[ -n "$_pi_hit" ]]; then
                    _pi_confidence="HIGH"
                    _pi_pattern="download_execute"
                    _pi_string=$(echo "$_pi_hit" | sed 's/^[[:space:]]*//' | head -c 200)
                fi
            fi

            # Check C: Encoding obfuscation — hex/octal sequences
            # Legitimate package scripts have zero reason to encode strings this way
            if [[ -z "$_pi_hit" ]]; then
                _pi_hit=$(echo "$_pi_clean" | grep -E \
                    '(\\x[0-9a-fA-F]{2}){4,}|(\\[0-7]{3}){4,}' | head -1) || true
                if [[ -n "$_pi_hit" ]]; then
                    _pi_confidence="HIGH"
                    _pi_pattern="encoding_obfuscation"
                    _pi_string=$(echo "$_pi_hit" | sed 's/^[[:space:]]*//' | head -c 200)
                fi
            fi

            # Check D: Process detachment chain — nohup+setsid
            # Package installers never need to detach from the controlling terminal
            if [[ -z "$_pi_hit" ]]; then
                _pi_hit=$(echo "$_pi_clean" | grep -iE "nohup.*setsid|setsid.*nohup" | head -1) || true
                if [[ -n "$_pi_hit" ]]; then
                    _pi_confidence="HIGH"
                    _pi_pattern="process_detachment"
                    _pi_string=$(echo "$_pi_hit" | sed 's/^[[:space:]]*//' | head -c 200)
                fi
            fi

            # ── Gate: only report if at least one signal fired ─────────────
            if [[ -z "$_pi_hit" && "$_pi_is_orphan" == false ]]; then
                continue
            fi

            if [[ -n "$_pi_hit" ]]; then
                if [[ "$_pi_is_orphan" == true ]]; then
                    log_finding "Orphan DPKG postinst with suspicious content [$_pi_pattern]: $_postinst"
                else
                    log_finding "DPKG postinst suspicious content [$_pi_pattern]: $_postinst"
                fi
            else
                log_finding "Orphan DPKG postinst (package not installed): $_postinst"
            fi

            local _pi_hash _pi_meta
            _pi_hash=$(get_file_hash "$_postinst")
            _pi_meta=$(get_file_metadata "$_postinst")

            add_finding "PackageManager" "DpkgPostinst" "dpkg_postinst" "$_postinst" \
                "DPKG postinst: $_pi_pkgname" "$_pi_confidence" \
                "$_pi_hash" "$_pi_meta" "" "$_pi_pattern" "$_pi_string"
        done < <(find "$dpkg_info_dir" -maxdepth 1 -type f -name "*.postinst" -print0 2>/dev/null)
    fi

    # ═══════════════════════════════════════════════════════════════════════════
    # RPM %post scripts
    # RPM packages embed post-install scriptlets that run as root after install.
    # One call to `rpm -qa --scripts` dumps all scriptlets — parse the output
    # to extract and scan each %post block without expensive per-package calls.
    # ═══════════════════════════════════════════════════════════════════════════
    if command -v rpm &>/dev/null; then
        local _rpm_tmp="$TEMP_DATA/rpm_scripts.txt"
        timeout 30 rpm -qa --scripts 2>/dev/null > "$_rpm_tmp" || true

        if [[ -s "$_rpm_tmp" ]]; then
            local _rpm_pkg="" _in_post=false _post_buf=""

            _flush_rpm_post() {
                [[ -z "$_rpm_pkg" || -z "$_post_buf" ]] && return
                local _rp_confidence="LOW" _rp_pattern="" _rp_string=""
                if check_suspicious_patterns "$_post_buf"; then
                    _rp_confidence="HIGH"
                    _rp_pattern="$MATCHED_PATTERN"
                    _rp_string="$MATCHED_STRING"
                    log_finding "RPM %post script with suspicious content: $_rpm_pkg"
                    add_finding "PackageManager" "RpmPost" "rpm_post_script" \
                        "/var/lib/rpm/$_rpm_pkg" \
                        "RPM %post: $_rpm_pkg" "$_rp_confidence" \
                        "N/A" "N/A" "" "$_rp_pattern" "$_rp_string"
                fi
            }

            while IFS= read -r _rline; do
                if [[ "$_rline" =~ ^package[[:space:]](.+)$ ]]; then
                    _flush_rpm_post
                    _rpm_pkg="${BASH_REMATCH[1]}"
                    _in_post=false
                    _post_buf=""
                elif [[ "$_rline" =~ ^postinstall[[:space:]]scriptlet ]]; then
                    _in_post=true
                    _post_buf=""
                elif [[ "$_rline" =~ ^(preinstall|preuninstall|postuninstall|verify|filetrigger)[[:space:]]scriptlet ]]; then
                    _flush_rpm_post
                    _in_post=false
                    _post_buf=""
                elif [[ "$_in_post" == true ]]; then
                    _post_buf+="$_rline"$'\n'
                fi
            done < "$_rpm_tmp"
            _flush_rpm_post   # flush last package
            unset -f _flush_rpm_post
        fi
        rm -f "$_rpm_tmp" 2>/dev/null || true
    fi

    log_check "at.allow / at.deny access control files"

    # Check at.allow and at.deny
    local at_files=(
        "/etc/at.allow"
        "/etc/at.deny"
    )

    for at_file in "${at_files[@]}"; do
        if [[ -f "$at_file" ]]; then
            local hash=$(get_file_hash "$at_file")
            local metadata=$(get_file_metadata "$at_file")

            add_finding "Scheduled" "AtAccess" "at_access" "$at_file" "At access control: $(basename "$at_file")" "MEDIUM" "$hash" "$metadata" ""
        fi
    done

    log_check "doas.conf (OpenBSD-style sudo alternative)"

    # Check doas configuration (OpenBSD-style sudo alternative)
    if [[ -f "/etc/doas.conf" ]]; then
        local hash=$(get_file_hash "/etc/doas.conf")
        local metadata=$(get_file_metadata "/etc/doas.conf")
        local content=$(cat "/etc/doas.conf" 2>/dev/null || echo "")

        local confidence="MEDIUM"
        local finding_matched_pattern=""
        local finding_matched_string=""
        local permissive_match=$(echo "$content" | grep -iE "(permit nopass|persist)" | head -1) || true
        if [[ -n "$permissive_match" ]]; then
            confidence="HIGH"
            finding_matched_pattern="permissive_doas"
            finding_matched_string="$permissive_match"
            log_finding "Potentially permissive doas configuration"
        fi

        add_finding "Privilege" "Doas" "doas_config" "/etc/doas.conf" "Doas privilege escalation config" "$confidence" "$hash" "$metadata" "" "$finding_matched_pattern" "$finding_matched_string"
    fi

    log_check "User git configs (credential helpers and hooks)"

    # Check for user git configs (can contain credential helpers or hooks)
    if [[ $EUID_CHECK -eq 0 ]]; then
        while IFS=: read -r username _ uid _ _ homedir _; do
            if [[ $uid -ge 1000 ]] || [[ $uid -eq 0 ]]; then
                local gitconfig="$homedir/.gitconfig"
                if [[ -f "$gitconfig" ]]; then
                    local hash=$(get_file_hash "$gitconfig")
                    local metadata=$(get_file_metadata "$gitconfig")
                    local content=$(<"$gitconfig" 2>/dev/null || echo "")

                    local confidence="LOW"
                    local finding_matched_pattern=""
                    local finding_matched_string=""
                    local helper_match=$(echo "$content" | grep -iE "(credential.*helper|core.*pager|core.*editor.*sh)" | head -1) || true
                    if [[ -n "$helper_match" ]]; then
                        confidence="MEDIUM"
                        finding_matched_pattern="git_helper"
                        finding_matched_string="$helper_match"
                    fi
                    if check_suspicious_patterns "$content"; then
                        confidence="HIGH"
                        finding_matched_pattern="$MATCHED_PATTERN"
                        finding_matched_string="$MATCHED_STRING"
                        log_finding "Suspicious git config for user $username: $gitconfig"
                    fi

                    add_finding "GitConfig" "User" "git_config" "$gitconfig" "User git config for $username" "$confidence" "$hash" "$metadata" "user=$username" "$finding_matched_pattern" "$finding_matched_string"
                fi
            fi
        done < /etc/passwd
    else
        if [[ -f "$HOME/.gitconfig" ]]; then
            local hash=$(get_file_hash "$HOME/.gitconfig")
            local metadata=$(get_file_metadata "$HOME/.gitconfig")
            local content=$(<"$HOME/.gitconfig" 2>/dev/null || echo "")

            local confidence="LOW"
            local finding_matched_pattern=""
            local finding_matched_string=""
            local helper_match=$(echo "$content" | grep -iE "(credential.*helper|core.*pager|core.*editor.*sh)" | head -1) || true
            if [[ -n "$helper_match" ]]; then
                confidence="MEDIUM"
                finding_matched_pattern="git_helper"
                finding_matched_string="$helper_match"
            fi
            if check_suspicious_patterns "$content"; then
                confidence="HIGH"
                finding_matched_pattern="$MATCHED_PATTERN"
                finding_matched_string="$MATCHED_STRING"
                log_finding "Suspicious git config: $HOME/.gitconfig"
            fi

            add_finding "GitConfig" "User" "git_config" "$HOME/.gitconfig" "Current user git config" "$confidence" "$hash" "$metadata" "user=$(whoami)" "$finding_matched_pattern" "$finding_matched_string"
        fi
    fi

    log_check "Web server directories for webshells"

    # Check web server directories for potential webshells
    local web_dirs=(
        "/var/www"
        "/usr/share/nginx"
        "/etc/nginx"
        "/etc/apache2"
        "/etc/httpd"
    )

    for web_dir in "${web_dirs[@]}"; do
        if [[ -d "$web_dir" ]]; then
            # Look for recently modified PHP/ASP files (last 30 days), limit to 100 files
            local _web_count=0
            while IFS= read -r -d '' web_file; do
                (( _web_count++ )) || true
                if [[ $_web_count -gt 100 ]]; then
                    log_warn "Web shell scan cap (100 files) reached in $web_dir — remaining files not scanned"
                    break
                fi

                local hash=$(get_file_hash "$web_file")
                local metadata=$(get_file_metadata "$web_file")

                # Extract mod_time from already-fetched metadata (no extra stat fork)
                local mod_time=0
                [[ "$metadata" =~ modified:([0-9]+) ]] && mod_time="${BASH_REMATCH[1]}"
                local current_time=$SCAN_EPOCH
                local days_old=$(( (current_time - mod_time) / 86400 ))

                # Content-gated only — report if webshell pattern found regardless of age
                local confidence="LOW"
                local finding_matched_pattern=""
                local finding_matched_string=""
                local content
                content=$(head -100 "$web_file" 2>/dev/null || echo "")
                local webshell_match
                webshell_match=$(echo "$content" | grep -oiE "(eval|base64_decode|system\(|exec\(|shell_exec|passthru|proc_open|popen)" | head -1) || true
                if [[ -n "$webshell_match" ]]; then
                    confidence="HIGH"
                    finding_matched_pattern="webshell_pattern"
                    finding_matched_string="$webshell_match"
                    log_finding "Potential webshell detected: $web_file"
                fi

                if [[ $confidence != "LOW" ]]; then
                    add_finding "WebShell" "Suspicious" "web_file" "$web_file" "Web file with suspicious content in $web_dir" "$confidence" "$hash" "$metadata" "days_old=$days_old" "$finding_matched_pattern" "$finding_matched_string"
                fi
            done < <(find "$web_dir" -xdev -type f \( -name "*.php" -o -name "*.asp" -o -name "*.aspx" -o -name "*.jsp" \) -print0 2>/dev/null)
        fi
    done
}

################################################################################
# SSH Persistence Check
################################################################################

check_ssh_persistence() {
    log_info "[8/9] Checking SSH persistence mechanisms..."

    # Collect user home directories to check
    local _ssh_homes=()
    if [[ $EUID_CHECK -eq 0 ]]; then
        while IFS=: read -r _su_name _ _su_uid _ _ _su_home _; do
            if ([[ $_su_uid -ge 1000 ]] || [[ $_su_uid -eq 0 ]]) && [[ -n "$_su_home" ]] && [[ "$_su_home" != "/" ]]; then
                _ssh_homes+=("${_su_home}:${_su_name}")
            fi
        done < /etc/passwd
    else
        _ssh_homes+=("${HOME}:$(whoami)")
    fi

    log_check "SSH authorized_keys files (all users)"

    # Read AuthorizedKeysFile directive from sshd_config (may specify non-default path)
    local _ak_directive
    _ak_directive=$(grep -iE "^[[:space:]]*AuthorizedKeysFile[[:space:]]" \
        /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
        | awk '{print $2}' | head -1) || true
    local _ak_patterns=(".ssh/authorized_keys")  # default
    if [[ -n "$_ak_directive" ]] && [[ "$_ak_directive" != ".ssh/authorized_keys" ]]; then
        _ak_patterns+=("$_ak_directive")
    fi

    for _ssh_entry in "${_ssh_homes[@]}"; do
        local _ssh_home="${_ssh_entry%%:*}"
        local _ssh_user="${_ssh_entry##*:}"
        local _ssh_dir="$_ssh_home/.ssh"

        # ── authorized_keys ───────────────────────────────────────────────────
        # Attackers add their public key to gain persistent access without a password.
        # Flag: file present, with analysis of key options (command=, restrict, from=)
        for _ak_pattern in "${_ak_patterns[@]}"; do
            local _ak_file
            if [[ "$_ak_pattern" == /* ]]; then
                # Absolute path -- expand %u for username
                _ak_file="${_ak_pattern//%u/$_ssh_user}"
            else
                _ak_file="${_ssh_home}/${_ak_pattern}"
            fi
            [[ -f "$_ak_file" ]] || continue
        if true; then
            local _ak_hash _ak_meta
            _ak_hash=$(get_file_hash "$_ak_file") || true
            _ak_meta=$(get_file_metadata "$_ak_file") || true

            local _ak_confidence="MEDIUM"
            local _ak_pattern="authorized_keys_present"
            local _ak_string="$_ak_file"

            # Extract mod time
            local _ak_mod_time=0
            [[ "$_ak_meta" =~ modified:([0-9]+) ]] && _ak_mod_time="${BASH_REMATCH[1]}"
            local _ak_days_old=$(( (SCAN_EPOCH - _ak_mod_time) / 86400 ))

            # Check for suspicious key options: command= (forced command / RCE)
            # from= with suspicious hosts, or inline execution patterns
            local _ak_cmd_match
            _ak_cmd_match=$(grep -v "^#" "$_ak_file" 2>/dev/null | grep -oiE 'command="([^"\\]|\\.){0,200}"' | head -1) || true
            if [[ -n "$_ak_cmd_match" ]]; then
                _ak_confidence="HIGH"
                _ak_pattern="authorized_keys_command_option"
                _ak_string="$_ak_cmd_match"
                log_finding "SSH authorized_keys has command= option ($_ssh_user): $_ak_cmd_match"

                # Deeper check: is the forced command content suspicious?
                if echo "$_ak_cmd_match" | grep -qiE "$UNIFIED_SUSPICIOUS_PATTERN"; then
                    _ak_confidence="CRITICAL"
                    _ak_pattern="authorized_keys_suspicious_command"
                    log_finding "SSH authorized_keys command= contains suspicious content ($_ssh_user)"
                fi
            fi

            # (time-based elevation removed — no baseline context)

            add_finding_new "SSH" "$_ak_confidence" "$_ak_file" "$_ak_hash" \
                "$(get_owner_from_metadata "$_ak_meta")" "$(get_permissions_from_metadata "$_ak_meta")" \
                "$_ak_days_old" "unmanaged" "" "" "$_ssh_user" "$_ak_pattern" "$_ak_string"
        fi
        done  # _ak_patterns loop

        log_check "~/.ssh/rc login hook ($_ssh_user)"

        # ── ~/.ssh/rc ─────────────────────────────────────────────────────────
        # Executed by sshd on every SSH login for the user (before shell launch).
        # Attackers use this for login hooks, beacons, or persistent execution.
        local _rc_file="$_ssh_dir/rc"
        if [[ -f "$_rc_file" ]]; then
            local _rc_hash _rc_meta
            _rc_hash=$(get_file_hash "$_rc_file") || true
            _rc_meta=$(get_file_metadata "$_rc_file") || true

            local _rc_confidence="HIGH"   # Any ~/.ssh/rc is unusual and warrants review
            local _rc_pattern="ssh_rc_present"
            local _rc_string="$_rc_file"

            local _rc_mod_time=0
            [[ "$_rc_meta" =~ modified:([0-9]+) ]] && _rc_mod_time="${BASH_REMATCH[1]}"
            local _rc_days_old=$(( (SCAN_EPOCH - _rc_mod_time) / 86400 ))

            log_finding "SSH rc file present ($_ssh_user): $_rc_file"

            # Content analysis
            if analyze_script_content "$_rc_file"; then
                _rc_confidence="CRITICAL"
                _rc_pattern="ssh_rc_suspicious_content"
                _rc_string="$MATCHED_STRING"
                log_finding "SSH rc file contains suspicious content ($_ssh_user): $MATCHED_STRING"
            elif quick_suspicious_check "$(head -n 50 "$_rc_file" 2>/dev/null | tr -d '\0')"; then
                _rc_confidence="CRITICAL"
                _rc_pattern="ssh_rc_suspicious_content"
                _rc_string="$MATCHED_STRING"
                log_finding "SSH rc file contains suspicious pattern ($_ssh_user): $MATCHED_STRING"
            fi

            add_finding_new "SSH" "$_rc_confidence" "$_rc_file" "$_rc_hash" \
                "$(get_owner_from_metadata "$_rc_meta")" "$(get_permissions_from_metadata "$_rc_meta")" \
                "$_rc_days_old" "unmanaged" "" "" "$_ssh_user" "$_rc_pattern" "$_rc_string"
        fi
    done

    # ─── System account SSH keys (UID 1-999) ─────────────────────────────────
    # These are excluded from the regular per-user scan above — scan them separately
    # System accounts with SSH keys are always suspicious (e.g., news, nobody, mail)
    log_check "System account SSH authorized_keys (UID 1-999)"

    if [[ $EUID_CHECK -eq 0 ]]; then
        while IFS=: read -r _sys_user _ _sys_uid _ _ _sys_home _; do
            [[ "$_sys_uid" -lt 1 ]] && continue    # skip uid 0 (root — handled above)
            [[ "$_sys_uid" -ge 1000 ]] && continue  # skip regular users — handled above
            [[ -z "$_sys_home" ]] || [[ "$_sys_home" == "/" ]] && continue
            [[ -d "$_sys_home/.ssh" ]] || continue

            local _ak_file="$_sys_home/.ssh/authorized_keys"
            [[ -f "$_ak_file" ]] || continue

            local _hash; _hash=$(get_file_hash "$_ak_file")
            local _meta; _meta=$(get_file_metadata "$_ak_file")

            local _confidence="HIGH"
            local _matched_pattern="system_account_ssh_key"
            local _matched_string="user=$_sys_user;uid=$_sys_uid"

            log_finding "System account has SSH authorized_keys: $_sys_user (uid=$_sys_uid) -> $_ak_file"

            # Analyze any command= forced commands in the key file
            local _cmd_match
            _cmd_match=$(grep -v "^#" "$_ak_file" 2>/dev/null | grep -oiE 'command="([^"\\]|\\.){0,200}"' | head -1) || true
            if [[ -n "$_cmd_match" ]]; then
                local _cmd_content="${_cmd_match#command=\"}"
                _cmd_content="${_cmd_content%\"}"
                if analyze_content_string "$_cmd_content" "$_ak_file"; then
                    _confidence="CRITICAL"
                    _matched_pattern="system_account_ssh_forced_command_malicious"
                    _matched_string="$MATCHED_STRING"
                fi
            fi

            add_finding "SSH" "SystemAccount" "system_account_ssh_key" "$_ak_file" "System account SSH key: $_sys_user (uid=$_sys_uid)" "$_confidence" "$_hash" "$_meta" "user=$_sys_user|uid=$_sys_uid" "$_matched_pattern" "$_matched_string"
        done < /etc/passwd
    fi
}

check_polkit_persistence() {
    log_info "[NEW] Checking Polkit (PolicyKit) persistence..."

    # ─── .pkla files (Polkit < 0.106) ───────────────────────────────────────
    log_check "Polkit PKLA rules (/etc/polkit-1/localauthority/)"

    local _pkla_dir="/etc/polkit-1/localauthority/50-local.d"
    if [[ -d "$_pkla_dir" ]]; then
        while IFS= read -r -d '' _pkla; do
            local _hash; _hash=$(get_file_hash "$_pkla")
            local _meta; _meta=$(get_file_metadata "$_pkla")
            check_file_package "$_pkla"
            local _pkg="$PKG_STATUS"

            local _confidence="LOW"
            local _matched_pattern=""
            local _matched_string=""

            [[ "$_pkg" == "unmanaged" ]] && _confidence="HIGH"

            local _content
            _content=$(cat "$_pkla" 2>/dev/null | tr -d '\0') || true

            # Check for triple Result=yes (unconditional bypass)
            local _any="" _inactive="" _active=""
            grep -qiE "^ResultAny[[:space:]]*=[[:space:]]*yes" <<< "$_content" && _any="yes"
            grep -qiE "^ResultInactive[[:space:]]*=[[:space:]]*yes" <<< "$_content" && _inactive="yes"
            grep -qiE "^ResultActive[[:space:]]*=[[:space:]]*yes" <<< "$_content" && _active="yes"

            local _identity
            _identity=$(grep -iE "^Identity[[:space:]]*=" <<< "$_content" | head -1) || true

            if [[ "$_any" == "yes" && "$_inactive" == "yes" && "$_active" == "yes" ]]; then
                _confidence="CRITICAL"
                _matched_pattern="polkit_pkla_all_result_yes"
                _matched_string="ResultAny=yes;ResultInactive=yes;ResultActive=yes"
                log_finding "Polkit PKLA: unconditional auth bypass (all Result=yes): $_pkla"
                # Wildcard identity makes it even worse but confidence is already CRITICAL
                if [[ "$_identity" =~ "unix-user:\*" ]] || [[ "$_identity" =~ "unix-group:\*" ]]; then
                    _matched_string="$_matched_string;Identity=wildcard"
                    log_finding "Polkit PKLA: wildcard identity with all Result=yes: $_pkla"
                fi
            elif [[ -n "$_any" || -n "$_inactive" || -n "$_active" ]]; then
                [[ "$_confidence" != "CRITICAL" ]] && _confidence="HIGH"
                _matched_pattern="polkit_pkla_partial_yes"
                _matched_string="ResultAny=${_any:-no};ResultInactive=${_inactive:-no};ResultActive=${_active:-no}"
                log_finding "Polkit PKLA: partial Result=yes: $_pkla"
            fi

            add_finding "Privilege" "Polkit" "polkit_pkla" "$_pkla" "Polkit PKLA: $(basename "$_pkla")" "$_confidence" "$_hash" "$_meta" "package=$_pkg" "$_matched_pattern" "$_matched_string"
        done < <(find "$_pkla_dir" -maxdepth 2 -name "*.pkla" -type f -print0 2>/dev/null)
    fi

    # ─── .rules files (Polkit >= 0.106, JS-based) ───────────────────────────
    log_check "Polkit rules.d (JS-based, /etc/polkit-1/rules.d/)"

    local _rules_dir="/etc/polkit-1/rules.d"
    if [[ -d "$_rules_dir" ]]; then
        while IFS= read -r -d '' _rules; do
            local _hash; _hash=$(get_file_hash "$_rules")
            local _meta; _meta=$(get_file_metadata "$_rules")
            check_file_package "$_rules"
            local _pkg="$PKG_STATUS"

            local _confidence="LOW"
            local _matched_pattern=""
            local _matched_string=""

            [[ "$_pkg" == "unmanaged" ]] && _confidence="HIGH"

            local _content
            _content=$(cat "$_rules" 2>/dev/null | tr -d '\0') || true

            # Strip single-line JS comments before analysis to reduce FPs
            local _content_clean
            _content_clean=$(grep -v "^[[:space:]]*//" <<< "$_content") || _content_clean="$_content"

            # Check for unconditional polkit.Result.YES (no if/condition before return)
            if grep -qiE "return[[:space:]]+polkit\.Result\.YES" <<< "$_content_clean" 2>/dev/null; then
                # Check if the return is inside a conditional block
                # Check if the YES return is immediately preceded by an if() within 5 lines
                local _yes_has_local_condition
                _yes_has_local_condition=$(grep -B5 -iE "return[[:space:]]+polkit\.Result\.YES" \
                    <<< "$_content_clean" 2>/dev/null | grep -ciE "if[[:space:]]*\(") || true
                if [[ "${_yes_has_local_condition:-0}" -gt 0 ]]; then
                    [[ "$_confidence" == "LOW" ]] && _confidence="MEDIUM"
                    _matched_pattern="polkit_rules_conditioned_yes"
                    _matched_string=$(grep -iE "return[[:space:]]+polkit\.Result\.YES" <<< "$_content_clean" | head -1) || true
                    log_finding "Polkit rules: conditioned polkit.Result.YES: $_rules"
                else
                    # Unconditional — CRITICAL
                    _confidence="CRITICAL"
                    _matched_pattern="polkit_rules_unconditional_yes"
                    _matched_string=$(grep -iE "return[[:space:]]+polkit\.Result\.YES" <<< "$_content_clean" | head -1) || true
                    log_finding "Polkit rules: unconditional polkit.Result.YES: $_rules"
                fi
            fi

            # Secondary: run analyze_script_content for NEVER_WHITELIST hits in rules
            if analyze_content_string "$_content" "$_rules"; then
                _confidence="CRITICAL"
                _matched_pattern="${_matched_pattern:+${_matched_pattern}+}polkit_rules_malicious_content"
                _matched_string="$MATCHED_STRING"
            fi

            add_finding "Privilege" "Polkit" "polkit_rules" "$_rules" "Polkit rules: $(basename "$_rules")" "$_confidence" "$_hash" "$_meta" "package=$_pkg" "$_matched_pattern" "$_matched_string"
        done < <(find "$_rules_dir" -maxdepth 1 -name "*.rules" -type f -print0 2>/dev/null)
    fi
}

check_dbus_persistence() {
    log_info "[NEW] Checking D-Bus and NetworkManager dispatcher persistence..."

    # ─── D-Bus system service activation files ───────────────────────────────
    log_check "D-Bus system service files (/usr/share/dbus-1/system-services/)"

    local _dbus_svc_dir="/usr/share/dbus-1/system-services"
    if [[ -d "$_dbus_svc_dir" ]]; then
        while IFS= read -r -d '' _dsvc; do
            local _hash; _hash=$(get_file_hash "$_dsvc")
            local _meta; _meta=$(get_file_metadata "$_dsvc")
            check_file_package "$_dsvc"
            local _pkg="$PKG_STATUS"

            local _confidence="LOW"
            local _matched_pattern=""
            local _matched_string=""

            [[ "$_pkg" == "unmanaged" ]] && _confidence="HIGH"

            # Extract Exec= line
            local _exec_line
            _exec_line=$(grep -E "^Exec=" "$_dsvc" 2>/dev/null | head -1 | cut -d'=' -f2-) || true

            if [[ -n "$_exec_line" ]]; then
                # Extract the executable path (first word)
                local _exec_target
                read -r _exec_target _ <<< "$_exec_line"

                if [[ ! -f "$_exec_target" ]] && [[ -n "$_exec_target" ]]; then
                    # Dangling Exec= — file not found
                    _confidence="HIGH"
                    _matched_pattern="dbus_dangling_exec"
                    _matched_string="Exec=$_exec_line (target not found)"
                    log_finding "D-Bus service has dangling Exec= target: $_dsvc ($_exec_target)"
                elif [[ -f "$_exec_target" ]]; then
                    check_file_package "$_exec_target"
                    local _exec_pkg="$PKG_STATUS"

                    if [[ "$_exec_pkg" == "unmanaged" ]]; then
                        _confidence="HIGH"
                        _matched_pattern="dbus_unmanaged_exec_target"
                        _matched_string="Exec=$_exec_target"
                        log_finding "D-Bus service Exec= target is unmanaged: $_exec_target"
                    fi

                    # Analyze target content
                    local _exec_content
                    _exec_content=$(head -n 300 "$_exec_target" 2>/dev/null | tr -d '\0') || true
                    if [[ -n "$_exec_content" ]] && analyze_content_string "$_exec_content" "$_exec_target"; then
                        _confidence="CRITICAL"
                        _matched_pattern="dbus_malicious_exec_content"
                        _matched_string="$MATCHED_STRING"
                        log_finding "D-Bus service Exec= target has malicious content: $_exec_target"
                    fi

                    # Flag execution from suspicious locations
                    if [[ "$_exec_target" =~ ^(/tmp|/dev/shm|/var/tmp)/ ]]; then
                        _confidence="CRITICAL"
                        _matched_pattern="dbus_exec_suspicious_location"
                        _matched_string="Exec=$_exec_target"
                        log_finding "D-Bus service Exec= from suspicious location: $_exec_target"
                    fi
                fi
            fi

            # Check for SystemdService= field (DBus activation of a systemd unit)
            local _svc_unit
            _svc_unit=$(grep -E "^SystemdService=" "$_dsvc" 2>/dev/null | cut -d'=' -f2- | head -1) || true
            if [[ -n "$_svc_unit" ]]; then
                # Verify the referenced systemd unit is a known/enabled unit
                if ! systemctl is-enabled "$_svc_unit" &>/dev/null 2>&1; then
                    [[ "$_confidence" == "LOW" ]] && _confidence="MEDIUM"
                    _matched_pattern="${_matched_pattern:-dbus_systemd_service}"
                    _matched_string="SystemdService=$_svc_unit"
                    log_finding "D-Bus service references SystemdService= unit: $_svc_unit ($_dsvc)"
                fi
            fi

            add_finding "EventTriggered" "DBus" "dbus_service" "$_dsvc" "D-Bus service: $(basename "$_dsvc")" "$_confidence" "$_hash" "$_meta" "package=$_pkg|exec=$_exec_line" "$_matched_pattern" "$_matched_string"
        done < <(find "$_dbus_svc_dir" -maxdepth 1 -name "*.service" -type f -print0 2>/dev/null)
    fi

    # D-Bus policy files — wildcard allow directives
    log_check "D-Bus policy files (/etc/dbus-1/system.d/)"
    local _dbus_conf_dir="/etc/dbus-1/system.d"
    if [[ -d "$_dbus_conf_dir" ]]; then
        while IFS= read -r -d '' _dconf; do
            local _hash; _hash=$(get_file_hash "$_dconf")
            local _meta; _meta=$(get_file_metadata "$_dconf")
            check_file_package "$_dconf"
            local _pkg="$PKG_STATUS"

            local _confidence="LOW"
            local _matched_pattern=""
            local _matched_string=""
            [[ "$_pkg" == "unmanaged" ]] && _confidence="MEDIUM"

            local _content
            _content=$(cat "$_dconf" 2>/dev/null | tr -d '\0') || true

            # Flag wildcard allow policies
            local _wildcard_hit
            _wildcard_hit=$(grep -iE '<allow (own|send_destination)="(\*|[^"]*\.\*)"' <<< "$_content" | head -1) || true
            if [[ -n "$_wildcard_hit" ]]; then
                _confidence="HIGH"
                _matched_pattern="dbus_wildcard_policy"
                _matched_string="${_wildcard_hit:0:200}"
                log_finding "D-Bus policy has wildcard allow directive: $_dconf"
            fi

            add_finding "EventTriggered" "DBus" "dbus_policy" "$_dconf" "D-Bus policy: $(basename "$_dconf")" "$_confidence" "$_hash" "$_meta" "package=$_pkg" "$_matched_pattern" "$_matched_string"
        done < <(find "$_dbus_conf_dir" -maxdepth 1 -name "*.conf" -type f -print0 2>/dev/null)
    fi

    # ─── NetworkManager Dispatcher ──────────────────────────────────────────
    log_check "NetworkManager dispatcher scripts (/etc/NetworkManager/dispatcher.d/)"

    local _nm_dir="/etc/NetworkManager/dispatcher.d"
    if [[ -d "$_nm_dir" ]]; then
        while IFS= read -r -d '' _nms; do
            # Skip non-executable files — NM dispatcher only runs executable scripts
            [[ -x "$_nms" ]] || continue

            local _hash; _hash=$(get_file_hash "$_nms")
            local _meta; _meta=$(get_file_metadata "$_nms")
            check_file_package "$_nms"
            local _pkg="$PKG_STATUS"

            local _confidence="LOW"
            local _matched_pattern=""
            local _matched_string=""

            [[ "$_pkg" == "unmanaged" ]] && _confidence="HIGH"

            local _content
            _content=$(head -n 300 "$_nms" 2>/dev/null | tr -d '\0') || true
            if [[ -n "$_content" ]] && analyze_content_string "$_content" "$_nms"; then
                _confidence="CRITICAL"
                _matched_pattern="$MATCHED_PATTERN"
                _matched_string="$MATCHED_STRING"
                log_finding "Suspicious NM dispatcher script: $_nms"
            fi

            add_finding "EventTriggered" "NMDispatcher" "nm_dispatcher_script" "$_nms" "NM dispatcher: $(basename "$_nms")" "$_confidence" "$_hash" "$_meta" "package=$_pkg" "$_matched_pattern" "$_matched_string"
        done < <(find "$_nm_dir" -maxdepth 2 -type f -print0 2>/dev/null)
    fi
}

check_udev_persistence() {
    log_info "[NEW] Checking udev rules persistence..."

    log_check "Udev rules (RUN+= persistence)"

    local _udev_dirs=(
        "/etc/udev/rules.d"
        "/lib/udev/rules.d"
        "/run/udev/rules.d"
    )

    for _udev_dir in "${_udev_dirs[@]}"; do
        [[ -d "$_udev_dir" ]] || continue
        local _is_run_dir=false
        [[ "$_udev_dir" == "/run/udev/rules.d" ]] && _is_run_dir=true

        while IFS= read -r -d '' _rule; do
            local _hash; _hash=$(get_file_hash "$_rule")
            local _meta; _meta=$(get_file_metadata "$_rule")
            check_file_package "$_rule"
            local _pkg="$PKG_STATUS"

            local _confidence="LOW"
            local _matched_pattern=""
            local _matched_string=""

            # /run/udev/rules.d files are always suspicious — runtime injection
            if [[ "$_is_run_dir" == "true" ]]; then
                _confidence="HIGH"
                _matched_pattern="udev_runtime_rule"
                _matched_string="$(basename "$_rule") in /run/udev/rules.d"
                log_finding "Runtime udev rule in /run/udev/rules.d: $_rule"
            elif [[ "$_pkg" == "unmanaged" ]]; then
                _confidence="MEDIUM"
            fi

            local _content
            _content=$(cat "$_rule" 2>/dev/null | tr -d '\0') || true

            # Extract all RUN+= values
            local _run_val
            while IFS= read -r _run_line; do
                _run_val=""
                # Try double-quoted
                _run_val=$(grep -oiE 'RUN\+?=[[:space:]]*"[^"]+"' <<< "$_run_line" | grep -oE '"[^"]+"' | tr -d '"' | head -1) || true
                # Try single-quoted
                if [[ -z "$_run_val" ]]; then
                    _run_val=$(grep -oiE "RUN\+?=[[:space:]]*'[^']+'" <<< "$_run_line" | grep -oE "'[^']+'" | tr -d "'" | head -1) || true
                fi
                # Try unquoted (value ends at whitespace or end of line)
                if [[ -z "$_run_val" ]]; then
                    _run_val=$(grep -oiE 'RUN\+?=[[:space:]]*[^"'"'"'[:space:]]+' <<< "$_run_line" | sed 's/RUN+\?=[[:space:]]*//' | head -1) || true
                fi
                [[ -z "$_run_val" ]] && continue

                # Analyze the RUN+= command string
                if analyze_content_string "$_run_val" "$_rule"; then
                    _confidence="CRITICAL"
                    _matched_pattern="udev_run_malicious_command"
                    _matched_string="${_run_val:0:200}"
                    log_finding "Udev rule RUN+= has malicious command: $_rule"
                    break
                fi

                # Flag at/cron delegation (common udev foreground bypass)
                if [[ "$_run_val" =~ "at now" ]] || [[ "$_run_val" =~ "at +" ]] || [[ "$_run_val" =~ "crontab" ]]; then
                    [[ "$_confidence" != "CRITICAL" ]] && _confidence="HIGH"
                    _matched_pattern="udev_run_at_delegation"
                    _matched_string="${_run_val:0:200}"
                    log_finding "Udev rule RUN+= delegates to at/cron: $_rule"
                fi

                # Flag execution from suspicious locations
                if [[ "$_run_val" =~ ^(/tmp|/dev/shm|/var/tmp)/ ]]; then
                    _confidence="CRITICAL"
                    _matched_pattern="udev_run_suspicious_location"
                    _matched_string="${_run_val:0:200}"
                    log_finding "Udev rule RUN+= executes from suspicious location: $_run_val"
                fi

                # If RUN+= points to a script, analyze its content
                local _run_bin
                read -r _run_bin _ <<< "$_run_val"
                if [[ -f "$_run_bin" ]]; then
                    local _run_content
                    _run_content=$(head -n 200 "$_run_bin" 2>/dev/null | tr -d '\0') || true
                    if [[ -n "$_run_content" ]] && analyze_content_string "$_run_content" "$_run_bin"; then
                        _confidence="CRITICAL"
                        _matched_pattern="udev_run_target_malicious"
                        _matched_string="$MATCHED_STRING"
                        log_finding "Udev rule RUN+= target has malicious content: $_run_bin"
                    fi
                fi

                [[ -z "$_matched_string" ]] && _matched_string="${_run_val:0:200}"
            done < <(grep -iE "RUN\+?=" "$_rule" 2>/dev/null || true)

            add_finding "EventTriggered" "Udev" "udev_rule" "$_rule" "Udev rule: $(basename "$_rule")" "$_confidence" "$_hash" "$_meta" "package=$_pkg|dir=$(basename "$_udev_dir")" "$_matched_pattern" "$_matched_string"
        done < <(find "$_udev_dir" -maxdepth 1 -name "*.rules" -type f -print0 2>/dev/null)
    done
}

check_container_persistence() {
    log_info "[NEW] Checking container/Docker escape persistence..."

    # Check for Dockerfiles in suspicious locations
    log_check "Dockerfiles in user-writable locations"
    while IFS= read -r -d '' _df; do
        local _hash; _hash=$(get_file_hash "$_df")
        local _meta; _meta=$(get_file_metadata "$_df")
        local _confidence="HIGH"
        local _matched_pattern="dockerfile_suspicious_location"
        local _matched_string="$(dirname "$_df")"
        local _content
        _content=$(cat "$_df" 2>/dev/null | tr -d '\0') || true

        if grep -qiE "(nsenter|socat exec:|--privileged)" <<< "$_content" 2>/dev/null; then
            _confidence="CRITICAL"
            local _hit
            _hit=$(grep -iE "(nsenter|socat exec:|--privileged)" <<< "$_content" | head -1) || true
            _matched_pattern="dockerfile_escape_technique"
            _matched_string="${_hit:0:200}"
            log_finding "Dockerfile contains container escape technique: $_df"
        else
            log_finding "Dockerfile in suspicious location: $_df"
        fi

        add_finding "Container" "Docker" "dockerfile_suspicious" "$_df" "Dockerfile: $(dirname "$_df")" "$_confidence" "$_hash" "$_meta" "" "$_matched_pattern" "$_matched_string"
    done < <(find /tmp /root /home /var/tmp -maxdepth 3 -name "Dockerfile" -type f -print0 2>/dev/null)

    # Docker daemon config
    log_check "Docker daemon configuration"
    if [[ -f /etc/docker/daemon.json ]]; then
        local _hash; _hash=$(get_file_hash /etc/docker/daemon.json)
        local _meta; _meta=$(get_file_metadata /etc/docker/daemon.json)
        local _content
        _content=$(cat /etc/docker/daemon.json 2>/dev/null | tr -d '\0') || true
        local _confidence="LOW"
        local _matched_pattern=""
        local _matched_string=""

        if grep -qiE '"userns-remap"[[:space:]]*:[[:space:]]*"(|none)"' <<< "$_content" 2>/dev/null || \
           grep -qiE '"no-new-privileges"[[:space:]]*:[[:space:]]*false' <<< "$_content" 2>/dev/null; then
            _confidence="MEDIUM"
            _matched_pattern="docker_daemon_weakened_security"
            _matched_string=$(grep -iE '"(userns-remap|no-new-privileges)"' <<< "$_content" | head -1) || true
        fi

        add_finding "Container" "Docker" "docker_daemon_config" "/etc/docker/daemon.json" "Docker daemon config" "$_confidence" "$_hash" "$_meta" "" "$_matched_pattern" "$_matched_string"
    fi

    # Running/stopped containers
    if ! command -v docker &>/dev/null; then
        log_info "Docker not found — skipping container inspection"
        return
    fi

    log_check "Docker container security posture"

    local _all_container_ids
    _all_container_ids=$(timeout 10 docker ps -aq 2>/dev/null) || true
    local _total_containers
    _total_containers=$(echo "$_all_container_ids" | grep -c . 2>/dev/null || echo 0)
    local _container_ids
    _container_ids=$(echo "$_all_container_ids" | head -20)
    if [[ "$_total_containers" -gt 20 ]]; then
        log_warn "Container scan: $(( _total_containers - 20 )) containers beyond the 20-container limit were not inspected"
    fi

    [[ -z "$_container_ids" ]] && { log_info "No Docker containers found"; return; }

    while IFS= read -r _cid; do
        [[ -z "$_cid" ]] && continue

        local _inspect
        _inspect=$(timeout 10 docker inspect "$_cid" 2>/dev/null) || continue

        local _name
        _name=$(grep -oiE '"Name"[[:space:]]*:[[:space:]]*"[^"]+"' <<< "$_inspect" | head -1 | grep -oiE '"[^"]+"$' | tr -d '"') || _name="$_cid"

        local _privileged
        _privileged=$(grep -oiE '"Privileged"[[:space:]]*:[[:space:]]*[a-z]+' <<< "$_inspect" | grep -oiE '[a-z]+$') || _privileged="false"

        local _pid_mode
        _pid_mode=$(grep -oiE '"PidMode"[[:space:]]*:[[:space:]]*"[^"]+"' <<< "$_inspect" | head -1 | grep -oiE '"[^"]+"$' | tr -d '"') || _pid_mode=""

        local _confidence="LOW"
        local _matched_pattern=""
        local _matched_string=""

        if [[ "$_privileged" == "true" ]]; then
            _confidence="HIGH"
            _matched_pattern="container_privileged"
            _matched_string="Privileged=true"
            log_finding "Privileged Docker container: $_name ($_cid)"

            if [[ "$_pid_mode" == "host" ]]; then
                _confidence="CRITICAL"
                _matched_pattern="container_privileged_pid_host"
                _matched_string="Privileged=true;PidMode=host"
                log_finding "Privileged + host PID namespace container: $_name ($_cid)"
            fi
        fi

        # Docker socket bind-mount check
        if grep -qiE '"/var/run/docker\.sock"' <<< "$_inspect" 2>/dev/null; then
            _confidence="CRITICAL"
            _matched_pattern="container_docker_sock_mount"
            _matched_string="$_matched_string;docker.sock bind-mounted"
            log_finding "Docker socket bind-mounted into container: $_name ($_cid)"
        fi

        # Check entrypoint/cmd for nsenter
        local _entrypoint
        _entrypoint=$(grep -oiE '"Entrypoint"[[:space:]]*:[[:space:]]*\[[^\]]+\]' <<< "$_inspect" | head -1) || true
        if [[ -n "$_entrypoint" ]] && grep -qiE "nsenter" <<< "$_entrypoint" 2>/dev/null; then
            _confidence="CRITICAL"
            _matched_pattern="container_nsenter_entrypoint"
            _matched_string="nsenter in entrypoint"
            log_finding "Container entrypoint contains nsenter: $_name ($_cid)"
        fi

        local _meta; _meta=$(get_file_metadata "/dev/null") || _meta=""  # placeholder metadata
        add_finding "Container" "Docker" "docker_container" "/var/run/docker.sock" "Container: $_name ($_cid)" "$_confidence" "N/A" "$_meta" "privileged=$_privileged|pid_mode=$_pid_mode" "$_matched_pattern" "$_matched_string"
    done <<< "$_container_ids"
}

################################################################################
# Binary Integrity Check
################################################################################

check_binary_integrity() {
    log_info "[9/9] Checking system binary integrity..."
    log_check "System binary integrity (dpkg -V / rpm -Va)"

    local _bin_dirs=("/usr/bin" "/usr/sbin" "/bin" "/sbin")

    _report_modified_binary() {
        local _file="$1"
        local _hash _meta _days=0
        _hash=$(get_file_hash "$_file") || _hash="N/A"
        _meta=$(get_file_metadata "$_file") || _meta="N/A"
        [[ "$_meta" =~ modified:([0-9]+) ]] && _days=$(( (SCAN_EPOCH - ${BASH_REMATCH[1]}) / 86400 ))
        log_finding "Modified system binary detected: $_file"
        add_finding_new "BinaryIntegrity" "CRITICAL" "$_file" "$_hash" \
            "$(get_owner_from_metadata "$_meta")" "$(get_permissions_from_metadata "$_meta")" \
            "$_days" "modified" "" "" "" "modified_system_binary" "$_file"
    }

    _is_critical_path() {
        local _f="$1"
        for _bd in "${_bin_dirs[@]}"; do
            [[ "$_f" == "$_bd/"* ]] && return 0
        done
        [[ "$_f" == */lib/security/* || "$_f" == */lib*/security/* ]] && return 0
        return 1
    }

    if command -v dpkg &>/dev/null; then
        # Scope-first: identify only packages that own files in critical directories.
        # dpkg -S is a fast DB lookup (~ms per file), far cheaper than dpkg -V on all pkgs.
        local _dv_pkgs
        _dv_pkgs=$(
            find /usr/bin /usr/sbin /bin /sbin -maxdepth 1 -type f -print0 2>/dev/null \
            | xargs -0 -n 200 dpkg -S 2>/dev/null \
            | awk -F: '{print $1}'
            # Also include packages owning PAM security modules
            find /lib/security /lib/x86_64-linux-gnu/security \
                 /lib/aarch64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security \
                 /usr/lib/aarch64-linux-gnu/security \
                 -maxdepth 1 -name "*.so" -print0 2>/dev/null \
            | xargs -0 -n 200 dpkg -S 2>/dev/null \
            | awk -F: '{print $1}'
        )
        _dv_pkgs=$(echo "$_dv_pkgs" | sort -u)

        if [[ -z "$_dv_pkgs" ]]; then
            log_warn "Binary integrity: no packages found owning critical binaries — skipping"
            unset -f _report_modified_binary _is_critical_path
            return
        fi

        # Verify only the scoped package set, in parallel (4 workers)
        local _dv_output
        _dv_output=$(echo "$_dv_pkgs" | xargs -P4 -I{} dpkg --verify {} 2>/dev/null || true)

        while IFS= read -r _dv_line; do
            [[ -z "$_dv_line" ]] && continue
            # Skip conffiles (dpkg marks them with " c " as second field)
            [[ "$_dv_line" =~ ^[^[:space:]]+[[:space:]]+c[[:space:]] ]] && continue
            local _dv_file
            _dv_file=$(echo "$_dv_line" | awk '{print $NF}')
            [[ -z "$_dv_file" ]] && continue
            _is_critical_path "$_dv_file" || continue
            _report_modified_binary "$_dv_file"
        done <<< "$_dv_output"

    elif command -v rpm &>/dev/null; then
        # Scope-first: identify packages owning files in critical directories via rpm -qf
        local _rv_pkgs
        _rv_pkgs=$(
            find /usr/bin /usr/sbin /bin /sbin -maxdepth 1 -type f -print0 2>/dev/null \
            | xargs -0 -n 200 rpm -qf 2>/dev/null \
            | grep -v "not owned"
            find /lib/security /usr/lib/security /lib64/security /usr/lib64/security \
                 -maxdepth 1 -name "*.so" -print0 2>/dev/null \
            | xargs -0 -n 200 rpm -qf 2>/dev/null \
            | grep -v "not owned"
        )
        _rv_pkgs=$(echo "$_rv_pkgs" | sort -u)

        if [[ -z "$_rv_pkgs" ]]; then
            log_warn "Binary integrity: no packages found owning critical binaries — skipping"
            unset -f _report_modified_binary _is_critical_path
            return
        fi

        # Verify only the scoped package set, in parallel (4 workers)
        local _rv_output
        _rv_output=$(echo "$_rv_pkgs" | xargs -P4 -I{} rpm -V {} 2>/dev/null || true)

        while IFS= read -r _rv_line; do
            [[ -z "$_rv_line" ]] && continue
            local _rv_file
            _rv_file=$(echo "$_rv_line" | awk '{print $NF}')
            [[ -z "$_rv_file" ]] && continue
            _is_critical_path "$_rv_file" || continue
            _report_modified_binary "$_rv_file"
        done <<< "$_rv_output"

    else
        log_warn "No package manager (dpkg/rpm) found — binary integrity check skipped"
        return
    fi

    unset -f _report_modified_binary _is_critical_path

    # ─── SUID/SGID active filesystem scan ────────────────────────────────────
    log_check "SUID/SGID files (active filesystem scan)"

    local _suid_paths=(
        "/usr/bin" "/usr/sbin" "/bin" "/sbin"
        "/usr/local/bin" "/usr/local/sbin"
        "/opt" "/tmp" "/dev/shm" "/var/tmp"
    )

    local _suid_count=0
    for _sp in "${_suid_paths[@]}"; do
        [[ -d "$_sp" ]] || continue
        while IFS= read -r -d '' _suid_file; do
            _suid_count=$(( _suid_count + 1 ))
            [[ $_suid_count -gt 200 ]] && { log_info "SUID scan: result limit reached (200), truncating"; break 2; }

            local _hash; _hash=$(get_file_hash "$_suid_file")
            local _meta; _meta=$(get_file_metadata "$_suid_file")
            check_file_package "$_suid_file"
            local _pkg="$PKG_STATUS"

            local _confidence="LOW"
            local _matched_pattern="suid_binary"
            local _matched_string="$(basename "$_suid_file")"

            # Suspicious location — always CRITICAL
            if [[ "$_suid_file" =~ ^(/tmp|/dev/shm|/var/tmp)/ ]]; then
                _confidence="CRITICAL"
                _matched_pattern="suid_suspicious_location"
                _matched_string="SUID in $(dirname "$_suid_file")"
                log_finding "SUID binary in suspicious location: $_suid_file"
            elif [[ "$_pkg" == "unmanaged" ]]; then
                _confidence="CRITICAL"
                _matched_pattern="suid_unmanaged_binary"
                _matched_string="unmanaged SUID: $(basename "$_suid_file")"
                log_finding "Unmanaged SUID binary: $_suid_file"
            fi

            # If SUID file is a shell script, analyze content
            local _ftype
            _ftype=$(file "$_suid_file" 2>/dev/null || echo "")
            if [[ "$_ftype" =~ (script|text|ASCII) ]]; then
                local _content
                _content=$(head -n 200 "$_suid_file" 2>/dev/null | tr -d '\0') || true
                if [[ -n "$_content" ]] && analyze_content_string "$_content" "$_suid_file"; then
                    _confidence="CRITICAL"
                    _matched_pattern="suid_script_malicious_content"
                    _matched_string="$MATCHED_STRING"
                    log_finding "SUID shell script with malicious content: $_suid_file"
                fi
            fi

            add_finding "Privilege" "SUID" "suid_binary" "$_suid_file" "SUID binary: $(basename "$_suid_file")" "$_confidence" "$_hash" "$_meta" "package=$_pkg" "$_matched_pattern" "$_matched_string"
        done < <(find "$_sp" -xdev -maxdepth 3 -perm -4000 -type f -print0 2>/dev/null)
    done
    if [[ $_suid_count -gt 200 ]]; then
        log_warn "SUID scan: $_suid_count SUID files found -- only first 200 inspected"
    fi

    log_check "SGID files (active filesystem scan)"
    local _sgid_count=0
    for _sp in "${_suid_paths[@]}"; do
        [[ -d "$_sp" ]] || continue
        while IFS= read -r -d '' _sgid_file; do
            _sgid_count=$(( _sgid_count + 1 ))
            [[ $_sgid_count -gt 100 ]] && break 2

            local _hash; _hash=$(get_file_hash "$_sgid_file")
            local _meta; _meta=$(get_file_metadata "$_sgid_file")
            check_file_package "$_sgid_file"
            local _pkg="$PKG_STATUS"

            local _confidence="LOW"
            local _matched_pattern="sgid_binary"
            [[ "$_pkg" == "unmanaged" ]] && { _confidence="HIGH"; _matched_pattern="sgid_unmanaged_binary"; log_finding "Unmanaged SGID binary: $_sgid_file"; }
            [[ "$_sgid_file" =~ ^(/tmp|/dev/shm|/var/tmp)/ ]] && { _confidence="CRITICAL"; _matched_pattern="sgid_suspicious_location"; log_finding "SGID binary in suspicious location: $_sgid_file"; }

            add_finding "Privilege" "SGID" "sgid_binary" "$_sgid_file" "SGID binary: $(basename "$_sgid_file")" "$_confidence" "$_hash" "$_meta" "package=$_pkg" "$_matched_pattern" "$(basename "$_sgid_file")"
        done < <(find "$_sp" -xdev -maxdepth 3 -perm -2000 -type f -print0 2>/dev/null)
    done
    if [[ $_sgid_count -gt 100 ]]; then
        log_warn "SGID scan: $_sgid_count SGID files found -- only first 100 inspected"
    fi

    # ─── File Capabilities (getcap) ───────────────────────────────────────────
    log_check "File capabilities (getcap)"

    if command -v getcap &>/dev/null; then
        # GTFOBins that are dangerous with cap_setuid
        local _gtfobins=("bash" "sh" "python" "python2" "python3" "perl" "ruby" "find" "vim" "vi" "nmap" "awk" "gawk" "mawk" "less" "more" "tee" "cp" "rsync" "tar")

        local _cap_paths=("/usr/bin" "/usr/sbin" "/bin" "/sbin" "/usr/local/bin" "/usr/local/sbin" "/opt" "/srv" "/home")
        local _cap_output=""
        for _cap_path in "${_cap_paths[@]}"; do
            [[ -d "$_cap_path" ]] || continue
            _cap_output+=$(timeout 30 getcap -r "$_cap_path" 2>/dev/null || true)
            _cap_output+=$'\n'
        done

        while IFS= read -r _cap_line; do
            [[ -z "$_cap_line" ]] && continue
            # Format: /path/to/binary = cap_net_raw+ep
            local _cap_file _cap_caps
            read -r _cap_file _ _cap_caps <<< "$_cap_line"
            [[ -z "$_cap_file" ]] && continue

            local _hash; _hash=$(get_file_hash "$_cap_file")
            local _meta; _meta=$(get_file_metadata "$_cap_file")
            check_file_package "$_cap_file"
            local _pkg="$PKG_STATUS"

            local _confidence="LOW"
            local _matched_pattern="file_capability"
            local _matched_string="$_cap_caps"

            # cap_sys_admin on anything → CRITICAL
            if [[ "$_cap_caps" =~ "cap_sys_admin" ]]; then
                _confidence="CRITICAL"
                _matched_pattern="cap_sys_admin"
                log_finding "cap_sys_admin capability: $_cap_file ($_cap_caps)"
            # cap_setuid on GTFOBin → CRITICAL
            elif [[ "$_cap_caps" =~ "cap_setuid" ]]; then
                local _basename
                _basename=$(basename "$_cap_file")
                local _is_gtfobin=false
                for _gtf in "${_gtfobins[@]}"; do
                    if [[ "$_basename" == "$_gtf" ]] || [[ "$_basename" =~ ^${_gtf}[0-9.]+$ ]]; then
                        _is_gtfobin=true
                        break
                    fi
                done
                if [[ "$_is_gtfobin" == "true" ]]; then
                    _confidence="CRITICAL"
                    _matched_pattern="cap_setuid_gtfobin"
                    log_finding "cap_setuid on GTFOBin: $_cap_file ($_cap_caps)"
                elif [[ "$_pkg" == "unmanaged" ]]; then
                    _confidence="HIGH"
                    _matched_pattern="cap_setuid_unmanaged"
                    log_finding "cap_setuid on unmanaged binary: $_cap_file"
                fi
            # cap_net_raw on pkg-owned utility → LOW (expected for ping, tcpdump)
            elif [[ "$_cap_caps" =~ "cap_net_raw" ]] && [[ "$_pkg" == "managed" ]]; then
                _confidence="LOW"
            elif [[ "$_pkg" == "unmanaged" ]]; then
                _confidence="MEDIUM"
            fi

            add_finding "Privilege" "Capability" "file_capability" "$_cap_file" "File capability: $(basename "$_cap_file") ($_cap_caps)" "$_confidence" "$_hash" "$_meta" "package=$_pkg|caps=$_cap_caps" "$_matched_pattern" "$_matched_string"
        done <<< "$_cap_output"
    else
        log_info "getcap not available — skipping file capability scan"
    fi

    # ─── Binary Hijacking — Renamed originals (.original/.old/.bak/.real) ───
    log_check "Binary hijacking (renamed originals)"

    local _hijack_dirs=("/bin" "/usr/bin" "/sbin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin")
    for _hd in "${_hijack_dirs[@]}"; do
        [[ -d "$_hd" ]] || continue
        while IFS= read -r -d '' _renamed; do
            local _base_with_suffix; _base_with_suffix=$(basename "$_renamed")
            # Strip suffix to get active name
            local _active_name="${_base_with_suffix%.original}"
            _active_name="${_active_name%.old}"
            _active_name="${_active_name%.bak}"
            _active_name="${_active_name%.real}"
            local _active_path="$_hd/$_active_name"

            local _hash; _hash=$(get_file_hash "$_renamed")
            local _meta; _meta=$(get_file_metadata "$_renamed")

            local _confidence="MEDIUM"
            local _matched_pattern="renamed_binary"
            local _matched_string="$(basename "$_renamed")"

            if [[ -f "$_active_path" ]]; then
                # Active file exists — check if it's a wrapper script
                local _ftype
                _ftype=$(file "$_active_path" 2>/dev/null || echo "")
                if [[ "$_ftype" =~ (script|text|ASCII) ]] || head -c 3 "$_active_path" 2>/dev/null | grep -qE "^#!"; then
                    # Active binary is a shell script — likely a wrapper
                    _confidence="CRITICAL"
                    _matched_pattern="binary_hijack_wrapper"
                    _matched_string="Renamed: $(basename "$_renamed") → Wrapper: $_active_name"
                    log_finding "Binary hijacking detected: $_active_path is wrapper, original at $_renamed"

                    local _wrapper_content
                    _wrapper_content=$(head -n 200 "$_active_path" 2>/dev/null | tr -d '\0') || true
                    if [[ -n "$_wrapper_content" ]] && analyze_content_string "$_wrapper_content" "$_active_path"; then
                        _matched_string="$MATCHED_STRING"
                    fi
                else
                    _confidence="HIGH"
                    _matched_pattern="renamed_binary_active_present"
                    _matched_string="Renamed: $(basename "$_renamed") | Active: $_active_name exists"
                    log_finding "Renamed binary with active counterpart: $_renamed"
                fi
            else
                log_finding "Renamed binary (no active counterpart): $_renamed"
            fi

            add_finding "Privilege" "BinaryHijack" "renamed_binary" "$_renamed" "Renamed binary: $(basename "$_renamed")" "$_confidence" "$_hash" "$_meta" "active=$_active_path" "$_matched_pattern" "$_matched_string"
        done < <(find "$_hd" -maxdepth 1 -type f \( -name "*.original" -o -name "*.old" -o -name "*.bak" -o -name "*.real" \) -print0 2>/dev/null)
    done
}

################################################################################
# Main Execution
################################################################################

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_usage
                exit 0
                ;;
            -a|--all)
                FILTER_MODE="all"
                shift
                ;;
            -m|--min-confidence)
                if [[ -n "${2:-}" ]]; then
                    MIN_CONFIDENCE="$2"
                    shift 2
                else
                    echo "Error: --min-confidence requires a value (LOW|MEDIUM|HIGH|CRITICAL)"
                    exit 1
                fi
                ;;
            *)
                echo "Error: Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Validate MIN_CONFIDENCE if set
    if [[ -n "$MIN_CONFIDENCE" ]]; then
        case "$MIN_CONFIDENCE" in
            "LOW"|"MEDIUM"|"HIGH"|"CRITICAL")
                # Valid
                ;;
            *)
                log_warn "Invalid MIN_CONFIDENCE value: '$MIN_CONFIDENCE'"
                log_warn "Valid values are: LOW, MEDIUM, HIGH, CRITICAL"
                log_warn "Using default: MEDIUM"
                MIN_CONFIDENCE="MEDIUM"
                ;;
        esac
    fi

    print_banner

    # Show filter mode
    if [[ "$FILTER_MODE" == "suspicious_only" ]]; then
        log_info "Filter Mode: Suspicious only (MEDIUM/HIGH/CRITICAL)"
    else
        log_info "Filter Mode: All findings"
    fi
    if [[ -n "$MIN_CONFIDENCE" ]]; then
        log_info "Minimum Confidence: $MIN_CONFIDENCE"
    fi
    echo

    # Check permissions
    if [[ $EUID_CHECK -ne 0 ]]; then
        log_warn "Not running as root. Some checks will be limited."
        log_warn "Run with sudo for complete analysis."
        echo
    fi

    log_info "Starting Linux persistence detection on $(hostname) at $(date)"
    log_info "Running as user: $(whoami) (UID: $EUID_CHECK)"
    echo

    # Initialize output
    init_output

    # Build combined patterns for optimized matching (performance optimization)
    build_combined_patterns

    # Capture scan epoch once — avoids date +%s subprocess calls inside per-file loops
    SCAN_EPOCH=$(date +%s)
    echo

    # Run all detection modules in parallel for speed
    # Each module writes to its own temp CSV/JSONL; logs buffered and printed in order
    log_info "Launching detection modules in parallel..."
    echo

    local _mods=(systemd cron shell_profiles init_scripts kernel_preload additional backdoors ssh binary_integrity bootloader polkit dbus udev container)
    local _mod_fns=(check_systemd check_cron check_shell_profiles check_init_scripts check_kernel_and_preload check_additional_persistence check_common_backdoors check_ssh_persistence check_binary_integrity check_bootloader_persistence check_polkit_persistence check_dbus_persistence check_udev_persistence check_container_persistence)
    local _mod_pids=()

    local _mi=0
    for _mfn in "${_mod_fns[@]}"; do
        local _mname="${_mods[$_mi]}"
        local _mcsv="${TEMP_DATA}/${_mname}.csv"
        local _mjsonl="${TEMP_DATA}/${_mname}.jsonl"
        local _mlog="${TEMP_DATA}/${_mname}.log"
        > "$_mcsv"
        > "$_mjsonl"
        (
            CSV_FILE="$_mcsv"
            JSONL_FILE="$_mjsonl"
            MODULE_NAME="$_mname"
            "$_mfn"
        ) > "$_mlog" 2>&1 &
        _mod_pids+=($!)
        _mi=$(( _mi + 1 ))
    done

    # Wait for each module in display order, print buffered log, merge findings
    _mi=0
    for _mname in "${_mods[@]}"; do
        if ! wait "${_mod_pids[$_mi]}"; then
            echo "[WARN] Module '${_mname}' exited with error — findings may be incomplete" >&2
        fi
        cat "${TEMP_DATA}/${_mname}.log"
        echo
        cat "${TEMP_DATA}/${_mname}.csv"  >> "$CSV_FILE"
        cat "${TEMP_DATA}/${_mname}.jsonl" >> "$JSONL_FILE"
        _mi=$(( _mi + 1 ))
    done

    # Summary
    log_info "=========================================="
    log_info "Detection Complete!"
    log_info "=========================================="
    FINDINGS_COUNT=$(grep -c '^{' "$JSONL_FILE" 2>/dev/null || echo 0)
    log_info "Total findings logged: $FINDINGS_COUNT"
    log_info "Results saved to:"
    log_info "  CSV:   $CSV_FILE"
    log_info "  JSONL: $JSONL_FILE"
    echo

    # ── Human-readable report (.txt) ────────────────────────────────────────
    local REPORT_FILE="${OUTPUT_DIR}/persistnux_${HOSTNAME}_${TIMESTAMP}_report.txt"
    local SCAN_END_EPOCH SCAN_ELAPSED HOST_IP
    SCAN_END_EPOCH=$(date +%s)
    SCAN_ELAPSED=$(( SCAN_END_EPOCH - SCAN_EPOCH ))
    HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}') || HOST_IP="N/A"

    # Count findings by confidence from JSONL (single pass per level)
    local CNT_CRITICAL CNT_HIGH CNT_MEDIUM CNT_LOW
    # Count findings by confidence using JSON field parse (avoids false counts from field content)
    CNT_CRITICAL=$(python3 -c "
import sys, json
count = 0
for line in open('$JSONL_FILE'):
    try:
        if json.loads(line).get('confidence') == 'CRITICAL': count += 1
    except: pass
print(count)
" 2>/dev/null || grep -c '"confidence":"CRITICAL"' "$JSONL_FILE" 2>/dev/null || echo 0)
    CNT_HIGH=$(python3 -c "
import sys, json
count = 0
for line in open('$JSONL_FILE'):
    try:
        if json.loads(line).get('confidence') == 'HIGH': count += 1
    except: pass
print(count)
" 2>/dev/null || grep -c '"confidence":"HIGH"' "$JSONL_FILE" 2>/dev/null || echo 0)
    CNT_MEDIUM=$(python3 -c "
import sys, json
count = 0
for line in open('$JSONL_FILE'):
    try:
        if json.loads(line).get('confidence') == 'MEDIUM': count += 1
    except: pass
print(count)
" 2>/dev/null || grep -c '"confidence":"MEDIUM"' "$JSONL_FILE" 2>/dev/null || echo 0)
    CNT_LOW=$(python3 -c "
import sys, json
count = 0
for line in open('$JSONL_FILE'):
    try:
        if json.loads(line).get('confidence') == 'LOW': count += 1
    except: pass
print(count)
" 2>/dev/null || grep -c '"confidence":"LOW"' "$JSONL_FILE" 2>/dev/null || echo 0)

    cat > "$REPORT_FILE" << REPORT
================================================================================
  Persistnux — Linux Persistence Detection Report
================================================================================
  Version    : 2.4.0
  Date/Time  : $(date '+%Y-%m-%d %H:%M:%S %Z')
  Hostname   : ${HOSTNAME}
  IP Address : ${HOST_IP}
  Run by     : $(whoami) (UID: $(id -u))
  Scan time  : ${SCAN_ELAPSED}s
  Filter mode: ${FILTER_MODE}

--------------------------------------------------------------------------------
  FINDINGS SUMMARY
--------------------------------------------------------------------------------
  CRITICAL : ${CNT_CRITICAL}
  HIGH     : ${CNT_HIGH}
  MEDIUM   : ${CNT_MEDIUM}
  LOW      : ${CNT_LOW}
  ─────────────────
  TOTAL    : ${FINDINGS_COUNT}

--------------------------------------------------------------------------------
  OUTPUT FILES
--------------------------------------------------------------------------------
  Report : ${REPORT_FILE}
  CSV    : ${CSV_FILE}
  JSONL  : ${JSONL_FILE}

--------------------------------------------------------------------------------
  DETECTION MODULES RUN
--------------------------------------------------------------------------------
  [1/14]  Systemd (services, timers, generators, .path units, OnFailure= hooks)
  [2/14]  Cron & scheduled tasks (cron.d, cron.daily/weekly/monthly/hourly, at)
  [3/14]  Shell profiles (system-wide + per-user, all major shells)
  [4/14]  Init scripts (rc.local, init.d, MOTD)
  [5/14]  Kernel & library preloading (ld.so.preload, ld.so.conf, LKMs, modprobe)
  [6/14]  Additional persistence (XDG, environment, sudoers, PAM)
  [7/14]  Common backdoor locations (APT/YUM hooks, DPKG postinst, webshells, git)
  [8/14]  SSH persistence (authorized_keys, ~/.ssh/rc)
  [9/14]  Binary integrity (dpkg -V / rpm -Va — modified system binaries)
  [10/14] Bootloader (GRUB cmdline, initrd dropped scripts, dracut hooks)
  [11/14] Polkit (rules granting unconditional privilege escalation)
  [12/14] D-Bus (service activation files, wildcard policies)
  [13/14] Udev (RUN+= commands in udev rules)
  [14/14] Container (Docker security posture — privileged, host mounts, backdoors)

--------------------------------------------------------------------------------
  NOTES
--------------------------------------------------------------------------------
  - Confidence levels: CRITICAL > HIGH > MEDIUM > LOW
  - All findings include file hash, owner, permissions, and package status
  - Package integrity verified via dpkg --verify / rpm -V where applicable
  - Review JSONL output for machine-readable data: jq . ${JSONL_FILE}
  - Exit code 1 is returned when CRITICAL findings exist (for CI/CD integration)
================================================================================
REPORT

    log_info "  Report: $REPORT_FILE"
    echo

    # Cleanup
    rm -rf "$TEMP_DATA" 2>/dev/null

    log_info "Analysis completed at $(date)"

    # Exit non-zero if CRITICAL findings exist — enables CI/CD integration
    # and automated alerting pipelines that check exit code.
    if [[ ${CNT_CRITICAL:-0} -gt 0 ]]; then
        exit 1
    fi
}

# Run main function
main "$@"
