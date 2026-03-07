#!/bin/bash
################################################################################
# Persistnux - Linux Persistence Detection Tool
# A comprehensive DFIR tool to detect known Linux persistence mechanisms
# Author: DFIR Community Project
# License: MIT
# Version: 1.9.0
################################################################################

set -eo pipefail

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

# Filter mode: "suspicious_only" (default) or "all"
FILTER_MODE="${FILTER_MODE:-suspicious_only}"
MIN_CONFIDENCE="${MIN_CONFIDENCE:-}"

# Check if running as root
EUID_CHECK=$(id -u)

# Performance: Package manager cache to avoid repeated lookups
# Format: PKG_CACHE["/path/to/file"]="status:package_name" or "unmanaged"
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
    "sh -i >\$ /dev/tcp/"
    "sh -i >\$ /dev/udp/"
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
    "/\.[a-z]"                    # Hidden file/directory (starts with dot)
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
    "socat.*TCP:"                # Socat TCP connection (potentially malicious)
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
    "LD_PRELOAD=.*/(tmp|dev/shm|var/tmp)/"     # LD_PRELOAD pointing to staging dirs
    "LD_LIBRARY_PATH=.*/(tmp|dev/shm|var/tmp)/" # LD_LIBRARY_PATH pointing to staging dirs
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

    # ISC-C1 FIX: Auto-derive UNIFIED_SUSPICIOUS_PATTERN from the authoritative arrays.
    # Previously this was a manually maintained string that diverged silently whenever
    # new patterns were added to SUSPICIOUS_COMMANDS or NEVER_WHITELIST_PATTERNS.
    # Now it is built from those combined patterns — zero drift guaranteed.
    UNIFIED_SUSPICIOUS_PATTERN="${COMBINED_NEVER_WHITELIST_PATTERN}|${COMBINED_COMMAND_PATTERN}|${COMBINED_NETWORK_PATTERN}"
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

Persistnux - Linux Persistence Detection Tool v1.9.0
Comprehensive DFIR tool to detect Linux persistence mechanisms

OPTIONS:
  -h, --help              Show this help message
  -a, --all               Show all findings (default: suspicious only)
  -m, --min-confidence    Minimum confidence level (LOW|MEDIUM|HIGH)

ENVIRONMENT VARIABLES:
  OUTPUT_DIR              Custom output directory (default: ./persistnux_output)
  FILTER_MODE             Filter mode: "suspicious_only" or "all" (default: suspicious_only)
  MIN_CONFIDENCE          Minimum confidence filter (LOW|MEDIUM|HIGH)

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

    Linux Persistence Detection Tool v1.9.0
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
       [[ "$file" =~ /gems/gems/ ]]; then
        result="runtime-managed"
        PKG_CACHE["$file"]="$result"
        echo "$result"
        return 0
    fi

    # Check dpkg (Debian/Ubuntu) - single call to avoid duplicate lookups
    if command -v dpkg &> /dev/null; then
        local dpkg_output
        dpkg_output=$(dpkg -S "$file" 2>/dev/null) || true

        # If canonical path lookup fails, try original path (kernel modules use /lib/modules not /usr/lib/modules)
        if [[ -z "$dpkg_output" ]] && [[ "$file" != "$original_file" ]]; then
            dpkg_output=$(dpkg -S "$original_file" 2>/dev/null) || true
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
                dpkg_output=$(dpkg -S "$alt_path" 2>/dev/null) || true
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
                full_verify=$(dpkg --verify "$package" 2>/dev/null) || true
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

    # Not managed by package manager - cache and return
    PKG_CACHE["$file"]="unmanaged"
    echo "unmanaged"
    return 1
}

# Extract the first executable path from a command
get_executable_from_command() {
    local command="$1"

    # Remove ALL systemd prefixes (@, -, :, +, !) - can be multiple like !!
    while [[ "$command" =~ ^[@:+!\-] ]]; do
        command="${command#?}"
    done

    # Extract first word (the executable)
    local executable=$(echo "$command" | awk '{print $1}')

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
        full_line=$(echo "$script_content_clean" | grep -iE "$COMBINED_NEVER_WHITELIST_PATTERN" | head -1) || true
        if [[ -n "$full_line" ]]; then
            MATCHED_PATTERN="never_whitelist"
            MATCHED_STRING=$(echo "$full_line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | head -c 200)
            return 0  # SUSPICIOUS - found dangerous pattern
        fi
    fi

    # ISC-C2 FIX: Use COMBINED_COMMAND_PATTERN (auto-built from SUSPICIOUS_COMMANDS array)
    # instead of the orphan hand-maintained script_pattern_combined string.
    # This ensures analyze_script_content() is always in sync with SUSPICIOUS_COMMANDS.
    if [[ -n "$COMBINED_COMMAND_PATTERN" ]]; then
        local full_line
        full_line=$(echo "$script_content_clean" | grep -iE "$COMBINED_COMMAND_PATTERN" | head -1) || true
        if [[ -n "$full_line" ]]; then
            MATCHED_PATTERN="script_suspicious"
            MATCHED_STRING=$(echo "$full_line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | head -c 200)

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
        full_line=$(echo "$content_single_line" | grep -iE "$COMBINED_MULTILINE_PATTERN" | head -1) || true
        if [[ -n "$full_line" ]]; then
            MATCHED_PATTERN="multiline_suspicious"
            MATCHED_STRING=$(echo "$full_line" | head -c 200)
            return 0  # SUSPICIOUS - found multi-line dangerous pattern
        fi
    fi

    # Check for encoding-based obfuscation (hex/octal/ANSI-C encoding)
    # Legitimate scripts have no reason to encode strings this way.
    # 4+ consecutive hex/octal = intentional encoding. 2+ ANSI-C sequences = intentional.

    # Hex escape sequences: \x41\x42\x43 (shell/perl/python style)
    local hex_line
    hex_line=$(echo "$script_content_clean" | grep -E '(\\x[0-9a-fA-F]{2}){4,}' | head -1) || true
    if [[ -n "$hex_line" ]]; then
        MATCHED_PATTERN="hex_encoding"
        MATCHED_STRING=$(echo "$hex_line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | head -c 200)
        return 0  # SUSPICIOUS - hex-encoded payload
    fi

    # Octal escape sequences: \101\102\060 (shell/perl style)
    local octal_line
    octal_line=$(echo "$script_content_clean" | grep -E '(\\[0-7]{3}){4,}' | head -1) || true
    if [[ -n "$octal_line" ]]; then
        MATCHED_PATTERN="octal_encoding"
        MATCHED_STRING=$(echo "$octal_line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | head -c 200)
        return 0  # SUSPICIOUS - octal-encoded payload
    fi

    # ANSI-C quoting: $'\x41\x62\x63' (bash-specific hex encoding in strings)
    # Threshold lowered from {3,} to {2,}: 2 encoded chars is already intentional
    # Short payloads like $'\x62\x61\x73\x68' ("bash") were previously missed at {3,}
    local ansi_line
    ansi_line=$(echo "$script_content_clean" | grep -E "\\\$'(\\\\x[0-9a-fA-F]{2}|\\\\[0-7]{3}){2,}'" | head -1) || true
    if [[ -n "$ansi_line" ]]; then
        MATCHED_PATTERN="ansi_c_encoding"
        MATCHED_STRING=$(echo "$ansi_line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | head -c 200)
        return 0  # SUSPICIOUS - ANSI-C encoded payload
    fi

    # tr-based character substitution piped to execution (ROT13, ROT47, custom ciphers)
    # Pattern: tr '...' '...' | bash/sh  — obfuscation via character rotation
    local tr_exec_line
    tr_exec_line=$(echo "$script_content_clean" | grep -iE "tr[[:space:]]+['\"].+['\"].*\|[[:space:]]*(bash|sh|dash|zsh|exec)" | head -1) || true
    if [[ -n "$tr_exec_line" ]]; then
        MATCHED_PATTERN="tr_cipher_obfuscation"
        MATCHED_STRING=$(echo "$tr_exec_line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | head -c 200)
        return 0  # SUSPICIOUS - tr cipher obfuscation piped to shell
    fi

    # rev-based string reversal piped to execution
    local rev_exec_line
    rev_exec_line=$(echo "$script_content_clean" | grep -iE "rev[[:space:]]*\|[[:space:]]*(bash|sh|dash|zsh)" | head -1) || true
    if [[ -n "$rev_exec_line" ]]; then
        MATCHED_PATTERN="rev_obfuscation"
        MATCHED_STRING=$(echo "$rev_exec_line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | head -c 200)
        return 0  # SUSPICIOUS - string reversal piped to shell
    fi

    # Language-specific network/exec patterns (Python, Perl, Ruby)
    # These appear in scripts that use language stdlib instead of shell commands,
    # making them invisible to shell-command pattern checks.
    local lang_exec_line
    lang_exec_line=$(echo "$script_content_clean" | grep -oE \
        "socket\.connect\(|pty\.spawn\(|subprocess\.Popen[^)]{0,60}shell[[:space:]]*=[[:space:]]*True|os\.(system|popen|exec[vl]p?)\(|TCPSocket\.new\(" \
        | head -1) || true
    if [[ -n "$lang_exec_line" ]]; then
        MATCHED_PATTERN="language_network_exec"
        MATCHED_STRING="${lang_exec_line:0:200}"
        return 0  # SUSPICIOUS - language-specific network or shell-execution pattern
    fi

    # Check for high-entropy strings (obfuscation detection)
    # Look for long strings/variables with suspiciously high entropy
    # This catches: variable substitution, high-ascii characters, encrypted payloads
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue

        # Extract variable assignments with long values (potential obfuscation)
        # ISC-C10 FIX: Only flag HIGH entropy when paired with an execution context indicator
        # on the same line (eval, exec, base64 -d, bash, sh -c, openssl -d).
        # Standalone high-entropy strings (certificates, UUIDs, API keys, hashes) are
        # too noisy to flag without execution context — they don't continue the loop.
        local _value=""
        if [[ "$line" =~ =\"([^\"]{30,})\" ]]; then
            _value="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ =\'([^\']{30,})\' ]]; then
            _value="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ =([^[:space:]]{30,}) ]]; then
            _value="${BASH_REMATCH[1]}"
            _value="${_value#[\"\']}"
            _value="${_value%[\"\']}"
        fi

        if [[ -n "$_value" ]] && is_high_entropy "$_value" 4.5; then
            if echo "$line" | grep -qiE 'eval|exec\b|base64.*-d|bash\b|sh -c|openssl.*-d'; then
                MATCHED_PATTERN="high_entropy_exec"
                MATCHED_STRING="${_value:0:50}..."
                return 0  # SUSPICIOUS - high entropy data with execution context
            fi
            # Standalone high entropy without execution context: skip (too many FPs)
        fi

    done <<< "$script_content_clean"

    return 1  # Clean - no suspicious patterns found
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
    # Replace quotes with double quotes and wrap in quotes if contains comma, quote, or newline
    if [[ "$field" =~ [,\"$'\n'] ]]; then
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

    # ISC-C8 FIX: Escalate HIGH → CRITICAL for SUID/SGID files with suspicious content.
    # SUID/SGID + suspicious patterns is the most dangerous persistence combination:
    # an attacker-controlled setuid binary that spawns a shell or downloads a payload.
    # Permissions field format: "rwsr-xr-x" or "rws--x--x" etc. (s in user/group position).
    if [[ "$confidence" == "HIGH" ]] && [[ "$file_permissions" =~ [sS] ]]; then
        confidence="CRITICAL"
        matched_pattern="${matched_pattern}+suid_sgid"
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
    echo "$(escape_csv "$timestamp"),$(escape_csv "$HOSTNAME"),$(escape_csv "$category"),$(escape_csv "$confidence"),$(escape_csv "$file_path"),$(escape_csv "$file_hash"),$(escape_csv "$file_owner"),$(escape_csv "$file_permissions"),$(escape_csv "$file_age_days"),$(escape_csv "$package_status"),$(escape_csv "$command"),$(escape_csv "$enabled_status"),$(escape_csv "$description"),$(escape_csv "$matched_pattern"),$(escape_csv "$matched_string")" >> "$CSV_FILE"

    # JSONL output (new structure with proper escaping)
    cat >> "$JSONL_FILE" << EOF
{"timestamp":"$timestamp","hostname":"$HOSTNAME","category":"$(escape_json "$category")","confidence":"$confidence","file_path":"$(escape_json "$file_path")","file_hash":"$file_hash","file_owner":"$(escape_json "$file_owner")","file_permissions":"$file_permissions","file_age_days":"$file_age_days","package_status":"$(escape_json "$package_status")","command":"$(escape_json "$command")","enabled_status":"$(escape_json "$enabled_status")","description":"$(escape_json "$description")","matched_pattern":"$(escape_json "$matched_pattern")","matched_string":"$(escape_json "$matched_string")"}
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
    elif [[ "$additional_info" =~ preview=([^|]+) ]]; then
        command="${BASH_REMATCH[1]}"
    elif [[ "$additional_info" =~ content_preview=([^|]+) ]]; then
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
    echo "timestamp,hostname,category,confidence,file_path,file_hash,file_owner,file_permissions,file_age_days,package_status,command,enabled_status,description,matched_pattern,matched_string" > "$CSV_FILE"

    # Clear JSONL file
    > "$JSONL_FILE"

    log_info "Output directory: $OUTPUT_DIR"
    log_info "CSV output: $CSV_FILE"
    log_info "JSONL output: $JSONL_FILE"
}

################################################################################
# Detection Modules
################################################################################

# Check systemd services
check_systemd() {
    log_info "[1/7] Checking systemd services..."

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
            if [[ $uid -ge 0 ]]; then
                local user_systemd_dir="$homedir/.config/systemd/user"
                if [[ -d "$user_systemd_dir" ]] && [[ "$user_systemd_dir" != "$HOME/.config/systemd/user" ]]; then
                    systemd_paths+=("$user_systemd_dir")
                fi
            fi
        done < /etc/passwd
    fi

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
                if [[ -f "$service_file" ]]; then
                    exec_start=$(grep -E "^ExecStart=" "$service_file" 2>/dev/null | head -1 | cut -d'=' -f2- || echo "")
                    exec_pre=$(grep -E "^ExecStartPre=" "$service_file" 2>/dev/null | cut -d'=' -f2- | tr '\n' ';' || echo "")
                    exec_post=$(grep -E "^ExecStartPost=" "$service_file" 2>/dev/null | cut -d'=' -f2- | tr '\n' ';' || echo "")
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
                if [[ "$enabled_status" == "disabled" ]]; then
                    local _timer_basename="${service_name%.service}.timer"
                    local _timer_found=false
                    local _tdir
                    for _tdir in "$(dirname "$service_file")" /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /run/systemd/system /etc/systemd/user /usr/lib/systemd/user; do
                        if [[ -f "${_tdir}/${_timer_basename}" ]]; then
                            _timer_found=true
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

                                # Recent + enabled + unknown = suspicious
                                if [[ "$confidence" == "MEDIUM" ]] && [[ $days_old -lt 7 ]] && [[ "$enabled_status" == "enabled" ]]; then
                                    confidence="HIGH"
                                    finding_matched_pattern="recent_unknown"
                                    finding_matched_string="${days_old} days old"
                                    log_finding "Recently created enabled service with unknown command: $service_file"
                                fi

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

                # Extract owner and permissions from metadata
                local owner=$(get_owner_from_metadata "$metadata")
                local permissions=$(get_permissions_from_metadata "$metadata")

                # Use new structured format directly (DEFER hash until filtering)
                # Include matched pattern and string for forensic analysis
                add_finding_new "Systemd Service" "$confidence" "$service_file" "DEFER" "$owner" "$permissions" "$days_old" "$package_status" "$exec_start" "$enabled_status" "$service_name" "$finding_matched_pattern" "$finding_matched_string"

            # NOTE: Only scan .service files for persistence detection
            # .socket and .timer files don't contain ExecStart commands - they only
            # define socket/timer activation and reference other .service files.
            # From a forensics perspective, only .service files contain the actual
            # persistence mechanism (the executable/script being run).
            done < <(find "$path" -maxdepth 1 -type f -name "*.service" -print0 2>/dev/null)
        fi
    done

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
                if [[ "$executable" =~ ^/(tmp|dev/shm|var/tmp) ]] || [[ "$executable" =~ /\.[a-z] ]]; then
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
    log_info "[2/7] Checking cron jobs and scheduled tasks..."

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
            content=$(grep -Ev "^#|^$" "$cron_path" 2>/dev/null | head -20) || true
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
                cron_command=$(echo "$cron_line" | awk '{for(i=7;i<=NF;i++) printf "%s ", $i; print ""}') || true
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
                content=$(grep -Ev "^#|^$" "$cron_file" 2>/dev/null | head -20) || true
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
                    cron_command=$(echo "$cron_line" | awk '{for(i=7;i<=NF;i++) printf "%s ", $i; print ""}') || true
                    if analyze_cron_command "$cron_command" "$cron_file"; then
                        [[ "$confidence" != "CRITICAL" ]] && confidence="HIGH"
                        finding_matched_pattern="${CRON_ANALYSIS_REASON%%:*}"
                        finding_matched_string="${CRON_ANALYSIS_REASON#*:}"
                        log_finding "Crontab entry suspicious ($CRON_ANALYSIS_REASON): $cron_file"
                    fi
                done <<< "$content"

                add_finding "Cron" "System" "crontab_file" "$cron_file" "Crontab: $(basename "$cron_file")" "$confidence" "$hash" "$metadata" "package=$package_status" "$finding_matched_pattern" "$finding_matched_string"

            done < <(find "$cron_dir" -type f -print0 2>/dev/null)
        fi
    done

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

                    if [[ $days_old -lt 7 ]]; then
                        confidence="HIGH"
                        finding_matched_pattern="recently_created"
                        finding_matched_string="${days_old} days old"
                        log_finding "Recently created cron script: $cron_script (${days_old} days old)"
                    fi

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

    # User crontabs
    # Analyze each entry with the full execution chain (same flow as /etc/crontab and /etc/cron.d)
    if [[ $EUID_CHECK -eq 0 ]]; then
        while IFS=: read -r username _ uid _; do
            if [[ $uid -ge 0 ]]; then
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
                        if [[ "$cron_line" =~ ^@ ]]; then
                            cron_command=$(echo "$cron_line" | awk '{for(i=2;i<=NF;i++) printf "%s ", $i; print ""}') || true
                        else
                            cron_command=$(echo "$cron_line" | awk '{for(i=6;i<=NF;i++) printf "%s ", $i; print ""}') || true
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
                if [[ "$cron_line" =~ ^@ ]]; then
                    cron_command=$(echo "$cron_line" | awk '{for(i=2;i<=NF;i++) printf "%s ", $i; print ""}') || true
                else
                    cron_command=$(echo "$cron_line" | awk '{for(i=6;i<=NF;i++) printf "%s ", $i; print ""}') || true
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
                        # At spool files are named with the job ID embedded (format varies by system)
                        # Check if numeric job ID matches anywhere in spool filename
                        if [[ "$spool_name" == *"$known_id"* ]]; then
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
}

# Check shell profiles and RC files
check_shell_profiles() {
    log_info "[3/7] Checking shell profiles and RC files..."

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

                # ISC-C5 FIX: Time-based elevation for recently modified profiles
                local mod_time=0
                [[ "$metadata" =~ modified:([0-9]+) ]] && mod_time="${BASH_REMATCH[1]}"
                local days_old=$(( (SCAN_EPOCH - mod_time) / 86400 ))
                if [[ $days_old -lt 7 ]] && [[ "$confidence" == "MEDIUM" ]]; then
                    confidence="HIGH"
                    finding_matched_pattern="${finding_matched_pattern:-recent_modification}"
                    finding_matched_string="${finding_matched_string:-${days_old} days old}"
                    log_finding "Recently modified system profile: $profile (${days_old} days old)"
                fi

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

                    # ISC-C5 FIX: Time-based elevation for recently modified profile.d scripts
                    local mod_time=0
                    [[ "$metadata" =~ modified:([0-9]+) ]] && mod_time="${BASH_REMATCH[1]}"
                    local days_old=$(( (SCAN_EPOCH - mod_time) / 86400 ))
                    if [[ $days_old -lt 7 ]] && [[ "$confidence" == "MEDIUM" ]]; then
                        confidence="HIGH"
                        finding_matched_pattern="${finding_matched_pattern:-recent_modification}"
                        finding_matched_string="${finding_matched_string:-${days_old} days old}"
                        log_finding "Recently modified profile.d script: $profile_file (${days_old} days old)"
                    fi

                    add_finding "ShellProfile" "System" "profile_script" "$profile_file" "Profile.d script: $(basename "$profile_file")" "$confidence" "$hash" "$metadata" "days_old=${days_old};package=$package_status" "$finding_matched_pattern" "$finding_matched_string"

                done < <(find "$profile" -type f -print0 2>/dev/null)
            fi
        fi
    done

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
            if [[ $uid -ge 0 ]]; then
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

                        # ISC-C5 FIX: Time-based elevation for recently modified user profiles
                        local mod_time=0
                        [[ "$metadata" =~ modified:([0-9]+) ]] && mod_time="${BASH_REMATCH[1]}"
                        local days_old=$(( (SCAN_EPOCH - mod_time) / 86400 ))
                        if [[ $days_old -lt 7 ]] && [[ "$confidence" == "MEDIUM" ]]; then
                            confidence="HIGH"
                            finding_matched_pattern="${finding_matched_pattern:-recent_modification}"
                            finding_matched_string="${finding_matched_string:-${days_old} days old}"
                            log_finding "Recently modified user profile: $profile_path (${days_old} days old, user: $username)"
                        fi

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

                # ISC-C5 FIX: Time-based elevation for recently modified non-root user profiles
                local mod_time=0
                [[ "$metadata" =~ modified:([0-9]+) ]] && mod_time="${BASH_REMATCH[1]}"
                local days_old=$(( (SCAN_EPOCH - mod_time) / 86400 ))
                if [[ $days_old -lt 7 ]] && [[ "$confidence" == "MEDIUM" ]]; then
                    confidence="HIGH"
                    finding_matched_pattern="${finding_matched_pattern:-recent_modification}"
                    finding_matched_string="${finding_matched_string:-${days_old} days old}"
                    log_finding "Recently modified user profile: $profile_path (${days_old} days old)"
                fi

                add_finding "ShellProfile" "User" "user_profile" "$profile_path" "Current user profile" "$confidence" "$hash" "$metadata" "days_old=${days_old};user=$(whoami);package=$package_status" "$finding_matched_pattern" "$finding_matched_string"
            fi
        done
    fi
}

# Check init scripts and rc.local
check_init_scripts() {
    log_info "[4/7] Checking init scripts and rc.local..."

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

        done < <(find "/etc/init.d" -maxdepth 1 -type f -print0 2>/dev/null)
    fi

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
    log_info "[5/7] Checking kernel modules and library preloading..."

    # ═══════════════════════════════════════════════════════════════════════════
    # Suspicious locations for libraries/modules - these should NEVER contain
    # legitimate system libraries or kernel modules
    # ═══════════════════════════════════════════════════════════════════════════
    local suspicious_locations_pattern="^/(tmp|dev/shm|var/tmp|home|root)/|/\."

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
    log_info "[6/7] Checking additional persistence mechanisms..."

    # XDG autostart
    local autostart_dirs=(
        "/etc/xdg/autostart"
        "$HOME/.config/autostart"
    )

    # When running as root, scan all users' XDG autostart directories
    if [[ $EUID_CHECK -eq 0 ]]; then
        while IFS=: read -r _ _ _ _ _ homedir _; do
            local _user_autostart="$homedir/.config/autostart"
            if [[ "$_user_autostart" != "$HOME/.config/autostart" ]] && [[ -d "$_user_autostart" ]]; then
                autostart_dirs+=("$_user_autostart")
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
}

# Check common backdoor locations (inspired by Crackdown and DFIR research)
check_common_backdoors() {
    log_info "[7/7] Checking common backdoor locations..."

    # APT/YUM configuration files that can be abused
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
        while IFS= read -r -d '' _postinst; do
            local _pi_confidence="LOW"
            local _pi_pattern="" _pi_string=""
            local _pi_is_orphan=false

            # ── Signal 1: Orphan check ─────────────────────────────────────
            local _pi_pkgname
            _pi_pkgname=$(basename "$_postinst" .postinst)
            _pi_pkgname="${_pi_pkgname%%:*}"   # strip :arch suffix (e.g. bash:amd64 → bash)

            if command -v dpkg-query &>/dev/null; then
                local _pi_status
                _pi_status=$(dpkg-query -W -f='${Status}' "$_pi_pkgname" 2>/dev/null || echo "")
                if [[ "$_pi_status" != *"install ok installed"* ]]; then
                    _pi_is_orphan=true
                    _pi_confidence="MEDIUM"
                    _pi_pattern="orphan_postinst"
                    _pi_string="package $_pi_pkgname not installed"
                fi
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
        rpm -qa --scripts 2>/dev/null > "$_rpm_tmp" || true

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

    # Check for user git configs (can contain credential helpers or hooks)
    if [[ $EUID_CHECK -eq 0 ]]; then
        while IFS=: read -r username _ uid _ _ homedir _; do
            if [[ $uid -ge 0 ]]; then
                local gitconfig="$homedir/.gitconfig"
                if [[ -f "$gitconfig" ]]; then
                    local hash=$(get_file_hash "$gitconfig")
                    local metadata=$(get_file_metadata "$gitconfig")
                    local content=$(cat "$gitconfig" 2>/dev/null || echo "")

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
            local content=$(cat "$HOME/.gitconfig" 2>/dev/null || echo "")

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
                [[ $_web_count -gt 100 ]] && break

                local hash=$(get_file_hash "$web_file")
                local metadata=$(get_file_metadata "$web_file")

                # Extract mod_time from already-fetched metadata (no extra stat fork)
                local mod_time=0
                [[ "$metadata" =~ modified:([0-9]+) ]] && mod_time="${BASH_REMATCH[1]}"
                local current_time=$SCAN_EPOCH
                local days_old=$(( (current_time - mod_time) / 86400 ))

                local confidence="LOW"
                local finding_matched_pattern=""
                local finding_matched_string=""
                if [[ $days_old -lt 30 ]]; then
                    confidence="MEDIUM"
                    finding_matched_pattern="recently_modified"
                    finding_matched_string="${days_old} days old"

                    # Check for webshell patterns
                    local content=$(head -100 "$web_file" 2>/dev/null || echo "")
                    local webshell_match=$(echo "$content" | grep -oiE "(eval|base64_decode|system\(|exec\(|shell_exec|passthru|proc_open|popen)" | head -1) || true
                    if [[ -n "$webshell_match" ]]; then
                        confidence="HIGH"
                        finding_matched_pattern="webshell_pattern"
                        finding_matched_string="$webshell_match"
                        log_finding "Potential webshell detected: $web_file (modified ${days_old} days ago)"
                    fi
                fi

                if [[ $confidence != "LOW" ]]; then
                    add_finding "WebShell" "Suspicious" "web_file" "$web_file" "Recently modified web file in $web_dir (${days_old} days old)" "$confidence" "$hash" "$metadata" "days_old=$days_old" "$finding_matched_pattern" "$finding_matched_string"
                fi
            done < <(find "$web_dir" -type f \( -name "*.php" -o -name "*.asp" -o -name "*.aspx" -o -name "*.jsp" \) -print0 2>/dev/null)
        fi
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
                    echo "Error: --min-confidence requires a value (LOW|MEDIUM|HIGH)"
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
            "LOW"|"MEDIUM"|"HIGH")
                # Valid
                ;;
            *)
                log_warn "Invalid MIN_CONFIDENCE value: '$MIN_CONFIDENCE'"
                log_warn "Valid values are: LOW, MEDIUM, HIGH"
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

    # Run detection modules
    check_systemd
    echo

    check_cron
    echo

    check_shell_profiles
    echo

    check_init_scripts
    echo

    check_kernel_and_preload
    echo

    check_additional_persistence
    echo

    check_common_backdoors
    echo

    # Summary
    log_info "=========================================="
    log_info "Detection Complete!"
    log_info "=========================================="
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
    CNT_CRITICAL=$(grep -c '"confidence":"CRITICAL"' "$JSONL_FILE" 2>/dev/null || echo 0)
    CNT_HIGH=$(grep -c '"confidence":"HIGH"'     "$JSONL_FILE" 2>/dev/null || echo 0)
    CNT_MEDIUM=$(grep -c '"confidence":"MEDIUM"'  "$JSONL_FILE" 2>/dev/null || echo 0)
    CNT_LOW=$(grep -c '"confidence":"LOW"'      "$JSONL_FILE" 2>/dev/null || echo 0)

    cat > "$REPORT_FILE" << REPORT
================================================================================
  Persistnux — Linux Persistence Detection Report
================================================================================
  Version    : 1.9.0
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
  [1/7] Systemd (services, timers, generators)
  [2/7] Cron & scheduled tasks (cron.d, cron.daily/weekly/monthly/hourly, at)
  [3/7] Shell profiles (system-wide + per-user, all major shells)
  [4/7] Init scripts (rc.local, init.d, MOTD)
  [5/7] Kernel & library preloading (ld.so.preload, ld.so.conf, LKMs, modprobe)
  [6/7] Additional persistence (XDG, environment, sudoers, PAM, MOTD)
  [7/7] Common backdoor locations (APT/YUM hooks, DPKG postinst, RPM %post,
        YUM/DNF plugins, sudoers.d, webshells, git configs)

--------------------------------------------------------------------------------
  NOTES
--------------------------------------------------------------------------------
  - Confidence levels: CRITICAL > HIGH > MEDIUM > LOW
  - All findings include file hash, owner, permissions, and package status
  - Package integrity verified via dpkg --verify / rpm -V where applicable
  - Review JSONL output for machine-readable data: jq . ${JSONL_FILE}
================================================================================
REPORT

    log_info "  Report: $REPORT_FILE"
    echo

    # Cleanup
    rm -rf "$TEMP_DATA" 2>/dev/null

    log_info "Analysis completed at $(date)"
}

# Run main function
main "$@"
