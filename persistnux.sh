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
    "/bin/bash -c exec 5<>/dev/tcp/"
    "/bin/bash -c exec 5<>/dev/udp/"
    "nc -e /bin/sh"
    "/bin/sh | nc"
    "mknod.*backpipe"
    "telnet.*bash"
    "socat exec:"
    "xterm -display"
)

declare -a SUSPICIOUS_COMMANDS=(
    "curl.*\|.*bash"              # Download and execute via curl
    "curl.*\|.*sh"                # Download and execute via curl
    "wget.*\|.*bash"              # Download and execute via wget
    "wget.*\|.*sh"                # Download and execute via wget
    "curl.* sh -c"                # Download and execute via curl
    "wget.* sh -c"                # Download and execute via wget
    "curl.*-o.*/tmp"              # Download to /tmp via curl
    "wget.*-O.*/tmp"              # Download to /tmp via wget
    "chmod \+x.*/tmp"             # Making /tmp files executable
    "chmod \+x.*/dev/shm"         # Making /dev/shm files executable
    "chmod 777 "                  # Overly permissive permissions (with trailing space)
    "base64 -d"                   # Base64 decode (common obfuscation)
    "base64 --decode"             # Base64 decode (long form)
    "eval.*\\\$.*base64"          # Eval with base64 decoded content
    "echo.*\|.*base64.*-d"        # Echo piped to base64 decode
    "python.*-c.*import"          # Python inline code with imports
    "perl -e"                     # Perl inline code
    "ruby -e"                     # Ruby inline code
    "php -r"                      # PHP inline code
    "php.*fsockopen"              # PHP socket connection
    "openssl.*-d.*-base64"        # OpenSSL base64 decode
)

# Suspicious execution locations - these patterns are checked against file paths
# and ExecStart commands to identify potential staging/hiding locations
declare -a SUSPICIOUS_LOCATIONS=(
    "^/dev/shm/"                  # Execution from shared memory
    "^/tmp/"                      # Execution from temp directory
    "^/var/tmp/"                  # Execution from persistent temp
    "/\.[a-z]"                    # Hidden file/directory (starts with dot)
    "\.\./\.\."                   # Multiple parent traversals (path escape attempt)
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
    "\| *nc "                    # Piping to netcat
    "\| *bash"                   # Piping to bash
    "\| *sh "                    # Piping to sh (with space to avoid false positives)
    "\| */bin/sh"                # Piping to /bin/sh
    "\| */bin/bash"              # Piping to /bin/bash
    ">&[ ]*/dev/"                # Redirecting to /dev/ (reverse shell pattern)
    "exec [0-9].*socket"         # Bash exec with fd and socket (reverse shell setup)
    "python.*import socket.*connect"  # Python socket connect (more specific)
    "python.*socket\.socket"     # Python socket creation (more specific)
    "perl.*socket.*connect"      # Perl socket connect (more specific)
    "ruby.*TCPSocket"            # Ruby TCP socket (more specific)
    "ruby.*Socket\.new"          # Ruby socket creation
    "socat.*exec:"               # Socat with exec (reverse shell)
    "socat.*TCP:"                # Socat TCP connection (potentially malicious)
    "telnet.*\|.*bash"           # Telnet piped to bash
    "telnet.*\|.*sh"             # Telnet piped to sh
    "xterm -display"             # Xterm display redirection (reverse shell)
    "mknod.*backpipe"            # Named pipe for reverse shell
    "mkfifo.*/tmp"               # Named pipe in /tmp (common for reverse shells)
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
)

# Unified quick suspicious content check pattern (used by all modules)
# This is a single pattern combining the most common indicators for fast detection
UNIFIED_SUSPICIOUS_PATTERN="curl|wget|nc |netcat|/tmp/|/dev/shm|/dev/tcp|/dev/udp|base64|chmod \\+x|bash -c|sh -c|eval |exec [0-9]"

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

# Build combined regex patterns for faster matching
build_combined_patterns() {
    # Join array elements with | for regex alternation
    local IFS='|'
    COMBINED_NETWORK_PATTERN="(${SUSPICIOUS_NETWORK_PATTERNS[*]})"
    COMBINED_COMMAND_PATTERN="(${SUSPICIOUS_COMMANDS[*]})"
    COMBINED_LOCATION_PATTERN="(${SUSPICIOUS_LOCATIONS[*]})"
    COMBINED_FILE_PATTERN="(${SUSPICIOUS_FILES[*]})"
}

# Helper: Check single category and set match info
_check_category() {
    local content="$1"
    local category="$2"
    local combined_pattern="$3"
    shift 3
    local -a patterns=("$@")

    # Fast initial check with combined pattern
    if ! echo "$content" | grep -qE "$combined_pattern" 2>/dev/null; then
        return 1  # No match in this category
    fi

    # Found something - now identify which specific pattern matched
    for pattern in "${patterns[@]}"; do
        local match=$(echo "$content" | grep -oE "$pattern" 2>/dev/null | head -1)
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

    # Try to find the actual match for reporting
    local match
    match=$(echo "$content" | grep -oiE "$UNIFIED_SUSPICIOUS_PATTERN" | head -1) || true
    if [[ -n "$match" ]]; then
        MATCHED_PATTERN="unified_suspicious"
        MATCHED_STRING="$match"
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

    Linux Persistence Detection Tool v1.8.0
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
    if [[ -f "$file" ]] && [[ -r "$file" ]]; then
        sha256sum "$file" 2>/dev/null | awk '{print $1}' || echo "N/A"
    else
        echo "N/A"
    fi
}

# Get file metadata
get_file_metadata() {
    local file="$1"
    if [[ -e "$file" ]]; then
        stat -c "mode:%a|owner:%U:%G|size:%s|modified:%Y|accessed:%X|changed:%Z" "$file" 2>/dev/null || echo "N/A"
    else
        echo "N/A"
    fi
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
    while IFS= read -r line; do
        local unit_name state
        unit_name=$(echo "$line" | awk '{print $1}')
        state=$(echo "$line" | awk '{print $2}')

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

    # Check dpkg (Debian/Ubuntu) - single call to avoid duplicate lookups
    if command -v dpkg &> /dev/null; then
        local dpkg_output
        dpkg_output=$(dpkg -S "$file" 2>/dev/null) || true
        if [[ -n "$dpkg_output" ]]; then
            local package=$(echo "$dpkg_output" | cut -d':' -f1 | head -n1)

            # Verify file hasn't been tampered with
            # dpkg --verify returns errors if file modified/missing
            local verify_output=$(dpkg --verify "$package" 2>/dev/null | grep -F "$file")
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
        if [[ -n "$rpm_output" ]] && [[ "$rpm_output" != *"not owned"* ]]; then
            local package=$(echo "$rpm_output" | head -n1)

            # Verify file integrity using rpm -V
            local verify_output=$(rpm -V "$package" 2>/dev/null | grep -F "$file")
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
            # Fallback to AWK Shannon entropy if gzip not available
            local entropy=$(echo -n "$data" | fold -w1 | sort | uniq -c | awk -v len="$length" '
                BEGIN { entropy = 0 }
                {
                    freq = $1 / len
                    if (freq > 0) {
                        entropy -= freq * log(freq) / log(2)
                    }
                }
                END { printf "%.2f", entropy }
            ')
            echo "$entropy"
            return
        fi

        local compressed_size=$(echo -n "$data" | gzip -c 2>/dev/null | wc -c)

        # Handle gzip failure - fallback to AWK
        if [[ -z "$compressed_size" ]] || [[ "$compressed_size" -eq 0 ]]; then
            local entropy=$(echo -n "$data" | fold -w1 | sort | uniq -c | awk -v len="$length" '
                BEGIN { entropy = 0 }
                {
                    freq = $1 / len
                    if (freq > 0) {
                        entropy -= freq * log(freq) / log(2)
                    }
                }
                END { printf "%.2f", entropy }
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
        # For medium strings (30-199), use AWK Shannon entropy (more accurate)
        # AWK is better for medium-length strings; gzip only efficient for very long strings
        local entropy=$(echo -n "$data" | fold -w1 | sort | uniq -c | awk -v len="$length" '
            BEGIN { entropy = 0 }
            {
                freq = $1 / len
                if (freq > 0) {
                    entropy -= freq * log(freq) / log(2)
                }
            }
            END { printf "%.2f", entropy }
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

    local entropy=$(calculate_entropy "$string")

    # Use awk for float comparison
    local is_high=$(awk -v e="$entropy" -v t="$threshold" 'BEGIN { print (e > t) ? 1 : 0 }')

    if [[ "$is_high" -eq 1 ]]; then
        return 0  # High entropy - suspicious
    else
        return 1  # Normal entropy
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
    local script_content
    script_content=$(head -n 1000 "$script_file" 2>/dev/null) || true

    # Build combined pattern from NEVER_WHITELIST_PATTERNS (joined with |)
    local never_whitelist_combined=""
    for pattern in "${NEVER_WHITELIST_PATTERNS[@]}"; do
        if [[ -n "$never_whitelist_combined" ]]; then
            never_whitelist_combined="${never_whitelist_combined}|${pattern}"
        else
            never_whitelist_combined="$pattern"
        fi
    done

    # Check all dangerous patterns in single grep call
    if [[ -n "$never_whitelist_combined" ]]; then
        local match
        match=$(echo "$script_content" | grep -oiE "$never_whitelist_combined" | head -1) || true
        if [[ -n "$match" ]]; then
            MATCHED_PATTERN="never_whitelist"
            MATCHED_STRING="$match"
            return 0  # SUSPICIOUS - found dangerous pattern
        fi
    fi

    # Combined script-specific suspicious patterns (single grep call)
    local script_pattern_combined="eval.*\\$|exec.*\\$|\\$\\(curl|\\$\\(wget|base64.*-d|openssl.*enc.*-d|mkfifo|nc.*-l.*-p|socat.*TCP|python.*-c|perl.*-e|ruby.*-e|awk.*system|/proc/self/exe|chmod.*\\+x.*tmp|chmod.*777"

    local match
    match=$(echo "$script_content" | grep -oiE "$script_pattern_combined" | head -1) || true
    if [[ -n "$match" ]]; then
        MATCHED_PATTERN="script_suspicious"
        MATCHED_STRING="$match"
        return 0  # SUSPICIOUS - found dangerous script pattern
    fi

    # Check for multi-line suspicious patterns (heredocs, split commands)
    # Uses tr to convert newlines to spaces for cross-line matching
    local content_single_line
    content_single_line=$(echo "$script_content" | tr '\n' ' ')
    for pattern in "${MULTILINE_SUSPICIOUS_PATTERNS[@]}"; do
        local match
        match=$(echo "$content_single_line" | grep -oiE "$pattern" | head -1) || true
        if [[ -n "$match" ]]; then
            MATCHED_PATTERN="multiline_suspicious"
            MATCHED_STRING="$match"
            return 0  # SUSPICIOUS - found multi-line dangerous pattern
        fi
    done

    # Check for high-entropy strings (obfuscation detection)
    # Look for long strings/variables with suspiciously high entropy
    # This catches: variable substitution, high-ascii characters, encrypted payloads
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue

        # Extract variable assignments with long values (potential obfuscation)
        # Try to match quoted strings first (double quotes)
        if [[ "$line" =~ =\"([^\"]{30,})\" ]]; then
            local value="${BASH_REMATCH[1]}"
            if is_high_entropy "$value" 4.5; then
                MATCHED_PATTERN="high_entropy"
                MATCHED_STRING="${value:0:50}..."
                return 0  # SUSPICIOUS - high entropy indicates obfuscation
            fi
        # Try single quoted strings
        elif [[ "$line" =~ =\'([^\']{30,})\' ]]; then
            local value="${BASH_REMATCH[1]}"
            if is_high_entropy "$value" 4.5; then
                MATCHED_PATTERN="high_entropy"
                MATCHED_STRING="${value:0:50}..."
                return 0  # SUSPICIOUS - high entropy indicates obfuscation
            fi
        # Fall back to unquoted strings without spaces
        elif [[ "$line" =~ =([^[:space:]]{30,}) ]]; then
            local value="${BASH_REMATCH[1]}"
            # Remove surrounding quotes if present
            value="${value#\"}"
            value="${value#\'}"
            value="${value%\"}"
            value="${value%\'}"
            if is_high_entropy "$value" 4.5; then
                MATCHED_PATTERN="high_entropy"
                MATCHED_STRING="${value:0:50}..."
                return 0  # SUSPICIOUS - high entropy indicates obfuscation
            fi
        fi

    done <<< "$script_content"

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

    # Match -c 'code' or -c "code" or -e 'code' or -e "code"
    if [[ "$full_command" =~ \ -[ce]\ +[\"\'](.+)[\"\'] ]]; then
        inline_code="${BASH_REMATCH[1]}"
    elif [[ "$full_command" =~ \ -[ce]\ +([^\ ]+) ]]; then
        # Unquoted inline code
        inline_code="${BASH_REMATCH[1]}"
    fi

    [[ -z "$inline_code" ]] && return 1  # No inline code found

    # ─────────────────────────────────────────────────────────────────
    # CHECK 1: Suspicious patterns in inline code
    # ─────────────────────────────────────────────────────────────────
    if quick_suspicious_check "$inline_code"; then
        INLINE_CODE_REASON="suspicious_pattern"
        return 0
    fi

    # Check NEVER_WHITELIST patterns
    local never_whitelist_combined=""
    for pattern in "${NEVER_WHITELIST_PATTERNS[@]}"; do
        if [[ -n "$never_whitelist_combined" ]]; then
            never_whitelist_combined="${never_whitelist_combined}|${pattern}"
        else
            never_whitelist_combined="$pattern"
        fi
    done
    if [[ -n "$never_whitelist_combined" ]]; then
        if echo "$inline_code" | grep -qiE "$never_whitelist_combined"; then
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

# Check if command is executing a known-safe system binary
is_command_safe() {
    local command="$1"

    # First check: Does it contain NEVER_WHITELIST patterns?
    # This check ALWAYS takes precedence - even package-managed files with dangerous patterns are flagged
    for pattern in "${NEVER_WHITELIST_PATTERNS[@]}"; do
        if echo "$command" | grep -qiE "$pattern"; then
            return 1  # DANGEROUS - never whitelist
        fi
    done

    # Extract executable for subsequent checks
    local executable=$(get_executable_from_command "$command")

    # Second check: Path-based validation (CRITICAL FIX)
    # A path is only safe if it's BOTH in a standard location AND package-managed
    # This prevents /usr/bin/evil_miner from being marked safe just because it's in /usr/bin
    for path in "${KNOWN_GOOD_EXECUTABLE_PATHS[@]}"; do
        if echo "$command" | grep -qE "$path"; then
            # Path matches known-good location, but we MUST verify it's package-managed
            if [[ -n "$executable" ]] && [[ -f "$executable" ]]; then
                local pkg_status pkg_return=0
                pkg_status=$(is_package_managed "$executable") || pkg_return=$?

                # Only trust if package-managed AND not modified
                if [[ $pkg_return -eq 0 ]]; then
                    return 0  # Safe - standard path AND package-managed
                elif [[ $pkg_return -eq 2 ]]; then
                    # Package file was MODIFIED - treat as dangerous
                    return 1  # DANGEROUS - modified package file
                fi
                # If pkg_return=1 (unmanaged), fall through to continue checking
            fi
            # Path matched but file not package-managed - NOT automatically safe
            # Continue to other checks
        fi
    done

    # Third check: Does it match known-good command patterns?
    for pattern in "${KNOWN_GOOD_COMMAND_PATTERNS[@]}"; do
        if echo "$command" | grep -qE "$pattern"; then
            return 0  # Safe - benign command pattern
        fi
    done

    # Fourth check: Is the executable itself package-managed (even if not in standard path)?
    # Example: /opt/vendor/bin/tool that IS package-managed
    if [[ -n "$executable" ]] && [[ -f "$executable" ]]; then
        local pkg_status pkg_return=0
        pkg_status=$(is_package_managed "$executable") || pkg_return=$?

        if [[ $pkg_return -eq 0 ]]; then
            return 0  # Safe - package-managed binary
        elif [[ $pkg_return -eq 2 ]]; then
            return 1  # DANGEROUS - modified package file
        fi
    fi

    return 1  # Unknown/suspicious command
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
get_owner_from_metadata() {
    local metadata="$1"
    echo "$metadata" | grep -oP 'owner:\K[^|]+' || echo "N/A"
}

# Extract permissions from metadata string
get_permissions_from_metadata() {
    local metadata="$1"
    echo "$metadata" | grep -oP 'mode:\K[^|]+' || echo "N/A"
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

    # Extract structured fields from metadata and additional_info
    local owner=$(echo "$metadata" | grep -oP 'owner:\K[^|]+' | head -1 || echo "N/A")
    local permissions=$(echo "$metadata" | grep -oP 'mode:\K[^|]+' | head -1 || echo "N/A")
    local days_old=$(echo "$additional_info" | grep -oP 'days_old=\K[0-9]+' | head -1 || echo "N/A")
    local package_status=$(echo "$additional_info" | grep -oP 'package=\K[^|]+' | head -1 || echo "unmanaged")
    local enabled=$(echo "$additional_info" | grep -oP 'enabled=\K[^|]+' | head -1 || echo "")

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
    log_info "[1/8] Checking systemd services..."

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

    for path in "${systemd_paths[@]}"; do
        if [[ -d "$path" ]]; then
            while IFS= read -r -d '' service_file; do
                local metadata=$(get_file_metadata "$service_file")
                local service_name=$(basename "$service_file")

                # Extract ExecStart from service file
                local exec_start=""
                if [[ -f "$service_file" ]]; then
                    exec_start=$(grep -E "^ExecStart=" "$service_file" 2>/dev/null | head -1 | cut -d'=' -f2- || echo "")
                fi

                # Check if service is enabled (using cache for performance)
                local enabled_status
                enabled_status=$(get_systemctl_enabled_status "$service_name")

                local confidence="MEDIUM"
                local finding_matched_pattern=""
                local finding_matched_string=""
                local package_status="unmanaged"
                local skip_pattern_analysis=false

                # Check modification time of service file
                local mod_time=$(stat -c %Y "$service_file" 2>/dev/null || stat -f %m "$service_file" 2>/dev/null || echo "0")
                local current_time=$(date +%s)
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
                                    # Script is package-managed and verified - LOW, skip analysis
                                    confidence="LOW"
                                    skip_pattern_analysis=true
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
                                    if [[ "$script_to_analyze" =~ ^/(tmp|dev/shm|var/tmp) ]]; then
                                        confidence="HIGH"
                                        finding_matched_pattern="suspicious_location"
                                        finding_matched_string="$script_to_analyze"
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
                                if [[ "$exec_start" =~ \ -[ce]\  ]] || [[ "$exec_start" =~ \ -[ce]$ ]]; then
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
                                    finding_matched_pattern="interpreter_interactive"
                                    finding_matched_string="$executable"
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
                                # Binary is package-managed and verified - LOW, skip analysis
                                confidence="LOW"
                                skip_pattern_analysis=true
                                package_status="$exec_pkg_status"

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
                                        finding_matched_string="$executable"
                                        log_finding "Systemd service script contains suspicious content: $executable"
                                    fi
                                fi

                                # Pattern analysis on ExecStart command
                                if [[ "$skip_pattern_analysis" != true ]] && [[ "$confidence" != "HIGH" ]]; then
                                    local dangerous_match=$(echo "$exec_start" | grep -oiE "(curl.*\||wget.*\||nc -e|/dev/tcp/|/dev/udp/|bash -i|sh -i)" | head -1)
                                    if [[ -n "$dangerous_match" ]]; then
                                        confidence="HIGH"
                                        finding_matched_pattern="dangerous_command"
                                        finding_matched_string="$dangerous_match"
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

                                # Default reason if no specific pattern found
                                if [[ -z "$finding_matched_pattern" ]]; then
                                    finding_matched_pattern="unmanaged_binary"
                                    finding_matched_string="$executable"
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

                else
                    # No ExecStart found - can't verify anything
                    # Keep default MEDIUM confidence
                    package_status="no_execstart"
                    finding_matched_pattern="no_execstart"
                    finding_matched_string="service has no ExecStart"
                fi

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
            if [[ "$script_file" =~ ^/(tmp|dev/shm|var/tmp) ]]; then
                CRON_ANALYSIS_REASON="suspicious_location:$script_file"
                return 0
            fi

            # Analyze script content for suspicious patterns
            if is_script "$script_file"; then
                if analyze_script_content "$script_file"; then
                    CRON_ANALYSIS_REASON="suspicious_script_content:$script_file"
                    return 0
                fi
            fi

            # Unmanaged but no suspicious content - still flag as unmanaged
            CRON_ANALYSIS_REASON="unmanaged_script:$script_file"
            return 0

        else
            # No script file - check for INLINE CODE (-c/-e flags)
            if [[ "$cron_command" =~ \ -[ce]\  ]] || [[ "$cron_command" =~ \ -[ce]$ ]]; then
                # Analyze the inline code content for patterns and obfuscation
                if analyze_inline_code "$cron_command"; then
                    CRON_ANALYSIS_REASON="inline_code_suspicious:$INLINE_CODE_REASON"
                else
                    CRON_ANALYSIS_REASON="inline_code:-c/-e flag"
                fi
                return 0
            fi
            # Interactive interpreter without script - skip
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
    if [[ "$executable" =~ ^/(tmp|dev/shm|var/tmp) ]]; then
        CRON_ANALYSIS_REASON="suspicious_location:$executable"
        return 0
    fi

    # If it's a script file, analyze content
    if is_script "$executable"; then
        if analyze_script_content "$executable"; then
            CRON_ANALYSIS_REASON="suspicious_script_content:$executable"
            return 0
        fi
    fi

    # Unmanaged binary but no suspicious content
    CRON_ANALYSIS_REASON="unmanaged_binary:$executable"
    return 0
}

# Check cron jobs
check_cron() {
    log_info "[2/8] Checking cron jobs and scheduled tasks..."

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
                cron_command=$(echo "$cron_line" | awk '{for(i=6;i<=NF;i++) printf "%s ", $i; print ""}') || true
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
                    cron_command=$(echo "$cron_line" | awk '{for(i=6;i<=NF;i++) printf "%s ", $i; print ""}') || true
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
                    local mod_time
                    mod_time=$(stat -c %Y "$cron_script" 2>/dev/null || stat -f %m "$cron_script" 2>/dev/null || echo "0")
                    local current_time
                    current_time=$(date +%s)
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
    if [[ $EUID_CHECK -eq 0 ]]; then
        while IFS=: read -r username _ uid _; do
            if [[ $uid -ge 1000 ]] || [[ $uid -eq 0 ]]; then
                local user_cron=$(crontab -u "$username" -l 2>/dev/null || echo "")
                if [[ -n "$user_cron" ]]; then
                    local confidence="MEDIUM"
                    local finding_matched_pattern=""
                    local finding_matched_string=""
                    if quick_suspicious_check "$user_cron"; then
                        confidence="HIGH"
                        finding_matched_pattern="$MATCHED_PATTERN"
                        finding_matched_string="$MATCHED_STRING"
                        log_finding "Suspicious user crontab for: $username"
                    fi

                    add_finding "Cron" "User" "user_crontab" "/var/spool/cron/crontabs/$username" "User $username crontab entries" "$confidence" "N/A" "user=$username" "preview=${user_cron:0:100}" "$finding_matched_pattern" "$finding_matched_string"
                fi
            fi
        done < /etc/passwd
    else
        # Non-root: check only current user
        local user_cron=$(crontab -l 2>/dev/null || echo "")
        if [[ -n "$user_cron" ]]; then
            local finding_matched_pattern=""
            local finding_matched_string=""
            if quick_suspicious_check "$user_cron"; then
                finding_matched_pattern="$MATCHED_PATTERN"
                finding_matched_string="$MATCHED_STRING"
            fi
            add_finding "Cron" "User" "user_crontab" "~/.crontab" "Current user crontab" "MEDIUM" "N/A" "user=$(whoami)" "preview=${user_cron:0:100}" "$finding_matched_pattern" "$finding_matched_string"
        fi
    fi

    # Check at jobs
    if command -v atq &> /dev/null; then
        local at_jobs=$(atq 2>/dev/null || echo "")
        if [[ -n "$at_jobs" ]]; then
            log_info "Found at jobs"
            while read -r job_line; do
                local job_id=$(echo "$job_line" | awk '{print $1}')
                local job_details=$(at -c "$job_id" 2>/dev/null | tail -20 || echo "")

                local confidence="LOW"
                local finding_matched_pattern=""
                local finding_matched_string=""
                if quick_suspicious_check "$job_details"; then
                    confidence="HIGH"
                    finding_matched_pattern="$MATCHED_PATTERN"
                    finding_matched_string="$MATCHED_STRING"
                    log_finding "Suspicious at job: $job_id"
                fi

                add_finding "Scheduled" "At" "at_job" "/var/spool/cron/atjobs/$job_id" "At job $job_id" "$confidence" "N/A" "$job_line" "job_id=$job_id" "$finding_matched_pattern" "$finding_matched_string"
            done <<< "$at_jobs"
        fi
    fi
}

# Check shell profiles and RC files
check_shell_profiles() {
    log_info "[3/8] Checking shell profiles and RC files..."

    local profile_files=(
        "/etc/profile"
        "/etc/profile.d"
        "/etc/bash.bashrc"
        "/etc/bashrc"
        "/etc/zsh/zshrc"
        "/etc/zshrc"
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

                add_finding "ShellProfile" "System" "profile_file" "$profile" "System shell profile" "$confidence" "$hash" "$metadata" "package=$package_status" "$finding_matched_pattern" "$finding_matched_string"

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

                    add_finding "ShellProfile" "System" "profile_script" "$profile_file" "Profile.d script: $(basename "$profile_file")" "$confidence" "$hash" "$metadata" "package=$package_status" "$finding_matched_pattern" "$finding_matched_string"

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

                        add_finding "ShellProfile" "User" "user_profile" "$profile_path" "User profile for $username" "$confidence" "$hash" "$metadata" "user=$username" "$finding_matched_pattern" "$finding_matched_string"
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
                    confidence="MEDIUM"
                    finding_matched_pattern="$MATCHED_PATTERN"
                    finding_matched_string="$MATCHED_STRING"
                elif analyze_script_content "$profile_path"; then
                    confidence="MEDIUM"
                    finding_matched_pattern="$MATCHED_PATTERN"
                    finding_matched_string="$MATCHED_STRING"
                fi

                add_finding "ShellProfile" "User" "user_profile" "$profile_path" "Current user profile" "$confidence" "$hash" "$metadata" "user=$(whoami)" "$finding_matched_pattern" "$finding_matched_string"
            fi
        done
    fi
}

# Check SSH persistence
check_ssh() {
    log_info "[4/8] Checking SSH persistence mechanisms..."

    # SSH authorized_keys
    if [[ $EUID_CHECK -eq 0 ]]; then
        while IFS=: read -r username _ uid _ _ homedir _; do
            if [[ $uid -ge 1000 ]] || [[ $uid -eq 0 ]]; then
                local ssh_dir="$homedir/.ssh"
                if [[ -d "$ssh_dir" ]]; then
                    # authorized_keys
                    if [[ -f "$ssh_dir/authorized_keys" ]]; then
                        local hash=$(get_file_hash "$ssh_dir/authorized_keys")
                        local metadata=$(get_file_metadata "$ssh_dir/authorized_keys")
                        local key_count=$(grep -c "^ssh-" "$ssh_dir/authorized_keys" 2>/dev/null || echo "0")

                        add_finding "SSH" "AuthorizedKeys" "ssh_authorized_keys" "$ssh_dir/authorized_keys" "User $username has $key_count SSH authorized keys" "MEDIUM" "$hash" "$metadata" "user=$username|keys=$key_count"
                    fi

                    # Check for suspicious SSH config
                    if [[ -f "$ssh_dir/config" ]]; then
                        local hash=$(get_file_hash "$ssh_dir/config")
                        local metadata=$(get_file_metadata "$ssh_dir/config")
                        local suspicious_config=$(grep -iE "(ProxyCommand|LocalForward|RemoteForward|DynamicForward)" "$ssh_dir/config" 2>/dev/null || echo "")

                        local confidence="LOW"
                        local finding_matched_pattern=""
                        local finding_matched_string=""
                        if [[ -n "$suspicious_config" ]]; then
                            confidence="MEDIUM"
                            finding_matched_pattern="ssh_forwarding"
                            finding_matched_string="$suspicious_config"
                        fi

                        add_finding "SSH" "Config" "ssh_config" "$ssh_dir/config" "User SSH config for $username" "$confidence" "$hash" "$metadata" "user=$username" "$finding_matched_pattern" "$finding_matched_string"
                    fi
                fi
            fi
        done < /etc/passwd
    else
        # Non-root
        if [[ -f "$HOME/.ssh/authorized_keys" ]]; then
            local hash=$(get_file_hash "$HOME/.ssh/authorized_keys")
            local metadata=$(get_file_metadata "$HOME/.ssh/authorized_keys")
            local key_count=$(grep -c "^ssh-" "$HOME/.ssh/authorized_keys" 2>/dev/null || echo "0")

            add_finding "SSH" "AuthorizedKeys" "ssh_authorized_keys" "$HOME/.ssh/authorized_keys" "Current user has $key_count SSH authorized keys" "MEDIUM" "$hash" "$metadata" "keys=$key_count"
        fi
    fi

    # System SSH config
    if [[ -f "/etc/ssh/sshd_config" ]]; then
        local hash=$(get_file_hash "/etc/ssh/sshd_config")
        local metadata=$(get_file_metadata "/etc/ssh/sshd_config")
        local suspicious_sshd=$(grep -iE "(PermitRootLogin yes|PasswordAuthentication yes|PermitEmptyPasswords yes|AuthorizedKeysFile)" /etc/ssh/sshd_config 2>/dev/null | grep -v "^#" || echo "")

        local confidence="LOW"
        local finding_matched_pattern=""
        local finding_matched_string=""
        if echo "$suspicious_sshd" | grep -qiE "(PermitRootLogin yes|PermitEmptyPasswords yes)"; then
            confidence="MEDIUM"
            finding_matched_pattern="insecure_sshd"
            finding_matched_string="$suspicious_sshd"
        fi

        add_finding "SSH" "SystemConfig" "sshd_config" "/etc/ssh/sshd_config" "SSH daemon configuration" "$confidence" "$hash" "$metadata" "" "$finding_matched_pattern" "$finding_matched_string"
    fi
}

# Check init scripts and rc.local
check_init_scripts() {
    log_info "[5/8] Checking init scripts and rc.local..."

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
            while IFS= read -r -d '' rc_file; do
                # We're looking for actual FILES, not symlinks (symlinks are normal)
                if [[ -f "$rc_file" ]] && [[ ! -L "$rc_file" ]]; then
                    # Non-symlink file in rc*.d is suspicious
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
        fi
    done
}

# Check kernel modules and library preloading
check_kernel_and_preload() {
    log_info "[6/8] Checking kernel modules and library preloading..."

    # LD_PRELOAD in environment and configs
    local preload_files=(
        "/etc/ld.so.preload"
        "/etc/ld.so.conf"
        "/etc/ld.so.conf.d"
    )

    for preload_file in "${preload_files[@]}"; do
        if [[ -e "$preload_file" ]]; then
            if [[ -f "$preload_file" ]]; then
                local hash=$(get_file_hash "$preload_file")
                local metadata=$(get_file_metadata "$preload_file")
                local content=$(cat "$preload_file" 2>/dev/null || echo "")

                if [[ -n "$content" ]] && [[ "$content" != "" ]]; then
                    log_finding "LD_PRELOAD configuration found: $preload_file"
                    add_finding "Preload" "LDPreload" "ld_preload" "$preload_file" "LD_PRELOAD config with content" "HIGH" "$hash" "$metadata" "content=$content"
                else
                    add_finding "Preload" "LDPreload" "ld_preload" "$preload_file" "LD_PRELOAD config (empty)" "LOW" "$hash" "$metadata" ""
                fi

            elif [[ -d "$preload_file" ]]; then
                while IFS= read -r -d '' conf_file; do
                    local hash=$(get_file_hash "$conf_file")
                    local metadata=$(get_file_metadata "$conf_file")

                    add_finding "Preload" "LDConfig" "ld_config" "$conf_file" "LD configuration: $(basename "$conf_file")" "LOW" "$hash" "$metadata" ""
                done < <(find "$preload_file" -type f -print0 2>/dev/null)
            fi
        fi
    done

    # Check loaded kernel modules
    if [[ $EUID_CHECK -eq 0 ]]; then
        log_info "Enumerating loaded kernel modules..."
        while read -r module_line; do
            local module_name=$(echo "$module_line" | awk '{print $1}')
            local module_size=$(echo "$module_line" | awk '{print $2}')
            local module_used=$(echo "$module_line" | awk '{print $3}')

            # Find module file
            local module_path=$(modinfo -F filename "$module_name" 2>/dev/null || echo "N/A")
            local hash="N/A"
            local metadata="N/A"

            if [[ "$module_path" != "N/A" ]] && [[ -f "$module_path" ]]; then
                hash=$(get_file_hash "$module_path")
                metadata=$(get_file_metadata "$module_path")
            fi

            add_finding "Kernel" "Module" "kernel_module" "$module_path" "Loaded module: $module_name (size: $module_size, used: $module_used)" "LOW" "$hash" "$metadata" "module=$module_name"
        done < <(lsmod | tail -n +2)
    fi

    # Check for kernel module auto-loading configs
    local module_configs=(
        "/etc/modules"
        "/etc/modules-load.d"
    )

    for mod_config in "${module_configs[@]}"; do
        if [[ -e "$mod_config" ]]; then
            if [[ -f "$mod_config" ]]; then
                local hash=$(get_file_hash "$mod_config")
                local metadata=$(get_file_metadata "$mod_config")

                add_finding "Kernel" "ModuleConfig" "module_config" "$mod_config" "Kernel module auto-load config" "MEDIUM" "$hash" "$metadata" ""

            elif [[ -d "$mod_config" ]]; then
                while IFS= read -r -d '' conf_file; do
                    local hash=$(get_file_hash "$conf_file")
                    local metadata=$(get_file_metadata "$conf_file")

                    add_finding "Kernel" "ModuleConfig" "module_config" "$conf_file" "Module config: $(basename "$conf_file")" "MEDIUM" "$hash" "$metadata" ""
                done < <(find "$mod_config" -type f -print0 2>/dev/null)
            fi
        fi
    done
}

# Check additional persistence locations
check_additional_persistence() {
    log_info "[7/8] Checking additional persistence mechanisms..."

    # XDG autostart
    local autostart_dirs=(
        "/etc/xdg/autostart"
        "$HOME/.config/autostart"
    )

    for autostart_dir in "${autostart_dirs[@]}"; do
        if [[ -d "$autostart_dir" ]]; then
            while IFS= read -r -d '' desktop_file; do
                local hash=$(get_file_hash "$desktop_file")
                local metadata=$(get_file_metadata "$desktop_file")
                local exec_line=$(grep "^Exec=" "$desktop_file" 2>/dev/null | cut -d'=' -f2- || echo "")

                local confidence="LOW"
                local finding_matched_pattern=""
                local finding_matched_string=""
                if quick_suspicious_check "$exec_line"; then
                    confidence="HIGH"
                    finding_matched_pattern="$MATCHED_PATTERN"
                    finding_matched_string="$MATCHED_STRING"
                    log_finding "Suspicious XDG autostart: $desktop_file"
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
    fi

    # Check sudoers for persistence
    if [[ $EUID_CHECK -eq 0 ]]; then
        if [[ -f "/etc/sudoers" ]]; then
            local hash=$(get_file_hash "/etc/sudoers")
            local metadata=$(get_file_metadata "/etc/sudoers")

            add_finding "Privilege" "Sudoers" "sudoers_file" "/etc/sudoers" "Sudoers configuration" "LOW" "$hash" "$metadata" ""
        fi

        if [[ -d "/etc/sudoers.d" ]]; then
            while IFS= read -r -d '' sudoers_file; do
                local hash=$(get_file_hash "$sudoers_file")
                local metadata=$(get_file_metadata "$sudoers_file")

                add_finding "Privilege" "Sudoers" "sudoers_drop_in" "$sudoers_file" "Sudoers drop-in: $(basename "$sudoers_file")" "MEDIUM" "$hash" "$metadata" ""
            done < <(find /etc/sudoers.d -type f -print0 2>/dev/null)
        fi
    fi

    # Check for PAM backdoors
    if [[ -d "/etc/pam.d" ]]; then
        while IFS= read -r -d '' pam_file; do
            local hash=$(get_file_hash "$pam_file")
            local metadata=$(get_file_metadata "$pam_file")
            local suspicious_pam=$(grep -v "^#" "$pam_file" 2>/dev/null | grep -E "pam_.*\.so" | grep -vE "(pam_unix|pam_systemd|pam_permit|pam_deny|pam_env|pam_limits)" || echo "")

            local confidence="LOW"
            local finding_matched_pattern=""
            local finding_matched_string=""
            if [[ -n "$suspicious_pam" ]]; then
                confidence="MEDIUM"
                finding_matched_pattern="unusual_pam_module"
                finding_matched_string="$suspicious_pam"
            fi

            add_finding "PAM" "Config" "pam_config" "$pam_file" "PAM config: $(basename "$pam_file")" "$confidence" "$hash" "$metadata" "" "$finding_matched_pattern" "$finding_matched_string"
        done < <(find /etc/pam.d -type f -print0 2>/dev/null)
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
                local content=$(head -n 100 "$motd_script" 2>/dev/null || echo "")

                local confidence="LOW"
                local finding_matched_pattern=""
                local finding_matched_string=""
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

                add_finding "MOTD" "Script" "motd_script" "$motd_script" "MOTD script: $(basename "$motd_script")" "$confidence" "$hash" "$metadata" "" "$finding_matched_pattern" "$finding_matched_string"
            done < <(find "$motd_dir" -type f -print0 2>/dev/null)
        fi
    done
}

# Check common backdoor locations (inspired by Crackdown and DFIR research)
check_common_backdoors() {
    log_info "[8/8] Checking common backdoor locations..."

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
            if [[ $uid -ge 1000 ]] || [[ $uid -eq 0 ]]; then
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

            add_finding "GitConfig" "User" "git_config" "$HOME/.gitconfig" "Current user git config" "LOW" "$hash" "$metadata" "user=$(whoami)"
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
            # Look for recently modified PHP/ASP files (last 30 days)
            while IFS= read -r -d '' web_file; do
                local hash=$(get_file_hash "$web_file")
                local metadata=$(get_file_metadata "$web_file")

                # Check modification time
                local mod_time=$(stat -c %Y "$web_file" 2>/dev/null || stat -f %m "$web_file" 2>/dev/null || echo "0")
                local current_time=$(date +%s)
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
            done < <(find "$web_dir" -type f \( -name "*.php" -o -name "*.asp" -o -name "*.aspx" -o -name "*.jsp" \) -print0 2>/dev/null | head -100)
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
    echo

    # Run detection modules
    check_systemd
    echo

    check_cron
    echo

    check_shell_profiles
    echo

    check_ssh
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

    # Cleanup
    rm -rf "$TEMP_DATA" 2>/dev/null

    log_info "Analysis completed at $(date)"
}

# Run main function
main "$@"
