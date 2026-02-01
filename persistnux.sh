#!/bin/bash
################################################################################
# Persistnux - Linux Persistence Detection Tool
# A comprehensive DFIR tool to detect known Linux persistence mechanisms
# Author: DFIR Community Project
# License: MIT
# Version: 1.7.2
################################################################################

# Note: Using set -o pipefail but NOT set -e, as many commands (grep, stat, etc.)
# return non-zero exit codes in normal operation which would prematurely terminate the script
set -o pipefail

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
    "curl.*|.*bash"
    "curl.*|.*sh"
    "wget.*|.*bash"
    "wget.*|.*sh"
    "curl.*sh -c"
    "wget.*sh -c"
    "chmod \+x.*tmp"
    "chmod 777"
    "base64.*decode"
    "eval.*base64"
    "echo.*base64.*decode"
    "python.*-c.*socket"
    "perl.*socket"
    "ruby.*socket"
    "php.*fsockopen"
    "ncat"
    "socat"
)

declare -a SUSPICIOUS_LOCATIONS=(
    "/dev/shm"
    "/tmp"
    "/var/tmp"
    "hidden directory"
    "\.\."
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
declare -a NEVER_WHITELIST_PATTERNS=(
    "/dev/tcp/"
    "/dev/udp/"
    "bash -i"
    "sh -i"
    "nc -e"
    "| nc"
    "| bash"
    "| sh"
    ">& /dev/"
    "exec.*socket"
    "python.*socket"
    "perl.*socket"
    "ruby.*socket"
    "socat"
    "telnet.*bash"
    "xterm -display"
    "mknod.*backpipe"
)

# Check if content matches suspicious patterns
check_suspicious_patterns() {
    local content="$1"
    local pattern_type="${2:-all}"  # all, network, command, location, file

    # Network-based patterns
    if [[ "$pattern_type" == "all" ]] || [[ "$pattern_type" == "network" ]]; then
        for pattern in "${SUSPICIOUS_NETWORK_PATTERNS[@]}"; do
            if echo "$content" | grep -qE "$pattern" 2>/dev/null; then
                return 0  # Found suspicious pattern
            fi
        done
    fi

    # Command-based patterns
    if [[ "$pattern_type" == "all" ]] || [[ "$pattern_type" == "command" ]]; then
        for pattern in "${SUSPICIOUS_COMMANDS[@]}"; do
            if echo "$content" | grep -qE "$pattern" 2>/dev/null; then
                return 0  # Found suspicious pattern
            fi
        done
    fi

    # Location-based patterns
    if [[ "$pattern_type" == "all" ]] || [[ "$pattern_type" == "location" ]]; then
        for pattern in "${SUSPICIOUS_LOCATIONS[@]}"; do
            if echo "$content" | grep -qE "$pattern" 2>/dev/null; then
                return 0  # Found suspicious pattern
            fi
        done
    fi

    # File-based patterns
    if [[ "$pattern_type" == "all" ]] || [[ "$pattern_type" == "file" ]]; then
        for pattern in "${SUSPICIOUS_FILES[@]}"; do
            if echo "$content" | grep -qE "$pattern" 2>/dev/null; then
                return 0  # Found suspicious pattern
            fi
        done
    fi

    return 1  # No suspicious patterns found
}

################################################################################
# Utility Functions
################################################################################

show_usage() {
    cat << EOF
Usage: sudo ./persistnux.sh [OPTIONS]

Persistnux - Linux Persistence Detection Tool v1.7.2
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

    Linux Persistence Detection Tool v1.7.2
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

# Check if file is managed by package manager (reduces false positives)
is_package_managed() {
    local file="$1"

    # Check dpkg (Debian/Ubuntu)
    if command -v dpkg &> /dev/null; then
        if dpkg -S "$file" &>/dev/null; then
            local package=$(dpkg -S "$file" 2>/dev/null | cut -d':' -f1 | head -n1)

            # Verify file hasn't been tampered with
            # dpkg --verify returns errors if file modified/missing
            if command -v dpkg &> /dev/null; then
                local verify_output=$(dpkg --verify "$package" 2>/dev/null | grep -F "$file" || true)
                if [[ -n "$verify_output" ]]; then
                    # File has been modified - flag as compromised
                    echo "dpkg:$package:MODIFIED"
                    return 2  # Special return code for modified package file
                fi
            fi

            echo "dpkg:$package"
            return 0
        fi
    fi

    # Check rpm (RedHat/CentOS/Fedora)
    if command -v rpm &> /dev/null; then
        if rpm -qf "$file" &>/dev/null; then
            local package=$(rpm -qf "$file" 2>/dev/null | head -n1)

            # Verify file integrity using rpm -V
            local verify_output=$(rpm -V "$package" 2>/dev/null | grep -F "$file" || true)
            if [[ -n "$verify_output" ]]; then
                # File has been modified
                echo "rpm:$package:MODIFIED"
                return 2  # Special return code for modified package file
            fi

            echo "rpm:$package"
            return 0
        fi
    fi

    # Not managed by package manager
    echo "unmanaged"
    return 1
}

# Extract the first executable path from a command
get_executable_from_command() {
    local command="$1"

    # Remove systemd prefixes (@, -, :, +, !)
    command="${command#[@\-:+!]}"

    # Extract first word (the executable)
    local executable=$(echo "$command" | awk '{print $1}')

    # Remove quotes if present
    executable="${executable//\"/}"
    executable="${executable//\'/}"

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

    # Safe argument parsing without eval
    # We'll manually tokenize respecting quotes
    local -a args=()
    local current_arg=""
    local in_single_quote=0
    local in_double_quote=0
    local i=0
    local len=${#command}
    local char=""

    while [[ $i -lt $len ]]; do
        char="${command:$i:1}"

        if [[ $in_single_quote -eq 1 ]]; then
            if [[ "$char" == "'" ]]; then
                in_single_quote=0
            else
                current_arg+="$char"
            fi
        elif [[ $in_double_quote -eq 1 ]]; then
            if [[ "$char" == '"' ]]; then
                in_double_quote=0
            else
                current_arg+="$char"
            fi
        elif [[ "$char" == "'" ]]; then
            in_single_quote=1
        elif [[ "$char" == '"' ]]; then
            in_double_quote=1
        elif [[ "$char" == " " ]] || [[ "$char" == $'\t' ]]; then
            if [[ -n "$current_arg" ]]; then
                args+=("$current_arg")
                current_arg=""
            fi
        else
            current_arg+="$char"
        fi

        i=$((i + 1))
    done

    # Add last argument if present
    if [[ -n "$current_arg" ]]; then
        args+=("$current_arg")
    fi

    # Need at least interpreter + one more arg
    if [[ ${#args[@]} -lt 2 ]]; then
        echo ""
        return 1
    fi

    # Look through remaining arguments for the script file
    local arg=""
    for ((i=1; i<${#args[@]}; i++)); do
        arg="${args[i]}"

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
analyze_script_content() {
    local script_file="$1"

    # Check if file exists and is readable
    if [[ ! -f "$script_file" ]] || [[ ! -r "$script_file" ]]; then
        return 1  # Cannot analyze, treat as clean
    fi

    # Read first 1000 lines of script (to avoid huge files)
    local script_content=$(head -n 1000 "$script_file" 2>/dev/null)

    # Check for dangerous patterns in NEVER_WHITELIST_PATTERNS
    for pattern in "${NEVER_WHITELIST_PATTERNS[@]}"; do
        if echo "$script_content" | grep -qiE "$pattern"; then
            return 0  # SUSPICIOUS - found dangerous pattern
        fi
    done

    # Check for additional script-specific suspicious patterns
    local suspicious_script_patterns=(
        "eval.*\$"                    # eval with variables
        "exec.*\$"                    # exec with variables
        "\$\(curl"                    # Command substitution with curl
        "\$\(wget"                    # Command substitution with wget
        "base64.*-d"                  # Base64 decode (potential obfuscation)
        "openssl.*enc.*-d"            # Encrypted payload decryption
        "mkfifo"                      # Named pipes (common in reverse shells)
        "nc.*-l.*-p"                  # Netcat listener
        "socat.*TCP"                  # Socat TCP connections
        "python.*-c"                  # Python one-liners
        "perl.*-e"                    # Perl one-liners
        "ruby.*-e"                    # Ruby one-liners
        "awk.*system"                 # AWK system calls
        "/proc/self/exe"              # Self-execution tricks
        "chmod.*\+x.*tmp"             # Making temp files executable
        "chmod.*777"                  # Overly permissive permissions
    )

    for pattern in "${suspicious_script_patterns[@]}"; do
        if echo "$script_content" | grep -qiE "$pattern"; then
            return 0  # SUSPICIOUS - found dangerous script pattern
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
        # Patterns: variable=LONGSTRING or variable="LONGSTRING" or variable='LONGSTRING'

        # Try to match quoted strings first (double quotes)
        if [[ "$line" =~ =\"([^\"]{30,})\" ]]; then
            local value="${BASH_REMATCH[1]}"

            # Check entropy of this value
            if is_high_entropy "$value" 4.5; then
                return 0  # SUSPICIOUS - high entropy indicates obfuscation
            fi
        # Try single quoted strings
        elif [[ "$line" =~ =\'([^\']{30,})\' ]]; then
            local value="${BASH_REMATCH[1]}"

            # Check entropy of this value
            if is_high_entropy "$value" 4.5; then
                return 0  # SUSPICIOUS - high entropy indicates obfuscation
            fi
        # Fall back to unquoted strings without spaces
        elif [[ "$line" =~ =([^[:space:]]{30,}) ]]; then
            local value="${BASH_REMATCH[1]}"
            # Remove surrounding quotes if present (in case regex caught partial quotes)
            value="${value#\"}"
            value="${value#\'}"
            value="${value%\"}"
            value="${value%\'}"

            # Check entropy of this value
            if is_high_entropy "$value" 4.5; then
                return 0  # SUSPICIOUS - high entropy indicates obfuscation
            fi
        fi

    done <<< "$script_content"

    return 1  # Clean - no suspicious patterns found
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
                local pkg_status=$(is_package_managed "$executable")
                local pkg_return=$?

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
        local pkg_status=$(is_package_managed "$executable")
        local pkg_return=$?

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

    # CSV output (new structure)
    echo "$(escape_csv "$timestamp"),$(escape_csv "$HOSTNAME"),$(escape_csv "$category"),$(escape_csv "$confidence"),$(escape_csv "$file_path"),$(escape_csv "$file_hash"),$(escape_csv "$file_owner"),$(escape_csv "$file_permissions"),$(escape_csv "$file_age_days"),$(escape_csv "$package_status"),$(escape_csv "$command"),$(escape_csv "$enabled_status"),$(escape_csv "$description")" >> "$CSV_FILE"

    # JSONL output (new structure with proper escaping)
    cat >> "$JSONL_FILE" << EOF
{"timestamp":"$timestamp","hostname":"$HOSTNAME","category":"$(escape_json "$category")","confidence":"$confidence","file_path":"$(escape_json "$file_path")","file_hash":"$file_hash","file_owner":"$(escape_json "$file_owner")","file_permissions":"$file_permissions","file_age_days":"$file_age_days","package_status":"$(escape_json "$package_status")","command":"$(escape_json "$command")","enabled_status":"$(escape_json "$enabled_status")","description":"$(escape_json "$description")"}
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

    # Call new structured function
    add_finding_new "$clean_category" "$confidence" "$location" "$hash" "$owner" "$permissions" "$days_old" "$package_status" "$command" "$enabled" "$persistence_type"
}

# Initialize output files
init_output() {
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$TEMP_DATA"

    # CSV header (new structured format)
    echo "timestamp,hostname,category,confidence,file_path,file_hash,file_owner,file_permissions,file_age_days,package_status,command,enabled_status,description" > "$CSV_FILE"

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

                # Note: We don't skip if ExecStart is empty - timers, sockets, and some services don't have it
                # We still want to report these files for completeness

                # Check if service is enabled
                local enabled_status="disabled"
                if systemctl is-enabled "$service_name" &>/dev/null; then
                    enabled_status="enabled"
                fi

                local confidence="MEDIUM"

                # Check modification time (recently modified = more suspicious)
                local mod_time=$(stat -c %Y "$service_file" 2>/dev/null || stat -f %m "$service_file" 2>/dev/null || echo "0")
                local current_time=$(date +%s)
                local days_old=$(( (current_time - mod_time) / 86400 ))

                # Only analyze ExecStart if it exists
                local executable=""
                local script_to_analyze=""

                if [[ -n "$exec_start" ]]; then
                    # First: Check for explicitly dangerous patterns (HIGH confidence)
                    if echo "$exec_start" | grep -qiE "(curl.*\||wget.*\||nc -e|/dev/tcp/|/dev/udp/|bash -i|sh -i)"; then
                        confidence="HIGH"
                        log_finding "Dangerous command in systemd service: $service_file"
                    elif check_suspicious_patterns "$exec_start"; then
                        confidence="HIGH"
                        log_finding "Suspicious systemd service (advanced patterns): $service_file"
                    # Second: Check if command is safe (downgrade confidence)
                    elif is_command_safe "$exec_start"; then
                        # Safe system binary execution
                        confidence="LOW"
                    # Third: Unknown command + recent modification = suspicious
                    elif [[ $days_old -lt 7 ]] && [[ "$enabled_status" == "enabled" ]]; then
                        confidence="HIGH"
                        log_finding "Recently created enabled systemd service with unknown command: $service_file (${days_old} days old)"
                    # Fourth: Unknown command but old and package-managed = probably safe
                    else
                        # Will be downgraded further if package-managed
                        confidence="MEDIUM"
                    fi

                    # Fifth: Check if ExecStart uses an interpreter (python/perl/bash/etc.)
                    # CRITICAL: Analyze the script argument, not the interpreter binary
                    executable=$(get_executable_from_command "$exec_start")

                if [[ -n "$executable" ]] && [[ -f "$executable" ]]; then
                    # Check if executable is an interpreter
                    if is_interpreter "$executable"; then
                        # First, verify the interpreter binary itself isn't compromised
                        local interp_pkg_status=$(is_package_managed "$executable")
                        local interp_pkg_return=$?

                        if [[ $interp_pkg_return -eq 2 ]]; then
                            # Interpreter binary itself was MODIFIED - CRITICAL
                            confidence="CRITICAL"
                            log_finding "Systemd service uses modified interpreter binary: $executable"
                        elif [[ $interp_pkg_return -eq 1 ]]; then
                            # Interpreter is unmanaged - very suspicious
                            if [[ ! "$executable" =~ ^/(usr/bin|usr/local/bin|bin) ]]; then
                                confidence="HIGH"
                                log_finding "Systemd service uses unmanaged interpreter from unusual location: $executable"
                            fi
                        fi

                        # Extract the script file from arguments
                        script_to_analyze=$(get_script_from_interpreter_command "$exec_start")

                        if [[ -n "$script_to_analyze" ]] && [[ -f "$script_to_analyze" ]]; then
                            log_finding "Systemd service uses interpreter: $service_file -> $executable $script_to_analyze"

                            # Analyze the script file, not the interpreter
                            if is_script "$script_to_analyze"; then
                                if analyze_script_content "$script_to_analyze"; then
                                    confidence="HIGH"
                                    log_finding "Interpreter script contains suspicious content: $script_to_analyze"
                                fi
                            fi

                            # Also check if the script itself is package-managed
                            local script_pkg_status=$(is_package_managed "$script_to_analyze")
                            local script_pkg_return=$?

                            if [[ $script_pkg_return -eq 2 ]]; then
                                # Script file was MODIFIED
                                confidence="CRITICAL"
                                log_finding "Interpreter script is modified package file: $script_to_analyze"
                            elif [[ $script_pkg_return -eq 1 ]]; then
                                # Script is unmanaged - suspicious if in unusual location
                                if [[ "$script_to_analyze" =~ ^/(tmp|dev|shm|var/tmp) ]]; then
                                    confidence="HIGH"
                                    log_finding "Interpreter executing script from suspicious location: $script_to_analyze"
                                elif [[ "$script_to_analyze" =~ ^/(opt|usr/local|home) ]]; then
                                    # Common but unmanaged locations - keep MEDIUM
                                    [[ "$confidence" == "LOW" ]] && confidence="MEDIUM"
                                fi
                            fi
                        else
                            # Interpreter with no file argument (inline code via -c flag)
                            # This is inherently suspicious
                            if [[ "$exec_start" =~ \ -c\  ]]; then
                                confidence="HIGH"
                                log_finding "Systemd service uses interpreter with inline code (-c flag): $service_file"
                            fi
                        fi
                    else
                        # Not an interpreter - check if it's a script directly
                        if is_script "$executable"; then
                            if analyze_script_content "$executable"; then
                                confidence="HIGH"
                                log_finding "Systemd service executes script with suspicious content: $service_file -> $executable"
                            fi
                        fi

                        # Check if the executable itself is package-managed
                        local exec_pkg_status=$(is_package_managed "$executable")
                        local exec_pkg_return=$?

                        if [[ $exec_pkg_return -eq 2 ]]; then
                            # Executable file was MODIFIED
                            confidence="CRITICAL"
                            log_finding "Systemd service executes modified package file: $executable"
                        elif [[ $exec_pkg_return -eq 1 ]]; then
                            # Executable is unmanaged - suspicious if in unusual location
                            if [[ "$executable" =~ ^/(tmp|dev|shm|var/tmp) ]]; then
                                confidence="HIGH"
                                log_finding "Systemd service executes file from suspicious location: $executable"
                            fi
                        fi
                    fi
                fi
                fi  # End of: if [[ -n "$exec_start" ]]

                # Determine package status for reporting
                # Use the executable's package status if available (already checked above)
                local package_status="unmanaged"
                if [[ -n "$executable" ]] && [[ -f "$executable" ]]; then
                    # Check if we already have package status from interpreter or exec checks
                    if is_interpreter "$executable"; then
                        # Reuse interp_pkg_status if it was an interpreter
                        if [[ -n "${interp_pkg_status:-}" ]]; then
                            package_status="$interp_pkg_status"
                        else
                            package_status=$(is_package_managed "$executable")
                        fi
                    elif [[ -n "${exec_pkg_status:-}" ]]; then
                        # Reuse exec_pkg_status from non-interpreter checks
                        package_status="$exec_pkg_status"
                    else
                        # This shouldn't happen but check anyway
                        package_status=$(is_package_managed "$executable")
                    fi
                else
                    # No executable found, check if service file itself is package-managed
                    package_status=$(is_package_managed "$service_file")
                    confidence=$(adjust_confidence_for_package "$confidence" "$package_status")
                fi

                # Extract owner and permissions from metadata
                local owner=$(get_owner_from_metadata "$metadata")
                local permissions=$(get_permissions_from_metadata "$metadata")

                # Use new structured format directly (DEFER hash until filtering)
                add_finding_new "Systemd Service" "$confidence" "$service_file" "DEFER" "$owner" "$permissions" "$days_old" "$package_status" "$exec_start" "$enabled_status" "$service_name"

            done < <(find "$path" -maxdepth 1 -type f \( -name "*.service" -o -name "*.timer" -o -name "*.socket" \) -print0 2>/dev/null)
        fi
    done
}

# Check cron jobs
check_cron() {
    log_info "[2/8] Checking cron jobs and scheduled tasks..."

    # System crontabs
    local cron_files=(
        "/etc/crontab"
        "/etc/cron.d"
        "/etc/cron.daily"
        "/etc/cron.hourly"
        "/etc/cron.weekly"
        "/etc/cron.monthly"
        "/var/spool/cron"
        "/var/spool/cron/crontabs"
    )

    for cron_path in "${cron_files[@]}"; do
        if [[ -e "$cron_path" ]]; then
            if [[ -f "$cron_path" ]]; then
                # Single file
                local hash=$(get_file_hash "$cron_path")
                local metadata=$(get_file_metadata "$cron_path")
                local content=$(grep -Ev "^#|^$" "$cron_path" 2>/dev/null | head -20 || echo "")

                local confidence="MEDIUM"
                if echo "$content" | grep -qiE "(curl|wget|nc|netcat|/tmp|/dev/shm|/dev/tcp|/dev/udp|base64)"; then
                    confidence="HIGH"
                    log_finding "Suspicious cron job in: $cron_path"
                elif check_suspicious_patterns "$content"; then
                    confidence="HIGH"
                    log_finding "Suspicious cron job (advanced patterns): $cron_path"
                fi

                # Check if cron file is a script and analyze its content
                if is_script "$cron_path"; then
                    if analyze_script_content "$cron_path"; then
                        confidence="HIGH"
                        log_finding "Cron file contains suspicious script content: $cron_path"
                    fi
                fi

                # Check if cron entries use interpreters
                while IFS= read -r cron_line; do
                    [[ -z "$cron_line" ]] && continue

                    # Extract command from cron line (skip time/user fields)
                    local cron_command=$(echo "$cron_line" | awk '{for(i=6;i<=NF;i++) printf "%s ", $i; print ""}')
                    local cron_executable=$(get_executable_from_command "$cron_command")

                    if [[ -n "$cron_executable" ]] && [[ -f "$cron_executable" ]]; then
                        if is_interpreter "$cron_executable"; then
                            local cron_script=$(get_script_from_interpreter_command "$cron_command")
                            if [[ -n "$cron_script" ]] && [[ -f "$cron_script" ]]; then
                                if is_script "$cron_script"; then
                                    if analyze_script_content "$cron_script"; then
                                        confidence="HIGH"
                                        log_finding "Cron entry uses interpreter with suspicious script: $cron_path -> $cron_script"
                                    fi
                                fi
                            fi
                        fi
                    fi
                done <<< "$content"

                add_finding "Cron" "System" "cron_file" "$cron_path" "Cron configuration file" "$confidence" "$hash" "$metadata" "entries=$(echo "$content" | wc -l)"

            elif [[ -d "$cron_path" ]]; then
                # Directory of cron jobs
                while IFS= read -r -d '' cron_file; do
                    local hash=$(get_file_hash "$cron_file")
                    local metadata=$(get_file_metadata "$cron_file")
                    local content=$(grep -Ev "^#|^$" "$cron_file" 2>/dev/null | head -10 || echo "")

                    local confidence="MEDIUM"

                    # Check modification time
                    local mod_time=$(stat -c %Y "$cron_file" 2>/dev/null || stat -f %m "$cron_file" 2>/dev/null || echo "0")
                    local current_time=$(date +%s)
                    local days_old=$(( (current_time - mod_time) / 86400 ))

                    if echo "$content" | grep -qiE "(curl|wget|nc|netcat|/tmp|/dev/shm|/dev/tcp|/dev/udp|base64|chmod \+x)"; then
                        confidence="HIGH"
                        log_finding "Suspicious cron job: $cron_file"
                    elif check_suspicious_patterns "$content"; then
                        confidence="HIGH"
                        log_finding "Suspicious cron job (advanced patterns): $cron_file"
                    elif [[ $days_old -lt 7 ]]; then
                        confidence="HIGH"
                        log_finding "Recently created cron job: $cron_file (${days_old} days old)"
                    fi

                    # Check if cron job is a script and analyze its content
                    if is_script "$cron_file"; then
                        if analyze_script_content "$cron_file"; then
                            confidence="HIGH"
                            log_finding "Cron job script contains suspicious content: $cron_file"
                        fi
                    fi

                    # Check if cron entries use interpreters
                    while IFS= read -r cron_line; do
                        [[ -z "$cron_line" ]] && continue

                        # Extract command from cron line
                        local cron_command=$(echo "$cron_line" | awk '{for(i=6;i<=NF;i++) printf "%s ", $i; print ""}')
                        local cron_executable=$(get_executable_from_command "$cron_command")

                        if [[ -n "$cron_executable" ]] && [[ -f "$cron_executable" ]]; then
                            if is_interpreter "$cron_executable"; then
                                local cron_script=$(get_script_from_interpreter_command "$cron_command")
                                if [[ -n "$cron_script" ]] && [[ -f "$cron_script" ]]; then
                                    if is_script "$cron_script"; then
                                        if analyze_script_content "$cron_script"; then
                                            confidence="HIGH"
                                            log_finding "Cron entry uses interpreter with suspicious script: $cron_file -> $cron_script"
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    done <<< "$content"

                    # Check if file is package-managed and adjust confidence
                    local package_status=$(is_package_managed "$cron_file")
                    confidence=$(adjust_confidence_for_package "$confidence" "$package_status")

                    add_finding "Cron" "System" "cron_script" "$cron_file" "Scheduled script: $(basename "$cron_file")" "$confidence" "$hash" "$metadata" "content_preview=${content:0:100}|days_old=$days_old|package=$package_status"

                done < <(find "$cron_path" -type f -print0 2>/dev/null)
            fi
        fi
    done

    # User crontabs
    if [[ $EUID_CHECK -eq 0 ]]; then
        while IFS=: read -r username _ uid _; do
            if [[ $uid -ge 1000 ]] || [[ $uid -eq 0 ]]; then
                local user_cron=$(crontab -u "$username" -l 2>/dev/null || echo "")
                if [[ -n "$user_cron" ]]; then
                    local confidence="MEDIUM"
                    if echo "$user_cron" | grep -qiE "(curl|wget|nc|netcat|/tmp|/dev/shm|/dev/tcp|/dev/udp|base64)"; then
                        confidence="HIGH"
                        log_finding "Suspicious user crontab for: $username"
                    fi

                    add_finding "Cron" "User" "user_crontab" "/var/spool/cron/crontabs/$username" "User $username crontab entries" "$confidence" "N/A" "user=$username" "preview=${user_cron:0:100}"
                fi
            fi
        done < /etc/passwd
    else
        # Non-root: check only current user
        local user_cron=$(crontab -l 2>/dev/null || echo "")
        if [[ -n "$user_cron" ]]; then
            add_finding "Cron" "User" "user_crontab" "~/.crontab" "Current user crontab" "MEDIUM" "N/A" "user=$(whoami)" "preview=${user_cron:0:100}"
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
                if echo "$job_details" | grep -qiE "(curl|wget|nc|netcat)"; then
                    confidence="HIGH"
                    log_finding "Suspicious at job: $job_id"
                fi

                add_finding "Scheduled" "At" "at_job" "/var/spool/cron/atjobs/$job_id" "At job $job_id" "$confidence" "N/A" "$job_line" "job_id=$job_id"
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
                local suspicious_content=$(grep -iE "(curl|wget|nc |netcat|eval|base64.*decode|chmod \+x)" "$profile" 2>/dev/null || echo "")

                local confidence="LOW"
                if [[ -n "$suspicious_content" ]]; then
                    confidence="HIGH"
                    log_finding "Suspicious content in profile: $profile"
                fi

                # Check if file is package-managed and adjust confidence
                local package_status=$(is_package_managed "$profile")
                confidence=$(adjust_confidence_for_package "$confidence" "$package_status")

                add_finding "ShellProfile" "System" "profile_file" "$profile" "System shell profile" "$confidence" "$hash" "$metadata" "suspicious_lines=$(echo "$suspicious_content" | wc -l)|package=$package_status"

            elif [[ -d "$profile" ]]; then
                while IFS= read -r -d '' profile_file; do
                    local hash=$(get_file_hash "$profile_file")
                    local metadata=$(get_file_metadata "$profile_file")
                    local suspicious_content=$(grep -iE "(curl|wget|nc |netcat|eval|base64.*decode)" "$profile_file" 2>/dev/null || echo "")

                    local confidence="LOW"
                    if [[ -n "$suspicious_content" ]]; then
                        confidence="HIGH"
                        log_finding "Suspicious profile script: $profile_file"
                    fi

                    # Check if file is package-managed and adjust confidence
                    local package_status=$(is_package_managed "$profile_file")
                    confidence=$(adjust_confidence_for_package "$confidence" "$package_status")

                    add_finding "ShellProfile" "System" "profile_script" "$profile_file" "Profile.d script: $(basename "$profile_file")" "$confidence" "$hash" "$metadata" "package=$package_status"

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
                        local suspicious_content=$(grep -iE "(curl|wget|nc |netcat|eval|base64.*decode|chmod \+x)" "$profile_path" 2>/dev/null || echo "")

                        local confidence="LOW"
                        if [[ -n "$suspicious_content" ]]; then
                            confidence="HIGH"
                            log_finding "Suspicious user profile: $profile_path (user: $username)"
                        fi

                        add_finding "ShellProfile" "User" "user_profile" "$profile_path" "User profile for $username" "$confidence" "$hash" "$metadata" "user=$username"
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
                local suspicious_content=$(grep -iE "(curl|wget|nc |netcat|eval|base64.*decode)" "$profile_path" 2>/dev/null || echo "")

                local confidence="LOW"
                if [[ -n "$suspicious_content" ]]; then
                    confidence="MEDIUM"
                fi

                add_finding "ShellProfile" "User" "user_profile" "$profile_path" "Current user profile" "$confidence" "$hash" "$metadata" "user=$(whoami)"
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
                        if [[ -n "$suspicious_config" ]]; then
                            confidence="MEDIUM"
                        fi

                        add_finding "SSH" "Config" "ssh_config" "$ssh_dir/config" "User SSH config for $username" "$confidence" "$hash" "$metadata" "user=$username"
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
        if echo "$suspicious_sshd" | grep -qiE "(PermitRootLogin yes|PermitEmptyPasswords yes)"; then
            confidence="MEDIUM"
        fi

        add_finding "SSH" "SystemConfig" "sshd_config" "/etc/ssh/sshd_config" "SSH daemon configuration" "$confidence" "$hash" "$metadata" ""
    fi
}

# Check init scripts and rc.local
check_init_scripts() {
    log_info "[5/8] Checking init scripts and rc.local..."

    local init_paths=(
        "/etc/rc.local"
        "/etc/rc.d/rc.local"
        "/etc/init.d"
        "/etc/rc*.d"
    )

    for init_path in "${init_paths[@]}"; do
        if [[ -e "$init_path" ]]; then
            if [[ -f "$init_path" ]]; then
                local hash=$(get_file_hash "$init_path")
                local metadata=$(get_file_metadata "$init_path")
                local content=$(grep -Ev "^#|^$" "$init_path" 2>/dev/null | head -20 || echo "")

                local confidence="MEDIUM"
                if echo "$content" | grep -qiE "(curl|wget|nc|netcat|/tmp|/dev/shm)"; then
                    confidence="HIGH"
                    log_finding "Suspicious init script: $init_path"
                fi

                add_finding "Init" "Script" "init_script" "$init_path" "Init script: $(basename "$init_path")" "$confidence" "$hash" "$metadata" ""

            elif [[ -d "$init_path" ]]; then
                while IFS= read -r -d '' init_file; do
                    # Skip if it's a symbolic link to /dev/null or similar
                    if [[ -L "$init_file" ]]; then
                        local link_target=$(readlink -f "$init_file")
                        if [[ "$link_target" == "/dev/null" ]]; then
                            continue
                        fi
                    fi

                    local hash=$(get_file_hash "$init_file")
                    local metadata=$(get_file_metadata "$init_file")
                    local content=$(grep -Ev "^#|^$" "$init_file" 2>/dev/null | head -10 || echo "")

                    local confidence="LOW"
                    if echo "$content" | grep -qiE "(curl|wget|nc|netcat|/tmp|/dev/shm)"; then
                        confidence="HIGH"
                        log_finding "Suspicious init script: $init_file"
                    fi

                    add_finding "Init" "Script" "init_script" "$init_file" "Init script: $(basename "$init_file")" "$confidence" "$hash" "$metadata" "dir=$(dirname "$init_file")"

                done < <(find "$init_path" -maxdepth 1 -type f -print0 2>/dev/null)
            fi
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
                if echo "$exec_line" | grep -qiE "(curl|wget|nc|netcat|/tmp|/dev/shm|bash -c|sh -c)"; then
                    confidence="HIGH"
                    log_finding "Suspicious XDG autostart: $desktop_file"
                fi

                add_finding "Autostart" "XDG" "xdg_autostart" "$desktop_file" "XDG autostart: $(basename "$desktop_file") | Exec: $exec_line" "$confidence" "$hash" "$metadata" ""
            done < <(find "$autostart_dir" -type f -name "*.desktop" -print0 2>/dev/null)
        fi
    done

    # Check /etc/environment
    if [[ -f "/etc/environment" ]]; then
        local hash=$(get_file_hash "/etc/environment")
        local metadata=$(get_file_metadata "/etc/environment")
        local suspicious_env=$(grep -iE "(LD_PRELOAD|LD_LIBRARY_PATH)" /etc/environment 2>/dev/null || echo "")

        local confidence="LOW"
        if [[ -n "$suspicious_env" ]]; then
            confidence="HIGH"
            log_finding "Suspicious environment variables in /etc/environment"
        fi

        add_finding "Environment" "System" "environment_file" "/etc/environment" "System environment file" "$confidence" "$hash" "$metadata" ""
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
            if [[ -n "$suspicious_pam" ]]; then
                confidence="MEDIUM"
            fi

            add_finding "PAM" "Config" "pam_config" "$pam_file" "PAM config: $(basename "$pam_file")" "$confidence" "$hash" "$metadata" ""
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

                local confidence="LOW"
                if grep -qiE "(curl|wget|nc|netcat|base64)" "$motd_script" 2>/dev/null; then
                    confidence="HIGH"
                    log_finding "Suspicious MOTD script: $motd_script"
                fi

                add_finding "MOTD" "Script" "motd_script" "$motd_script" "MOTD script: $(basename "$motd_script")" "$confidence" "$hash" "$metadata" ""
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
                if check_suspicious_patterns "$content"; then
                    confidence="HIGH"
                    log_finding "Suspicious package manager config: $config_dir"
                fi

                add_finding "PackageManager" "Config" "pkg_config" "$config_dir" "Package manager configuration: $(basename "$config_dir")" "$confidence" "$hash" "$metadata" ""

            elif [[ -d "$config_dir" ]]; then
                while IFS= read -r -d '' config_file; do
                    local hash=$(get_file_hash "$config_file")
                    local metadata=$(get_file_metadata "$config_file")
                    local content=$(head -50 "$config_file" 2>/dev/null || echo "")

                    local confidence="LOW"
                    if check_suspicious_patterns "$content"; then
                        confidence="HIGH"
                        log_finding "Suspicious package manager config: $config_file"
                    fi

                    add_finding "PackageManager" "Config" "pkg_config" "$config_file" "Package manager config: $(basename "$config_file")" "$confidence" "$hash" "$metadata" ""
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
        if echo "$content" | grep -qiE "(permit nopass|persist)"; then
            confidence="HIGH"
            log_finding "Potentially permissive doas configuration"
        fi

        add_finding "Privilege" "Doas" "doas_config" "/etc/doas.conf" "Doas privilege escalation config" "$confidence" "$hash" "$metadata" ""
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
                    if echo "$content" | grep -qiE "(credential.*helper|core.*pager|core.*editor.*sh)"; then
                        confidence="MEDIUM"
                    fi
                    if check_suspicious_patterns "$content"; then
                        confidence="HIGH"
                        log_finding "Suspicious git config for user $username: $gitconfig"
                    fi

                    add_finding "GitConfig" "User" "git_config" "$gitconfig" "User git config for $username" "$confidence" "$hash" "$metadata" "user=$username"
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
            # Limit to 100 files to avoid excessive processing
            local web_file_count=0
            while IFS= read -r -d '' web_file; do
                # Limit number of files processed
                web_file_count=$((web_file_count + 1))
                if [[ $web_file_count -gt 100 ]]; then
                    break
                fi

                local hash=$(get_file_hash "$web_file")
                local metadata=$(get_file_metadata "$web_file")

                # Check modification time
                local mod_time=$(stat -c %Y "$web_file" 2>/dev/null || stat -f %m "$web_file" 2>/dev/null || echo "0")
                local current_time=$(date +%s)
                local days_old=$(( (current_time - mod_time) / 86400 ))

                local confidence="LOW"
                if [[ $days_old -lt 30 ]]; then
                    confidence="MEDIUM"

                    # Check for webshell patterns
                    local content=$(head -100 "$web_file" 2>/dev/null || echo "")
                    if echo "$content" | grep -qiE "(eval|base64_decode|system\(|exec\(|shell_exec|passthru|proc_open|popen)"; then
                        confidence="HIGH"
                        log_finding "Potential webshell detected: $web_file (modified ${days_old} days ago)"
                    fi
                fi

                if [[ $confidence != "LOW" ]]; then
                    add_finding "WebShell" "Suspicious" "web_file" "$web_file" "Recently modified web file in $web_dir (${days_old} days old)" "$confidence" "$hash" "$metadata" "days_old=$days_old"
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
