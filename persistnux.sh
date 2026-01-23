#!/bin/bash
################################################################################
# Persistnux - Linux Persistence Detection Tool
# A comprehensive DFIR tool to detect known Linux persistence mechanisms
# Author: DFIR Community Project
# License: MIT
# Version: 1.0.0
################################################################################

set -euo pipefail

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

# Check if running as root
EUID_CHECK=$(id -u)

################################################################################
# Utility Functions
################################################################################

print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
    ____                  _       __
   / __ \___  __________(_)____/ /___  __  ___  __
  / /_/ / _ \/ ___/ ___/ / ___/ __/ / / / |/_/ |/_/
 / ____/  __/ /  (__  ) (__  ) /_/ /_/ />  <_>  <
/_/    \___/_/  /____/_/____/\__/\__,_/_/|_/_/|_|

    Linux Persistence Detection Tool v1.0.0
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
    ((FINDINGS_COUNT++))
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

# Add finding to output
add_finding() {
    local category="$1"
    local subcategory="$2"
    local persistence_type="$3"
    local location="$4"
    local description="$5"
    local confidence="$6"  # LOW, MEDIUM, HIGH, CRITICAL
    local hash="$7"
    local metadata="$8"
    local additional_info="${9:-}"

    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # CSV output
    echo "$(escape_csv "$timestamp"),$(escape_csv "$category"),$(escape_csv "$subcategory"),$(escape_csv "$persistence_type"),$(escape_csv "$location"),$(escape_csv "$description"),$(escape_csv "$confidence"),$(escape_csv "$hash"),$(escape_csv "$metadata"),$(escape_csv "$additional_info")" >> "$CSV_FILE"

    # JSONL output
    cat >> "$JSONL_FILE" << EOF
{"timestamp":"$timestamp","hostname":"$HOSTNAME","category":"$category","subcategory":"$subcategory","persistence_type":"$persistence_type","location":"$location","description":"$description","confidence":"$confidence","sha256":"$hash","metadata":"$metadata","additional_info":"$additional_info"}
EOF
}

# Initialize output files
init_output() {
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$TEMP_DATA"

    # CSV header
    echo "timestamp,category,subcategory,persistence_type,location,description,confidence,sha256,metadata,additional_info" > "$CSV_FILE"

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
    log_info "Checking systemd services..."

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
                local hash=$(get_file_hash "$service_file")
                local metadata=$(get_file_metadata "$service_file")
                local service_name=$(basename "$service_file")

                # Extract ExecStart from service file
                local exec_start=""
                if [[ -f "$service_file" ]]; then
                    exec_start=$(grep -E "^ExecStart=" "$service_file" 2>/dev/null | head -1 | cut -d'=' -f2- || echo "")
                fi

                # Check if service is enabled
                local enabled_status="disabled"
                if systemctl is-enabled "$service_name" &>/dev/null; then
                    enabled_status="enabled"
                fi

                local confidence="MEDIUM"
                # Increase confidence for suspicious patterns
                if echo "$exec_start" | grep -qiE "(curl|wget|nc|netcat|/tmp|/dev/shm|base64|chmod \+x)"; then
                    confidence="HIGH"
                    log_finding "Suspicious systemd service: $service_file"
                fi

                add_finding "Systemd" "Service" "systemd_service" "$service_file" "Service: $service_name | Status: $enabled_status | ExecStart: $exec_start" "$confidence" "$hash" "$metadata" "enabled=$enabled_status"

            done < <(find "$path" -maxdepth 1 -type f \( -name "*.service" -o -name "*.timer" -o -name "*.socket" \) -print0 2>/dev/null)
        fi
    done
}

# Check cron jobs
check_cron() {
    log_info "Checking cron jobs and scheduled tasks..."

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
                if echo "$content" | grep -qiE "(curl|wget|nc|netcat|/tmp|/dev/shm|base64)"; then
                    confidence="HIGH"
                    log_finding "Suspicious cron job in: $cron_path"
                fi

                add_finding "Cron" "System" "cron_file" "$cron_path" "Cron configuration file" "$confidence" "$hash" "$metadata" "entries=$(echo "$content" | wc -l)"

            elif [[ -d "$cron_path" ]]; then
                # Directory of cron jobs
                while IFS= read -r -d '' cron_file; do
                    local hash=$(get_file_hash "$cron_file")
                    local metadata=$(get_file_metadata "$cron_file")
                    local content=$(grep -Ev "^#|^$" "$cron_file" 2>/dev/null | head -10 || echo "")

                    local confidence="MEDIUM"
                    if echo "$content" | grep -qiE "(curl|wget|nc|netcat|/tmp|/dev/shm|base64|chmod \+x)"; then
                        confidence="HIGH"
                        log_finding "Suspicious cron job: $cron_file"
                    fi

                    add_finding "Cron" "System" "cron_script" "$cron_file" "Scheduled script: $(basename "$cron_file")" "$confidence" "$hash" "$metadata" "content_preview=${content:0:100}"

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
                    if echo "$user_cron" | grep -qiE "(curl|wget|nc|netcat|/tmp|/dev/shm|base64)"; then
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
    log_info "Checking shell profiles and RC files..."

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

                add_finding "ShellProfile" "System" "profile_file" "$profile" "System shell profile" "$confidence" "$hash" "$metadata" "suspicious_lines=$(echo "$suspicious_content" | wc -l)"

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

                    add_finding "ShellProfile" "System" "profile_script" "$profile_file" "Profile.d script: $(basename "$profile_file")" "$confidence" "$hash" "$metadata" ""

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
    log_info "Checking SSH persistence mechanisms..."

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
    log_info "Checking init scripts and rc.local..."

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
    log_info "Checking kernel modules and library preloading..."

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
    log_info "Checking additional persistence mechanisms..."

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

################################################################################
# Main Execution
################################################################################

main() {
    print_banner

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
