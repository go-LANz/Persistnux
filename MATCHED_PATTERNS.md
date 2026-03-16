# Persistnux — Matched Pattern Reference

## Version 2.4.0

Every finding written to CSV and JSONL contains a `matched_pattern` field that identifies exactly which detection rule triggered the finding. This document maps every pattern to its producing module, the precise condition that triggers it, and its meaning for an investigator.

Patterns are grouped by producing module. A single finding carries exactly one pattern (or `pattern+suid_sgid` when the SUID/SGID escalation rule fires on top of another pattern).

---

## Pattern Index

| Pattern | Module | Default Confidence |
|---|---|---|
| [modified_package](#modified_package) | systemd, cron, init, kernel | CRITICAL |
| [never_whitelist](#never_whitelist) | systemd, additional, backdoors | HIGH/CRITICAL |
| [suspicious_script_content](#suspicious_script_content) | systemd, shell, additional, backdoors | HIGH |
| [suspicious_location](#suspicious_location) | systemd, kernel | HIGH |
| [dangerous_command](#dangerous_command) | systemd | HIGH |
| [modified_script](#modified_script) | systemd, additional | CRITICAL |
| [modified_binary](#modified_binary) | systemd, additional | CRITICAL |
| [unmanaged_script](#unmanaged_script) | systemd, additional | MEDIUM→HIGH |
| [unmanaged_binary](#unmanaged_binary) | systemd, additional | MEDIUM→HIGH |
| [unmanaged](#unmanaged) | multiple | MEDIUM |
| [inline_code](#inline_code) | systemd, additional | HIGH |
| [inline_code_suspicious](#inline_code_suspicious) | systemd, additional | HIGH/CRITICAL |
| [interpreter_interactive](#interpreter_interactive) | systemd, additional | HIGH |
| [modified_interpreter](#modified_interpreter) | systemd | CRITICAL |
| [unresolved_executable](#unresolved_executable) | systemd, additional | MEDIUM |
| [suspicious_exec_hook](#suspicious_exec_hook) | systemd | HIGH |
| [modified_exec_hook](#modified_exec_hook) | systemd | CRITICAL |
| [unmanaged_exec_hook](#unmanaged_exec_hook) | systemd | HIGH |
| [env_directive_ld_inject](#env_directive_ld_inject) | systemd | HIGH |
| [env_file_ld_inject](#env_file_ld_inject) | systemd | HIGH |
| [missing_env_file](#missing_env_file) | systemd | MEDIUM |
| [modified_env_file](#modified_env_file) | systemd | CRITICAL |
| [unmanaged_generator](#unmanaged_generator) | systemd | MEDIUM→HIGH |
| [modified_generator](#modified_generator) | systemd | CRITICAL |
| [suspicious_location_generator](#suspicious_location_generator) | systemd | CRITICAL |
| [suspicious_name](#suspicious_name) | cron | MEDIUM |
| [hidden_at_job](#hidden_at_job) | cron | HIGH |
| [modified_anacrontab](#modified_anacrontab) | cron | CRITICAL |
| [unmanaged_anacrontab](#unmanaged_anacrontab) | cron | MEDIUM |
| [non_symlink_in_rcd](#non_symlink_in_rcd) | init | HIGH |
| [broken_rcd_symlink](#broken_rcd_symlink) | init | MEDIUM |
| [suspicious_rcd_symlink](#suspicious_rcd_symlink) | init | HIGH |
| [suspicious_rcd_symlink_temp](#suspicious_rcd_symlink_temp) | init | CRITICAL |
| [ld_preload_entry](#ld_preload_entry) | kernel | MEDIUM |
| [preload_suspicious_location](#preload_suspicious_location) | kernel | CRITICAL |
| [preload_verified_lib](#preload_verified_lib) | kernel | MEDIUM |
| [preload_modified_lib](#preload_modified_lib) | kernel | CRITICAL |
| [preload_unmanaged_lib](#preload_unmanaged_lib) | kernel | HIGH |
| [modified_ld_config](#modified_ld_config) | kernel | CRITICAL |
| [suspicious_lib_path](#suspicious_lib_path) | kernel | HIGH |
| [unmanaged_ld_config](#unmanaged_ld_config) | kernel | HIGH |
| [module_suspicious_location](#module_suspicious_location) | kernel | CRITICAL |
| [module_nonstandard_location](#module_nonstandard_location) | kernel | HIGH |
| [modified_kernel_module](#modified_kernel_module) | kernel | CRITICAL |
| [unmanaged_kernel_module](#unmanaged_kernel_module) | kernel | HIGH |
| [module_file_missing](#module_file_missing) | kernel | HIGH |
| [modified_module_config](#modified_module_config) | kernel | CRITICAL |
| [unmanaged_module_config](#unmanaged_module_config) | kernel | MEDIUM |
| [ld_preload_env](#ld_preload_env) | additional | HIGH |
| [dangerous_sudoers_rule](#dangerous_sudoers_rule) | additional | HIGH |
| [unmanaged_pam_module](#unmanaged_pam_module) | additional | CRITICAL |
| [modified_pam_module](#modified_pam_module) | additional | CRITICAL |
| [pam_exec_script](#pam_exec_script) | additional | MEDIUM |
| [pam_exec_verified_script](#pam_exec_verified_script) | additional | LOW |
| [pam_exec_modified_script](#pam_exec_modified_script) | additional | CRITICAL |
| [pam_exec_missing_script](#pam_exec_missing_script) | additional | CRITICAL |
| [pam_exec_suspicious_location](#pam_exec_suspicious_location) | additional | CRITICAL |
| [pam_script_hook](#pam_script_hook) | additional | MEDIUM |
| [pam_script_hook_verified](#pam_script_hook_verified) | additional | LOW |
| [pam_script_hook_modified](#pam_script_hook_modified) | additional | CRITICAL |
| [pam_security_unmanaged_exec](#pam_security_unmanaged_exec) | additional | HIGH |
| [pam_env_ld_preload](#pam_env_ld_preload) | additional | HIGH |
| [pam_env_ld_preload_verified](#pam_env_ld_preload_verified) | additional | MEDIUM |
| [pam_env_user_ld_preload](#pam_env_user_ld_preload) | additional | HIGH |
| [pam_env_user_ld_preload_verified](#pam_env_user_ld_preload_verified) | additional | MEDIUM |
| [apt_hook_directive](#apt_hook_directive) | backdoors | MEDIUM→HIGH |
| [apt_hook_malicious_command](#apt_hook_malicious_command) | backdoors | CRITICAL |
| [permissive_doas](#permissive_doas) | backdoors | HIGH |
| [git_helper](#git_helper) | backdoors | MEDIUM→HIGH |
| [webshell_pattern](#webshell_pattern) | backdoors | HIGH |
| [system_account_ssh_key](#system_account_ssh_key) | ssh | HIGH |
| [system_account_ssh_forced_command_malicious](#system_account_ssh_forced_command_malicious) | ssh | CRITICAL |
| [grub_init_standard](#grub_init_standard) | bootloader | LOW |
| [grub_init_injection](#grub_init_injection) | bootloader | HIGH |
| [grub_init_malicious_content](#grub_init_malicious_content) | bootloader | CRITICAL |
| [root_dropped_script](#root_dropped_script) | bootloader | MEDIUM |
| [root_dropped_script_malicious](#root_dropped_script_malicious) | bootloader | HIGH/CRITICAL |
| [dracut_pre_pivot_hook](#dracut_pre_pivot_hook) | bootloader | HIGH |
| [dracut_sysroot_shadow_write](#dracut_sysroot_shadow_write) | bootloader | CRITICAL |
| [dracut_hook_malicious_content](#dracut_hook_malicious_content) | bootloader | CRITICAL |
| [dracut_unmanaged_module](#dracut_unmanaged_module) | bootloader | HIGH |
| [initramfs_rootmnt_shadow_write](#initramfs_rootmnt_shadow_write) | bootloader | CRITICAL |
| [polkit_pkla_all_result_yes](#polkit_pkla_all_result_yes) | polkit | CRITICAL |
| [polkit_pkla_partial_yes](#polkit_pkla_partial_yes) | polkit | HIGH |
| [polkit_rules_unconditional_yes](#polkit_rules_unconditional_yes) | polkit | CRITICAL |
| [polkit_rules_conditioned_yes](#polkit_rules_conditioned_yes) | polkit | MEDIUM→HIGH |
| [dbus_dangling_exec](#dbus_dangling_exec) | dbus | HIGH |
| [dbus_unmanaged_exec_target](#dbus_unmanaged_exec_target) | dbus | HIGH |
| [dbus_malicious_exec_content](#dbus_malicious_exec_content) | dbus | CRITICAL |
| [dbus_exec_suspicious_location](#dbus_exec_suspicious_location) | dbus | CRITICAL |
| [dbus_wildcard_policy](#dbus_wildcard_policy) | dbus | HIGH |
| [udev_runtime_rule](#udev_runtime_rule) | udev | HIGH |
| [udev_run_malicious_command](#udev_run_malicious_command) | udev | CRITICAL |
| [udev_run_at_delegation](#udev_run_at_delegation) | udev | HIGH |
| [udev_run_suspicious_location](#udev_run_suspicious_location) | udev | CRITICAL |
| [udev_run_target_malicious](#udev_run_target_malicious) | udev | CRITICAL |
| [dockerfile_suspicious_location](#dockerfile_suspicious_location) | container | HIGH |
| [dockerfile_escape_technique](#dockerfile_escape_technique) | container | CRITICAL |
| [docker_daemon_weakened_security](#docker_daemon_weakened_security) | container | HIGH |
| [container_privileged](#container_privileged) | container | HIGH |
| [container_privileged_pid_host](#container_privileged_pid_host) | container | CRITICAL |
| [container_docker_sock_mount](#container_docker_sock_mount) | container | CRITICAL |
| [container_nsenter_entrypoint](#container_nsenter_entrypoint) | container | CRITICAL |
| [suid_binary](#suid_binary) | binary | LOW→HIGH |
| [suid_unmanaged_binary](#suid_unmanaged_binary) | binary | CRITICAL |
| [suid_suspicious_location](#suid_suspicious_location) | binary | CRITICAL |
| [suid_script_malicious_content](#suid_script_malicious_content) | binary | CRITICAL |
| [sgid_binary](#sgid_binary) | binary | LOW→HIGH |
| [sgid_unmanaged_binary](#sgid_unmanaged_binary) | binary | HIGH |
| [sgid_suspicious_location](#sgid_suspicious_location) | binary | CRITICAL |
| [file_capability](#file_capability) | binary | LOW→CRITICAL |
| [cap_setuid_gtfobin](#cap_setuid_gtfobin) | binary | CRITICAL |
| [cap_setuid_unmanaged](#cap_setuid_unmanaged) | binary | HIGH |
| [cap_sys_admin](#cap_sys_admin) | binary | CRITICAL |
| [renamed_binary](#renamed_binary) | binary | MEDIUM |
| [renamed_binary_active_present](#renamed_binary_active_present) | binary | HIGH |
| [binary_hijack_wrapper](#binary_hijack_wrapper) | binary | HIGH/CRITICAL |

---

## Systemd Module Patterns

### `modified_package`
**Module:** check_systemd (also: check_cron, check_init_scripts, check_kernel_and_preload)
**Trigger:** `dpkg --verify` or `rpm -Va` reports the file has been altered from its installed state — hash mismatch, size change, or permission change.
**Confidence:** CRITICAL
**Investigator note:** A package-managed system binary or config has been replaced or tampered with. This is the strongest integrity indicator — treat as rootkit/binary replacement until proven otherwise. The `file_hash` field contains the current on-disk hash.

---

### `never_whitelist`
**Module:** check_systemd, check_additional_persistence, check_common_backdoors
**Trigger:** Any field (ExecStart, script content, cron command, hook command) matches `COMBINED_NEVER_WHITELIST_PATTERN` — patterns that are never legitimate in system persistence contexts: `/dev/tcp/`, `/dev/udp/`, `bash -i`, `socat exec:`, `nsenter -t 1`, `mkfifo /tmp`, `| bash`, `| sh`, `exec N<>/dev/`, etc.
**Confidence:** HIGH (escalates to CRITICAL if the file is also package-modified)
**Investigator note:** The literal matched string is in `matched_string`. These patterns have no legitimate use in service files or cron jobs.

---

### `suspicious_script_content`
**Module:** check_systemd, check_shell_profiles, check_init_scripts, check_additional_persistence, check_common_backdoors
**Trigger:** `analyze_script_content()` returns true — the script's full content matches one or more patterns from `SUSPICIOUS_COMMANDS`, `SUSPICIOUS_NETWORK_PATTERNS`, `MULTILINE_SUSPICIOUS_PATTERNS`, or `NETWORK_INDICATOR_PATTERNS`. The script is unmanaged (package-verified scripts with suspicious content use `never_whitelist` instead).
**Confidence:** HIGH
**Investigator note:** The specific pattern and matched line are in `matched_pattern` and `matched_string`.

---

### `suspicious_location`
**Module:** check_systemd, check_kernel_and_preload
**Trigger:** The executable or library path in ExecStart/LD_PRELOAD resolves to a world-writable or temporary directory: `/tmp/`, `/dev/shm/`, `/var/tmp/`, hidden paths starting with `.`.
**Confidence:** HIGH
**Investigator note:** Execution from temporary locations is a classic staging technique. Files here survive only until next reboot or cleanup — check if the file is still present.

---

### `dangerous_command`
**Module:** check_systemd
**Trigger:** ExecStart line matches download-execute patterns (`curl|bash`, `wget|sh`, `curl -o /tmp && chmod +x`) or reverse shell patterns that didn't match NEVER_WHITELIST but are clearly hostile.
**Confidence:** HIGH

---

### `modified_script`
**Module:** check_systemd, check_additional_persistence
**Trigger:** The script path extracted from ExecStart is owned by a package, but `dpkg --verify` or `rpm -Va` reports it modified.
**Confidence:** CRITICAL
**Investigator note:** A trusted script in a trusted location has been overwritten. Compare hash against package repository.

---

### `modified_binary`
**Module:** check_systemd, check_additional_persistence
**Trigger:** The direct binary in ExecStart is package-owned but fails integrity verification.
**Confidence:** CRITICAL

---

### `unmanaged_script`
**Module:** check_systemd, check_additional_persistence
**Trigger:** The script path extracted from ExecStart exists on disk but is not owned by any package manager. After `analyze_script_content()` returns false (no suspicious patterns), the finding is still emitted at MEDIUM as an unmanaged persistence point. If `analyze_script_content()` returns true, confidence escalates to HIGH with `suspicious_script_content`.
**Confidence:** MEDIUM (no patterns) → HIGH (with patterns)

---

### `unmanaged_binary`
**Module:** check_systemd, check_additional_persistence
**Trigger:** A direct executable in ExecStart exists but is not package-managed and is not a script (no shebang). Location and content analysis follow.
**Confidence:** MEDIUM → HIGH depending on location and content analysis

---

### `unmanaged`
**Module:** Multiple modules
**Trigger:** Generic fallback for unmanaged files where no more specific sub-pattern applies. Used for cron files, init scripts, sudoers drop-ins, and similar artifacts that exist outside package management without triggering a more specific pattern.
**Confidence:** MEDIUM

---

### `inline_code`
**Module:** check_systemd, check_additional_persistence
**Trigger:** ExecStart invokes an interpreter with `-c` or `-e` (inline code) but the inline payload does not match any suspicious pattern. Still flagged because inline code in a service file is unusual.
**Confidence:** HIGH

---

### `inline_code_suspicious`
**Module:** check_systemd, check_additional_persistence
**Trigger:** ExecStart uses `-c`/`-e` inline code AND the payload matches suspicious patterns or has high entropy with execution.
**Confidence:** HIGH → CRITICAL

---

### `interpreter_interactive`
**Module:** check_systemd, check_additional_persistence
**Trigger:** ExecStart invokes a shell or interpreter directly with interactive flags (`bash -i`, `sh -s`) or with no script argument at all. Interactive shells in service files have no legitimate use.
**Confidence:** HIGH

---

### `modified_interpreter`
**Module:** check_systemd
**Trigger:** The interpreter binary itself (e.g., `/usr/bin/python3`, `/bin/bash`) fails package integrity verification. Indicates the interpreter has been replaced — everything it runs is compromised.
**Confidence:** CRITICAL

---

### `unresolved_executable`
**Module:** check_systemd, check_additional_persistence
**Trigger:** The executable path in ExecStart does not exist on disk at scan time. Could be a broken service, a script that was deleted, or a path that was staged for later use.
**Confidence:** MEDIUM

---

### `suspicious_exec_hook`
**Module:** check_systemd
**Trigger:** `ExecStartPre=` or `ExecStartPost=` contains a command that matches `COMBINED_NEVER_WHITELIST_PATTERN` or `SUSPICIOUS_COMMANDS`.
**Confidence:** HIGH
**Investigator note:** Pre/post hooks run before/after the main ExecStart. Attackers add malicious hooks to legitimate services so the hook fires whenever the service restarts (e.g., on system update).

---

### `modified_exec_hook`
**Module:** check_systemd
**Trigger:** An ExecStartPre/Post hook runs a binary that is package-owned but integrity-modified.
**Confidence:** CRITICAL

---

### `unmanaged_exec_hook`
**Module:** check_systemd
**Trigger:** An ExecStartPre/Post hook runs an unmanaged binary (not owned by any package).
**Confidence:** HIGH

---

### `env_directive_ld_inject`
**Module:** check_systemd
**Trigger:** The service file contains `Environment=LD_PRELOAD=...`, `Environment=LD_LIBRARY_PATH=...`, or `Environment=PATH=...` inline. Inlining LD_PRELOAD in a service file injects a library into every process the service spawns.
**Confidence:** HIGH (unless already CRITICAL from another check)

---

### `env_file_ld_inject`
**Module:** check_systemd
**Trigger:** `EnvironmentFile=` points to an unmanaged file that contains `LD_PRELOAD=`, `LD_LIBRARY_PATH=`, or `PATH=` entries.
**Confidence:** HIGH
**Investigator note:** Stealthier than inline injection — the service file itself looks clean, but the referenced env file contains the preload.

---

### `missing_env_file`
**Module:** check_systemd
**Trigger:** `EnvironmentFile=` references a path that does not exist on disk. The service would start without the env file (most systemd env files use `-` prefix to make them optional). May indicate the env file was removed after loading, or a broken deployment.
**Confidence:** MEDIUM (only set if current confidence is LOW or MEDIUM)

---

### `modified_env_file`
**Module:** check_systemd
**Trigger:** `EnvironmentFile=` points to a package-managed file that has been integrity-modified.
**Confidence:** CRITICAL

---

### `unmanaged_generator`
**Module:** check_systemd
**Trigger:** A systemd generator binary (in `/etc/systemd/system-generators`, `/usr/lib/systemd/system-generators`, etc.) is not package-managed. Generators run at boot before units are loaded and can inject arbitrary unit files.
**Confidence:** MEDIUM → HIGH (based on location and content)

---

### `modified_generator`
**Module:** check_systemd
**Trigger:** A package-managed systemd generator fails integrity verification.
**Confidence:** CRITICAL

---

### `suspicious_location_generator`
**Module:** check_systemd
**Trigger:** A systemd generator exists in a suspicious or ephemeral location (`/tmp`, `/dev/shm`, `/run/systemd/system-generators`). Runtime generators in `/run/` persist only until reboot.
**Confidence:** CRITICAL

---

## Cron Module Patterns

### `suspicious_name`
**Module:** check_cron
**Trigger:** The cron job name or filename matches suspicious patterns (hidden files, random-looking names, names mimicking system files with extra characters).
**Confidence:** MEDIUM

---

### `hidden_at_job`
**Module:** check_cron
**Trigger:** A file in `/var/spool/at/` has a hidden filename (starts with `.`). Legitimate `at` jobs use numeric filenames; hidden filenames indicate manual creation to avoid `atq` listing.
**Confidence:** HIGH

---

### `modified_anacrontab`
**Module:** check_cron
**Trigger:** `/etc/anacrontab` is package-owned but fails integrity verification.
**Confidence:** CRITICAL

---

### `unmanaged_anacrontab`
**Module:** check_cron
**Trigger:** `/etc/anacrontab` exists but is not owned by any package. On most distros this file is package-managed.
**Confidence:** MEDIUM

---

## Init Scripts Module Patterns

### `non_symlink_in_rcd`
**Module:** check_init_scripts
**Trigger:** A regular file (not a symlink) exists in `/etc/rc0.d/` through `/etc/rc6.d/`. These directories should contain only symlinks to `/etc/init.d/` scripts. A regular file indicates manual placement.
**Confidence:** HIGH

---

### `broken_rcd_symlink`
**Module:** check_init_scripts
**Trigger:** A symlink in `/etc/rc*.d/` points to a target that does not exist. May indicate a deleted script that left its activation symlink, or a reference to a staged file.
**Confidence:** MEDIUM

---

### `suspicious_rcd_symlink`
**Module:** check_init_scripts
**Trigger:** A symlink in `/etc/rc*.d/` points to a target outside `/etc/init.d/` — for example `/opt/`, `/home/`, or `/usr/local/`. Legitimate rc*.d symlinks only point into `/etc/init.d/`.
**Confidence:** HIGH

---

### `suspicious_rcd_symlink_temp`
**Module:** check_init_scripts
**Trigger:** A symlink in `/etc/rc*.d/` points into a temp directory (`/tmp/`, `/dev/shm/`, `/var/tmp/`). High-confidence indicator of tampering.
**Confidence:** CRITICAL

---

## Kernel/Preload Module Patterns

### `ld_preload_entry`
**Module:** check_kernel_and_preload
**Trigger:** A library path is listed in `/etc/ld.so.preload`. Any entry in this file causes the library to be injected into every process on the system. Even package-managed entries are flagged (unusual for system packages to use ld.so.preload).
**Confidence:** MEDIUM (verified) → HIGH (unmanaged) → CRITICAL (modified or suspicious location)

---

### `preload_suspicious_location`
**Module:** check_kernel_and_preload
**Trigger:** A library listed in `/etc/ld.so.preload` resides in `/tmp/`, `/dev/shm/`, `/var/tmp/`, a hidden directory, `/home/`, or `/root/`. No legitimate system library lives in these locations.
**Confidence:** CRITICAL

---

### `preload_verified_lib`
**Module:** check_kernel_and_preload
**Trigger:** A library in `/etc/ld.so.preload` is package-managed and unmodified. Unusual — very few legitimate packages use ld.so.preload.
**Confidence:** MEDIUM

---

### `preload_modified_lib`
**Module:** check_kernel_and_preload
**Trigger:** A library in `/etc/ld.so.preload` is package-managed but has been modified on disk.
**Confidence:** CRITICAL

---

### `preload_unmanaged_lib`
**Module:** check_kernel_and_preload
**Trigger:** A library in `/etc/ld.so.preload` is not owned by any package.
**Confidence:** HIGH

---

### `modified_ld_config`
**Module:** check_kernel_and_preload
**Trigger:** An `/etc/ld.so.conf` or `/etc/ld.so.conf.d/*.conf` file is package-managed but integrity-modified.
**Confidence:** CRITICAL

---

### `suspicious_lib_path`
**Module:** check_kernel_and_preload
**Trigger:** An `/etc/ld.so.conf*` file adds a temp directory (`/tmp`, `/dev/shm`, `/var/tmp`) to the library search path. Libraries from temp dirs would be loaded by all processes.
**Confidence:** HIGH

---

### `unmanaged_ld_config`
**Module:** check_kernel_and_preload
**Trigger:** An `/etc/ld.so.conf.d/*.conf` file exists but is not package-managed.
**Confidence:** HIGH

---

### `module_suspicious_location`
**Module:** check_kernel_and_preload
**Trigger:** A currently-loaded kernel module (from `lsmod`) has its `.ko` file in a suspicious/temp location rather than `/lib/modules/` or `/usr/lib/modules/`.
**Confidence:** CRITICAL

---

### `module_nonstandard_location`
**Module:** check_kernel_and_preload
**Trigger:** A loaded kernel module's `.ko` file is outside both standard module directories. Examples: `/opt/`, `/home/`, custom paths.
**Confidence:** HIGH

---

### `modified_kernel_module`
**Module:** check_kernel_and_preload
**Trigger:** A package-managed kernel module fails integrity verification.
**Confidence:** CRITICAL

---

### `unmanaged_kernel_module`
**Module:** check_kernel_and_preload
**Trigger:** A loaded kernel module is in a standard location (`/lib/modules/`) but not owned by any package. May be a manually compiled out-of-tree module.
**Confidence:** HIGH

---

### `module_file_missing`
**Module:** check_kernel_and_preload
**Trigger:** A module appears in `lsmod` (currently loaded) but its `.ko` file cannot be found on disk via `modinfo`. Possible indicators: module was loaded from a temp file that was deleted (common rootkit technique), or `modinfo` returns no filename (built-in).
**Confidence:** HIGH

---

### `modified_module_config`
**Module:** check_kernel_and_preload
**Trigger:** An `/etc/modprobe.d/*.conf` file is package-managed but integrity-modified. These files control module loading — modification can blacklist security modules (SELinux, AppArmor, seccomp) or redirect module loading.
**Confidence:** CRITICAL

---

### `unmanaged_module_config`
**Module:** check_kernel_and_preload
**Trigger:** An `/etc/modprobe.d/*.conf` or `/etc/modules-load.d/*.conf` file is not package-managed.
**Confidence:** MEDIUM

---

## Additional Persistence Module Patterns

### `ld_preload_env`
**Module:** check_additional_persistence
**Trigger:** `/etc/environment` contains `LD_PRELOAD=` or `LD_LIBRARY_PATH=`. These variables in the system environment file inject libraries into every login session. The legitimate mechanism is `/etc/ld.so.preload`, not `/etc/environment`.
**Confidence:** HIGH

---

### `dangerous_sudoers_rule`
**Module:** check_additional_persistence
**Trigger:** `/etc/sudoers` or a file in `/etc/sudoers.d/` contains `NOPASSWD`, `ALL=(ALL) ALL`, or `ALL:ALL` patterns granting unrestricted privilege escalation without authentication.
**Confidence:** HIGH

---

### `unmanaged_pam_module`
**Module:** check_additional_persistence
**Trigger:** A PAM module (`.so` file) referenced in `/etc/pam.d/` is not owned by any package. PAM modules run as root on every authentication event — an unmanaged module can capture credentials or grant unauthorized access.
**Confidence:** CRITICAL

---

### `modified_pam_module`
**Module:** check_additional_persistence
**Trigger:** A package-managed PAM `.so` file has been replaced or altered (integrity verification failure). The most direct form of PAM backdoor.
**Confidence:** CRITICAL

---

### `pam_exec_script`
**Module:** check_additional_persistence
**Trigger:** `pam_exec.so` is configured in a PAM stack, pointing to an existing script. `pam_exec.so` runs arbitrary programs at authentication time as root.
**Confidence:** MEDIUM (verified script) → escalates based on script content and package status

---

### `pam_exec_verified_script`
**Module:** check_additional_persistence
**Trigger:** The script called by `pam_exec.so` is package-managed and unmodified.
**Confidence:** LOW

---

### `pam_exec_modified_script`
**Module:** check_additional_persistence
**Trigger:** The script called by `pam_exec.so` is package-managed but has been modified.
**Confidence:** CRITICAL

---

### `pam_exec_missing_script`
**Module:** check_additional_persistence
**Trigger:** `pam_exec.so` references a script path that does not exist on disk. May indicate a script was deleted after use, or a reference to a staged future payload.
**Confidence:** CRITICAL

---

### `pam_exec_suspicious_location`
**Module:** check_additional_persistence
**Trigger:** The script referenced by `pam_exec.so` resides in a temp or suspicious location (`/tmp/`, `/dev/shm/`, `/var/tmp/`, hidden directories).
**Confidence:** CRITICAL

---

### `pam_script_hook`
**Module:** check_additional_persistence
**Trigger:** A PAM service config references a `pam_script.so` hook file in `/etc/security/`. `pam_script.so` executes scripts at authentication stages (auth, account, session, password).
**Confidence:** MEDIUM

---

### `pam_script_hook_verified`
**Module:** check_additional_persistence
**Trigger:** The hook script for `pam_script.so` is package-verified.
**Confidence:** LOW

---

### `pam_script_hook_modified`
**Module:** check_additional_persistence
**Trigger:** The hook script for `pam_script.so` is package-managed but integrity-modified.
**Confidence:** CRITICAL

---

### `pam_security_unmanaged_exec`
**Module:** check_additional_persistence
**Trigger:** A file in `/etc/security/` that is executed by a PAM relay module (`pam_python.so`, `pam_perl.so`) is not package-managed or has suspicious content.
**Confidence:** HIGH

---

### `pam_env_ld_preload`
**Module:** check_additional_persistence
**Trigger:** `/etc/security/pam_env.conf` (system-level `pam_env.so` config) contains `LD_PRELOAD` or `LD_LIBRARY_PATH` that points to an unmanaged library.
**Confidence:** HIGH

---

### `pam_env_ld_preload_verified`
**Module:** check_additional_persistence
**Trigger:** Same as above but the referenced library is package-verified.
**Confidence:** MEDIUM

---

### `pam_env_user_ld_preload`
**Module:** check_additional_persistence
**Trigger:** A user's `~/.pam_environment` file contains `LD_PRELOAD` or `LD_LIBRARY_PATH` pointing to an unmanaged library. Injects a library into that user's sessions only.
**Confidence:** HIGH

---

### `pam_env_user_ld_preload_verified`
**Module:** check_additional_persistence
**Trigger:** Same as above but the referenced library is package-verified.
**Confidence:** MEDIUM

---

## Backdoors Module Patterns

### `apt_hook_directive`
**Module:** check_common_backdoors
**Trigger:** A file in `/etc/apt/apt.conf.d/` contains `DPkg::Post-Invoke`, `DPkg::Pre-Invoke`, `APT::Update::Pre-Invoke`, or `APT::Update::Post-Invoke` directives. These hooks execute commands every time `apt install` or `apt update` runs.
**Confidence:** MEDIUM (managed file) → HIGH (unmanaged file)

---

### `apt_hook_malicious_command`
**Module:** check_common_backdoors
**Trigger:** The hook command string extracted from an APT hook directive matches NEVER_WHITELIST or SUSPICIOUS patterns via `analyze_script_content()`.
**Confidence:** CRITICAL

---

### `permissive_doas`
**Module:** check_common_backdoors
**Trigger:** `/etc/doas.conf` contains a rule that grants unrestricted privilege escalation — `nopass`, `permit` without restrictions, or wildcard user grants. `doas` is an OpenBSD alternative to `sudo` present on some Linux systems.
**Confidence:** HIGH

---

### `git_helper`
**Module:** check_common_backdoors
**Trigger:** A git config file (`/etc/gitconfig`, `~/.gitconfig`, `.git/config`) contains a `credential.helper` entry pointing to a custom executable, or `core.pager` set to a suspicious command. Credential helpers run on every `git push`/`pull` that requires authentication.
**Confidence:** MEDIUM (standard path) → HIGH (unmanaged or suspicious content)

---

### `webshell_pattern`
**Module:** check_common_backdoors
**Trigger:** A file in a web directory (`/var/www/`, `/var/www/html/`, `/usr/share/nginx/html/`, `/srv/http/`) with a web-executable extension (`.php`, `.asp`, `.aspx`, `.jsp`) matches web shell content patterns: `system(`, `exec(`, `passthru(`, `shell_exec(`, `_POST[`, `_GET[`, `<%`, `request.getParameter`.
**Confidence:** HIGH

---

## SSH Module Patterns

### `system_account_ssh_key`
**Module:** check_ssh_persistence
**Trigger:** A system account (UID 1-999 — service accounts like `www-data`, `daemon`, `nobody`, `news`) has an `authorized_keys` file in its `.ssh/` directory. System accounts should not have SSH keys as they are not interactive login accounts.
**Confidence:** HIGH

---

### `system_account_ssh_forced_command_malicious`
**Module:** check_ssh_persistence
**Trigger:** A key in a system account's `authorized_keys` has a `command="..."` option whose content matches suspicious patterns (reverse shells, download-execute, NEVER_WHITELIST).
**Confidence:** CRITICAL

---

## Bootloader Module Patterns

### `grub_init_standard`
**Module:** check_bootloader_persistence
**Trigger:** `/etc/default/grub` or a file in `/etc/default/grub.d/` contains `init=` in the kernel command line, but the target is one of the standard init paths: `/sbin/init`, `/lib/systemd/systemd`, `/usr/lib/systemd/systemd`, `/bin/busybox`, `/sbin/upstart`.
**Confidence:** LOW

---

### `grub_init_injection`
**Module:** check_bootloader_persistence
**Trigger:** A GRUB config contains `init=<path>` where the path is not a recognized standard init binary. Overriding `init=` in the kernel command line replaces the entire init system — whatever runs instead has full root access to the uninitialized system.
**Confidence:** HIGH

---

### `grub_init_malicious_content`
**Module:** check_bootloader_persistence
**Trigger:** The binary or script pointed to by the injected `init=` parameter matches malicious content patterns.
**Confidence:** CRITICAL

---

### `root_dropped_script`
**Module:** check_bootloader_persistence
**Trigger:** An executable shell script (`.sh`) is found in `/` or at maxdepth 2 from root, in directories that are not standard system directories. Attackers drop init scripts at the filesystem root for GRUB `init=` targeting.
**Confidence:** MEDIUM

---

### `root_dropped_script_malicious`
**Module:** check_bootloader_persistence
**Trigger:** A root-dropped script matches suspicious content patterns.
**Confidence:** HIGH → CRITICAL

---

### `dracut_pre_pivot_hook`
**Module:** check_bootloader_persistence
**Trigger:** A file in `/usr/lib/dracut/modules.d/*/module-setup.sh` contains `inst_hook pre-pivot` — a hook that runs during initrd boot before the root filesystem is mounted. Pre-pivot hooks have unrestricted access to the early boot environment.
**Confidence:** HIGH

---

### `dracut_sysroot_shadow_write`
**Module:** check_bootloader_persistence
**Trigger:** A dracut pre-pivot hook script contains writes to `/sysroot/etc/shadow` or `/sysroot/etc/passwd`. This is the direct mechanism for injecting a backdoor user into the system before the OS boots.
**Confidence:** CRITICAL

---

### `dracut_hook_malicious_content`
**Module:** check_bootloader_persistence
**Trigger:** A dracut hook script contains other malicious patterns beyond shadow writes — download-execute, reverse shell setup, NEVER_WHITELIST matches.
**Confidence:** CRITICAL

---

### `dracut_unmanaged_module`
**Module:** check_bootloader_persistence
**Trigger:** A dracut module directory (`/usr/lib/dracut/modules.d/<name>/`) is not package-managed. Custom dracut modules have no legitimate reason to be unmanaged on production systems.
**Confidence:** HIGH

---

### `initramfs_rootmnt_shadow_write`
**Module:** check_bootloader_persistence
**Trigger:** A file in `/etc/initramfs-tools/scripts/` or `/etc/initramfs-tools/hooks/` writes to `$rootmnt/etc/shadow` or `$rootmnt/etc/passwd`. This is the Ubuntu/Debian equivalent of `dracut_sysroot_shadow_write` — injecting a backdoor user during initramfs boot.
**Confidence:** CRITICAL

---

## Polkit Module Patterns

### `polkit_pkla_all_result_yes`
**Module:** check_polkit_persistence
**Trigger:** A `.pkla` file in `/etc/polkit-1/localauthority/50-local.d/` has all three result fields set to `yes`: `ResultAny=yes`, `ResultInactive=yes`, and `ResultActive=yes`. This unconditionally grants the specified action to the matching identity, bypassing authentication in all contexts.
**Confidence:** CRITICAL

---

### `polkit_pkla_partial_yes`
**Module:** check_polkit_persistence
**Trigger:** A `.pkla` file has one or two (but not all three) result fields set to `yes`. Grants unauthenticated access in specific contexts (active session, inactive session, or any session).
**Confidence:** HIGH

---

### `polkit_rules_unconditional_yes`
**Module:** check_polkit_persistence
**Trigger:** A JavaScript `.rules` file in `/etc/polkit-1/rules.d/` contains `return polkit.Result.YES` without any conditional logic (`if` statement) — the rule always grants the action.
**Confidence:** CRITICAL

---

### `polkit_rules_conditioned_yes`
**Module:** check_polkit_persistence
**Trigger:** A `.rules` file contains `return polkit.Result.YES` inside a conditional block. Grants access to a subset of subjects matching the condition.
**Confidence:** MEDIUM (broad condition) → HIGH (minimal condition)

---

## D-Bus / NetworkManager Module Patterns

### `dbus_dangling_exec`
**Module:** check_dbus_persistence
**Trigger:** A D-Bus system service file (`/usr/share/dbus-1/system-services/*.service`) has an `Exec=` directive pointing to a binary that does not exist on disk. D-Bus activates this path on demand — if the file is later placed there, it executes as the configured user.
**Confidence:** HIGH

---

### `dbus_unmanaged_exec_target`
**Module:** check_dbus_persistence
**Trigger:** The `Exec=` target of a D-Bus system service file exists but is not package-managed.
**Confidence:** HIGH

---

### `dbus_malicious_exec_content`
**Module:** check_dbus_persistence
**Trigger:** The `Exec=` target script of a D-Bus service file contains malicious patterns (NEVER_WHITELIST, suspicious commands).
**Confidence:** CRITICAL

---

### `dbus_exec_suspicious_location`
**Module:** check_dbus_persistence
**Trigger:** The `Exec=` target of a D-Bus service file resides in `/tmp/`, `/dev/shm/`, or `/var/tmp/`.
**Confidence:** CRITICAL

---

### `dbus_wildcard_policy`
**Module:** check_dbus_persistence
**Trigger:** An `/etc/dbus-1/system.d/*.conf` policy file contains `<allow own="*">` or `<allow send_destination="*">` — granting any process ownership of any D-Bus name or permission to send to any destination. This disables D-Bus access control.
**Confidence:** HIGH

---

## Udev Module Patterns

### `udev_runtime_rule`
**Module:** check_udev_persistence
**Trigger:** A `.rules` file exists in `/run/udev/rules.d/`. Rules in `/run/` are created at runtime (not from packages or admin config) and are lost on reboot — but are active until then. Any file here is unusual.
**Confidence:** HIGH

---

### `udev_run_malicious_command`
**Module:** check_udev_persistence
**Trigger:** A `RUN+=` directive in a udev rule contains a command string that matches NEVER_WHITELIST or SUSPICIOUS_COMMANDS patterns.
**Confidence:** CRITICAL

---

### `udev_run_at_delegation`
**Module:** check_udev_persistence
**Trigger:** A `RUN+=` directive delegates to `at now` or `at +N` (or `crontab`). Udev rules run in a foreground context — using `at` offloads the actual payload to run asynchronously, bypassing the timeout that kills long-running udev rules.
**Confidence:** HIGH

---

### `udev_run_suspicious_location`
**Module:** check_udev_persistence
**Trigger:** A `RUN+=` directive executes a script from `/tmp/`, `/dev/shm/`, or `/var/tmp/`.
**Confidence:** CRITICAL

---

### `udev_run_target_malicious`
**Module:** check_udev_persistence
**Trigger:** A `RUN+=` directive references a script file that, when read, contains malicious patterns.
**Confidence:** CRITICAL

---

## Container Module Patterns

### `dockerfile_suspicious_location`
**Module:** check_container_persistence
**Trigger:** A `Dockerfile` is found in `/tmp/`, `/root/`, `/home/`, or `/var/tmp/` (searched with maxdepth 3). Dockerfiles in user-writable or temp locations are not part of legitimate CI/CD workflows on production systems.
**Confidence:** HIGH

---

### `dockerfile_escape_technique`
**Module:** check_container_persistence
**Trigger:** A Dockerfile contains container escape techniques: `nsenter` (namespace entry from container to host), `socat exec:` (socket-based shell), or `--privileged` in a `RUN` command.
**Confidence:** CRITICAL

---

### `docker_daemon_weakened_security`
**Module:** check_container_persistence
**Trigger:** `/etc/docker/daemon.json` contains security-weakening configuration: `userns-remap` set to null or empty string (disabling user namespace isolation), or `no-new-privileges` set to false.
**Confidence:** HIGH

---

### `container_privileged`
**Module:** check_container_persistence
**Trigger:** A running or stopped Docker container (from `docker inspect`) has `HostConfig.Privileged: true`. Privileged containers have full access to all host devices and capabilities.
**Confidence:** HIGH

---

### `container_privileged_pid_host`
**Module:** check_container_persistence
**Trigger:** A Docker container is both privileged (`Privileged: true`) AND runs in the host PID namespace (`HostConfig.PidMode: host`). This combination gives the container full visibility of and signaling access to all host processes.
**Confidence:** CRITICAL

---

### `container_docker_sock_mount`
**Module:** check_container_persistence
**Trigger:** A Docker container has `/var/run/docker.sock` bind-mounted into it. Anything inside the container with access to the socket can control the Docker daemon and escape to host.
**Confidence:** CRITICAL

---

### `container_nsenter_entrypoint`
**Module:** check_container_persistence
**Trigger:** A container's `Entrypoint` or `Cmd` contains `nsenter`. `nsenter -t 1` from a privileged container enters the host's mount, network, PID, or UTS namespace — full container escape.
**Confidence:** CRITICAL

---

## Binary Integrity Module Patterns

### `suid_binary`
**Module:** check_binary_integrity
**Trigger:** A file with SUID bit set (`-rwsr-xr-x`) is found during the active filesystem scan. Package-owned SUID binaries are LOW confidence; unmanaged ones escalate.
**Confidence:** LOW (verified) → HIGH (unmanaged) → CRITICAL (suspicious location or malicious content)

---

### `suid_unmanaged_binary`
**Module:** check_binary_integrity
**Trigger:** A SUID binary in the scan paths (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/bin`, `/usr/local/sbin`, `/opt`, `/tmp`, `/dev/shm`, `/var/tmp`) is not package-managed. SUID binaries must be package-managed on production systems.
**Confidence:** CRITICAL

---

### `suid_suspicious_location`
**Module:** check_binary_integrity
**Trigger:** A SUID binary is found in `/tmp/`, `/dev/shm/`, or `/var/tmp/`. Absolutely no legitimate use.
**Confidence:** CRITICAL

---

### `suid_script_malicious_content`
**Module:** check_binary_integrity
**Trigger:** A SUID file is a shell script (has shebang) whose content matches malicious patterns. SUID scripts run as root with attacker-controlled content.
**Confidence:** CRITICAL

---

### `sgid_binary`
**Module:** check_binary_integrity
**Trigger:** A file with SGID bit set found in the scan paths. Package-owned SGID binaries in standard locations are LOW.
**Confidence:** LOW → HIGH depending on package status and location

---

### `sgid_unmanaged_binary`
**Module:** check_binary_integrity
**Trigger:** An SGID binary is not package-managed.
**Confidence:** HIGH

---

### `sgid_suspicious_location`
**Module:** check_binary_integrity
**Trigger:** An SGID binary is in `/tmp/`, `/dev/shm/`, or `/var/tmp/`.
**Confidence:** CRITICAL

---

### `file_capability`
**Module:** check_binary_integrity
**Trigger:** `getcap` reports a Linux capability set on a file. Capabilities grant partial root-like privileges — `cap_net_raw` for ping/tcpdump is expected; others are suspicious.
**Confidence:** LOW (expected capabilities on package-owned files) → CRITICAL (dangerous capabilities)

---

### `cap_setuid_gtfobin`
**Module:** check_binary_integrity
**Trigger:** `cap_setuid+ep` is set on a binary whose name matches the GTFOBins list: `bash`, `sh`, `python`, `python2`, `python3`, `perl`, `ruby`, `find`, `vim`, `vi`, `nmap`, `awk`, `gawk`, `mawk`, `less`, `more`, `tee`, `cp`, `rsync`, `tar`. These binaries can trivially escalate to root using `cap_setuid`.
**Confidence:** CRITICAL

---

### `cap_setuid_unmanaged`
**Module:** check_binary_integrity
**Trigger:** `cap_setuid+ep` is set on a binary not in the GTFOBins list and not package-managed.
**Confidence:** HIGH

---

### `cap_sys_admin`
**Module:** check_binary_integrity
**Trigger:** `cap_sys_admin` is set on any binary. This capability covers a vast range of privileged operations — mount, container management, device creation — and is effectively equivalent to root for most attack purposes.
**Confidence:** CRITICAL

---

### `renamed_binary`
**Module:** check_binary_integrity
**Trigger:** A file with a renamed-original suffix (`.original`, `.old`, `.bak`, `.real`) is found in a system binary directory (`/bin`, `/usr/bin`, `/sbin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`). May indicate the original was moved aside to be replaced by a wrapper.
**Confidence:** MEDIUM

---

### `renamed_binary_active_present`
**Module:** check_binary_integrity
**Trigger:** A renamed original exists AND a file with the unsuffixed name also exists in the same directory, but the active file is NOT a shell script (both exist, no wrapper detected). Suggests the original was duplicated and potentially modified.
**Confidence:** HIGH

---

### `binary_hijack_wrapper`
**Module:** check_binary_integrity
**Trigger:** A renamed original exists AND the active filename resolves to a shell script (shebang detected). The active file is a wrapper that likely calls the renamed original while adding malicious behavior. Analysis of the wrapper content follows — if malicious patterns are found, confidence escalates to CRITICAL.
**Confidence:** HIGH → CRITICAL (if wrapper content is malicious)

---

## Special Escalation Note

When `add_finding()` processes a finding at HIGH confidence and the file has SUID or SGID permissions, the matched_pattern is modified to `<original_pattern>+suid_sgid` and confidence is escalated to CRITICAL. This automatic escalation applies across all modules.

---

*Last Updated: 2026-03-16 | Version: 2.4.0*
