# Persistnux — Persistence Mechanisms Reference

## Version 2.4.0

Authoritative list of all persistence mechanism categories detected by Persistnux v2.4.0. For each category: the exact filesystem paths scanned, the artifact fields parsed, and the confidence rules applied.

---

## Module Execution Model

All 14 detection modules launch simultaneously as background subshells. Each writes to a per-module temp log and CSV/JSONL file. The main process waits for each module in display order, then prints its buffered output and merges its findings into the master output files.

```
Module:   1      2      3      4      5      6      7      8      9     10    11    12    13    14
Name:  sysmd  cron  shell  init   kern  addtl  bkdrs   ssh  binint boot  polk  dbus  udev  cont
```

---

## 1. Systemd Services

**Function:** `check_systemd()`

### Paths Scanned

**Service files:**
- `/etc/systemd/system/*.service`
- `/usr/lib/systemd/system/*.service`
- `/lib/systemd/system/*.service`
- `/run/systemd/system/*.service`
- `/etc/systemd/user/*.service`
- `/usr/lib/systemd/user/*.service`
- `~/.config/systemd/user/*.service` (all user homes when root)

**Timer files** (for disabled-service correlation):
- Same directories as above, `*.timer`

**Generator directories:**
- `/etc/systemd/system-generators/`
- `/usr/local/lib/systemd/system-generators/`
- `/usr/lib/systemd/system-generators/`
- `/lib/systemd/system-generators/`

### Artifact Fields Parsed

From each `.service` file:
- `ExecStart=` — main command
- `ExecStartPre=` — pre-start hooks (semicolon-separated)
- `ExecStartPost=` — post-start hooks (semicolon-separated)
- `OnFailure=` — failure handler unit names
- `Environment=` — inline key=value environment pairs
- `EnvironmentFile=` — external environment file path

From each `.timer` file:
- `OnBootSec=`, `OnCalendar=`, `OnUnitActiveSec=` — schedule values
- `Unit=` — activated service name (cross-referenced for non-corresponding units)

### Confidence Rules

| Condition | Confidence |
|---|---|
| ExecStart matches NEVER_WHITELIST | HIGH |
| Script/binary is package-modified | CRITICAL |
| Script/binary is unmanaged + suspicious content | HIGH |
| Script/binary is unmanaged, no patterns | MEDIUM |
| Inline interpreter code (`-c`/`-e`) with patterns | HIGH→CRITICAL |
| Generator in temp location | CRITICAL |
| EnvironmentFile missing | MEDIUM |
| EnvironmentFile has LD_PRELOAD | HIGH |
| EnvironmentFile is modified | CRITICAL |

---

## 2. Cron Jobs & Scheduled Tasks

**Function:** `check_cron()`

### Paths Scanned

**System crontabs:**
- `/etc/crontab`
- `/etc/cron.d/*.conf` and plain files

**Periodic directories (no schedule, script execution):**
- `/etc/cron.daily/`
- `/etc/cron.hourly/`
- `/etc/cron.weekly/`
- `/etc/cron.monthly/`

**User crontabs (when root):**
- `/var/spool/cron/`
- `/var/spool/cron/crontabs/`

**Anacron:**
- `/etc/anacrontab`

**AT jobs:**
- `/var/spool/at/` (hidden filenames flagged)

**Access control:**
- `/etc/at.allow`
- `/etc/at.deny`
- `/etc/cron.allow`
- `/etc/cron.deny`

### Artifact Fields Parsed

From standard crontab entries:
- Fields 1-5: schedule (minute, hour, dom, month, dow)
- Field 6: user (for `/etc/crontab` and `/etc/cron.d/` only)
- Field 7+: command string

From `@special` entries: `@reboot`, `@daily`, etc. — command extracted from field 3+.

From AT jobs: full file content analyzed.

### Confidence Rules

| Condition | Confidence |
|---|---|
| Command matches NEVER_WHITELIST | HIGH |
| Command matches SUSPICIOUS_COMMANDS | HIGH |
| File is package-modified | CRITICAL |
| anacrontab is unmanaged | MEDIUM |
| AT job has hidden filename | HIGH |
| Access control file references nonexistent user | MEDIUM |

---

## 3. Shell Profiles & RC Files

**Function:** `check_shell_profiles()`

### Paths Scanned

**System-wide (always):**
- `/etc/profile`
- `/etc/profile.d/*.sh`
- `/etc/bash.bashrc`
- `/etc/bashrc`
- `/etc/zsh/zshrc`
- `/etc/zshrc`
- `/etc/zsh/zshenv` (sourced for ALL zsh invocations, including non-interactive)
- `/etc/zsh/zprofile`
- `/etc/zsh/zlogin`
- `/etc/fish/config.fish`

**Per-user (when root — all users with home dirs):**
- `~/.bashrc`
- `~/.bash_profile`
- `~/.bash_login`
- `~/.profile`
- `~/.zshrc`
- `~/.zprofile`
- `~/.zlogin`
- `~/.zshenv` (most powerful — sourced for every zsh invocation)
- `~/.bash_logout`
- `~/.config/fish/config.fish`

### Artifact Fields Parsed

- Full file content (first 500 lines)
- File package status
- File mtime (age in days)

### Confidence Rules

| Condition | Confidence |
|---|---|
| Content matches NEVER_WHITELIST | HIGH |
| Content matches SUSPICIOUS_COMMANDS | HIGH |
| File is package-modified | CRITICAL |
| Unmanaged, no patterns | MEDIUM |
| Modified within 7 days + patterns | HIGH |

---

## 4. Init Scripts & RC.local

**Function:** `check_init_scripts()`

### Paths Scanned

**rc.local:**
- `/etc/rc.local`
- `/etc/rc.d/rc.local`

**SysV init scripts:**
- `/etc/init.d/` (each file)

**Runlevel directories:**
- `/etc/rc0.d/` through `/etc/rc6.d/` (symlinks and regular files)

### Artifact Fields Parsed

From each init script:
- Full file content
- Package status
- Symlink target (for rc*.d entries)

From rc*.d symlinks:
- `readlink -f` target path
- Target existence on disk
- Target content if it's a file

### Confidence Rules

| Condition | Confidence |
|---|---|
| Script content matches suspicious patterns | HIGH |
| Script is package-modified | CRITICAL |
| Regular file in rc*.d (not symlink) | HIGH |
| Symlink to non-existent target | MEDIUM |
| Symlink target outside /etc/init.d/ | HIGH |
| Symlink target in /tmp, /dev/shm, /var/tmp | CRITICAL |

---

## 5. Kernel Modules & Library Preloading

**Function:** `check_kernel_and_preload()`

### Paths Scanned

**LD_PRELOAD:**
- `/etc/ld.so.preload` (each line is a library path)

**Dynamic linker configs:**
- `/etc/ld.so.conf`
- `/etc/ld.so.conf.d/*.conf`
- Non-standard paths from config files — actual `.so*` files scanned

**Environment injection:**
- `/etc/environment` (LD_PRELOAD/LD_LIBRARY_PATH lines)

**Kernel module configs:**
- `/etc/modprobe.d/*.conf`
- `/etc/modprobe.conf`
- `/etc/modules`
- `/etc/modules-load.d/*.conf`

**Loaded modules:**
- `lsmod` output — each module name resolved to `.ko` path via `modinfo -F filename`

### Artifact Fields Parsed

From `/etc/ld.so.preload`: library path per line.

From `/etc/ld.so.conf*`: include directives and library search paths.

From `lsmod`: module name, size, use count.

From `modinfo`: `filename` field (`.ko` path), `vermagic`.

### Confidence Rules

| Condition | Confidence |
|---|---|
| Any entry in /etc/ld.so.preload | MEDIUM baseline |
| Preload library in temp/hidden dir | CRITICAL |
| Preload library is modified | CRITICAL |
| Preload library is unmanaged | HIGH |
| Non-standard library path added via ld.so.conf | MEDIUM→HIGH |
| Module loaded from temp location | CRITICAL |
| Module loaded from non-standard location | HIGH |
| Module file missing on disk | HIGH |
| Module config is package-modified | CRITICAL |

---

## 6. Additional Persistence Mechanisms

**Function:** `check_additional_persistence()`

### Paths Scanned

**XDG Autostart:**
- `/etc/xdg/autostart/*.desktop`
- `~/.config/autostart/*.desktop` (all user homes when root)

**Sudoers:**
- `/etc/sudoers`
- `/etc/sudoers.d/*`

**PAM:**
- `/etc/pam.d/` (all files)
- `/etc/pam.conf`
- PAM library directories (architecture-specific):
  - `/usr/lib/x86_64-linux-gnu/security/`
  - `/usr/lib/aarch64-linux-gnu/security/`
  - `/usr/lib/security/`
  - `/usr/lib64/security/`
  - `/lib/x86_64-linux-gnu/security/`
  - `/lib/aarch64-linux-gnu/security/`
  - `/lib/security/`
  - `/lib64/security/`
- `/etc/security/pam_env.conf`
- `~/.pam_environment` (per-user)
- `/etc/security/` (general scan for relay module scripts)

**MOTD:**
- `/etc/motd`
- `/etc/motd.d/*`
- `/etc/update-motd.d/*`

**Git credentials:**
- `/etc/gitconfig`
- `~/.gitconfig` (all user homes when root)

**Passwd checks:**
- `/etc/passwd` — UID 0 duplicate accounts
- `/etc/passwd` — shell field trailing whitespace masking
- `/etc/shells` — valid shell list for comparison

**Environment:**
- `/etc/environment`

### Artifact Fields Parsed

From `.desktop` files: `Exec=` field.

From sudoers: rule lines parsed for `NOPASSWD`, `ALL=(ALL)`, privilege patterns.

From PAM config files: module names, arguments (`pam_exec.so` script path, `pam_env.so` config paths).

From `/etc/passwd`: username, UID (field 3), shell (field 7).

### Confidence Rules

| Condition | Confidence |
|---|---|
| Sudoers: NOPASSWD or ALL=(ALL) ALL | HIGH |
| PAM module unmanaged | CRITICAL |
| PAM module modified | CRITICAL |
| pam_exec script missing | CRITICAL |
| pam_exec script in temp dir | CRITICAL |
| pam_exec script modified | CRITICAL |
| /etc/environment has LD_PRELOAD | HIGH |
| Duplicate UID 0 (non-root) account | CRITICAL |
| Shell field trailing space | HIGH |

---

## 7. Package Manager & Backdoor Locations

**Function:** `check_common_backdoors()`

### Paths Scanned

**APT configuration:**
- `/etc/apt/apt.conf.d/` (all files)
- `/usr/share/unattended-upgrades/` (all files)

**YUM/DNF configuration:**
- `/etc/yum.repos.d/`
- `/etc/yum.conf`
- `/etc/yum/pluginconf.d/`
- `/etc/dnf/pluginconf.d/`
- `/usr/lib/yum-plugins/`
- `/usr/lib/python*/site-packages/dnf-plugins/`

**DPKG postinst scripts:**
- `/var/lib/dpkg/info/*.postinst`

**RPM scripts:**
- Via `rpm -qa --scripts` (inline, no file path)

**AT/Doas access control:**
- `/etc/at.allow`
- `/etc/at.deny`
- `/etc/doas.conf`

**Git configs:**
- `/etc/gitconfig`
- `~/.gitconfig` (all user homes when root)

**Web directories (5 locations):**
- `/var/www/html/`
- `/var/www/`
- `/usr/share/nginx/html/`
- `/srv/http/`
- `/srv/www/`

### Artifact Fields Parsed

From APT conf files: `DPkg::Post-Invoke`, `DPkg::Pre-Invoke`, `APT::Update::Pre-Invoke`, `APT::Update::Post-Invoke` directive values. Hook command extracted from between quotes before semicolon.

From DPKG postinst: orphan detection (script exists but package is uninstalled) via bulk `dpkg-query -W` lookup. Content checked for download-execute and obfuscation patterns.

From web files: content patterns for PHP shells (`system(`, `exec(`, `shell_exec(`, `_POST[`, `_GET[`), JSP shells, ASP shells.

### Confidence Rules

| Condition | Confidence |
|---|---|
| APT hook in unmanaged conf file | HIGH |
| APT hook command matches malicious patterns | CRITICAL |
| DPKG postinst for uninstalled package | HIGH |
| postinst content matches patterns | HIGH→CRITICAL |
| Web file matches shell patterns | HIGH |
| doas.conf has permissive rule | HIGH |
| Git credential.helper is custom | MEDIUM→HIGH |

---

## 8. SSH Persistence

**Function:** `check_ssh_persistence()`

### Paths Scanned

**Per-user SSH (UID >= 1000, when root):**
- `~/.ssh/authorized_keys`
- `~/.ssh/rc`

**System account SSH (UID 1-999, when root):**
- `$homedir/.ssh/authorized_keys` for all system accounts in `/etc/passwd`

### Artifact Fields Parsed

From `authorized_keys`: each line parsed for key options. `command="..."` option extracted via regex and analyzed for suspicious content.

From `~/.ssh/rc`: full content analyzed.

### Confidence Rules

| Condition | Confidence |
|---|---|
| authorized_keys modified within 7 days | MEDIUM |
| authorized_keys has command= option | MEDIUM |
| command= content matches patterns | HIGH→CRITICAL |
| System account (UID 1-999) has any authorized_keys | HIGH |
| System account key command= is malicious | CRITICAL |
| ~/.ssh/rc present | MEDIUM |
| ~/.ssh/rc has suspicious content | HIGH→CRITICAL |

---

## 9. Binary Integrity

**Function:** `check_binary_integrity()`

### Paths Scanned

**Package integrity verification:**
- `/usr/bin/`, `/usr/sbin/`, `/bin/`, `/sbin/` — via `dpkg -V` or `rpm -Va`
- PAM library dirs — via `dpkg -V`

**SUID scan:**
- `/usr/bin/`, `/usr/sbin/`, `/bin/`, `/sbin/`
- `/usr/local/bin/`, `/usr/local/sbin/`
- `/opt/`
- `/tmp/`, `/dev/shm/`, `/var/tmp/`

**SGID scan:** same paths as SUID.

**File capabilities (getcap):**
- `/usr/bin/`, `/usr/sbin/`, `/bin/`, `/sbin/`
- `/usr/local/bin/`, `/usr/local/sbin/`

**Renamed binary hijacking:**
- `/bin/`, `/usr/bin/`, `/sbin/`, `/usr/sbin/`
- `/usr/local/bin/`, `/usr/local/sbin/`
- Files matching: `*.original`, `*.old`, `*.bak`, `*.real`

### Artifact Fields Parsed

From `dpkg -V` output: modified files with change indicators (permission, hash, size).

From `getcap -r`: binary path and capability string (e.g., `cap_setuid+ep`, `cap_net_raw+eip`).

From renamed binary dirs: suffix stripped to derive active name, active path stat'd for script detection (shebang check).

**GTFOBins list for `cap_setuid` escalation:**
`bash`, `sh`, `python`, `python2`, `python3`, `perl`, `ruby`, `find`, `vim`, `vi`, `nmap`, `awk`, `gawk`, `mawk`, `less`, `more`, `tee`, `cp`, `rsync`, `tar`

### Confidence Rules

| Condition | Confidence |
|---|---|
| Package-verified binary modified | CRITICAL |
| SUID binary, package-verified | LOW |
| SUID binary, unmanaged | CRITICAL |
| SUID binary in /tmp, /dev/shm, /var/tmp | CRITICAL |
| SUID shell script with malicious content | CRITICAL |
| SGID binary, unmanaged | HIGH |
| SGID binary in suspicious location | CRITICAL |
| cap_setuid on GTFOBins binary | CRITICAL |
| cap_sys_admin on any binary | CRITICAL |
| cap_net_raw on package-owned binary | LOW |
| Renamed + active is script wrapper | HIGH→CRITICAL |

---

## 10. Bootloader & Initramfs

**Function:** `check_bootloader_persistence()`

### Paths Scanned

**GRUB:**
- `/etc/default/grub`
- `/etc/default/grub.d/*.cfg`

**Root-dropped scripts:**
- `/` and subdirectories at maxdepth 2, excluding: `/etc/`, `/usr/`, `/bin/`, `/sbin/`, `/lib/`, `/opt/`, `/home/`, `/root/`, `/tmp/`, `/var/`, `/snap/`
- Files matching: `*.sh` with execute permission

**Dracut (RHEL/Fedora initramfs):**
- `/usr/lib/dracut/modules.d/*/module-setup.sh`
- Hook scripts referenced by `inst_hook pre-pivot` directives

**initramfs-tools (Ubuntu/Debian initramfs):**
- `/etc/initramfs-tools/scripts/` (all executable files)
- `/etc/initramfs-tools/hooks/` (all executable files)

**Initrd modification check:**
- `/boot/initrd.img-*` (mtime check, 7-day window)

### Artifact Fields Parsed

From GRUB configs: `GRUB_CMDLINE_LINUX_DEFAULT=` and `GRUB_CMDLINE_LINUX=` values. `init=` parameter extracted via bash regex from the combined cmdline string.

From `module-setup.sh`: `inst_hook pre-pivot <priority> <script>` lines parsed to extract hook script path.

From hook scripts: writes to `/sysroot/etc/shadow`, `/sysroot/etc/passwd` (`$rootmnt` variants for initramfs-tools), full content analysis.

### Confidence Rules

| Condition | Confidence |
|---|---|
| GRUB init= points to standard init | LOW |
| GRUB init= points to non-standard path | HIGH |
| GRUB init= target has malicious content | CRITICAL |
| Root-dropped .sh script found | MEDIUM |
| Root-dropped script has malicious content | HIGH→CRITICAL |
| Dracut pre-pivot hook found | HIGH |
| Hook writes to /sysroot/etc/shadow | CRITICAL |
| Dracut module is unmanaged | HIGH |
| initramfs-tools hook writes to $rootmnt/etc/shadow | CRITICAL |
| initrd.img modified within 7 days | MEDIUM |

---

## 11. Polkit (PolicyKit) Manipulation

**Function:** `check_polkit_persistence()`

### Paths Scanned

**.pkla files (PolicyKit < 0.106):**
- `/etc/polkit-1/localauthority/50-local.d/*.pkla`

**.rules files (PolicyKit >= 0.106):**
- `/etc/polkit-1/rules.d/*.rules`

### Artifact Fields Parsed

From `.pkla` files (KeyFile format):
- `[Group]` section names
- `Identity=` — subject specification (`unix-user:*`, `unix-group:wheel`, etc.)
- `Action=` — polkit action ID
- `ResultAny=`, `ResultInactive=`, `ResultActive=` — authorization result values

From `.rules` files (JavaScript):
- `polkit.addRule()` function calls
- `return polkit.Result.YES` statements and their conditional context
- `subject.isInGroup()`, `action.id` conditions

### Confidence Rules

| Condition | Confidence |
|---|---|
| All three Result fields set to yes | CRITICAL |
| One or two Result fields set to yes | HIGH |
| Wildcard Identity= (unix-user:*) | HIGH |
| Wildcard + all-yes | CRITICAL |
| Unconditional return polkit.Result.YES | CRITICAL |
| Conditioned polkit.Result.YES | MEDIUM→HIGH |
| File is unmanaged | HIGH (baseline) |

---

## 12. D-Bus & NetworkManager Dispatcher

**Function:** `check_dbus_persistence()`

### Paths Scanned

**D-Bus system service activation files:**
- `/usr/share/dbus-1/system-services/*.service`

**D-Bus system policy files:**
- `/etc/dbus-1/system.d/*.conf`

**NetworkManager dispatcher:**
- `/etc/NetworkManager/dispatcher.d/` (executable files only)

### Artifact Fields Parsed

From D-Bus `.service` files:
- `Exec=` line (first word is the binary path)
- `User=` (service runs as this user)
- `SystemdService=` (optional systemd unit correlation)

From D-Bus `.conf` files (XML):
- `<allow own="VALUE">` — name ownership grants
- `<allow send_destination="VALUE">` — send permission grants

From NM dispatcher scripts: full executable content analyzed.

### Confidence Rules

| Condition | Confidence |
|---|---|
| D-Bus Exec= target missing | HIGH |
| D-Bus Exec= target unmanaged | HIGH |
| D-Bus Exec= target malicious content | CRITICAL |
| D-Bus Exec= in temp location | CRITICAL |
| D-Bus policy has wildcard own= or send_destination= | HIGH |
| NM dispatcher script unmanaged | HIGH |
| NM dispatcher script has malicious content | HIGH→CRITICAL |

---

## 13. Udev Rules

**Function:** `check_udev_persistence()`

### Paths Scanned

**System admin rules:**
- `/etc/udev/rules.d/*.rules`

**Package-installed rules:**
- `/lib/udev/rules.d/*.rules`

**Runtime rules (highest suspicion):**
- `/run/udev/rules.d/*.rules`

### Artifact Fields Parsed

From each `.rules` file: lines containing `RUN+=` assignments. The command value (content between quotes) is extracted via regex:
```
RUN(\+?=|[[:space:]]*\+=[[:space:]]*)"[^"]+"
```

If the extracted command is a file path, the file's content is read and analyzed.

### Confidence Rules

| Condition | Confidence |
|---|---|
| Any rule in /run/udev/rules.d/ | HIGH |
| RUN+= contains NEVER_WHITELIST | CRITICAL |
| RUN+= delegates to at/crontab | HIGH |
| RUN+= executes from temp location | CRITICAL |
| RUN+= script has malicious content | CRITICAL |
| Rule in /lib/udev/ is unmanaged | MEDIUM |

---

## 14. Container Escape Persistence

**Function:** `check_container_persistence()`

### Paths Scanned

**Dockerfiles (filesystem search):**
- `/tmp/` (maxdepth 3)
- `/root/` (maxdepth 3)
- `/home/` (maxdepth 3)
- `/var/tmp/` (maxdepth 3)

**Docker daemon configuration:**
- `/etc/docker/daemon.json`

**Docker container inspection:**
- All container IDs from `docker ps -aq` (includes stopped containers)
- `docker inspect <id>` JSON output per container

### Artifact Fields Parsed

From `docker inspect` JSON:
- `Name` — container name
- `HostConfig.Privileged` — boolean
- `HostConfig.PidMode` — string (`host` or empty)
- `HostConfig.Binds` — array of bind-mount strings (checked for `/var/run/docker.sock`)
- `Config.Entrypoint` — array of entrypoint strings
- `Config.Cmd` — array of command strings

From `/etc/docker/daemon.json`:
- `userns-remap` field value
- `no-new-privileges` field value

### Confidence Rules

| Condition | Confidence |
|---|---|
| Dockerfile in temp/user dir | HIGH |
| Dockerfile has nsenter/socat exec/--privileged | CRITICAL |
| daemon.json weakens security | HIGH |
| Container is privileged | HIGH |
| Privileged + host PID namespace | CRITICAL |
| docker.sock bind-mounted in container | CRITICAL |
| Container entrypoint has nsenter | CRITICAL |
| Docker not installed | Skipped (graceful) |

---

## Confidence Scoring Summary

| Level | Meaning |
|---|---|
| **LOW** | Package-managed, unmodified, expected configuration |
| **MEDIUM** | Unmanaged but no suspicious patterns; or known-unusual but potentially legitimate |
| **HIGH** | Suspicious patterns present, unmanaged in sensitive location, or single strong indicator |
| **CRITICAL** | Package integrity failure, execution from temp dirs with SUID, pre-authentication hooks, initrd tampering, container escape primitives |

### Universal Escalation Rules

- **Any pattern + SUID/SGID bit** → CRITICAL (appends `+suid_sgid` to pattern)
- **Any file modified within 7 days** → one confidence tier up (LOW→MEDIUM, MEDIUM→HIGH)
- **Package verification failure** → CRITICAL regardless of current confidence

---

*Last Updated: 2026-03-16 | Version: 2.4.0*
