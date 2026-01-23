# Missing Persistence Mechanisms in Persistnux

## Current Coverage (v1.1.0)
✅ Systemd services/timers
✅ Cron jobs (system and user)
✅ Shell profiles (.bashrc, .profile, etc.)
✅ SSH authorized_keys
✅ Init scripts (/etc/init.d, /etc/rc.local)
✅ Kernel modules (enumeration)
✅ LD_PRELOAD (/etc/ld.so.preload)
✅ XDG autostart
✅ Sudoers files
✅ PAM configurations (basic)
✅ MOTD scripts
✅ Package manager configs (APT/YUM)
✅ At access control files
✅ Git configs
✅ Web shell detection (PHP/ASP/JSP)

## HIGH PRIORITY - To Add

### Boot/Pre-OS Persistence (T1542)
❌ **GRUB bootloader** - /boot/grub/, /etc/default/grub
❌ **Initramfs** - /boot/initrd.img, /boot/initramfs modifications
❌ **Dracut modules** - /usr/lib/dracut/modules.d/

### Systemd Advanced (T1543, T1053.006)
❌ **Systemd generators** - /etc/systemd/system-generators/
❌ **Systemd drop-in overrides** - *.d/ directories

### Event-Triggered Execution (T1546)
❌ **Udev rules** - /etc/udev/rules.d/
❌ **NetworkManager dispatchers** - /etc/NetworkManager/dispatcher.d/
❌ **Git hooks** - .git/hooks/ (pre-commit, post-merge, etc.)
❌ **Git pager** - core.pager in gitconfig

### Privilege Escalation (T1548)
❌ **SUID/SGID binaries** - Enumerate dangerous SUID/SGID files
❌ **Capabilities** - File capabilities (getcap output)

### Hijacking (T1574, T1554)
❌ **LD_LIBRARY_PATH** - Environment variable checks
❌ **System binary hijacking** - Wrapped system binaries

### Account Manipulation (T1136, T1098)
❌ **Backdoor user accounts** - UID 0 users, system users with shells
❌ **Password file manipulation** - /etc/passwd, /etc/shadow direct edits
❌ **Group manipulation** - /etc/group privileged group membership

### Pluggable Auth Modules (T1556.003)
❌ **PAM module detection** - Malicious .so files in /lib/security/
❌ **PAM config backdoors** - pam_exec.so abuse

### Installer Packages (T1546.016)
❌ **DPKG lifecycle scripts** - /var/lib/dpkg/info/*{pre,post}{inst,rm}
❌ **RPM scripts** - /var/tmp/rpm-tmp.*, /var/lib/rpm/

### PolicyKit & D-Bus (T1543)
❌ **Polkit rules** - /etc/polkit-1/rules.d/
❌ **D-Bus services** - /usr/share/dbus-1/system-services/

### Containers (T1610)
❌ **Docker escapes** - Privileged containers, mounted sockets
❌ **Container persistence** - /var/lib/docker/

## MEDIUM PRIORITY

### Init Systems
❌ **Upstart jobs** - /etc/init/ (legacy, rarely used)

### Advanced Rootkits (T1014)
❌ **Known rootkit artifacts** - Diamorphine, specific hiding techniques
❌ **Hidden files/dirs** - Rootkit-style hiding patterns

## DETECTION ENHANCEMENTS NEEDED

### Time-Based Anomalies
✅ Recently modified systemd services (< 7 days) - IMPLEMENTED
✅ Recently modified cron jobs (< 7 days) - IMPLEMENTED
❌ Recently modified files across ALL categories
❌ Files modified after system installation date

### Content Analysis
❌ Suspicious shell patterns in ALL executable files
❌ Network indicators (IP addresses, domains) in configs
❌ Encoding/obfuscation detection (base64, hex, etc.)

### Cross-Category Correlation
❌ Multiple persistence mechanisms by same user/UID
❌ Persistence chains (e.g., cron -> systemd -> ld_preload)

