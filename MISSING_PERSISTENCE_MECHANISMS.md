# Missing Persistence Mechanisms in Persistnux

## Current Coverage (v2.2.0)
✅ Systemd services (ExecStart/ExecStartPre/ExecStartPost analysis; timer-activated disabled services not skipped)
✅ Systemd generators (/etc/systemd/system-generators/ and user-generators)
✅ Cron jobs (system and user crontabs, cron.d, cron.daily/hourly/weekly/monthly; field extraction corrected; env -S evasion detected)
✅ Anacron (/etc/anacrontab)
✅ At jobs (atq, spool files, hidden spool detection)
✅ Shell profiles (.bashrc, .profile, .zshrc, .zshenv, fish config, /etc/profile.d; all user homes scanned when root; /run/user/ and hidden-path locations flagged)
✅ Init scripts (/etc/rc.local, /etc/init.d, rc*.d symlink verification)
✅ Kernel modules (lsmod + file integrity verification)
✅ LD_PRELOAD (/etc/ld.so.preload entries + library integrity check)
✅ LD library config (/etc/ld.so.conf, /etc/ld.so.conf.d/ — conf file integrity; non-standard path .so files scanned and verified)
✅ Kernel module parameters (/etc/modprobe.d/, /etc/modprobe.conf — file integrity; install directives analyzed; security module blacklists flagged)
✅ Kernel module auto-load configs (/etc/modules, /etc/modules-load.d/ — config integrity; referenced .ko files verified via modinfo)
✅ XDG autostart (.desktop files, Exec= analysis; all user homes scanned when root)
✅ Sudoers files (/etc/sudoers, /etc/sudoers.d/ — NOPASSWD/ALL patterns → HIGH)
✅ PAM module integrity (all .so files in /etc/pam.d/* + @include targets + /etc/pam.conf verified; absolute-path references extracted; modified → CRITICAL, unmanaged → HIGH)
✅ PAM exec backdoors (pam_exec.so script args — regex handles bare flags and key=value options; missing script → CRITICAL; suspicious location/content → CRITICAL)
✅ PAM relay modules (pam_python.so, pam_perl.so — script extracted and analyzed; unmanaged → CRITICAL)
✅ PAM script hooks (pam_script.so — hook files in /etc/security/ scanned; suspicious content → CRITICAL, unmanaged → HIGH)
✅ PAM config file integrity (/etc/pam.d/* files — modified package-owned configs → CRITICAL)
✅ PAM environment LD_PRELOAD (/etc/security/pam_env.conf and ~/.pam_environment — LD_PRELOAD library verified; unmanaged/modified → CRITICAL)
✅ /etc/security/ general scan (all files — modified package files → CRITICAL; executable unmanaged with suspicious content → HIGH)
✅ MOTD scripts (/etc/update-motd.d/ — package verification before content analysis; modified → CRITICAL)
✅ Package manager configs (APT apt.conf.d, YUM/DNF repos)
✅ At access control files (/etc/at.allow, /etc/at.deny)
✅ Git configs (~/.gitconfig — credential helpers, core.pager, core.editor; content analysis for all users including non-root)
✅ Web shell detection (PHP/ASP/JSP/ASPX files, webshell pattern matching; 100-file limit now functional)
✅ /etc/environment (LD_PRELOAD, LD_LIBRARY_PATH — env file flagged; referenced library paths verified via is_package_managed(); unmanaged/modified library → CRITICAL)
✅ Doas configuration (/etc/doas.conf — permissive rule detection)

❌ SSH authorized_keys — NOT implemented. No dedicated scan of ~/.ssh/authorized_keys
   or /root/.ssh/authorized_keys (forced-command keys, recently added keys, non-standard
   AuthorizedKeysFile location).

## HIGH PRIORITY - To Add

### Boot/Pre-OS Persistence (T1542)
❌ **GRUB bootloader** - /boot/grub/, /etc/default/grub
❌ **Initramfs** - /boot/initrd.img, /boot/initramfs modifications
❌ **Dracut modules** - /usr/lib/dracut/modules.d/

### Systemd Advanced (T1543, T1053.006)
✅ **Systemd generators** - Implemented: /etc/systemd/system-generators/ and all
   user-generator paths scanned; unmanaged generators flagged HIGH, modified CRITICAL
❌ **Systemd drop-in overrides** - *.d/ override directories not scanned. An attacker
   can add /etc/systemd/system/ssh.service.d/override.conf with a malicious
   ExecStartPost while leaving the original ssh.service file untouched.

### Event-Triggered Execution (T1546)
❌ **Udev rules** - /etc/udev/rules.d/ — RUN+= directives execute as root on hardware events
❌ **NetworkManager dispatchers** - /etc/NetworkManager/dispatcher.d/ — run as root on
   network state changes (interface up/down, DHCP, VPN)
❌ **Git hooks** - .git/hooks/ in user repositories not scanned (pre-commit, post-merge,
   post-checkout execute silently during normal developer workflow)
✅ **Git config pager/helper** - Implemented: core.pager and credential.helper in
   ~/.gitconfig flagged at MEDIUM; suspicious patterns escalate to HIGH

### Privilege Escalation (T1548)
❌ **SUID/SGID binary enumeration** - No proactive find -perm -4000 scan. SUID/SGID
   escalation only triggers on files already detected by other means. Attackers
   commonly install SUID shells (/usr/bin/find, /tmp/.bash -p) as standalone persistence.
❌ **File capabilities** - No getcap enumeration. cap_setuid, cap_sys_admin,
   cap_net_raw can be exploited without SUID and are invisible to the current checks.

### Hijacking (T1574, T1554)
✅ **LD_LIBRARY_PATH in /etc/environment** - Implemented: /etc/environment is scanned
   for both LD_PRELOAD and LD_LIBRARY_PATH entries
❌ **LD_LIBRARY_PATH in shell profiles / systemd units** - Not specifically detected
   when set inside .bashrc, /etc/profile.d scripts, or service Environment= directives
❌ **System binary hijacking** - No check for PATH prepending in shell profiles that
   would shadow system tools with attacker-controlled scripts

### Account Manipulation (T1136, T1098)
❌ **Backdoor user accounts** - No check for: UID 0 accounts besides root; system
   accounts (uid < 1000) with login shells (/bin/bash, /bin/sh, etc.)
❌ **Password file integrity** - /etc/passwd and /etc/shadow not checked via package
   verification or modification-time analysis
❌ **Group manipulation** - /etc/group not checked for unauthorized additions to
   privileged groups (sudo, docker, wheel, adm)

### Pluggable Auth Modules (T1556.003)
✅ **PAM module detection** - Implemented: all .so files in /etc/pam.d/*, @include
   targets, and /etc/pam.conf verified via is_package_managed(); absolute-path
   references extracted separately; modified → CRITICAL, unmanaged → HIGH
✅ **PAM exec backdoors** - Implemented: pam_exec.so regex handles bare flags and
   key=value options; missing script → CRITICAL; suspicious location/content → CRITICAL
✅ **PAM relay modules** - Implemented: pam_python.so and pam_perl.so script paths
   extracted and analyzed; unmanaged script → CRITICAL
✅ **PAM script hooks** - Implemented: pam_script.so hook files in /etc/security/
   scanned; suspicious content → CRITICAL, unmanaged hook → HIGH
✅ **PAM config integrity** - Implemented: /etc/pam.d/* files verified against package
   manager; modified package-owned PAM config → CRITICAL
✅ **PAM LD_PRELOAD** - Implemented: /etc/security/pam_env.conf and ~/.pam_environment
   (per-user, root only) scanned; unmanaged/modified LD_PRELOAD library → CRITICAL

### Installer Packages (T1546.016)
❌ **DPKG lifecycle scripts** - /var/lib/dpkg/info/*.{preinst,postinst,prerm,postrm}
   run as root during package operations; not scanned
❌ **RPM scripts** - /var/tmp/rpm-tmp.* temporary scripts not checked

### PolicyKit & D-Bus (T1543)
❌ **Polkit rules** - /etc/polkit-1/rules.d/ not checked
❌ **D-Bus services** - /usr/share/dbus-1/system-services/ not checked

### Containers (T1610)
❌ **Docker escapes** - Privileged containers, mounted /var/run/docker.sock not checked
❌ **Container persistence** - /var/lib/docker/ not scanned

### SSH (T1098.004)
❌ **authorized_keys** - No scan of ~/.ssh/authorized_keys or /root/.ssh/authorized_keys.
   No detection of: forced-command keys (command= prefix), recently added keys,
   non-standard AuthorizedKeysFile location in sshd_config
❌ **sshd_config analysis** - PermitRootLogin yes, AuthorizedKeysFile pointing to
   unexpected paths, PermitUserEnvironment yes not checked

## MEDIUM PRIORITY

### Init Systems
❌ **Upstart jobs** - /etc/init/ (legacy Ubuntu pre-15.04, rarely encountered)

### Advanced Rootkits (T1014)
❌ **Known rootkit artifacts** - Diamorphine, Reptile, specific hiding techniques
❌ **Hidden files/dirs** - Rootkit-style hiding patterns in system directories

## DETECTION ENHANCEMENTS NEEDED

### Time-Based Anomalies
✅ Recently modified systemd services (< 7 days) - IMPLEMENTED
✅ Recently modified cron jobs (< 7 days) - IMPLEMENTED
✅ Recently modified shell profiles (< 7 days) - IMPLEMENTED
✅ Recently modified web files (< 30 days) - IMPLEMENTED
❌ Recently modified files across remaining categories (init, kernel, PAM, etc.)
❌ Files modified after system installation date (cross-reference with dpkg log)

### Content Analysis
✅ Encoding/obfuscation detection - IMPLEMENTED: hex (\x41\x42), octal (\101\102),
   ANSI-C quoting ($'\x62\x61\x73\x68'), tr-cipher (ROT13/ROT47), rev-pipe, and
   high-entropy strings with execution context (eval, exec, base64 -d) are all detected
   in analyze_script_content()
✅ Inline code analysis (-c/-e flags) - IMPLEMENTED: analyze_inline_code() extracts
   and deeply analyzes arguments to interpreter -c/-e flags
❌ Network indicators (IP addresses, C2 domains) in non-script config files
❌ PYTHONPATH / RUBYLIB / PERL5LIB hijacking in shell profiles and environment files

### Cross-Category Correlation
❌ Multiple persistence mechanisms by same user/UID
❌ Persistence chains (e.g., cron -> systemd -> ld_preload)

