#!/bin/bash
###############################################################################
# Persistnux <- PANIX detection benchmark
#
# Applies a set of PANIX (https://github.com/Aegrah/PANIX) persistence
# techniques, runs Persistnux, and reports which artifacts were flagged and at
# what confidence — using a baseline diff so only NEW findings are attributed.
#
#   ┌──────────────────────────────────────────────────────────────────────┐
#   │  WARNING — this script INSTALLS REAL PERSISTENCE (backdoors, SUID     │
#   │  bits, cron/at jobs, PAM edits, rogue systemd units, …).             │
#   │  Run ONLY inside a disposable throwaway VM/container you can destroy. │
#   │  NEVER run on a production or personal host.                          │
#   └──────────────────────────────────────────────────────────────────────┘
#
# Requirements: root, a Debian/Ubuntu/Kali test box, internet (to clone PANIX),
#               and the persistnux.sh under test. Installs: at gcc libcap2-bin bc.
#
# Usage:  sudo ./tests/panix_benchmark.sh /path/to/persistnux.sh
###############################################################################
set -u

PNX="${1:-}"
[[ -z "$PNX" || ! -f "$PNX" ]] && { echo "usage: sudo $0 /path/to/persistnux.sh"; exit 1; }
[[ "$(id -u)" -eq 0 ]] || { echo "must run as root"; exit 1; }

PANIX_DIR="${PANIX_DIR:-/opt/PANIX}"
PANIX="$PANIX_DIR/panix.sh"
BENCH="${BENCH:-/tmp/persistnux_panix_bench}"
IP=127.0.0.1; PORT=9001
KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPanixBenchmarkTestKey0000000000000000000000 panix@bench"
mkdir -p "$BENCH"

export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq at gcc libcap2-bin bc git >/dev/null 2>&1
systemctl start atd 2>/dev/null || true
[[ -f "$PANIX" ]] || git clone --depth 1 https://github.com/Aegrah/PANIX.git "$PANIX_DIR" >/dev/null 2>&1

# technique : panix args (after -q) : detection regex (matched against the CSV)
TECHS=(
"cron:--cron --default --ip $IP --port $PORT:freedesktop_timesync1"
"systemd:--systemd --default --ip $IP --port $PORT:evil\.service|freedesktop\.resolved|/usr/local/lib/systemd/system"
"at:--at --default --ip $IP --port $PORT --time 'now + 1 minute':at_job|at_spool|/var/spool/(at|cron/atjobs)"
"authorized-keys:--authorized-keys --default --key '$KEY':authorized_keys"
"shell-profile:--shell-profile --default --ip $IP --port $PORT:/etc/profile|profile_file|profile_script"
"ld-preload:--ld-preload --ip $IP --port $PORT --binary /usr/bin/whoami:ld\.so\.preload|ld_preload"
"sudoers:--sudoers --username root:sudoers"
"suid:--suid --default:suid_gtfobin|suid_unmanaged|/usr/bin/find|/usr/bin/dash"
"udev:--udev --default --systemd --ip $IP --port $PORT:10-backdoor|udev_run|udev_rule"
"generator:--generator --ip $IP --port $PORT:system-generators|makecon"
"initd:--initd --default --ip $IP --port $PORT:ssh-procps|init_script"
"rc-local:--rc-local --default --ip $IP --port $PORT:rc\.local|rc_local"
"motd:--motd --default --ip $IP --port $PORT:137-python-upgrades|motd_script"
"xdg:--xdg --default --ip $IP --port $PORT:pkc12-register|xdg_autostart"
"dbus:--dbus --default --ip $IP --port $PORT:org.panix.persistence|dbus-panix|dbus_"
"polkit:--polkit:panix.pkla|99-panix.rules|polkit_"
"package-manager:--package-manager --apt --ip $IP --port $PORT:01python-upgrades|apt_hook"
"web-shell:--web-shell --language php --port 8899 --mechanism cmd:/var/www/html/panix|webshell"
"passwd-user:--passwd-user --default --username panixpwd --password Passw0rd123:panixpwd|non_root_uid_zero"
"cap:--cap --default:cap_setuid|file_capability"
"pam-exec:--pam --pam-exec --backdoor --ip $IP --port $PORT:pam_exec|pam_module|modified_pam"
)

runpnx(){ rm -rf "$1"; OUTPUT_DIR="$1" FILTER_MODE=all bash "$PNX" >/dev/null 2>&1; ls "$1"/*.csv 2>/dev/null | head -1; }
rank(){ case "$1" in CRITICAL) echo 4;; HIGH) echo 3;; MEDIUM) echo 2;; LOW) echo 1;; *) echo 0;; esac; }

echo "### BASELINE (pre-PANIX) ###"
BASE=$(runpnx "$BENCH/base"); cut -d',' -f3- "$BASE" | sort -u > "$BENCH/base_keys.txt"
echo "baseline rows: $(($(wc -l < "$BASE")-1))"

echo; echo "### APPLYING PANIX TECHNIQUES ###"
cd "$PANIX_DIR" || exit 1
for row in "${TECHS[@]}"; do
    name="${row%%:*}"; rest="${row#*:}"; args="${rest%%:*}"
    eval "timeout 90 bash \"$PANIX\" -q $args" >"$BENCH/apply_${name}.log" 2>&1
    printf '%-16s rc=%s\n' "$name" "$?"
done
pkill -f "php -S" 2>/dev/null || true

echo; echo "### POST-PANIX SCAN ###"
CSV=$(runpnx "$BENCH/post"); echo "post rows: $(($(wc -l < "$CSV")-1))"

echo; echo "### DETECTION (new findings vs baseline) ###"
printf '%-16s | %-8s | %-9s | %s\n' "TECHNIQUE" "DETECT" "CONF" "SAMPLE(path|pattern)"
printf -- '-%.0s' {1..96}; echo
det=0; total=0
for row in "${TECHS[@]}"; do
    name="${row%%:*}"; rest="${row#*:}"; regex="${rest#*:}"; total=$((total+1))
    best=""; sample=""
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        grep -qxF "$(cut -d',' -f3- <<< "$line")" "$BENCH/base_keys.txt" && continue
        c=$(cut -d',' -f4 <<< "$line")
        if [[ -z "$best" ]] || [[ $(rank "$c") -gt $(rank "$best") ]]; then
            best="$c"; sample="$(cut -d',' -f5 <<< "$line" | tail -c 40)|$(cut -d',' -f13 <<< "$line")"
        fi
    done < <(grep -iE "$regex" "$CSV")
    if [[ -z "$best" ]]; then printf '%-16s | %-8s |\n' "$name" "NO"; continue; fi
    mark="YES"; [[ "$best" == "LOW" ]] && mark="low-only"
    [[ "$best" != "LOW" ]] && det=$((det+1))
    printf '%-16s | %-8s | %-9s | %s\n' "$name" "$mark" "$best" "${sample:0:54}"
done
echo; echo "DETECTED (>=MEDIUM, new): $det / $total"

echo; echo "### TARGETED REVERT (avoids PANIX --revert global-find crawl) ###"
userdel -r panixpwd 2>/dev/null; sed -i '/panix/Id' /etc/passwd /etc/passwd- /etc/shadow /etc/shadow- \
    /etc/group /etc/group- /etc/gshadow /etc/gshadow- /etc/subuid /etc/subuid- /etc/subgid /etc/subgid- 2>/dev/null
rm -f /etc/passwd.backup /etc/passwd.bak 2>/dev/null
rm -rf /var/www/html/panix
rm -f /etc/dbus-1/system.d/org.panix.persistence.conf /usr/share/dbus-1/system-services/org.panix.persistence.service \
      /usr/local/bin/dbus-panix.sh /etc/NetworkManager/dispatcher.d/panix-dispatcher.sh \
      /etc/polkit-1/localauthority/50-local.d/panix.pkla /etc/polkit-1/rules.d/99-panix.rules \
      /etc/cron.d/freedesktop_timesync1 /etc/ld.so.preload /etc/udev/rules.d/10-backdoor.rules \
      /etc/udev/rules.d/12-systemdtest.rules /etc/update-motd.d/137-python-upgrades \
      /etc/xdg/autostart/pkc12-register.desktop /etc/init.d/ssh-procps /lib/preload_backdoor.so \
      /etc/apt/apt.conf.d/01python-upgrades /root/.ssh/authorized_keys.bak /root/.ssh/authorized_keys.backup
rm -rf /usr/local/lib/systemd/system/evil.service \
       /usr/local/lib/systemd/system/dbus-org.freedesktop.resolved.* \
       /usr/lib/systemd/system-generators/makecon /usr/lib/systemd/system-generators/generator
rm -f /etc/sudoers.d/root /etc/sudoers.d/*panix* 2>/dev/null; sed -i '/panix/Id' /etc/sudoers 2>/dev/null
atrm $(atq 2>/dev/null | awk '{print $1}') 2>/dev/null; rm -f /var/spool/cron/atjobs/* /var/spool/at/* 2>/dev/null
for f in /etc/profile /etc/rc.local /etc/pam.d/sshd /etc/pam.d/common-auth; do [ -f "$f.bak" ] && mv -f "$f.bak" "$f"; done
sed -i '/dev\/tcp\|preload_backdoor\|panix/Id' /etc/profile /etc/rc.local 2>/dev/null
sed -i '/panix@bench/d' /root/.ssh/authorized_keys 2>/dev/null
for b in find dash python python3 vim; do p=$(command -v $b 2>/dev/null); [ -n "$p" ] && chmod u-s "$(realpath "$p")" 2>/dev/null; done
for b in perl ruby ruby3.3 php php8.4 python3 python3.13 node; do p=$(command -v $b 2>/dev/null); [ -n "$p" ] && setcap -r "$(realpath "$p")" 2>/dev/null; done
systemctl daemon-reload 2>/dev/null
echo "revert done — verify residual (want empty):"
grep -RIl "panix\|freedesktop_timesync1\|pkc12-register\|org.panix\|preload_backdoor" /etc /usr/local 2>/dev/null | grep -v /mnt/ | head
