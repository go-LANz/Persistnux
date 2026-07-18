# PANIX Detection Benchmark

Persistnux uses [**PANIX**](https://github.com/Aegrah/PANIX) (Aegrah's Linux
persistence toolkit) as its standing detection benchmark. PANIX implements the
same persistence mechanisms Persistnux is designed to hunt, so it is an ideal
adversary emulator: install a technique, run Persistnux, confirm the artifact is
flagged at an actionable confidence.

The harness lives at [`tests/panix_benchmark.sh`](tests/panix_benchmark.sh).

> ⚠️ **The benchmark installs real persistence** (backdoors, SUID bits, cron/at
> jobs, PAM edits, rogue systemd units, a webshell, …). Run it **only in a
> disposable throwaway VM or container** you can destroy. Never on a production
> or personal host. The harness performs a targeted revert at the end, but the
> only safe assumption is that the box is contaminated.

## Running it

```bash
# inside a disposable Debian/Ubuntu/Kali VM, as root:
sudo ./tests/panix_benchmark.sh /path/to/persistnux.sh
```

It clones PANIX to `/opt/PANIX`, installs test deps (`at gcc libcap2-bin bc`),
takes a **baseline** Persistnux scan, applies each technique, re-scans, and
attributes detections by diffing against the baseline (so pre-existing findings
are never miscredited). It finishes with a targeted revert.

## Methodology notes

- **Baseline diff.** Only findings absent from the pre-PANIX baseline are counted
  as detections. This prevents crediting a technique for a finding that was
  already present (e.g. a distro's own APT hook).
- **`FILTER_MODE=all`.** The benchmark scans with all confidence levels so a
  `LOW`/baseline result is visible as `low-only` rather than a false miss.
- **Re-run on a clean box.** If a previous benchmark's revert was interrupted,
  leftover artifacts land in the next run's *baseline* and get excluded — re-run
  on a fresh VM for authoritative numbers.

## Results

Validated on **Kali Linux (rolling)** and **Ubuntu 22.04**, Persistnux v2.6.0.
Every PANIX file-based persistence technique that applies on the test box is
detected at `MEDIUM` or higher:

| PANIX technique | Persistnux module | Detected | Max confidence |
|---|---|:--:|---|
| `--cron` | Cron | ✅ | HIGH |
| `--systemd` (drops in `/usr/local/lib/systemd/system`) | Systemd Service | ✅ | CRITICAL |
| `--at` | Scheduled / At | ✅ | HIGH |
| `--authorized-keys` | SSH | ✅ | MEDIUM |
| `--shell-profile` | ShellProfile | ✅ | HIGH |
| `--ld-preload` | Preload | ✅ | HIGH |
| `--sudoers` | Privilege / Sudoers | ✅ | HIGH |
| `--suid` (SUID on a GTFOBin) | BinaryIntegrity / SUID | ✅ | CRITICAL |
| `--udev` | EventTriggered / Udev | ✅ | MEDIUM |
| `--generator` | Systemd / Generator | ✅ | CRITICAL |
| `--initd` | Init | ✅ | HIGH |
| `--rc-local` | Init / RcLocal | ✅ | HIGH |
| `--motd` | MOTD | ✅ | HIGH |
| `--xdg` | Autostart / XDG | ✅ | HIGH |
| `--dbus` | EventTriggered / DBus | ✅ | CRITICAL |
| `--polkit` | Privilege / Polkit | ✅ | CRITICAL |
| `--package-manager` (APT hook) | PackageManager / AptHook | ✅ | HIGH |
| `--web-shell` | WebShell | ✅ | HIGH |
| `--passwd-user` (UID 0) | UserAccount / Passwd | ✅ | CRITICAL |
| `--cap` (cap_setuid on a GTFOBin) | Privilege / Capability | ✅ | CRITICAL |
| `--pam --pam-exec` | PAM | ✅ | CRITICAL |

### Gaps this benchmark found and fixed (v2.6.0)

The benchmark surfaced three real detection failures, all fixed:

1. **`--systemd` was missed** — PANIX drops its unit in
   `/usr/local/lib/systemd/system`, a valid unit search path
   (`systemd-analyze unit-paths`) that Persistnux did not scan. Added.
2. **`--suid` and `--cap` were missed** — the entire `check_binary_integrity`
   module (SUID/SGID scan, capability scan, binary-hijack scan) was silently
   aborting under `set -eo pipefail` at the dpkg-verify step, so none of those
   scans ran. Fixed, plus **SUID/cap on a GTFOBin is now CRITICAL regardless of
   package status** (`dpkg --verify` does not report mode-only changes).
3. A package-verified udev rule whose `RUN+=` target was an ELF binary produced a
   **CRITICAL false positive**; content analysis now skips binaries.

## Scope / not benchmarked here

These PANIX modules are out of scope for the automated harness (environment or
philosophy), not known misses:

- **`--grub`, `--initramfs`, `--lkm`, `--rootkit`** — bootloader/initramfs/kernel-
  module vectors that aren't meaningful to install/verify in the WSL/container
  test box (no real boot, kernel module build often unavailable). Persistnux has
  static detection for the GRUB/initramfs/dracut/LKM artifacts; test on a full VM.
- **`--malicious-container` / docker** — requires a running Docker daemon.
- **`--system-binary`** — replaces a real system binary; heavy to revert safely.
- **`--bind-shell` / `--reverse-shell`** — runtime process persistence, not a
  file artifact this file-scanning tool targets.
- **`--network-manager`** — needs NetworkManager installed.
- **`--create-user` / `--backdoor-user`** — Persistnux deliberately does **not**
  flag every new `UID ≥ 1000` account (that is noise); it flags **UID 0
  duplicates** (CRITICAL, covered by `--passwd-user` above) and **system accounts
  (UID 1–999) that have SSH keys**. A plain new sudo user is intentionally not a
  finding.
