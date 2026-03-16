# Persistnux v2.4.0 — Production Readiness Review Findings

**Date:** 2026-03-16
**Reviewer:** PAI Code Review
**Script:** persistnux.sh v2.4.0 (6777 lines)
**Scope:** Detection logic, package verification, severity marking, CSV/JSONL output, bugs, speed
**Policy:** No code changes — findings only. User decides on action.

---

## Summary Table

| ID | Category | Severity | Area | Brief | Line(s) |
|----|----------|----------|------|-------|---------|
| FN-1 | FALSE_NEGATIVE | CRITICAL | Detection | `analyze_script_content()` called with content strings at 13 sites — function expects file path, returns 1 immediately on non-file input, silently skipping all script analysis | 1267, 1877, 1904, 5217, 5792, 5900, 5960, 6035, 6093, 6123, 6411, 6545 |
| FN-2 | FALSE_NEGATIVE | HIGH | Detection | Bootloader GRUB `init=` extraction: `[[:space:]]init=` misses first kernel parameter; trailing quote left on value after strip | 1853–1856 |
| FN-3 | FALSE_NEGATIVE | HIGH | Detection | SSH `analyze_script_content` called with forced-command string, not file path → forced-command content never analyzed for backdoors | 5792 |
| FN-4 | FALSE_NEGATIVE | HIGH | Detection | SUID script content passed as string to `analyze_script_content`, not as file path → SUID shell scripts never content-analyzed | 6411 |
| FN-5 | FALSE_NEGATIVE | HIGH | Detection | `get_executable_from_command()` returns env var assignment (e.g. `LD_PRELOAD=/lib/evil.so`) as executable instead of actual binary for `VAR=val /bin/sshd` ExecStart lines | 920–945 |
| FN-6 | FALSE_NEGATIVE | HIGH | Detection | Udev `RUN+=` regex requires double-quoted value — single-quoted and unquoted forms missed | 6089 |
| FN-7 | FALSE_NEGATIVE | HIGH | Detection | DBus `SystemdService=` field not checked — persistence via DBus-activated service not detected | 5931–5975 |
| FN-8 | FALSE_NEGATIVE | HIGH | Detection | DBus wildcard policy only matches literal `\*` — prefix wildcards like `org.freedesktop.*` missed | 6001 |
| FN-9 | FALSE_NEGATIVE | HIGH | Detection | Polkit conditional check marks all YES returns MEDIUM if any `if(` in file — legitimate conditionals inflate confidence, missing the distinction between blanket and conditional grants | 5882–5896 |
| FN-10 | FALSE_NEGATIVE | MEDIUM | Detection | SSH `authorized_keys` scan follows `/etc/passwd` UID ranges only — ignores `AuthorizedKeysFile` directive, misses non-default key locations | 5661–5669 |
| FN-11 | FALSE_NEGATIVE | MEDIUM | Detection | `check_systemd()` only extracts first `ExecStart=` line — multi-value or overridden units silently miss additional exec lines | 2084 |
| FN-12 | FALSE_NEGATIVE | MEDIUM | Detection | `check_systemd()` no line-continuation handling for `ExecStart=` — backslash-continued lines not joined before extraction | 2084 |
| FN-13 | FALSE_NEGATIVE | MEDIUM | Detection | SUSPICIOUS_LOCATIONS `"/\.[a-z]"` only matches lowercase hidden dirs — uppercase or mixed-case hidden dirs (`.X11-unix`, `.ICEauthority`) not matched | 131 |
| FN-14 | FALSE_NEGATIVE | MEDIUM | Detection | `NETWORK_INDICATOR_PATTERNS` TLD patterns miss bare URLs at end of line — trailing anchor needed after TLD group | 270, 272 |
| FN-15 | FALSE_NEGATIVE | MEDIUM | Detection | `"sh -i >\$ /dev/tcp/"` broken ERE pattern — `>$` is end-of-line anchor in ERE, bash reverse shell pattern never fires | 64 |
| FN-16 | FALSE_NEGATIVE | MEDIUM | Detection | LD_PRELOAD/LD_LIBRARY_PATH patterns only match `/tmp`, `/dev/shm`, `/var/tmp` staging dirs — user home dirs, `/opt`, `/srv` paths missed | 241–242 |
| FN-17 | FALSE_NEGATIVE | MEDIUM | Detection | `dracut` and initrd `find` calls have no `-maxdepth` — directories with unusual nesting skip detection and cause unbounded recursion | 1968, 2005 |
| FN-18 | FALSE_NEGATIVE | MEDIUM | Detection | Container scan capped at 20 (`head -20`) with no warning — large environments silently underscanned | 6197 |
| FN-19 | FALSE_NEGATIVE | LOW | Detection | SUID cap 200 / SGID cap 100 — no truncation notice in final report; analyst unaware scan was incomplete | 6381, 6429 |
| FN-20 | FALSE_NEGATIVE | LOW | Detection | `getcap -r` scan covers standard binary paths only — non-standard capability binaries outside those paths not found | 6453–6505 |
| BUG-1 | BUG | CRITICAL | Severity | SUID/SGID confidence escalation dead code: `[[ "$file_permissions" =~ [sS] ]]` checks for symbolic 's' but `stat -c "mode:%a"` produces octal (e.g. "4755") — HIGH→CRITICAL escalation has never fired | 1728, 627–631 |
| BUG-2 | BUG | CRITICAL | Detection | Same as FN-1 — `analyze_script_content()` two-argument calling convention broken at all 13 content-string call sites | 1267 |
| BUG-3 | BUG | CRITICAL | Detection | Same as FN-5 — `get_executable_from_command()` env var assignment returned as executable | 920–945 |
| BUG-4 | BUG | HIGH | Output | JSONL output: `$timestamp`, `$file_hash`, `$file_permissions`, `$file_age_days` not wrapped in `escape_json()` — special characters in these fields corrupt JSON | 1704–1757 |
| BUG-5 | BUG | HIGH | Package | DPKG postinst timeout: if `dpkg-query` times out (apt lock), `_dpkg_installed_pkgs` array stays empty → all 500+ postinst scripts marked orphaned → mass false positive surge | 5348–5364 |
| BUG-6 | BUG | HIGH | Package | PKG_CACHE not shared across module subshells — each of 14 parallel modules starts with empty cache after fork, eliminating cross-module cache benefits | 43–48, 6635–6681 |
| BUG-7 | BUG | MEDIUM | Detection | `escape_csv()` misses Unicode line separator U+2028 and paragraph separator U+2029 — analyst tools that split on these characters will produce malformed rows | 1658–1665 |
| BUG-8 | BUG | MEDIUM | Output | `grep -c '"confidence":"CRITICAL"'` in report generation counts raw string matches — a finding whose description contains `"confidence":"CRITICAL"` would inflate the CRITICAL count | 6703–6706 |
| BUG-9 | BUG | LOW | Runtime | No bash version check — `declare -A` associative arrays require bash 4.0+; script will fail cryptically on bash 3.x (macOS default) | 43–48 |
| BUG-10 | BUG | LOW | Runtime | `set -eo pipefail` at line 10 — subshells launched with `|| true` guard (`wait "${_mod_pids[$_mi]}" || true`) correctly suppress exit propagation, but any unguarded pipeline failure in modules will silently kill that subshell's output | 10, 6675 |
| BUG-11 | BUG | LOW | Runtime | High entropy detection: `while` loop spawns `awk` per variable-containing line — in scripts with many variable assignments, this creates hundreds of subprocesses per analyzed script | 1436–1466 |
| FP-1 | FALSE_POSITIVE | HIGH | Package | `"socat.*TCP:"` in `NEVER_WHITELIST_PATTERNS` — overrides package verification for legitimate admin tools that use socat for tunneling; any package-managed socat usage flagged CRITICAL | 227 |
| FP-2 | FALSE_POSITIVE | HIGH | Package | DPKG postinst mass false positive on apt lock timeout (same as BUG-5) — apt upgrade in progress → all postinst scripts appear orphaned | 5348–5364 |
| FP-3 | FALSE_POSITIVE | MEDIUM | Detection | Polkit conditional marking (same as FN-9) — legitimate use of conditionals in polkit rules inflates findings | 5882–5896 |
| FP-4 | FALSE_POSITIVE | LOW | Detection | `"socat.*TCP:"` over-broad pattern catches legitimate monitoring and tunneling setups beyond just the NEVER_WHITELIST context | 227 |
| PERF-1 | PERF | HIGH | Speed | `is_package_managed()` calls `timeout 5 dpkg -S "$file"` up to three sequential times per file — on systems with large package databases, each call is 1–3s; per-file cost up to 9s with no cross-module sharing (PKG_CACHE empty per subshell) | 760, 764, 789 |
| PERF-2 | PERF | HIGH | Speed | `find` in dracut/initrd modules without `-maxdepth` — on systems with deep initrd trees or if bind mounts exist, find recurses indefinitely | 1968, 2005 |
| PERF-3 | PERF | MEDIUM | Speed | High entropy `awk` subprocess per line — scripts with 1000+ variable assignments spawn 1000+ awk processes; consider batching with single awk invocation | 1436–1466 |
| Q-1 | QUALITY | HIGH | Report | Report `.txt` lists [1/9]..[9/9] — 14 modules actually run in v2.4.0. Five modules (bootloader, polkit, dbus, udev, container) completely absent from report summary | 6740–6749 |
| Q-2 | QUALITY | HIGH | Report | `exit 1` when CRITICAL findings exist (line 6771–6773) — undocumented CI/CD behavior; not mentioned in help text or README | 6771–6773 |
| Q-3 | QUALITY | MEDIUM | Compat | No bash version guard — script should check `$BASH_VERSION` and exit with clear message on bash < 4.0 | 1 |
| Q-4 | QUALITY | MEDIUM | Filtering | `should_include_finding()` accepts CRITICAL as valid `--min-confidence` value but error message and help text only list LOW|MEDIUM|HIGH — CRITICAL is undocumented | 1617–1654 |
| Q-5 | QUALITY | MEDIUM | Compat | Distro detection: no explicit check for Alpine (musl), Arch (pacman), or Gentoo (portage) — falls through to dpkg/rpm with unclear behavior | 689–908 |
| Q-6 | QUALITY | MEDIUM | Output | JSONL field values `$timestamp`, `$file_hash`, `$file_permissions`, `$file_age_days` not JSON-escaped — controlled input but worth hardening (same as BUG-4) | 1704–1757 |
| Q-7 | QUALITY | MEDIUM | Detection | `analyze_script_content()` calling convention inconsistency — some sites correctly pass file paths, 13 sites incorrectly pass content strings; no type check or warning | 1263–1468 |
| Q-8 | QUALITY | LOW | Output | CSV `escape_csv()` misses Unicode line terminators U+2028/U+2029 — same as BUG-7 | 1658–1665 |
| Q-9 | QUALITY | LOW | Output | `matched_string` truncation: no documented max length; very long matched strings may exceed analyst tool field limits | — |
| Q-10 | QUALITY | LOW | Docs | `file_hash` field uses DEFER optimization (computed post-filter) — behavior not documented; analysts may expect hash always present | — |
| Q-11 | QUALITY | LOW | Docs | Help text (`-h`) does not document `--min-confidence CRITICAL` or the `exit 1` on CRITICAL behavior | — |
| Q-12 | QUALITY | LOW | Detection | `"socat.*TCP:"` NEVER_WHITELIST entry too broad — consider narrowing to `socat.*TCP:.*exec:` or similar to avoid FP on legitimate admin tunnels | 227 |
| Q-13 | QUALITY | LOW | Compat | `snap` detection uses `snap list` — on systems where snapd is installed but not running, this may hang or error; no timeout | 689–908 |
| Q-14 | QUALITY | LOW | Runtime | Module failure in background subshell silently produces empty output — `wait "${_mod_pids[$_mi]}" || true` swallows errors; no indication in report that a module failed | 6675 |
| Q-15 | QUALITY | LOW | Detection | LD_PRELOAD/LD_LIBRARY_PATH scope limited to 3 staging dirs — gaps noted in FN-16 | 241–242 |
| Q-16 | QUALITY | LOW | Detection | Container scan 20-container hard cap with no warning (same as FN-18) — large fleet environments produce silently incomplete results | 6197 |

---

## Must-Fix (CRITICAL severity)

| ID | Brief |
|----|-------|
| FN-1 / BUG-2 | `analyze_script_content()` content-string calls → 13 sites, silent false negatives everywhere |
| BUG-1 | SUID/SGID escalation dead code — HIGH never becomes CRITICAL |
| BUG-3 / FN-5 | `get_executable_from_command()` returns env var, binary never verified |

## High Priority

| ID | Brief |
|----|-------|
| BUG-4 | JSONL fields not JSON-escaped — corrupt output |
| BUG-5 / FP-2 | DPKG postinst mass false positive on apt lock |
| BUG-6 | PKG_CACHE empty per subshell — cross-module caching never works |
| FN-2 | GRUB `init=` extraction misses first param and leaves trailing quote |
| FN-6 | Udev `RUN+=` misses single-quoted and unquoted forms |
| FN-7 | DBus `SystemdService=` not checked |
| FP-1 | `socat.*TCP:` NEVER_WHITELIST over-broad |
| PERF-1 | Triple sequential dpkg calls per file, empty PKG_CACHE per module |
| Q-1 | Report lists [1/9]..[9/9] instead of [1/14]..[14/14] |
| Q-2 | `exit 1` on CRITICAL undocumented |

---

## Finding Detail: FN-1 / BUG-2 (CRITICAL)

**`analyze_script_content()` — 13 content-string call sites**

`analyze_script_content()` is defined at line 1263. Its first line is:
```bash
local script_file="$1"
```
Line 1267:
```bash
[[ ! -f "$script_file" ]] || [[ ! -r "$script_file" ]] && return 1
```
The function treats `$1` as a **file path**. If the path doesn't exist or isn't readable, it returns 1 (clean) immediately.

Every one of the following call sites passes a **content string** (output of `head`, `cat`, or a variable holding command text), not a file path. The result is that `analyze_script_content` runs the `-f` test against the content string, finds it's not a path to an existing file, and returns 1 — silently marking the content as clean without any analysis:

| Line | Module | What's passed |
|------|--------|---------------|
| 1877 | bootloader | `$_init_content` (head -n 50 output) |
| 1904 | bootloader | `$_content` (cat of root .sh) |
| 5217 | shell_profiles | content string |
| 5792 | ssh | forced-command string from authorized_keys |
| 5900 | polkit | polkit rule content |
| 5960 | dbus | dbus config content |
| 6035 | udev | udev rule content |
| 6093 | container | container script content |
| 6123 | container | entrypoint content |
| 6411 | binary_integrity | SUID script content |
| 6545 | additional | additional script content |

The fix is to either: (a) write content to a temp file and pass that path, or (b) refactor `analyze_script_content()` to accept content via stdin or a second mode.

---

## Finding Detail: BUG-1 (CRITICAL)

**SUID/SGID escalation — octal format vs symbolic check**

`get_file_metadata()` at line 627:
```bash
stat -c "mode:%a|..." "$file"
```
`%a` is octal permissions. For a SUID binary: `"4755"`. For SGID: `"2755"`.

`add_finding_new()` at line 1728:
```bash
[[ "$file_permissions" =~ [sS] ]]
```
This regex looks for the character `s` or `S` in the permissions string. Octal `"4755"` contains no `s`. The regex **never matches**. The HIGH→CRITICAL escalation for SUID/SGID binaries has never fired in v2.4.0.

Fix: check octal bit directly, e.g. `[[ "${file_permissions:0:1}" =~ [124] ]]` for special bits, or switch to `stat -c "%A"` for symbolic format.

---

## Finding Detail: BUG-3 / FN-5 (CRITICAL)

**`get_executable_from_command()` — env var prefix returned as executable**

Line 920–945:
```bash
read -r executable _ <<< "$command"
```
For `ExecStart=LD_PRELOAD=/lib/evil.so /usr/bin/sshd -D`, this reads `LD_PRELOAD=/lib/evil.so` as `executable`. The actual binary `/usr/bin/sshd` is in `_` and discarded. Package verification then runs against `LD_PRELOAD=/lib/evil.so` which is not a path — `is_package_managed()` returns false (unmanaged) for it, triggering a HIGH finding on the env var string rather than correctly verifying the actual binary.

Worse: `LD_PRELOAD` itself is a persistence mechanism but the wrong file path is being checked and reported.

Fix: strip leading `KEY=value` tokens before reading executable.

---

## Finding Detail: BUG-4 (HIGH)

**JSONL fields not JSON-escaped**

`add_finding_new()` line 1755 constructs JSONL. Fields `$timestamp`, `$file_hash`, `$file_permissions`, `$file_age_days` are interpolated directly without `escape_json()`. If any of these contain a double-quote or backslash (e.g. a file path with unusual characters fed into file_hash via sha256sum), the JSON is malformed and will break downstream JSONL parsers.

The CSV line at 1751 correctly wraps all fields in `escape_csv()`.

---

## Finding Detail: BUG-5 / FP-2 (HIGH)

**DPKG postinst mass false positive on apt lock timeout**

Lines 5348–5364: The orphan detection for postinst scripts calls:
```bash
timeout 10 dpkg-query --showformat='${Package}\n' --show '*'
```
If `dpkg` is locked (e.g. `apt upgrade` running), this times out and `_dpkg_installed_pkgs` stays empty. The subsequent loop then marks every postinst script in `/var/lib/dpkg/info/*.postinst` as orphaned — potentially 500+ scripts — generating a mass false positive surge. No guard exists to detect the empty-array condition and skip or warn.

---

## Finding Detail: BUG-6 (HIGH)

**PKG_CACHE not shared across parallel module subshells**

`PKG_CACHE` is declared as a global associative array. But the 14 modules run as background subshells (fork). After fork, each subshell gets a copy of the parent's environment — but writes to PKG_CACHE inside the subshell are **not** visible to other subshells or the parent. Every module starts with an effectively empty cache. A file checked by `check_systemd` and again by `check_shell_profiles` results in two full dpkg lookups.

Fix: use a shared file-based cache (e.g. a temp file with `file_path|status` lines) and `flock` for concurrent writes, or pre-populate the cache in the parent before forking.

---

## Finding Detail: Q-1 (HIGH)

**Report lists [1/9]..[9/9] — 14 modules run**

Lines 6740–6749 generate the module summary in the `.txt` report:
```
[1/9] systemd
[2/9] cron
...
[9/9] binary_integrity
```
v2.4.0 runs 14 modules. The five new modules — bootloader, polkit, dbus, udev, container — are completely absent from the report. An analyst reading the report has no idea these scans ran or what they found.

---

*End of findings. 47 total: 20 FALSE_NEGATIVE, 11 BUG, 4 FALSE_POSITIVE, 3 PERF, 16 QUALITY.*
