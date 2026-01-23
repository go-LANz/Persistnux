# DFIR Quick Reference Guide

## Quick Start for Incident Response

### On Compromised System (Live Analysis)

```bash
# Download and run (if safe to do so)
wget https://raw.githubusercontent.com/yourusername/persistnux/main/persistnux.sh
chmod +x persistnux.sh
sudo ./persistnux.sh

# Or with custom output location
sudo OUTPUT_DIR=/tmp/ir_collection ./persistnux.sh
```

### Evidence Collection

```bash
# Compress output for transport
cd persistnux_output
tar -czf persistnux_evidence_$(hostname)_$(date +%Y%m%d_%H%M%S).tar.gz *.csv *.jsonl

# Calculate hash for chain of custody
sha256sum persistnux_evidence_*.tar.gz > evidence.sha256
```

## Triage Priorities

### 1. HIGH Confidence Findings (Immediate Review)

```bash
# Quick triage - HIGH confidence items
grep ",HIGH," persistnux_*.csv

# Or with jq for JSONL
jq 'select(.confidence == "HIGH")' persistnux_*.jsonl
```

**Common HIGH confidence indicators:**
- Systemd services with curl/wget/netcat in ExecStart
- Cron jobs downloading and executing code
- LD_PRELOAD configurations
- XDG autostart with suspicious commands
- Modified shell profiles with download commands

### 2. Persistence Categories by Risk

**Critical Categories to Review First:**
1. **Preload/LD_PRELOAD** - Library injection, often rootkit indicator
2. **Systemd Services** - System-level persistence with auto-start
3. **Cron/User Crontabs** - Scheduled execution, common for backdoors
4. **Init/RC Scripts** - Early boot persistence
5. **Shell Profiles** - Per-session execution for all users

**Secondary Review:**
6. **SSH Keys** - Unauthorized access maintenance
7. **Kernel Modules** - Deep system integration
8. **XDG Autostart** - User-level GUI persistence
9. **PAM Configurations** - Authentication bypass

### 3. Analysis Workflow

```bash
# Step 1: Count findings by category
cut -d',' -f2 persistnux_*.csv | tail -n +2 | sort | uniq -c | sort -rn

# Step 2: Extract all HIGH confidence findings
awk -F',' '$7 == "HIGH" {print $2,$4,$5}' persistnux_*.csv

# Step 3: Review files with suspicious indicators
grep -i "curl\|wget\|nc\|netcat" persistnux_*.csv

# Step 4: Timeline analysis - sort by timestamp
sort -t',' -k1 persistnux_*.csv
```

## Integration with Common DFIR Tools

### Splunk

```bash
# Create new index
splunk add index persistnux

# Import JSONL
cat persistnux_*.jsonl | splunk add oneshot -index persistnux -sourcetype persistnux:jsonl

# Search for high-risk items
index=persistnux confidence=HIGH | stats count by category subcategory
```

### ELK Stack (Elasticsearch)

```bash
# Bulk import JSONL
curl -H "Content-Type: application/x-ndjson" -XPOST "localhost:9200/persistnux/_bulk?pretty" --data-binary "@persistnux_output.jsonl"

# Query high-confidence findings
curl -X GET "localhost:9200/persistnux/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match": { "confidence": "HIGH" }
  }
}'
```

### Python Pandas Analysis

```python
import pandas as pd
import json

# Load CSV
df = pd.read_csv('persistnux_hostname_timestamp.csv')

# Or load JSONL
with open('persistnux_hostname_timestamp.jsonl') as f:
    data = [json.loads(line) for line in f]
df = pd.DataFrame(data)

# High-risk findings
high_risk = df[df['confidence'] == 'HIGH']
print(high_risk[['category', 'subcategory', 'location', 'description']])

# Category distribution
print(df['category'].value_counts())

# Timeline of HIGH confidence findings
high_risk_timeline = high_risk.sort_values('timestamp')
print(high_risk_timeline[['timestamp', 'category', 'location']])

# Export for report
high_risk.to_excel('high_risk_persistence.xlsx', index=False)
```

## Field Notes & IOCs

### Documenting Findings

For each HIGH confidence finding, document:

1. **File Location**: Full path from output
2. **SHA256 Hash**: From output for threat intelligence lookup
3. **Timestamp**: When was it created/modified
4. **Content Sample**: Command or script content
5. **Related Files**: Check for associated files/processes
6. **Network IOCs**: Any domains/IPs in commands

### IOC Extraction Examples

```bash
# Extract file paths from HIGH confidence findings
awk -F',' '$7 == "HIGH" {print $5}' persistnux_*.csv | sort -u

# Extract SHA256 hashes for threat intelligence lookup
awk -F',' '$7 == "HIGH" {print $8}' persistnux_*.csv | sort -u

# Extract URLs/IPs from descriptions (basic regex)
grep -oE 'https?://[^ ]+' persistnux_*.csv | sort -u
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' persistnux_*.csv | sort -u
```

## Comparison with Baseline

### Creating a Baseline

```bash
# On clean reference system
sudo ./persistnux.sh
mv persistnux_output/persistnux_*.csv baseline_$(hostname).csv
```

### Comparing Against Baseline

```bash
# Compare file lists (simplified)
awk -F',' 'NR>1 {print $5}' baseline.csv | sort > baseline_files.txt
awk -F',' 'NR>1 {print $5}' investigation.csv | sort > investigation_files.txt

# Files present in investigation but not baseline
comm -13 baseline_files.txt investigation_files.txt > new_persistence.txt

# Compare hashes for same files
awk -F',' 'NR>1 {print $5":"$8}' baseline.csv | sort > baseline_hashes.txt
awk -F',' 'NR>1 {print $5":"$8}' investigation.csv | sort > investigation_hashes.txt
comm -23 investigation_hashes.txt baseline_hashes.txt > modified_files.txt
```

## Report Generation

### Executive Summary Template

```bash
# Generate statistics
TOTAL=$(tail -n +2 persistnux_*.csv | wc -l)
HIGH=$(grep ",HIGH," persistnux_*.csv | wc -l)
MEDIUM=$(grep ",MEDIUM," persistnux_*.csv | wc -l)
LOW=$(grep ",LOW," persistnux_*.csv | wc -l)

echo "=== Persistence Detection Summary ==="
echo "Total Persistence Mechanisms: $TOTAL"
echo "HIGH Confidence: $HIGH"
echo "MEDIUM Confidence: $MEDIUM"
echo "LOW Confidence: $LOW"
echo ""
echo "Categories Detected:"
cut -d',' -f2 persistnux_*.csv | tail -n +2 | sort | uniq -c | sort -rn
```

## Next Steps After Detection

### For HIGH Confidence Findings:

1. **Isolate** - Consider network isolation if active threat
2. **Preserve** - Copy suspicious files before removal
3. **Analyze** - Static analysis of scripts/binaries
4. **Cross-reference** - Check process list, network connections
5. **Memory dump** - Capture if advanced persistence suspected
6. **Document** - Detailed notes for incident report

### Evidence Preservation:

```bash
# Create evidence directory
mkdir -p evidence/$(date +%Y%m%d)_$(hostname)

# Copy suspicious files (preserving metadata)
while read -r filepath; do
    if [[ -e "$filepath" ]]; then
        cp -p "$filepath" evidence/$(date +%Y%m%d)_$(hostname)/
    fi
done < <(awk -F',' '$7 == "HIGH" {print $5}' persistnux_*.csv)

# Create file listing with metadata
ls -laR evidence/ > evidence/file_listing.txt

# Hash everything
find evidence/ -type f -exec sha256sum {} \; > evidence/evidence_hashes.txt
```

## Limitations & Considerations

1. **False Positives**: LOW confidence findings often legitimate
2. **Evasion**: Advanced attackers may avoid common locations
3. **Live System**: Running on compromised system may be detected
4. **Rootkits**: Deep rootkits may hide from userland tools
5. **Performance**: Full scan can take 2-10 minutes depending on system

## Additional Resources

- MITRE ATT&CK: Persistence Tactics (TA0003)
- SANS DFIR Cheat Sheets
- Linux Forensics Resources

## Questions or Issues?

Open an issue on GitHub or contribute improvements to detection logic.
