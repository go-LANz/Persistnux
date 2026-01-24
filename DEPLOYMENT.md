# Persistnux Deployment Guide

## Quick Start

### Option 1: Direct Download (Recommended)

```bash
# Download the script
wget https://raw.githubusercontent.com/yourusername/persistnux/main/persistnux.sh

# Make it executable
chmod +x persistnux.sh

# Run it
sudo ./persistnux.sh
```

### Option 2: Git Clone

```bash
# Clone the repository
git clone https://github.com/yourusername/persistnux.git
cd persistnux

# Make executable
chmod +x persistnux.sh

# Run it
sudo ./persistnux.sh
```

### Option 3: Manual Copy

If you're working from a local repository:

```bash
# From your Mac/development machine, copy to Linux server
scp /Users/golanagi/Documents/GitHub/Persistnux/persistnux.sh user@server:/home/user/

# On the Linux server
chmod +x persistnux.sh
sudo ./persistnux.sh
```

---

## Testing on Local Linux System

If you're testing on a local Linux machine (not remote):

```bash
# Copy from current directory
cp /Users/golanagi/Documents/GitHub/Persistnux/persistnux.sh ~/Desktop/

# Make executable
chmod +x ~/Desktop/persistnux.sh

# Run it
cd ~/Desktop
sudo ./persistnux.sh
```

---

## Troubleshooting

### Error: "No such file or directory"

**Cause**: File doesn't exist at the specified path

**Solution**:
```bash
# Check if file exists
ls -la ~/Desktop/persistnux.sh

# If not, check where you are
pwd

# Copy from Git repository
cp /path/to/persistnux/persistnux.sh ~/Desktop/
```

### Error: "Permission denied"

**Cause**: File not executable

**Solution**:
```bash
chmod +x persistnux.sh
```

### Error: "bash: ./persistnux.sh: /bin/bash: bad interpreter"

**Cause**: Windows line endings (CRLF) instead of Unix (LF)

**Solution**:
```bash
# Install dos2unix
sudo apt-get install dos2unix  # Debian/Ubuntu
sudo yum install dos2unix      # RedHat/CentOS

# Convert line endings
dos2unix persistnux.sh

# Or use sed
sed -i 's/\r$//' persistnux.sh
```

---

## System Requirements

### Minimum Requirements
- Bash 4.0+
- Linux kernel 2.6+
- 10 MB free disk space
- Standard GNU utilities (find, grep, stat, sha256sum)

### Recommended
- Root/sudo access (for complete analysis)
- systemctl (for systemd detection)
- dpkg or rpm (for package manager integration)

### Supported Distributions
- ✅ Ubuntu 18.04+
- ✅ Debian 9+
- ✅ CentOS/RHEL 7+
- ✅ Fedora 30+
- ✅ Arch Linux
- ✅ Amazon Linux 2

---

## First Run

```bash
# Default: Show only suspicious findings
sudo ./persistnux.sh

# Expected output location
ls -la persistnux_output/

# View results
cat persistnux_output/persistnux_*.csv
```

---

## Testing with PANIX

To test detection capabilities with PANIX malware simulation:

```bash
# Install PANIX (for testing only!)
git clone https://github.com/Aegrah/PANIX.git
cd PANIX

# Install test persistence (WARNING: Only on test systems!)
sudo ./panix.sh --cron --at --systemd

# Run Persistnux
cd /path/to/persistnux
sudo ./persistnux.sh

# Check for HIGH confidence findings
grep ",HIGH," persistnux_output/persistnux_*.csv

# Cleanup PANIX persistence
cd /path/to/PANIX
sudo ./panix.sh --remove
```

---

## Production Deployment

### For Incident Response

```bash
# On compromised system
wget https://raw.githubusercontent.com/yourusername/persistnux/main/persistnux.sh
chmod +x persistnux.sh
sudo OUTPUT_DIR=/tmp/evidence ./persistnux.sh

# Package results
cd /tmp/evidence
tar -czf persistnux_evidence_$(hostname)_$(date +%Y%m%d_%H%M%S).tar.gz *.csv *.jsonl
sha256sum persistnux_evidence_*.tar.gz > evidence.sha256

# Transfer off system
scp persistnux_evidence_*.tar.gz analyst@forensics-server:/cases/current/
```

### For Scheduled Scanning

```bash
# Create cron job for daily scans
sudo crontab -e

# Add this line (runs daily at 2 AM)
0 2 * * * /usr/local/bin/persistnux.sh && find /var/log/persistnux -type f -mtime +30 -delete
```

### For CI/CD Integration

```bash
# In your CI/CD pipeline
- name: Security Scan - Persistence Detection
  run: |
    wget https://raw.githubusercontent.com/yourusername/persistnux/main/persistnux.sh
    chmod +x persistnux.sh
    sudo MIN_CONFIDENCE=HIGH ./persistnux.sh

    # Fail build if HIGH confidence findings
    if grep -q ",HIGH," persistnux_output/persistnux_*.csv; then
      echo "HIGH confidence persistence mechanisms detected!"
      exit 1
    fi
```

---

## Docker Testing

If you want to test in a Docker container:

```bash
# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y systemd cron
COPY persistnux.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/persistnux.sh
CMD ["/usr/local/bin/persistnux.sh"]
EOF

# Build and run
docker build -t persistnux-test .
docker run --rm persistnux-test
```

---

## Verification

After deployment, verify the tool works:

```bash
# Check version
./persistnux.sh --help | head -3

# Should show:
# Persistnux - Linux Persistence Detection Tool v1.2.0
# Comprehensive DFIR tool to detect Linux persistence mechanisms

# Run syntax check
bash -n persistnux.sh
# (No output = success)

# Test run (quick)
sudo ./persistnux.sh

# Verify output files created
ls -lh persistnux_output/
```

---

## Uninstallation

```bash
# Remove script
rm persistnux.sh

# Remove output directory
rm -rf persistnux_output/

# Remove from cron (if installed)
sudo crontab -e
# (remove the persistnux line)
```

---

## Support

- **Documentation**: See README.md, DFIR_GUIDE.md, FILTERING_GUIDE.md
- **Issues**: https://github.com/yourusername/persistnux/issues
- **Current Status**: See CURRENT_STATUS.md for what the tool does
