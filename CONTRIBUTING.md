# Contributing to Persistnux

Thank you for your interest in contributing to Persistnux! This tool is designed to help the DFIR community detect Linux persistence mechanisms.

## How to Contribute

### Reporting Issues

If you find a bug or have a suggestion:

1. Check if the issue already exists in the GitHub issue tracker
2. If not, create a new issue with:
   - Clear description of the problem or feature request
   - Steps to reproduce (for bugs)
   - Expected vs actual behavior
   - Your environment (Linux distro, kernel version, bash version)
   - Relevant output or error messages

### Adding New Persistence Detection

We welcome contributions that add detection for new persistence mechanisms!

#### Steps to Add a New Detection Module:

1. **Research the Persistence Mechanism**
   - Document where the persistence is stored
   - Identify configuration files, directories, or system settings
   - Note any required privileges (root vs user)
   - Reference MITRE ATT&CK techniques if applicable

2. **Create Detection Function**
   - Add a new function following the naming pattern: `check_<mechanism_name>()`
   - Use the existing helper functions:
     - `get_file_hash()` - Calculate SHA256
     - `get_file_metadata()` - Extract file permissions, ownership, timestamps
     - `add_finding()` - Add detection result to output
     - `log_finding()` - Log HIGH confidence findings to console

3. **Implement Confidence Scoring**
   - **LOW**: Standard configuration files, low suspicion
   - **MEDIUM**: Potentially suspicious but common
   - **HIGH**: Contains suspicious patterns (curl, wget, /tmp, base64, etc.)
   - **CRITICAL**: Reserved for advanced detections

4. **Add to Main Execution**
   - Call your function from `main()` in logical order
   - Add appropriate logging messages

5. **Test Your Detection**
   - Test on multiple Linux distributions (Ubuntu, CentOS, Debian, etc.)
   - Verify it works with and without root privileges
   - Ensure it handles missing files/directories gracefully
   - Confirm output format is correct

#### Example Detection Function:

```bash
check_new_persistence() {
    log_info "Checking [new persistence mechanism]..."

    local config_files=(
        "/path/to/config1"
        "/path/to/config2"
    )

    for config in "${config_files[@]}"; do
        if [[ -f "$config" ]]; then
            local hash=$(get_file_hash "$config")
            local metadata=$(get_file_metadata "$config")
            local suspicious_content=$(grep -iE "(suspicious|pattern)" "$config" 2>/dev/null || echo "")

            local confidence="LOW"
            if [[ -n "$suspicious_content" ]]; then
                confidence="HIGH"
                log_finding "Suspicious content in: $config"
            fi

            add_finding "Category" "Subcategory" "persistence_type" "$config" "Description" "$confidence" "$hash" "$metadata" "additional_info=value"
        fi
    done
}
```

### Improving Existing Detections

Enhancements to existing detection modules are welcome:

- **More comprehensive file paths**: Add common locations we might have missed
- **Better suspicious patterns**: Improve regex patterns for detection
- **Performance optimizations**: Make scans faster without sacrificing thoroughness
- **False positive reduction**: Improve confidence scoring accuracy

### Documentation Improvements

- Fix typos or unclear instructions
- Add usage examples
- Improve DFIR workflow guidance
- Translate documentation to other languages

### Code Style Guidelines

- Use bash best practices (shellcheck compliant)
- Add comments for complex logic
- Use descriptive variable names
- Follow the existing code structure
- Use `set -euo pipefail` for error handling

### Testing

Before submitting a pull request:

1. Run the script on a test system
2. Verify CSV and JSONL output formats are valid
3. Test with and without root privileges
4. Check for bash errors or warnings
5. Ensure no data corruption in output files

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature-name`)
3. Make your changes
4. Test thoroughly
5. Commit with clear messages
6. Push to your fork
7. Create a pull request with:
   - Clear description of changes
   - Why the change is needed
   - Any relevant issue numbers
   - Testing performed

### What We're Looking For

**High Priority:**
- Detection for new persistence mechanisms
- Support for different Linux distributions
- Performance improvements
- Offline analysis mode for forensic images

**Medium Priority:**
- Better suspicious pattern detection
- HTML report generation
- Integration scripts for common DFIR tools
- Baseline comparison features

**Future Enhancements:**
- Container-specific persistence detection
- YARA rule integration
- Automated threat intelligence lookups
- Timeline visualization

## Community Guidelines

- Be respectful and professional
- Help others in issues and discussions
- Share knowledge and techniques
- Focus on practical DFIR use cases
- Security research for defensive purposes

## Persistence Mechanisms We'd Like to Add

If you're looking for ideas to contribute:

- Docker/Podman container escape persistence
- Systemd generators
- DBus service activation
- Udev rules persistence
- APT/YUM package manager hooks
- GRUB bootloader modifications
- Kerberos/LDAP configuration backdoors
- Cloud-init script injection
- NetworkManager dispatcher scripts
- SystemTap/eBPF persistence
- Capability-based persistence
- Namespace persistence mechanisms

## Resources

- [MITRE ATT&CK - Linux Persistence](https://attack.mitre.org/tactics/TA0003/)
- [Linux Persistence Techniques](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Persistence.md)
- [SANS Linux Forensics](https://www.sans.org/blog/digital-forensics-cheat-sheets/)

## Questions?

Feel free to open an issue for discussion or reach out to maintainers.

Thank you for contributing to the DFIR community!
