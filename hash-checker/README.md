# File Hash Checker

A Python script for calculating, verifying, and managing file hashes for integrity checking and security monitoring.

## Features

- Calculate hashes for individual files or entire directories
- Support for MD5, SHA1, SHA256, and SHA512 algorithms
- Verify file integrity against known hash values
- Create and compare hash baselines for directories
- Batch verification from hash files
- JSON export for integration with other tools
- Progress tracking for large directory scans
- Automatic hash algorithm detection

## Requirements

- Python 3.6+

## Usage

### Calculate Hash of a Single File

```bash
# SHA256 hash (default)
python3 hash_checker.py hash /path/to/file.txt

# Specific algorithm
python3 hash_checker.py hash /path/to/file.txt -a md5

# All supported algorithms
python3 hash_checker.py hash /path/to/file.txt --all
```

### Scan Directory

```bash
# Basic directory scan
python3 hash_checker.py scan /path/to/directory

# Save to file
python3 hash_checker.py scan /path/to/directory -o hashes.txt

# Save as JSON
python3 hash_checker.py scan /path/to/directory --json results.json

# Non-recursive scan
python3 hash_checker.py scan /path/to/directory --no-recursive

# Different algorithm
python3 hash_checker.py scan /path/to/directory -a sha512
```

### Verify File Hash

```bash
# Verify against known hash
python3 hash_checker.py verify /path/to/file.txt abc123def456...

# Specify algorithm (auto-detected by default)
python3 hash_checker.py verify /path/to/file.txt abc123def456... -a sha256
```

### Verify from Hash File

```bash
# Verify all hashes in file
python3 hash_checker.py verify-file checksums.txt

# Save results as JSON
python3 hash_checker.py verify-file checksums.txt --json verification_results.json
```

### Create Hash Baseline

```bash
# Create baseline for directory
python3 hash_checker.py baseline /path/to/directory -o baseline.txt

# With different algorithm
python3 hash_checker.py baseline /path/to/directory -o baseline.txt -a sha512
```

### Compare Baselines

```bash
# Compare two baseline files
python3 hash_checker.py compare baseline_old.txt baseline_new.txt
```

## Examples

### Basic File Integrity Check
```bash
# Calculate hash
python3 hash_checker.py hash important_file.pdf
# Output: a1b2c3d4e5f6... important_file.pdf

# Verify later
python3 hash_checker.py verify important_file.pdf a1b2c3d4e5f6...
# Output: ✓ MATCH: important_file.pdf
```

### Directory Monitoring
```bash
# Create initial baseline
python3 hash_checker.py baseline /etc -o etc_baseline.txt

# Later, create new baseline and compare
python3 hash_checker.py baseline /etc -o etc_current.txt
python3 hash_checker.py compare etc_baseline.txt etc_current.txt
```

### Batch Verification
```bash
# Create hash file
python3 hash_checker.py scan /downloads -o downloads_hashes.txt

# Verify all files
python3 hash_checker.py verify-file downloads_hashes.txt
```

## Output Formats

### Standard Output
```
a1b2c3d4e5f6789...  /path/to/file1.txt
b2c3d4e5f6789a1...  /path/to/file2.txt
```

### Hash File Format
```
# Hash scan of /path/to/directory
# Created: Mon Jan 15 10:30:45 2024
# Algorithm: SHA256

a1b2c3d4e5f6789abcdef...  /path/to/file1.txt
b2c3d4e5f6789abcdef123...  /path/to/file2.txt
```

### JSON Format
```json
[
  {
    "file": "/path/to/file1.txt",
    "size": 1024,
    "modified": "Mon Jan 15 10:30:45 2024",
    "hash": "a1b2c3d4e5f6789abcdef...",
    "algorithm": "sha256"
  }
]
```

### Verification Results
```
Verification Results:
  Matches: 45
  Mismatches: 2
  Missing files: 1

✓ /path/to/file1.txt
✗ /path/to/file2.txt
  Expected:   a1b2c3d4e5f6...
  Calculated: b2c3d4e5f6789...
? /path/to/file3.txt (not found)
```

### Baseline Comparison
```
Baseline Comparison:
  Files added: 5
  Files removed: 2
  Files modified: 3
  Files unchanged: 150

Added files:
  + /etc/new_config.conf
  + /etc/security/new_rule.conf

Modified files:
  * /etc/passwd
  * /etc/hosts
  * /etc/ssh/sshd_config
```

## Use Cases

### Security Monitoring
- Monitor critical system files for unauthorized changes
- Verify downloaded files against publisher hashes
- Detect malware modifications to system files
- Audit file system integrity

### System Administration
- Create configuration baselines before changes
- Verify backup integrity
- Monitor log file directories for tampering
- Document system state for compliance

### Digital Forensics
- Create forensic images with hash verification
- Document evidence integrity
- Compare system states before/after incidents
- Maintain chain of custody records

### Software Development
- Verify build artifacts
- Check dependency integrity
- Monitor source code changes
- Release verification

## Algorithm Selection Guide

- **MD5**: Fast but cryptographically broken, use only for non-security purposes
- **SHA1**: Deprecated for security use, faster than SHA256
- **SHA256**: Current standard, good balance of security and performance
- **SHA512**: Highest security, slower but more resistant to future attacks

## Performance Notes

- Large files are processed in 4KB chunks to minimize memory usage
- Directory scans show progress every 10 files
- Consider using faster algorithms (MD5/SHA1) for large datasets if security isn't critical
- JSON output uses more memory but provides structured data

## Hash File Compatibility

The script can read hash files in the standard format:
```
hash_value  filename
hash_value  filename with spaces
```

Compatible with:
- `md5sum`, `sha256sum` output
- Most hash verification tools
- Custom hash files with comments (lines starting with #)
