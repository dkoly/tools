# SSL Certificate Checker

A Python script for checking SSL/TLS certificates, monitoring expiration dates, and analyzing certificate security properties.

## Features

- **Multi-host Certificate Checking**: Check multiple hosts concurrently
- **Expiration Monitoring**: Track certificate expiration dates with alerts
- **Certificate Analysis**: Detailed certificate information extraction
- **Multiple Input Methods**: Command line, file input, or URL lists
- **Various Output Formats**: Human-readable, JSON, CSV, and summary reports
- **Continuous Monitoring**: Real-time certificate monitoring with alerts
- **Security Analysis**: TLS version, cipher suites, and SAN analysis
- **Batch Processing**: Handle large lists of hosts efficiently

## Requirements

- Python 3.6+
- No external dependencies (uses standard library only)

## Usage

### Basic Certificate Checking

```bash
# Check a single host
python3 ssl_checker.py example.com

# Check multiple hosts
python3 ssl_checker.py example.com google.com github.com

# Check with custom port
python3 ssl_checker.py example.com:8443

# Check from file
python3 ssl_checker.py -f hosts.txt
```

### Advanced Options

```bash
# Verbose output with full certificate details
python3 ssl_checker.py example.com -v

# Check with custom timeout and workers
python3 ssl_checker.py example.com -t 5 -w 20

# Show only summary report
python3 ssl_checker.py example.com --summary

# Show certificates expiring within 30 days
python3 ssl_checker.py -f hosts.txt --expiring 30
```

### Export Options

```bash
# Save results to JSON
python3 ssl_checker.py -f hosts.txt --json results.json

# Save results to CSV
python3 ssl_checker.py -f hosts.txt --csv results.csv

# Both formats
python3 ssl_checker.py -f hosts.txt --json results.json --csv results.csv --summary
```

### Monitoring Mode

```bash
# Monitor certificates every hour (3600 seconds)
python3 ssl_checker.py -f hosts.txt --monitor 3600

# Monitor every 10 minutes for critical hosts
python3 ssl_checker.py critical-host.com --monitor 600
```

## Examples

### Basic Host Check
```bash
python3 ssl_checker.py github.com
```

Output:
```
Checking SSL certificates for 1 hosts...
Checked github.com:443 - success

============================================================
SUMMARY REPORT
============================================================
Total Hosts Checked: 1
Successful Checks: 1
Failed Checks: 0

Certificate Status:
 [#] Valid: 1
 [!] Expiring (30-90 days): 0
 [!] Expiring Soon (≤30 days): 0
 [X] Expired: 0
```

### Detailed Certificate Information
```bash
python3 ssl_checker.py github.com -v
```

Output:
```
============================================================
Host: github.com:443
Status: success
Checked: 2024-01-15T10:30:45.123456

Subject: github.com
Organization: GitHub, Inc.
Issuer: DigiCert TLS Hybrid ECC SHA384 2020 CA1
Valid From: 2023-03-14 00:00:00 UTC
Valid Until: 2024-03-13 23:59:59 UTC
[#] Certificate expires in 57 days
TLS Version: TLSv1.3
Cipher Suite: TLS_AES_256_GCM_SHA384
Encryption: 256 bits
SAN: github.com, www.github.com
Serial: 0A0630427F5BBCED1957343A40E55EDF
```

### Multiple Host Check with File Input
Create `hosts.txt`:
```
github.com
google.com
expired.badssl.com
wrong.host.badssl.com:443
```

Command:
```bash
python3 ssl_checker.py -f hosts.txt --summary
```

Output:
```
Checking SSL certificates for 4 hosts...
Checked github.com:443 - success
Checked google.com:443 - success
Checked expired.badssl.com:443 - success
Checked wrong.host.badssl.com:443 - ssl_error

============================================================
SUMMARY REPORT
============================================================
Total Hosts Checked: 4
Successful Checks: 3
Failed Checks: 1

Certificate Status:
 [#] Valid: 2
 [!] Expiring (30-90 days): 0
 [!] Expiring Soon (≤30 days): 0
 [X] Expired: 1

[X] EXPIRED CERTIFICATES:
  expired.badssl.com:443 - Expired 3287 days ago

[X] FAILED CHECKS:
  wrong.host.badssl.com:443 - SSL error: hostname 'wrong.host.badssl.com' doesn't match certificate
```

### Expiration Monitoring
```bash
python3 ssl_checker.py -f production_hosts.txt --expiring 90 --csv expiring_certs.csv
```

Shows only certificates expiring within 90 days and saves to CSV.

### Continuous Monitoring
```bash
python3 ssl_checker.py -f critical_hosts.txt --monitor 3600
```

Output:
```
Starting certificate monitoring (check every 3600 seconds)
Press Ctrl+C to stop...

[2024-01-15 10:30:45] Checking certificates...
Checked api.example.com:443 - success
Checked web.example.com:443 - success
[#] INFO: api.example.com:443 certificate expires in 25 days
Next check in 3600 seconds...
```

## Input File Formats

### Simple Host List
```
example.com
api.example.com
secure.example.com
```

### Host with Ports
```
example.com:443
api.example.com:8443
internal.example.com:9443
```

### Mixed Format with Comments
```
# Production servers
example.com
api.example.com:8443

# Development servers
dev.example.com
test.example.com:443
```

## Output Formats

### JSON Format
```json
[
  {
    "hostname": "example.com",
    "port": 443,
    "timestamp": "2024-01-15T10:30:45.123456",
    "status": "success",
    "error": null,
    "certificate": {
      "subject": {
        "commonName": "example.com",
        "organizationName": "Example Corp"
      },
      "issuer": {
        "commonName": "DigiCert TLS RSA SHA256 2020 CA1"
      },
      "not_before": "2023-01-01T00:00:00",
      "not_after": "2024-01-01T23:59:59",
      "days_until_expiry": 57,
      "status": "valid",
      "san": ["example.com", "www.example.com"],
      "version": "TLSv1.3",
      "cipher": ["TLS_AES_256_GCM_SHA384", "TLSv1.3", 256]
    }
  }
]
```

### CSV Format
```csv
Hostname,Port,Status,Error,Subject_CN,Issuer_CN,Valid_From,Valid_Until,Days_Until_Expiry,Certificate_Status,TLS_Version,Cipher_Suite,SAN_Count,Serial_Number
example.com,443,success,,example.com,DigiCert TLS RSA SHA256 2020 CA1,2023-01-01 00:00:00 UTC,2024-01-01 23:59:59 UTC,57,valid,TLSv1.3,TLS_AES_256_GCM_SHA384,2,1234567890ABCDEF
```

## Certificate Status Classifications

- **Valid**: Certificate is valid and expires in more than 90 days
- **Expiring Warning**: Certificate expires in 30-90 days
- **Expiring Soon**: Certificate expires in ≤30 days
- **Expired**: Certificate has already expired

## Error Handling

The script handles various error conditions:

- **DNS Resolution Failures**: When hostname cannot be resolved
- **Connection Timeouts**: When host doesn't respond within timeout
- **Connection Refused**: When host actively refuses connections
- **SSL/TLS Errors**: Certificate validation failures
- **Hostname Mismatches**: When certificate doesn't match hostname

## Use Cases

### SSL Certificate Inventory
```bash
# Generate complete certificate inventory
python3 ssl_checker.py -f all_hosts.txt --json inventory.json --csv inventory.csv --summary
```

### Expiration Monitoring
```bash
# Daily check for certificates expiring in 30 days
python3 ssl_checker.py -f production_hosts.txt --expiring 30 --csv daily_expiration_check.csv

# Weekly check for certificates expiring in 90 days
python3 ssl_checker.py -f all_hosts.txt --expiring 90 --json weekly_expiration_report.json
```

### Security Auditing
```bash
# Detailed security analysis
python3 ssl_checker.py -f hosts.txt -v > security_audit.txt
```

### Continuous Monitoring
```bash
# Production monitoring (every hour)
python3 ssl_checker.py -f production_hosts.txt --monitor 3600 2>&1 | tee ssl_monitor.log

# Critical system monitoring (every 5 minutes)
python3 ssl_checker.py critical.example.com --monitor 300
```

## Integration Examples

### Cron Job Setup
```bash
# Daily expiration check
0 9 * * * /usr/bin/python3 /path/to/ssl_checker.py -f /etc/ssl_hosts.txt --expiring 30 --csv /var/log/ssl_expiring.csv

# Weekly full inventory
0 6 * * 0 /usr/bin/python3 /path/to/ssl_checker.py -f /etc/ssl_hosts.txt --json /var/log/ssl_inventory_$(date +\%Y\%m\%d).json
```

### Nagios/Monitoring Integration
```bash
#!/bin/bash
# Nagios check script
EXPIRING_DAYS=30
CRITICAL_DAYS=7

RESULT=$(python3 ssl_checker.py "$1" --expiring $EXPIRING_DAYS --json /tmp/ssl_check.json)
DAYS=$(cat /tmp/ssl_check.json | jq -r '.[0].certificate.days_until_expiry // 999')

if [ "$DAYS" -lt 0 ]; then
    echo "CRITICAL: SSL certificate expired $((0-DAYS)) days ago"
    exit 2
elif [ "$DAYS" -lt $CRITICAL_DAYS ]; then
    echo "CRITICAL: SSL certificate expires in $DAYS days"
    exit 2
elif [ "$DAYS" -lt $EXPIRING_DAYS ]; then
    echo "WARNING: SSL certificate expires in $DAYS days"
    exit 1
else
    echo "OK: SSL certificate expires in $DAYS days"
    exit 0
fi
```

### Slack Notifications
```bash
#!/bin/bash
# Send expiring certificate alerts to Slack
WEBHOOK_URL="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

EXPIRING=$(python3 ssl_checker.py -f hosts.txt --expiring 30 --json /tmp/expiring.json)
COUNT=$(cat /tmp/expiring.json | jq length)

if [ "$COUNT" -gt 0 ]; then
    MESSAGE="⚠️ SSL Certificate Alert: $COUNT certificates expiring within 30 days"
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"$MESSAGE\"}" \
        "$WEBHOOK_URL"
fi
```

## Performance Notes

- **Concurrent Checking**: Default 10 workers, adjustable with `-w`
- **Timeout Handling**: Default 10 seconds, adjustable with `-t`
- **Memory Usage**: Minimal, results stored only in memory during execution
- **Large Scale**: Tested with 1000+ hosts, scales well with increased worker count

## Troubleshooting

### Common Issues

**Connection Timeouts**
```bash
# Increase timeout for slow networks
python3 ssl_checker.py slow-host.com -t 30
```

**DNS Resolution Issues**
```bash
# Check DNS resolution separately
nslookup hostname
```

**SSL Handshake Failures**
```bash
# Test with OpenSSL directly
openssl s_client -connect hostname:443 -servername hostname
```

**Large Host Lists**
```bash
# Reduce worker count for resource-constrained systems
python3 ssl_checker.py -f large_hosts.txt -w 5
```