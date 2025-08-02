# SSH Key Manager

A comprehensive bash script for managing SSH keys - generate, install, backup, and maintain SSH key pairs with ease.

## Features

- Generate SSH key pairs (RSA, Ed25519, ECDSA)
- List and inspect existing SSH keys
- Install public keys to remote hosts
- Backup and restore SSH keys
- Manage SSH agent (add/remove keys)
- Delete SSH key pairs securely
- Show SSH configuration
- Comprehensive error handling and validation

## Requirements

- Bash 4.0+
- SSH tools (`ssh-keygen`, `ssh-copy-id`, `ssh-add`)
- Linux/macOS environment

## Installation

```bash
chmod +x ssh_key_manager.sh
```

## Usage

### Generate SSH Keys

```bash
# Generate Ed25519 key (recommended)
./ssh_key_manager.sh generate mykey

# Generate RSA key with custom size
./ssh_key_manager.sh generate workkey rsa 4096

# Generate key with custom comment and passphrase
./ssh_key_manager.sh generate serverkey ed25519 "" "admin@company.com" "mypassphrase"
```

### List SSH Keys

```bash
# List all SSH keys with details
./ssh_key_manager.sh list
```

### Install Keys to Remote Hosts

```bash
# Install key to remote server
./ssh_key_manager.sh install mykey server.example.com

# Install key with specific username
./ssh_key_manager.sh install workkey 192.168.1.100 admin
```

### Backup and Restore

```bash
# Backup all SSH keys
./ssh_key_manager.sh backup

# Backup with custom name
./ssh_key_manager.sh backup work_backup_2024

# Restore from backup
./ssh_key_manager.sh restore ~/.ssh/backups/ssh_backup_20240115_103045.tar.gz
```

### SSH Agent Management

```bash
# Add key to SSH agent
./ssh_key_manager.sh add mykey

# Remove key from SSH agent
./ssh_key_manager.sh remove mykey
```

### Key Management

```bash
# Delete SSH key pair
./ssh_key_manager.sh delete oldkey

# Show SSH configuration
./ssh_key_manager.sh config
```

## Examples

### Generate and Deploy a New Key

```bash
# 1. Generate new key
./ssh_key_manager.sh generate production ed25519 "" "prod@company.com"

# 2. Add to SSH agent
./ssh_key_manager.sh add production

# 3. Install to server
./ssh_key_manager.sh install production prod-server.company.com

# 4. Test connection
ssh prod-server.company.com
```

### Backup Before System Migration

```bash
# Create backup
./ssh_key_manager.sh backup migration_backup

# On new system, restore keys
./ssh_key_manager.sh restore migration_backup.tar.gz

# Verify keys
./ssh_key_manager.sh list
```

### Key Lifecycle Management

```bash
# List current keys
./ssh_key_manager.sh list

# Generate new key
./ssh_key_manager.sh generate newkey

# Install to servers
./ssh_key_manager.sh install newkey server1.example.com
./ssh_key_manager.sh install newkey server2.example.com

# Remove old key from agent
./ssh_key_manager.sh remove oldkey

# Delete old key
./ssh_key_manager.sh delete oldkey
```

## Output Examples

### Key Generation
```
================================
    SSH Key Manager
================================

[INFO] Generating ed25519 SSH key: mykey
Generating public/private ed25519 key pair.
Your identification has been saved in /home/user/.ssh/mykey
Your public key has been saved in /home/user/.ssh/mykey.pub
[INFO] SSH key generated successfully!
[INFO] Private key: /home/user/.ssh/mykey
[INFO] Public key: /home/user/.ssh/mykey.pub

Public key content:
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@hostname
```

### Key Listing
```
SSH Keys in /home/user/.ssh:

Key: mykey
  Private key: ✓
  Info: 256 SHA256:abc123... user@hostname (ED25519)
  Agent: ✓ Loaded
  Public key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@hostname

Key: workkey
  Private key: ✓
  Info: 4096 SHA256:def456... work@company.com (RSA)
  Agent: ✗ Not loaded
  Public key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ... work@company.com
```

### Key Installation
```
[INFO] Installing public key 'mykey' to user@server.example.com
/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "/home/user/.ssh/mykey.pub"
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s)
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed
Number of key(s) added: 1
[INFO] Key installed successfully!
[INFO] Testing SSH connection...
SSH key authentication successful!
[INFO] SSH connection test passed!
```

## Supported Key Types

### Ed25519 (Recommended)
- Modern, secure, and fast
- Fixed key size (256-bit)
- Best choice for new keys

### RSA
- Traditional and widely supported
- Configurable key size (2048, 3072, 4096 bits)
- Larger key sizes for enhanced security

### ECDSA
- Elliptic curve cryptography
- Good performance and security
- Configurable curve sizes

## Security Features

### Key Generation
- Uses system's secure random number generator
- Proper file permissions (600 for private, 644 for public)
- Support for passphrases
- Validation of key parameters

### Backup Security
- Creates timestamped backups
- Compressed archives for efficient storage
- Backup verification
- Pre-restore backup creation

### Agent Management
- Secure key addition/removal
- Agent status checking
- Automatic agent startup when needed

## File Locations

- **SSH Directory**: `~/.ssh/`
- **Backup Directory**: `~/.ssh/backups/`
- **Config File**: `~/.ssh/config`
- **Private Keys**: `~/.ssh/keyname`
- **Public Keys**: `~/.ssh/keyname.pub`

## Best Practices

### Key Generation
1. **Use Ed25519** for new keys (best security/performance)
2. **Use strong passphrases** for private keys
3. **Use descriptive names** for different purposes
4. **Add meaningful comments** with email/purpose

### Key Management
1. **Regular backups** before system changes
2. **Rotate keys periodically** (annually recommended)
3. **Remove unused keys** from systems and agent
4. **Test connections** after key installation

### Security
1. **Never share private keys**
2. **Use different keys** for different purposes
3. **Monitor key usage** in logs
4. **Revoke compromised keys** immediately

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Fix SSH directory permissions
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_*
chmod 644 ~/.ssh/*.pub
```

**Agent Not Running**
```bash
# Start SSH agent
eval "$(ssh-agent -s)"
```

**Key Installation Fails**
```bash
# Check if SSH service is running on target
# Verify network connectivity
# Ensure target user exists
```

**Backup Restoration Issues**
```bash
# Verify backup file integrity
tar -tzf backup_file.tar.gz

# Check available disk space
df -h ~/.ssh
```

## Integration

### Use in Scripts
```bash
#!/bin/bash
# Generate and deploy key automatically
./ssh_key_manager.sh generate deploy_key ed25519 "" "deploy@company.com" ""
./ssh_key_manager.sh install deploy_key production-server.com deploy
```

### Cron Job for Backups
```bash
# Add to crontab for weekly backups
0 2 * * 0 /path/to/ssh_key_manager.sh backup weekly_$(date +\%Y\%m\%d)
```