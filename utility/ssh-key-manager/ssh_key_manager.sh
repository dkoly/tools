#!/bin/bash

# SSH Key Manager
# Manage SSH keys - create, install, backup, and maintain SSH key pairs

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
SSH_DIR="$HOME/.ssh"
KEY_TYPE="ed25519"
KEY_SIZE="4096"
BACKUP_DIR="$HOME/.ssh/backups"
CONFIG_FILE="$SSH_DIR/config"

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}    SSH Key Manager${NC}"
    echo -e "${BLUE}================================${NC}\n"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    local deps=("ssh-keygen" "ssh-copy-id" "ssh-add")
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_error "Required dependency not found: $dep"
            exit 1
        fi
    done
}

ensure_ssh_dir() {
    if [[ ! -d "$SSH_DIR" ]]; then
        mkdir -p "$SSH_DIR"
        chmod 700 "$SSH_DIR"
        log_info "Created SSH directory: $SSH_DIR"
    fi
}

generate_key() {
    local key_name="$1"
    local key_type="${2:-$KEY_TYPE}"
    local key_size="${3:-$KEY_SIZE}"
    local comment="${4:-$(whoami)@$(hostname)}"
    local passphrase="$5"
    
    ensure_ssh_dir
    
    local key_path="$SSH_DIR/$key_name"
    
    if [[ -f "$key_path" ]]; then
        log_warning "Key already exists: $key_path"
        read -p "Overwrite existing key? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Key generation cancelled"
            return 1
        fi
    fi
    
    log_info "Generating $key_type SSH key: $key_name"
    
    if [[ "$key_type" == "rsa" ]]; then
        ssh-keygen -t rsa -b "$key_size" -f "$key_path" -C "$comment" -N "$passphrase"
    elif [[ "$key_type" == "ed25519" ]]; then
        ssh-keygen -t ed25519 -f "$key_path" -C "$comment" -N "$passphrase"
    elif [[ "$key_type" == "ecdsa" ]]; then
        ssh-keygen -t ecdsa -b "$key_size" -f "$key_path" -C "$comment" -N "$passphrase"
    else
        log_error "Unsupported key type: $key_type"
        return 1
    fi
    
    chmod 600 "$key_path"
    chmod 644 "$key_path.pub"
    
    log_info "SSH key generated successfully!"
    log_info "Private key: $key_path"
    log_info "Public key: $key_path.pub"
    
    echo -e "\n${BLUE}Public key content:${NC}"
    cat "$key_path.pub"
    echo
}

list_keys() {
    ensure_ssh_dir
    
    echo -e "${BLUE}SSH Keys in $SSH_DIR:${NC}\n"
    
    local found_keys=0
    
    for key_file in "$SSH_DIR"/*.pub; do
        if [[ -f "$key_file" ]]; then
            found_keys=1
            local key_name=$(basename "$key_file" .pub)
            local private_key="$SSH_DIR/$key_name"
            
            echo -e "${GREEN}Key: $key_name${NC}"
            
            # Check if private key exists
            if [[ -f "$private_key" ]]; then
                echo "  Private key: ✓"
            else
                echo "  Private key: ✗"
            fi
            
            # Get key info
            local key_info=$(ssh-keygen -l -f "$key_file" 2>/dev/null || echo "Invalid key")
            echo "  Info: $key_info"
            
            # Check if key is loaded in agent
            if ssh-add -l 2>/dev/null | grep -q "$(ssh-keygen -l -f "$key_file" 2>/dev/null | awk '{print $2}')" 2>/dev/null; then
                echo "  Agent: ✓ Loaded"
            else
                echo "  Agent: ✗ Not loaded"
            fi
            
            echo "  Public key: $(cat "$key_file")"
            echo
        fi
    done
    
    if [[ $found_keys -eq 0 ]]; then
        log_info "No SSH keys found in $SSH_DIR"
    fi
}

install_key() {
    local key_name="$1"
    local target_host="$2"
    local target_user="${3:-$(whoami)}"
    
    local key_path="$SSH_DIR/$key_name.pub"
    
    if [[ ! -f "$key_path" ]]; then
        log_error "Public key not found: $key_path"
        return 1
    fi
    
    log_info "Installing public key '$key_name' to $target_user@$target_host"
    
    if ssh-copy-id -i "$key_path" "$target_user@$target_host"; then
        log_info "Key installed successfully!"
        
        # Test the connection
        log_info "Testing SSH connection..."
        if ssh -o ConnectTimeout=5 -o BatchMode=yes "$target_user@$target_host" 'echo "SSH key authentication successful!"'; then
            log_info "SSH connection test passed!"
        else
            log_warning "SSH connection test failed. Key may not be properly configured."
        fi
    else
        log_error "Failed to install SSH key"
        return 1
    fi
}

backup_keys() {
    local backup_name="${1:-ssh_backup_$(date +%Y%m%d_%H%M%S)}"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    ensure_ssh_dir
    mkdir -p "$BACKUP_DIR"
    
    if [[ ! -d "$SSH_DIR" ]] || [[ -z "$(ls -A "$SSH_DIR" 2>/dev/null)" ]]; then
        log_warning "No SSH directory or keys to backup"
        return 1
    fi
    
    log_info "Creating backup: $backup_path"
    
    # Create backup directory
    mkdir -p "$backup_path"
    
    # Copy all SSH files
    cp -r "$SSH_DIR"/* "$backup_path/" 2>/dev/null || true
    
    # Create backup info file
    cat > "$backup_path/backup_info.txt" << EOF
SSH Keys Backup
Created: $(date)
Hostname: $(hostname)
User: $(whoami)
Source: $SSH_DIR
EOF
    
    # Create tar archive
    tar -czf "$backup_path.tar.gz" -C "$BACKUP_DIR" "$backup_name"
    rm -rf "$backup_path"
    
    log_info "Backup created: $backup_path.tar.gz"
    log_info "Backup size: $(du -h "$backup_path.tar.gz" | cut -f1)"
}

restore_keys() {
    local backup_file="$1"
    
    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
        return 1
    fi
    
    log_warning "This will overwrite existing SSH keys!"
    read -p "Continue with restore? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Restore cancelled"
        return 1
    fi
    
    # Backup current keys first
    if [[ -d "$SSH_DIR" ]] && [[ -n "$(ls -A "$SSH_DIR" 2>/dev/null)" ]]; then
        log_info "Backing up current keys..."
        backup_keys "pre_restore_$(date +%Y%m%d_%H%M%S)"
    fi
    
    log_info "Restoring keys from: $backup_file"
    
    # Extract backup
    local temp_dir=$(mktemp -d)
    tar -xzf "$backup_file" -C "$temp_dir"
    
    # Find the backup directory
    local backup_dir=$(find "$temp_dir" -maxdepth 1 -type d ! -path "$temp_dir" | head -1)
    
    if [[ -z "$backup_dir" ]]; then
        log_error "Invalid backup file format"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # Remove existing SSH directory and restore
    rm -rf "$SSH_DIR"
    mkdir -p "$SSH_DIR"
    cp -r "$backup_dir"/* "$SSH_DIR/" 2>/dev/null || true
    
    # Set proper permissions
    chmod 700 "$SSH_DIR"
    find "$SSH_DIR" -name "*" -type f ! -name "*.pub" -exec chmod 600 {} \;
    find "$SSH_DIR" -name "*.pub" -type f -exec chmod 644 {} \;
    
    rm -rf "$temp_dir"
    
    log_info "Keys restored successfully!"
    log_info "Please verify your keys with: $0 list"
}

add_to_agent() {
    local key_name="$1"
    local key_path="$SSH_DIR/$key_name"
    
    if [[ ! -f "$key_path" ]]; then
        log_error "Private key not found: $key_path"
        return 1
    fi
    
    log_info "Adding key to SSH agent: $key_name"
    
    # Start ssh-agent if not running
    if ! pgrep -x ssh-agent > /dev/null; then
        log_info "Starting SSH agent..."
        eval "$(ssh-agent -s)"
    fi
    
    if ssh-add "$key_path"; then
        log_info "Key added to SSH agent successfully!"
    else
        log_error "Failed to add key to SSH agent"
        return 1
    fi
}

remove_from_agent() {
    local key_name="$1"
    local key_path="$SSH_DIR/$key_name"
    
    if [[ ! -f "$key_path" ]]; then
        log_error "Private key not found: $key_path"
        return 1
    fi
    
    log_info "Removing key from SSH agent: $key_name"
    
    if ssh-add -d "$key_path" 2>/dev/null; then
        log_info "Key removed from SSH agent successfully!"
    else
        log_warning "Key was not loaded in SSH agent or removal failed"
    fi
}

delete_key() {
    local key_name="$1"
    local private_key="$SSH_DIR/$key_name"
    local public_key="$SSH_DIR/$key_name.pub"
    
    if [[ ! -f "$private_key" ]] && [[ ! -f "$public_key" ]]; then
        log_error "Key not found: $key_name"
        return 1
    fi
    
    log_warning "This will permanently delete the SSH key: $key_name"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Key deletion cancelled"
        return 1
    fi
    
    # Remove from agent first
    if [[ -f "$private_key" ]]; then
        ssh-add -d "$private_key" 2>/dev/null || true
    fi
    
    # Delete files
    [[ -f "$private_key" ]] && rm "$private_key" && log_info "Deleted private key: $private_key"
    [[ -f "$public_key" ]] && rm "$public_key" && log_info "Deleted public key: $public_key"
    
    log_info "SSH key deleted: $key_name"
}

show_config() {
    echo -e "${BLUE}SSH Configuration:${NC}\n"
    echo "SSH Directory: $SSH_DIR"
    echo "Config File: $CONFIG_FILE"
    echo "Backup Directory: $BACKUP_DIR"
    echo "Default Key Type: $KEY_TYPE"
    echo "Default Key Size: $KEY_SIZE"
    echo
    
    if [[ -f "$CONFIG_FILE" ]]; then
        echo -e "${BLUE}SSH Config File Content:${NC}"
        cat "$CONFIG_FILE"
    else
        log_info "No SSH config file found"
    fi
}

show_usage() {
    cat << EOF
Usage: $0 <command> [options]

Commands:
  generate <name> [type] [size] [comment] [passphrase]  Generate new SSH key pair
  list                                                  List all SSH keys
  install <key_name> <host> [user]                     Install public key to remote host
  backup [name]                                         Backup SSH keys
  restore <backup_file>                                 Restore SSH keys from backup
  add <key_name>                                        Add key to SSH agent
  remove <key_name>                                     Remove key from SSH agent
  delete <key_name>                                     Delete SSH key pair
  config                                                Show SSH configuration
  help                                                  Show this help message

Key Types: rsa, ed25519, ecdsa
Default Key Type: $KEY_TYPE
Default Key Size: $KEY_SIZE (for RSA/ECDSA)

Examples:
  $0 generate mykey                                    # Generate ed25519 key named 'mykey'
  $0 generate workkey rsa 4096 "work@company.com"     # Generate RSA key with custom settings
  $0 list                                              # List all keys
  $0 install mykey server.example.com                 # Install key to remote server
  $0 backup                                            # Backup all SSH keys
  $0 add mykey                                         # Add key to SSH agent
EOF
}

main() {
    print_header
    check_dependencies
    
    if [[ $# -eq 0 ]]; then
        show_usage
        exit 1
    fi
    
    case "$1" in
        "generate")
            if [[ $# -lt 2 ]]; then
                log_error "Key name required"
                echo "Usage: $0 generate <name> [type] [size] [comment] [passphrase]"
                exit 1
            fi
            generate_key "$2" "${3:-}" "${4:-}" "${5:-}" "${6:-}"
            ;;
        "list")
            list_keys
            ;;
        "install")
            if [[ $# -lt 3 ]]; then
                log_error "Key name and host required"
                echo "Usage: $0 install <key_name> <host> [user]"
                exit 1
            fi
            install_key "$2" "$3" "${4:-}"
            ;;
        "backup")
            backup_keys "${2:-}"
            ;;
        "restore")
            if [[ $# -lt 2 ]]; then
                log_error "Backup file required"
                echo "Usage: $0 restore <backup_file>"
                exit 1
            fi
            restore_keys "$2"
            ;;
        "add")
            if [[ $# -lt 2 ]]; then
                log_error "Key name required"
                echo "Usage: $0 add <key_name>"
                exit 1
            fi
            add_to_agent "$2"
            ;;
        "remove")
            if [[ $# -lt 2 ]]; then
                log_error "Key name required"
                echo "Usage: $0 remove <key_name>"
                exit 1
            fi
            remove_from_agent "$2"
            ;;
        "delete")
            if [[ $# -lt 2 ]]; then
                log_error "Key name required"
                echo "Usage: $0 delete <key_name>"
                exit 1
            fi
            delete_key "$2"
            ;;
        "config")
            show_config
            ;;
        "help")
            show_usage
            ;;
        *)
            log_error "Unknown command: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi