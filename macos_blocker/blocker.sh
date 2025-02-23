#!/bin/bash
#
# MacSiteBlock - System Level Website Blocker (Revised)
# Version 2.0.0
#
# Must be run via sudo on macOS. Blocks domains by injecting them into /etc/hosts.
#
# Usage examples:
#   sudo ./MacSiteBlock.sh block example.com
#   sudo ./MacSiteBlock.sh unblock example.com
#   sudo ./MacSiteBlock.sh status
#   sudo ./MacSiteBlock.sh enable
#   sudo ./MacSiteBlock.sh disable
#   sudo ./MacSiteBlock.sh cleanup
#   sudo ./MacSiteBlock.sh restore
#   sudo ./MacSiteBlock.sh health
#

set -euo pipefail
IFS=$'\n\t'

##################################
# Configuration
##################################
HOSTS_FILE="/etc/hosts"
BACKUP_DIR="$HOME/.macsiteblock"
BACKUP_FILE="$BACKUP_DIR/hosts.backup"
DOMAINS_FILE="$BACKUP_DIR/domains.txt"
LOCK_FILE="$BACKUP_DIR/macsiteblock.lock"
LOG_FILE="$BACKUP_DIR/macsiteblock.log"
MAX_BACKUPS=5

# If you want to automatically also block "www." when blocking "example.com", set this to "true"
ALSO_BLOCK_WWW=true

# Protected domains that cannot be blocked
PROTECTED_DOMAINS=(
    "localhost"
    "localhost.localdomain"
    "local"
    "broadcasthost"
    "ip6-localhost"
    "ip6-loopback"
)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

##################################
# Logging
##################################
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$timestamp [$level] $message" >> "$LOG_FILE"
    case $level in
        "ERROR") echo -e "${RED}Error: $message${NC}" >&2 ;;
        "WARN")  echo -e "${YELLOW}Warning: $message${NC}" ;;
        "INFO")  echo -e "${GREEN}$message${NC}" ;;
        *)       echo "$message" ;;
    esac
}

##################################
# Permission Check
##################################
check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        log "ERROR" "This script must be run with sudo privileges."
        exit 1
    fi
}

##################################
# Initialization
##################################
init() {
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
        chmod 700 "$BACKUP_DIR"
        chown "$SUDO_USER:$(id -g "$SUDO_USER")" "$BACKUP_DIR"
    fi

    for file in "$DOMAINS_FILE" "$LOG_FILE"; do
        if [ ! -f "$file" ]; then
            touch "$file"
            chmod 600 "$file"
            chown "$SUDO_USER:$(id -g "$SUDO_USER")" "$file"
        fi
    done

    # Create an initial backup of /etc/hosts if not present
    if [ ! -f "$BACKUP_FILE" ]; then
        cp "$HOSTS_FILE" "$BACKUP_FILE"
        chmod 600 "$BACKUP_FILE"
        chown "$SUDO_USER:$(id -g "$SUDO_USER")" "$BACKUP_FILE"
    fi
}

##################################
# Locking
##################################
acquire_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local pid
        pid=$(cat "$LOCK_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log "ERROR" "Another instance of MacSiteBlock is running (PID: $pid). Exiting."
            exit 1
        fi
    fi
    echo $$ > "$LOCK_FILE"
}

release_lock() {
    rm -f "$LOCK_FILE"
}

##################################
# Domain Validation
##################################
validate_domain() {
    local domain=$1

    # Strip leading "*." if present (support partial wildcard input, though not real wildcard blocking in /etc/hosts)
    [[ $domain == \*.* ]] && domain="${domain#*.}"

    # A simpler domain validation approach (alphanumeric, dash, dot):
    if [[ ! $domain =~ ^[A-Za-z0-9.-]+$ ]]; then
        log "ERROR" "Invalid domain format: '$domain'"
        return 1
    fi

    # Check if domain is in protected list
    for protected in "${PROTECTED_DOMAINS[@]}"; do
        if [[ "$domain" == "$protected" ]]; then
            log "ERROR" "Cannot block protected domain: $domain"
            return 1
        fi
    done

    # Must have at least one dot (so we don't block "local" or "machine" inadvertently)
    if [[ "$domain" != *.* ]]; then
        log "ERROR" "Domain must contain at least one '.' (e.g., example.com). Got: $domain"
        return 1
    fi

    return 0
}

##################################
# Backup Hosts (Rotating)
##################################
backup_hosts() {
    local backup_timestamp
    backup_timestamp=$(date '+%Y%m%d_%H%M%S')
    local new_backup="$BACKUP_DIR/hosts.backup.$backup_timestamp"

    cp "$HOSTS_FILE" "$new_backup"
    chmod 600 "$new_backup"
    chown "$SUDO_USER:$(id -g "$SUDO_USER")" "$new_backup"

    # Rotate backups
    local old_backups
    old_backups=($(ls -t "$BACKUP_DIR"/hosts.backup.* 2>/dev/null || true))
    if [ ${#old_backups[@]} -gt $MAX_BACKUPS ]; then
        for ((i=$MAX_BACKUPS; i<${#old_backups[@]}; i++)); do
            rm -f "${old_backups[$i]}"
        done
    fi

    log "INFO" "Hosts file backed up as $(basename "$new_backup")."
}

##################################
# Restore Hosts
##################################
restore_hosts() {
    if [ -f "$BACKUP_FILE" ]; then
        cp "$BACKUP_FILE" "$HOSTS_FILE"
        flush_dns_cache
        log "INFO" "Hosts file restored from initial backup."
    else
        log "ERROR" "No backup file found at $BACKUP_FILE."
        exit 1
    fi
}

##################################
# Flush DNS Cache
##################################
flush_dns_cache() {
    # Clear macOS DNS cache
    dscacheutil -flushcache
    killall -HUP mDNSResponder || true

    log "INFO" "System DNS cache flushed. Reminder: close your browsers and reopen to ensure changes take effect."
}

##################################
# Duplicate Check
##################################
is_already_blocked() {
    local domain=$1
    if grep -Eq "^[#]*[[:space:]]*127\.0\.0\.1[[:space:]]+$domain[[:space:]]+[#]*" "$HOSTS_FILE"; then
        return 0
    fi
    return 1
}

##################################
# Block Domain
##################################
block_domain() {
    local domain=$1

    validate_domain "$domain" || return 1

    if is_already_blocked "$domain"; then
        log "WARN" "Domain '$domain' is already blocked."
        return 0
    fi

    local size
    size=$(stat -f%z "$HOSTS_FILE")
    if [ "$size" -gt 1048576 ]; then  # 1MB limit (arbitrary safeguard)
        log "ERROR" "Hosts file is too large (>1MB). Clean it up before adding more entries."
        return 1
    fi

    {
      echo "127.0.0.1     $domain    # MacSiteBlock"
      echo "::1           $domain    # MacSiteBlock"
      echo "fe80::1%lo0   $domain    # MacSiteBlock"
    } >> "$HOSTS_FILE"

    # Append domain to the tracked list (avoid duplicates here too)
    if ! grep -Fxq "$domain" "$DOMAINS_FILE"; then
        echo "$domain" >> "$DOMAINS_FILE"
    fi

    log "INFO" "Blocked domain: $domain"
    return 0
}

##################################
# (Optional) Also Block "www."
##################################
maybe_block_www() {
    local domain=$1
    if [ "$ALSO_BLOCK_WWW" = true ]; then
        # If domain does not start with "www." and isn't already so
        if [[ ! "$domain" =~ ^www\. ]]; then
            local www_domain="www.$domain"
            block_domain "$www_domain" || true
        fi
    fi
}

##################################
# Unblock Domain
##################################
unblock_domain() {
    local domain=$1
    validate_domain "$domain" || return 1

    # Remove lines for domain from /etc/hosts
    sed -i '' "/[[:space:]]$domain[[:space:]]*# MacSiteBlock/d" "$HOSTS_FILE"

    # Also remove from the domain list
    sed -i '' "/^$domain$/d" "$DOMAINS_FILE"

    log "INFO" "Unblocked domain: $domain"
    return 0
}

##################################
# Cleanup (Remove duplicates, empty lines)
##################################
cleanup() {
    local temp_file
    temp_file=$(mktemp)

    # Remove duplicates, empty lines
    awk '!seen[$0]++' "$HOSTS_FILE" | sed '/^[[:space:]]*$/d' > "$temp_file"

    # Validate we didn't remove critical lines
    if grep -qE "^127\.0\.0\.1[[:space:]]+localhost" "$temp_file"; then
        cp "$temp_file" "$HOSTS_FILE"
        rm -f "$temp_file"
        log "INFO" "Hosts file cleaned up (duplicates removed)."
    else
        rm -f "$temp_file"
        log "ERROR" "Cleanup would remove localhost line. Aborting."
        return 1
    fi
}

##################################
# Health Check
##################################
health_check() {
    local issues=0

    # Check critical localhost line in /etc/hosts
    if ! grep -qE "^127\.0\.0\.1[[:space:]]+localhost" "$HOSTS_FILE"; then
        log "ERROR" "Hosts file missing '127.0.0.1 localhost' line."
        ((issues++))
    fi

    # Check for duplicates
    local dupes
    dupes=$(sort "$HOSTS_FILE" | uniq -d)
    if [ -n "$dupes" ]; then
        log "WARN" "Duplicate entries in /etc/hosts. Consider running cleanup."
        ((issues++))
    fi

    if [ "$issues" -eq 0 ]; then
        log "INFO" "Health check passed."
        return 0
    else
        log "ERROR" "Health check found $issues issue(s)."
        return 1
    fi
}

##################################
# Status
##################################
show_status() {
    log "INFO" "Currently blocked domains:"
    if [ -s "$DOMAINS_FILE" ]; then
        cat "$DOMAINS_FILE"
    else
        log "INFO" "No domains are currently blocked."
    fi
}

##################################
# Enable (Block All in domains.txt)
##################################
enable_all() {
    local count=0
    while IFS= read -r domain; do
        if [ -n "$domain" ]; then
            block_domain "$domain" && ((count++))
        fi
    done < "$DOMAINS_FILE"
    flush_dns_cache
    log "INFO" "Enabled blocking for $count domain(s)."
}

##################################
# Disable (Unblock All in domains.txt)
##################################
disable_all() {
    local count=0
    while IFS= read -r domain; do
        if [ -n "$domain" ]; then
            unblock_domain "$domain" && ((count++))
        fi
    done < "$DOMAINS_FILE"
    flush_dns_cache
    log "INFO" "Disabled blocking for $count domain(s)."
}

##################################
# Usage
##################################
show_usage() {
    cat << EOF
Usage: sudo $0 [command] [domains...]

Commands:
  block [domain ...]   Block specified domain(s)
  unblock [domain ...] Unblock specified domain(s)
  status               Show all blocked domains
  enable               Enable blocking for all domains in $DOMAINS_FILE
  disable              Disable blocking for all domains in $DOMAINS_FILE
  backup               Create a timestamped backup of /etc/hosts
  restore              Restore /etc/hosts from the original backup
  cleanup              Remove duplicates from /etc/hosts
  health               Check for common issues in /etc/hosts
  help                 Show this help message

Examples:
  sudo $0 block example.com
  sudo $0 block *.example.com
  sudo $0 unblock example.com
  sudo $0 status

Note:
  - You must run this script with sudo privileges.
  - For best results, close and reopen your browsers after blocking/unblocking.
EOF
}

##################################
# Main
##################################
main() {
    check_sudo
    init
    acquire_lock
    trap release_lock EXIT

    local command=${1:-help}
    shift || true

    case "$command" in
        block)
            if [ $# -eq 0 ]; then
                log "ERROR" "Please specify at least one domain to block."
                show_usage
                exit 1
            fi
            backup_hosts
            for domain in "$@"; do
                block_domain "$domain"
                maybe_block_www "$domain"
            done
            flush_dns_cache
            ;;
        unblock)
            if [ $# -eq 0 ]; then
                log "ERROR" "Please specify at least one domain to unblock."
                show_usage
                exit 1
            fi
            backup_hosts
            for domain in "$@"; do
                unblock_domain "$domain"
                # Optionally unblock "www." domain as well if it exists
                if [ "$ALSO_BLOCK_WWW" = true ] && [[ ! "$domain" =~ ^www\. ]]; then
                    local www_domain="www.$domain"
                    unblock_domain "$www_domain" || true
                fi
            done
            flush_dns_cache
            ;;
        status)
            show_status
            ;;
        enable)
            backup_hosts
            enable_all
            ;;
        disable)
            backup_hosts
            disable_all
            ;;
        backup)
            backup_hosts
            ;;
        restore)
            restore_hosts
            ;;
        cleanup)
            backup_hosts
            cleanup
            ;;
        health)
            health_check
            ;;
        help | *)
            show_usage
            ;;
    esac
}

main "$@"

