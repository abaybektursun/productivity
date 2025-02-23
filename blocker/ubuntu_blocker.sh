#!/bin/bash
#
# UbuntuSiteBlock - System-Level Website Blocker (for Ubuntu)
# Version 2.0.0
#
# Must be run with sudo on Ubuntu. Blocks domains by editing /etc/hosts.

set -euo pipefail
IFS=$'\n\t'

##################################
# Configuration
##################################
HOSTS_FILE="/etc/hosts"
BACKUP_DIR="$HOME/.ubsitesblock"
BACKUP_FILE="$BACKUP_DIR/hosts.backup"
DOMAINS_FILE="$BACKUP_DIR/domains.txt"
LOCK_FILE="$BACKUP_DIR/ubsitesblock.lock"
LOG_FILE="$BACKUP_DIR/ubsitesblock.log"
MAX_BACKUPS=5

# If you want to automatically also block "www." when blocking "example.com", set to "true"
ALSO_BLOCK_WWW=true

# Protected domains that cannot be blocked
PROTECTED_DOMAINS=(
    "localhost"
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
        # Attempt to give ownership back to the non-root user
        if [ -n "${SUDO_USER:-}" ] && id "$SUDO_USER" &>/dev/null; then
            chown "$SUDO_USER":"$SUDO_USER" "$BACKUP_DIR"
        fi
    fi
    
    for file in "$DOMAINS_FILE" "$LOG_FILE"; do
        if [ ! -f "$file" ]; then
            touch "$file"
            chmod 600 "$file"
            if [ -n "${SUDO_USER:-}" ] && id "$SUDO_USER" &>/dev/null; then
                chown "$SUDO_USER":"$SUDO_USER" "$file"
            fi
        fi
    done

    # Create an initial backup of /etc/hosts if not present
    if [ ! -f "$BACKUP_FILE" ]; then
        cp "$HOSTS_FILE" "$BACKUP_FILE"
        chmod 600 "$BACKUP_FILE"
        if [ -n "${SUDO_USER:-}" ] && id "$SUDO_USER" &>/dev/null; then
            chown "$SUDO_USER":"$SUDO_USER" "$BACKUP_FILE"
        fi
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
            log "ERROR" "Another instance of UbuntuSiteBlock is running (PID: $pid). Exiting."
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

    # Strip leading "*." if present (supports wildcard input, though /etc/hosts can't truly do wildcard blocking)
    [[ $domain == \*.* ]] && domain="${domain#*.}"

    # Simple domain validation: alphanumeric, dots, hyphens
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

    # Must have at least one dot (to avoid blocking single-word local hosts)
    if [[ "$domain" != *.* ]]; then
        log "ERROR" "Domain must contain at least one '.' (example: example.com). Got: $domain"
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
    if [ -n "${SUDO_USER:-}" ] && id "$SUDO_USER" &>/dev/null; then
        chown "$SUDO_USER":"$SUDO_USER" "$new_backup"
    fi
    
    # Rotate backups
    local old_backups
    # shellcheck disable=SC2207
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
        log "INFO" "Hosts file restored from original backup."
    else
        log "ERROR" "No backup file found at $BACKUP_FILE."
        exit 1
    fi
}

##################################
# Flush DNS Cache (Ubuntu systemd-resolved)
##################################
flush_dns_cache() {
    if command -v systemd-resolve >/dev/null 2>&1; then
        systemd-resolve --flush-caches
    elif command -v resolvectl >/dev/null 2>&1; then
        resolvectl flush-caches
    else
        # Fallback: restart systemd-resolved (can be disruptive in some environments)
        systemctl restart systemd-resolved || true
    fi

    log "INFO" "System DNS cache flushed (or attempted). Close and reopen browsers if needed."
}


##################################
# Duplicate Check
##################################
is_already_blocked() {
    local domain=$1
    if grep -Eq "^[#]*[[:space:]]*127\.0\.0\.1[[:space:]]+$domain(\s|$)" "$HOSTS_FILE"; then
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

    # Check hosts file size (1MB limit, arbitrary safety check)
    local size
    size=$(stat -c%s "$HOSTS_FILE")
    if [ "$size" -gt 1048576 ]; then
        log "ERROR" "Hosts file is too large (>1MB). Clean it up before adding more entries."
        return 1
    fi

    {
      echo "127.0.0.1    $domain    # UbuntuSiteBlock"
      echo "::1          $domain    # UbuntuSiteBlock"
    } >> "$HOSTS_FILE"

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
    sed -i "/[[:space:]]$domain[[:space:]]*# UbuntuSiteBlock/d" "$HOSTS_FILE"

    # Remove from the domain list
    sed -i "/^$domain$/d" "$DOMAINS_FILE"

    log "INFO" "Unblocked domain: $domain"
    return 0
}

##################################
# Cleanup (Remove duplicates/empty lines)
##################################
cleanup() {
    local temp_file
    temp_file=$(mktemp)

    # Remove duplicate lines & empty lines
    awk '!seen[$0]++' "$HOSTS_FILE" | sed '/^[[:space:]]*$/d' > "$temp_file"

    # Ensure localhost wasn't lost
    if grep -qE "^127\.0\.0\.1[[:space:]]+localhost" "$temp_file"; then
        cp "$temp_file" "$HOSTS_FILE"
        rm -f "$temp_file"
        log "INFO" "Hosts file cleaned (duplicates removed)."
    else
        rm -f "$temp_file"
        log "ERROR" "Cleanup would remove critical localhost line. Aborting."
        return 1
    fi
}

##################################
# Health Check
##################################
health_check() {
    local issues=0

    # Ensure there's a localhost line
    if ! grep -qE "^127\.0\.0\.1[[:space:]]+localhost" "$HOSTS_FILE"; then
        log "ERROR" "Hosts file missing '127.0.0.1 localhost' line."
        ((issues++))
    fi

    # Check for duplicates
    local dupes
    dupes=$(sort "$HOSTS_FILE" | uniq -d)
    if [ -n "$dupes" ]; then
        log "WARN" "Duplicate entries found. Consider running 'cleanup'."
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
  block [domain ...]   Block the specified domain(s)
  unblock [domain ...] Unblock the specified domain(s)
  status               List all blocked domains
  enable               Re-block every domain in $DOMAINS_FILE
  disable              Unblock every domain in $DOMAINS_FILE
  backup               Create a timestamped backup of /etc/hosts
  restore              Restore /etc/hosts from the original backup
  cleanup              Remove duplicates/blank lines in /etc/hosts
  health               Check /etc/hosts for common issues
  help                 Show this message

Examples:
  sudo $0 block example.com
  sudo $0 block *.example.com
  sudo $0 unblock example.com
  sudo $0 status

Notes:
  - Must be run as root or via sudo.
  - Browsers cache DNS; close and reopen them after changes.
  - If ALSO_BLOCK_WWW=true, blocking "example.com" also blocks "www.example.com".
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
                # Optionally unblock "www." if ALSO_BLOCK_WWW=true
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

