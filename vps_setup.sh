#!/usr/bin/env bash
#
# VPS Security Hardening & Setup Script (Bash Version)
# Targets: Debian/Ubuntu
# Runs interactively to configure a secure VPS environment.

# Exit immediately if a command exits with a non-zero status
set -euo pipefail

# ANSI Colors for Output
COLOR_RESET="\033[0m"
COLOR_INFO="\033[1;34m"      # Bold Blue
COLOR_SUCCESS="\033[1;32m"   # Bold Green
COLOR_WARNING="\033[1;33m"   # Bold Yellow
COLOR_ERROR="\033[1;31m"     # Bold Red
COLOR_MUTED="\033[0;37m"     # Gray

LOG_FILE="/var/log/vps_setup.log"

log_info() {
    echo -e "${COLOR_INFO}[INFO]${COLOR_RESET} $1"
    echo "[INFO] $(date --iso-8601=seconds) $1" >> "$LOG_FILE"
}

log_success() {
    echo -e "${COLOR_SUCCESS}[SUCCESS]${COLOR_RESET} $1"
    echo "[SUCCESS] $(date --iso-8601=seconds) $1" >> "$LOG_FILE"
}

log_warning() {
    echo -e "${COLOR_WARNING}[WARNING]${COLOR_RESET} $1"
    echo "[WARNING] $(date --iso-8601=seconds) $1" >> "$LOG_FILE"
}

log_error() {
    echo -e "${COLOR_ERROR}[ERROR]${COLOR_RESET} $1" >&2
    echo "[ERROR] $(date --iso-8601=seconds) $1" >> "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Please use 'sudo ./vps_setup.sh'."
        exit 1
    fi
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local timestamp
        timestamp=$(date +"%Y%m%d_%H%M%S")
        local backup="${file}.bak_${timestamp}"
        cp "$file" "$backup"
        log_info "Backed up $file to $backup"
    fi
}

# --- Validation Functions ---

validate_hostname() {
    [[ "$1" =~ ^[a-zA-Z0-9-]{1,63}$ ]]
}

validate_username() {
    [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
}

validate_ssh_port() {
    if [[ ! "$1" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    local port=$1
    if (( port < 1 || port > 65535 )); then
        return 1
    fi
    # Exclude common database ports
    for banned in 1433 1521 3306 5432 6379 8080 27017; do
        if (( port == banned )); then
            return 1
        fi
    done
    return 0
}

validate_key_string() {
    local key="$1"
    # Match prefixes of common SSH public keys
    local pattern='^(ssh-rsa|ssh-dss|ssh-ed25519|ssh-xmss|ecdsa-sha2-nistp(256|384|521))[[:space:]]+[^[:space:]]+'
    [[ "$key" =~ $pattern ]]
}

validate_ssh_public_key() {
    local key_input="$1"
    # Resolve tilde in paths
    key_input="${key_input/#\~/$HOME}"
    
    if [[ -f "$key_input" ]]; then
        local file_content
        file_content=$(cat "$key_input")
        validate_key_string "$file_content"
    else
        validate_key_string "$key_input"
    fi
}

validate_swap_size() {
    if [[ ! "$1" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    local size=$1
    (( size >= 0 && size <= 64 ))
}

# --- Prompt Helper ---

prompt_input() {
    local prompt_text="$1"
    local default_val="$2"
    local validator_func="$3"
    local error_msg="$4"
    local out_var="$5"
    
    local display_prompt
    if [[ -n "$default_val" ]]; then
        display_prompt="${prompt_text} [${default_val}]: "
    else
        display_prompt="${prompt_text}: "
    fi
    
    while true; do
        read -r -p "$display_prompt" input_val
        input_val="${input_val:-$default_val}"
        
        if [[ -z "$input_val" ]]; then
            echo -e "${COLOR_WARNING}Input cannot be empty.${COLOR_RESET}"
            continue
        fi
        
        if "$validator_func" "$input_val"; then
            eval "$out_var=\"\$input_val\""
            break
        else
            echo -e "${COLOR_ERROR}${error_msg}${COLOR_RESET}"
        fi
    done
}

# --- Setting Modifiers ---

update_sysctl_setting() {
    local key="$1"
    local val="$2"
    local file="/etc/sysctl.conf"
    
    if grep -q -E "^\s*#?\s*${key}\s*=" "$file"; then
        sed -i -E "s|^\s*#?\s*${key}\s*=.*|${key} = ${val}|g" "$file"
    else
        echo "${key} = ${val}" >> "$file"
    fi
}

update_sshd_setting() {
    local key="$1"
    local val="$2"
    local file="/etc/ssh/sshd_config"
    
    if grep -q -i -E "^\s*#?\s*${key}\b" "$file"; then
        sed -i -E "s|^\s*#?\s*${key}\b.*|${key} ${val}|gI" "$file"
    else
        echo "${key} ${val}" >> "$file"
    fi
}

# --- Execution Steps ---

setup_hostname() {
    local host="$1"
    log_info "Setting hostname to '${host}'..."
    hostnamectl set-hostname "$host"
    
    backup_file "/etc/hosts"
    if ! grep -q "127.0.1.1" "/etc/hosts"; then
        echo -e "127.0.1.1\t${host}" >> "/etc/hosts"
    else
        # If hostname is not in the line, append it
        if ! grep -E "^127\.0\.1\.1[[:space:]]+.*${host}" "/etc/hosts" > /dev/null; then
            sed -i -E "s|^(127\.0\.1\.1[[:space:]]+)(.*)|\1${host} \2|g" "/etc/hosts"
        fi
    fi
    log_success "Hostname configured."
}

setup_swap() {
    local size_gb="$1"
    if (( size_gb == 0 )); then
        log_info "Skipping swap file creation as requested (size 0)."
        return
    fi
    
    local swap_path="/swapfile"
    if [[ -f "$swap_path" ]]; then
        log_warning "$swap_path already exists. Skipping swap creation."
        return
    fi
    
    log_info "Creating ${size_gb}GB swap file..."
    dd if=/dev/zero of="$swap_path" bs=1M count=$(( size_gb * 1024 ))
    
    log_info "Setting swap permissions..."
    chmod 600 "$swap_path"
    mkswap "$swap_path"
    swapon "$swap_path"
    
    backup_file "/etc/fstab"
    if ! grep -q "$swap_path" "/etc/fstab"; then
        log_info "Adding swap to /etc/fstab..."
        echo -e "\n${swap_path} none swap sw 0 0" >> "/etc/fstab"
    fi
    
    # Configure swappiness
    update_sysctl_setting "vm.swappiness" "10"
    sysctl -p > /dev/null
    
    log_success "Swap space configured."
}

install_packages() {
    log_info "Updating package repositories..."
    apt-get update
    
    log_info "Upgrading packages (this may take a few minutes)..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get upgrade -y -o Dpkg::Options::="--force-confold"
    
    log_info "Installing security tools and packages..."
    apt-get install -y nginx certbot python3-certbot-nginx ufw fail2ban unattended-upgrades rkhunter chkrootkit auditd chrony
    log_success "All packages installed."
}

configure_auto_updates() {
    log_info "Enabling automatic security updates..."
    export DEBIAN_FRONTEND=noninteractive
    dpkg-reconfigure -plow unattended-upgrades
    
    # Enforce period updates
    local auto_upgrades="/etc/apt/apt.conf.d/20auto-upgrades"
    cat <<EOF > "$auto_upgrades"
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    log_success "Automatic updates configured."
}

configure_sysctl_hardening() {
    log_info "Applying kernel sysctl hardening..."
    
    update_sysctl_setting "net.ipv4.conf.all.rp_filter" "1"
    update_sysctl_setting "net.ipv4.conf.default.rp_filter" "1"
    update_sysctl_setting "net.ipv4.conf.all.accept_redirects" "0"
    update_sysctl_setting "net.ipv6.conf.all.accept_redirects" "0"
    update_sysctl_setting "net.ipv4.conf.all.send_redirects" "0"
    update_sysctl_setting "net.ipv4.conf.all.accept_source_route" "0"
    update_sysctl_setting "net.ipv6.conf.all.accept_source_route" "0"
    update_sysctl_setting "net.ipv4.conf.all.log_martians" "1"
    update_sysctl_setting "net.ipv4.icmp_echo_ignore_all" "1"
    update_sysctl_setting "net.ipv4.tcp_syncookies" "1"
    update_sysctl_setting "net.ipv4.tcp_max_syn_backlog" "2048"
    update_sysctl_setting "net.ipv4.tcp_synack_retries" "2"
    update_sysctl_setting "net.ipv4.tcp_syn_retries" "5"
    
    # Advanced Settings
    update_sysctl_setting "kernel.randomize_va_space" "2"
    update_sysctl_setting "fs.suid_dumpable" "0"
    update_sysctl_setting "net.core.bpf_jit_harden" "2"
    
    sysctl -p > /dev/null
    log_success "Kernel parameters hardened."
}

configure_shared_memory() {
    log_info "Hardening shared memory (/dev/shm)..."
    backup_file "/etc/fstab"
    
    if grep -q -E "\s+/dev/shm\s+" "/etc/fstab"; then
        sed -i -E "s|.*\s+/dev/shm\s+.*|tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0|g" "/etc/fstab"
    else
        echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> "/etc/fstab"
    fi
    
    if mount -o remount /dev/shm 2>/dev/null; then
        log_success "Shared memory hardened and remounted."
    else
        log_warning "Could not remount /dev/shm immediately. Hardening will apply on next boot."
    fi
}

create_sudo_user() {
    local user="$1"
    local key_input="$2"
    key_input="${key_input/#\~/$HOME}"
    
    log_info "Checking user status..."
    if id "$user" &>/dev/null; then
        log_warning "User '$user' already exists. Skipping user creation."
    else
        log_info "Creating user '$user'..."
        useradd -m -s /bin/bash -G sudo "$user"
        passwd -l "$user"
        log_success "User '$user' created and added to sudo group."
    fi
    
    # Read public key content
    local key_str=""
    if [[ -f "$key_input" ]]; then
        key_str=$(cat "$key_input")
    else
        key_str="$key_input"
    fi
    
    local user_home
    user_home=$(getent passwd "$user" | cut -d: -f6)
    local ssh_dir="${user_home}/.ssh"
    local auth_keys="${ssh_dir}/authorized_keys"
    
    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    echo "$key_str" > "$auth_keys"
    chmod 600 "$auth_keys"
    
    chown -R "${user}:${user}" "$ssh_dir"
    log_success "SSH key deployed for user '$user'."
    
    # Configure passwordless sudo
    local sudoers_file="/etc/sudoers.d/${user}"
    if [[ ! -f "$sudoers_file" ]]; then
        echo "${user} ALL=(ALL) NOPASSWD:ALL" > "$sudoers_file"
        chmod 440 "$sudoers_file"
        log_info "Passwordless sudo configured for user '$user'."
    fi
}

configure_ssh_daemon() {
    local user="$1"
    local port="$2"
    
    log_info "Securing SSH Daemon config..."
    backup_file "/etc/ssh/sshd_config"
    
    # Write to a temporary config to validate before saving
    local temp_config="/etc/ssh/sshd_config.tmp"
    cp "/etc/ssh/sshd_config" "$temp_config"
    
    # Modifiers
    update_sshd_setting_temp() {
        local key="$1"
        local val="$2"
        if grep -q -i -E "^\s*#?\s*${key}\b" "$temp_config"; then
            sed -i -E "s|^\s*#?\s*${key}\b.*|${key} ${val}|gI" "$temp_config"
        else
            echo "${key} ${val}" >> "$temp_config"
        fi
    }
    
    update_sshd_setting_temp "Port" "$port"
    update_sshd_setting_temp "PasswordAuthentication" "no"
    update_sshd_setting_temp "PermitRootLogin" "no"
    update_sshd_setting_temp "PermitEmptyPasswords" "no"
    update_sshd_setting_temp "MaxAuthTries" "3"
    update_sshd_setting_temp "X11Forwarding" "no"
    update_sshd_setting_temp "LoginGraceTime" "30"
    update_sshd_setting_temp "AllowUsers" "$user"
    update_sshd_setting_temp "AllowAgentForwarding" "no"
    update_sshd_setting_temp "AllowTcpForwarding" "no"
    
    # Validate temporary configuration
    if sshd -t -f "$temp_config" 2>/dev/null; then
        mv "$temp_config" "/etc/ssh/sshd_config"
        chmod 600 "/etc/ssh/sshd_config"
        log_success "SSH config verified and updated."
    else
        log_error "Failed to validate updated SSH configuration. SSH configurations not applied."
        rm -f "$temp_config"
        exit 1
    fi
    
    log_info "Restarting SSH Daemon..."
    systemctl restart ssh
    log_success "SSH service restarted on port $port."
}

configure_fail2ban() {
    local port="$1"
    log_info "Configuring Fail2ban..."
    
    local local_jail="/etc/fail2ban/jail.local"
    backup_file "$local_jail"
    
    if [[ ! -f "$local_jail" ]]; then
        if [[ -f "/etc/fail2ban/jail.conf" ]]; then
            cp "/etc/fail2ban/jail.conf" "$local_jail"
        fi
    fi
    
    # Read and strip old [sshd] configuration if it exists
    local temp_jail="/tmp/jail.local.tmp"
    if [[ -f "$local_jail" ]]; then
        # This perl script safely removes the [sshd] block up to the next block or EOF
        perl -0777 -pe 's/\[sshd\].*?(?=\n\[\w+\]|\Z)//sg' "$local_jail" > "$temp_jail"
    else
        touch "$temp_jail"
    fi
    
    # Append the new customized block
    cat <<EOF >> "$temp_jail"

[sshd]
enabled = true
port = ${port}
banaction = ufw
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
EOF

    mv "$temp_jail" "$local_jail"
    chmod 644 "$local_jail"
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    log_success "Fail2ban customized jail configured and service restarted."
}

configure_ufw() {
    local port="$1"
    log_info "Configuring UFW Firewall..."
    
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Limit connections to prevent brute force on custom port
    log_info "Allowing custom SSH port $port with UFW limiting..."
    ufw limit "${port}/tcp"
    
    # Double check rule application before committing
    if ! ufw status numbered | grep -q "$port"; then
        log_warning "Verification alert: Custom port $port not seen in status listing. Re-applying rule."
        ufw allow "${port}/tcp"
    fi
    
    log_info "Enabling UFW..."
    ufw --force enable
    ufw status verbose
    log_success "Firewall active and rules applied."
}

start_aux_services() {
    log_info "Starting chrony time synchronization..."
    systemctl enable chrony
    systemctl start chrony
    
    log_info "Starting auditd daemon..."
    systemctl enable auditd
    systemctl start auditd
    
    log_info "Executing chkrootkit quick check..."
    chkrootkit || true
    
    log_info "Updating rkhunter properties database..."
    rkhunter --propupd || true
    
    log_success "Auxiliary services configuration complete."
}

# --- Main Logic ---

main() {
    check_root
    
    # Create the log file path if it does not exist
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    
    echo -e "\n${COLOR_SUCCESS}===============================================${COLOR_RESET}"
    echo -e "${COLOR_SUCCESS}   VPS SECURITY HARDENING & SETUP WIZARD (BASH) ${COLOR_RESET}"
    echo -e "${COLOR_SUCCESS}===============================================${COLOR_RESET}\n"
    
    # Detect default swap size matching system memory
    local default_swap=4
    if [[ -f "/proc/meminfo" ]]; then
        local mem_kb
        mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        default_swap=$(( mem_kb / (1024 * 1024) ))
        # Ensure at least 2GB
        if (( default_swap < 2 )); then
            default_swap=2
        fi
    fi
    
    # Variables to populate
    local target_hostname=""
    local target_username=""
    local target_ssh_port=""
    local target_ssh_key=""
    local target_swap_size=""
    
    # Gather inputs
    echo -e "\n${COLOR_MUTED}--> HOSTNAME CONFIGURATION:"
    echo -e "    This identifies your VPS on the network and in your command line prompt."
    echo -e "    Can contain letters, numbers, and hyphens (max 63 chars).${COLOR_RESET}"
    prompt_input "Enter new server hostname" "froniqo" validate_hostname "Hostname must contain only alphanumeric characters and hyphens (max 63 chars)." target_hostname
    
    echo -e "\n${COLOR_MUTED}--> ADMIN USER CONFIGURATION:"
    echo -e "    For security, root login is disabled. We will create a new administrator"
    echo -e "    user with sudo privileges to manage this server.${COLOR_RESET}"
    prompt_input "Enter username for the new sudo user" "linux" validate_username "Username must start with a lowercase letter or underscore, followed by lowercase alphanumeric/hyphen/underscore (max 32 chars)." target_username
    
    echo -e "\n${COLOR_MUTED}--> SSH PORT HARDENING:"
    echo -e "    Bots continuously scan port 22. Changing the port stops automated script attacks."
    echo -e "    Choose any port from 1 to 65535 (port 62 is set as default).${COLOR_RESET}"
    prompt_input "Enter custom SSH port number" "62" validate_ssh_port "Port must be an integer between 1 and 65535, excluding standard database ports." target_ssh_port
    
    echo -e "\n${COLOR_MUTED}--> CRYPTOGRAPHIC KEY AUTHENTICATION:"
    echo -e "    This secures access by requiring an SSH Key instead of a weak password."
    echo -e "    Paste the contents of your public key (e.g. starting with 'ssh-rsa' or 'ssh-ed25519')"
    echo -e "    or enter the absolute path to your public key file on this server.${COLOR_RESET}"
    prompt_input "Enter SSH public key string OR path to key file" "" validate_ssh_public_key "Invalid key string or key path. Ensure file exists or paste a valid public key (e.g. ssh-rsa ...)." target_ssh_key
    
    echo -e "\n${COLOR_MUTED}--> SWAP FILE (VIRTUAL MEMORY) CONFIGURATION:"
    echo -e "    Swap acts as backup memory when the VPS runs out of physical RAM."
    echo -e "    Setting this prevents application crashes due to Out-Of-Memory conditions.${COLOR_RESET}"
    prompt_input "Enter swap file size in GB (0 to disable)" "$default_swap" validate_swap_size "Please enter a valid integer between 0 and 64." target_swap_size
    
    # Summary
    echo -e "\nConfiguration Summary:"
    echo -e "  Hostname:   ${target_hostname}"
    echo -e "  Username:   ${target_username}"
    echo -e "  SSH Port:   ${target_ssh_port}"
    echo -e "  Swap Size:  ${target_swap_size} GB"
    echo -e "  SSH Key:    [Valid key or key path set]"
    echo -e "\nSetup logs will compile at: ${LOG_FILE}\n"
    
    echo -e "\n${COLOR_MUTED}--> START HARDENING INSTALLATION:"
    echo -e "    This will begin editing system configuration files, installing security tools,"
    echo -e "    setting up firewall rules, and applying kernel policies.${COLOR_RESET}"
    read -r -p "Begin VPS hardening now? (y/n): " confirm_setup
    if [[ ! "$confirm_setup" =~ ^[Yy]$ ]]; then
        echo "Installation aborted."
        exit 0
    fi
    
    log_info "Initializing VPS hardening..."
    
    # Run tasks
    setup_hostname "$target_hostname"
    setup_swap "$target_swap_size"
    install_packages
    configure_auto_updates
    configure_sysctl_hardening
    configure_shared_memory
    create_sudo_user "$target_username" "$target_ssh_key"
    configure_ssh_daemon "$target_username" "$target_ssh_port"
    configure_fail2ban "$target_ssh_port"
    configure_ufw "$target_ssh_port"
    start_aux_services
    
    log_success "All hardening configurations completed successfully."
    
    echo -e "\n${COLOR_WARNING}-------------------------------------------------------${COLOR_RESET}"
    echo -e "${COLOR_WARNING} IMPORTANT INSTRUCTIONS FOR YOUR NEXT CONNECTION:${COLOR_RESET}"
    echo -e "  1. Test your SSH connection in a NEW terminal window before closing this one!"
    echo -e "  2. Connection command: ssh -p ${target_ssh_port} ${target_username}@${target_hostname}"
    echo -e "${COLOR_WARNING}-------------------------------------------------------${COLOR_RESET}\n"
    
    echo -e "\n${COLOR_MUTED}--> REBOOT RECOMMENDED:"
    echo -e "    A system reboot is required to activate kernel security hardening modifications,"
    echo -e "    remount the secure /dev/shm partition, and load upgraded kernel modules.${COLOR_RESET}"
    read -r -p "Would you like to reboot the VPS now to apply all updates? (y/n) [n]: " confirm_reboot
    if [[ "$confirm_reboot" =~ ^[Yy]$ ]]; then
        log_info "Rebooting system now..."
        reboot
    else
        echo "Setup complete. Please reboot the VPS manually when convenient."
    fi
}

main
