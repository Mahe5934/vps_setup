#!/usr/bin/env python3
"""
VPS Security Hardening & Setup Script (Python Version)
Targets: Debian/Ubuntu
Runs interactively to configure a secure VPS environment.
"""

import os
import sys
import re
import subprocess
import shutil
from datetime import datetime

# ANSI Colors for Output
COLOR_RESET = "\033[0m"
COLOR_INFO = "\033[1;34m"      # Bold Blue
COLOR_SUCCESS = "\033[1;32m"   # Bold Green
COLOR_WARNING = "\033[1;33m"   # Bold Yellow
COLOR_ERROR = "\033[1;31m"     # Bold Red
COLOR_MUTED = "\033[0;37m"     # Gray

LOG_FILE = "/var/log/vps_setup.log"

def log_info(msg):
    print(f"{COLOR_INFO}[INFO]{COLOR_RESET} {msg}")
    append_log(f"[INFO] {msg}")

def log_success(msg):
    print(f"{COLOR_SUCCESS}[SUCCESS]{COLOR_RESET} {msg}")
    append_log(f"[SUCCESS] {msg}")

def log_warning(msg):
    print(f"{COLOR_WARNING}[WARNING]{COLOR_RESET} {msg}")
    append_log(f"[WARNING] {msg}")

def log_error(msg):
    print(f"{COLOR_ERROR}[ERROR]{COLOR_RESET} {msg}")
    append_log(f"[ERROR] {msg}")

def append_log(msg):
    timestamp = datetime.now().isoformat()
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {msg}\n")
    except Exception:
        pass

def run_cmd(cmd, check=True, shell=False, stdin_data=None):
    """Runs a shell command safely, logging outputs."""
    cmd_str = cmd if shell else " ".join(cmd)
    append_log(f"Running command: {cmd_str}")
    
    try:
        res = subprocess.run(
            cmd,
            shell=shell,
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=stdin_data,
            text=True
        )
        if res.stdout:
            append_log(f"stdout:\n{res.stdout}")
        if res.stderr:
            append_log(f"stderr:\n{res.stderr}")
        return res
    except subprocess.CalledProcessError as e:
        log_error(f"Command failed: {cmd_str}")
        log_error(f"Exit Code: {e.returncode}")
        log_error(f"Error Output:\n{e.stderr}")
        if check:
            sys.exit(1)
        return e

def check_root():
    if os.geteuid() != 0:
        log_error("This script must be run as root. Please use 'sudo python3 vps_setup.py'.")
        sys.exit(1)

def backup_file(filepath):
    if os.path.exists(filepath):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{filepath}.bak_{timestamp}"
        try:
            shutil.copy2(filepath, backup_path)
            log_info(f"Backed up {filepath} to {backup_path}")
            return backup_path
        except Exception as e:
            log_error(f"Failed to backup {filepath}: {e}")
            sys.exit(1)
    return None

# --- Interactive Prompts ---

def get_input(prompt_text, default=None, validator=None, error_msg=None):
    while True:
        display = f"{prompt_text} [{default}]: " if default else f"{prompt_text}: "
        val = input(display).strip()
        if not val and default:
            return default
        if not val:
            print(f"{COLOR_WARNING}Input cannot be empty.{COLOR_RESET}")
            continue
        if validator:
            if validator(val):
                return val
            else:
                print(f"{COLOR_ERROR}{error_msg or 'Invalid input. Please try again.'}{COLOR_RESET}")
        else:
            return val

def validate_username(username):
    # Username regex: lowercase letters, numbers, hyphens, underscores. Starts with letter/underscore. Max 32 chars.
    return re.match(r"^[a-z_][a-z0-9_-]{0,31}$", username) is not None

def validate_ssh_port(port_str):
    try:
        port = int(port_str)
        # Ports 1-65535, excluding known server ports to avoid conflict
        banned_ports = [1433, 1521, 3306, 5432, 6379, 8080, 27017]
        return 1 <= port <= 65535 and port not in banned_ports
    except ValueError:
        return False

def validate_ssh_public_key(key_input):
    # If it is a file path, check if it exists
    if os.path.exists(os.path.expanduser(key_input)):
        try:
            with open(os.path.expanduser(key_input), "r") as f:
                content = f.read().strip()
            return validate_key_string(content)
        except Exception:
            return False
    return validate_key_string(key_input)

def validate_key_string(key_str):
    valid_prefixes = (
        "ssh-rsa", "ssh-dss", "ssh-ed25519", "ssh-xmss",
        "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"
    )
    parts = key_str.strip().split()
    return len(parts) >= 2 and parts[0] in valid_prefixes

def validate_swap_size(size_str):
    try:
        size = int(size_str)
        return 0 <= size <= 64 # Reasonable range of 0 to 64 GB
    except ValueError:
        return False

def validate_hostname(hostname):
    return re.match(r"^[a-zA-Z0-9-]{1,63}$", hostname) is not None

# --- Configuration Operations ---

def update_sysctl(params):
    """Updates /etc/sysctl.conf configuration in a safe, idempotent manner."""
    filepath = "/etc/sysctl.conf"
    backup_file(filepath)
    
    with open(filepath, "r") as f:
        content = f.read()
        
    lines = content.splitlines()
    updated_lines = []
    
    # Track which parameters we have configured
    processed = set()
    
    for line in lines:
        line_stripped = line.strip()
        # Check if line is setting a parameter we care about
        matched = False
        for param, val in params.items():
            # Matches "param = val" or "#param = val"
            if re.match(rf"^\s*#?\s*{re.escape(param)}\s*=", line_stripped):
                updated_lines.append(f"{param} = {val}")
                processed.add(param)
                matched = True
                break
        if not matched:
            updated_lines.append(line)
            
    # Append any parameters not present in the original file
    for param, val in params.items():
        if param not in processed:
            updated_lines.append(f"{param} = {val}")
            
    with open(filepath, "w") as f:
        f.write("\n".join(updated_lines) + "\n")
        
    log_info("Applying sysctl changes...")
    run_cmd(["sysctl", "-p"])

def update_sshd_config(settings):
    """Updates sshd config file securely and validates configuration before reload."""
    filepath = "/etc/ssh/sshd_config"
    backup_file(filepath)
    
    with open(filepath, "r") as f:
        lines = f.read().splitlines()
        
    updated_lines = []
    processed = set()
    
    # We must be careful about Subsystem lines or Port lines.
    # To handle directives correctly, we replace matching lines
    for line in lines:
        line_stripped = line.strip()
        matched = False
        for key, val in settings.items():
            # Match commented out or existing key (e.g. "#PasswordAuthentication yes")
            # We match word boundaries to prevent matching "PasswordAuthentication" inside another setting
            if re.match(rf"^\s*#?\s*{re.escape(key)}\b", line_stripped):
                updated_lines.append(f"{key} {val}")
                processed.add(key)
                matched = True
                break
        if not matched:
            updated_lines.append(line)
            
    for key, val in settings.items():
        if key not in processed:
            updated_lines.append(f"{key} {val}")
            
    # Write to a temporary config file first to validate syntax
    temp_config = "/etc/ssh/sshd_config.tmp"
    with open(temp_config, "w") as f:
        f.write("\n".join(updated_lines) + "\n")
        
    # Run sshd -t on the temp configuration
    res = subprocess.run(["sshd", "-t", "-f", temp_config], capture_output=True, text=True)
    if res.returncode != 0:
        log_error("Invalid SSH configuration generated. Restoring original sshd_config.")
        log_error(res.stderr)
        if os.path.exists(temp_config):
            os.remove(temp_config)
        sys.exit(1)
    else:
        # Move temp to active sshd_config
        shutil.move(temp_config, filepath)
        os.chmod(filepath, 0o600)
        log_success("SSH Configuration validated successfully.")

# --- Execution Steps ---

def setup_hostname(hostname):
    log_info(f"Setting hostname to '{hostname}'...")
    run_cmd(["hostnamectl", "set-hostname", hostname])
    
    # Safely update /etc/hosts
    hosts_path = "/etc/hosts"
    backup_file(hosts_path)
    with open(hosts_path, "r") as f:
        lines = f.read().splitlines()
        
    hostname_mapped = False
    for i, line in enumerate(lines):
        if line.strip().startswith("127.0.1.1"):
            # Update the existing line
            parts = line.split()
            # If our hostname isn't in it, add it
            if hostname not in parts[1:]:
                lines[i] = f"127.0.1.1\t{hostname} " + " ".join(parts[1:])
            hostname_mapped = True
            break
            
    if not hostname_mapped:
        lines.append(f"127.0.1.1\t{hostname}")
        
    with open(hosts_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    log_success("Hostname configured.")

def setup_swap(swap_size_gb):
    if swap_size_gb == 0:
        log_info("Skipping swap file creation as requested (size 0).")
        return
        
    swap_path = "/swapfile"
    if os.path.exists(swap_path):
        log_warning(f"{swap_path} already exists. Skipping swap creation.")
        return
        
    log_info(f"Creating {swap_size_gb}GB swap file...")
    # Use dd for maximum reliability across filesystems (fallocate may fail on btrfs/f2fs)
    run_cmd(["dd", "if=/dev/zero", f"of={swap_path}", "bs=1M", f"count={swap_size_gb * 1024}"], check=True)
    
    log_info("Setting swap permissions...")
    os.chmod(swap_path, 0o600)
    run_cmd(["mkswap", swap_path])
    run_cmd(["swapon", swap_path])
    
    # Make swap permanent in /etc/fstab
    fstab_path = "/etc/fstab"
    backup_file(fstab_path)
    with open(fstab_path, "r") as f:
        fstab_content = f.read()
        
    if swap_path not in fstab_content:
        log_info("Adding swap file to /etc/fstab...")
        with open(fstab_path, "a") as f:
            f.write(f"\n{swap_path} none swap sw 0 0\n")
            
    log_success("Swap space set up successfully.")

def install_packages():
    log_info("Updating package indices...")
    run_cmd(["apt-get", "update"])
    
    log_info("Upgrading existing packages (this may take a few minutes)...")
    # Set DEBIAN_FRONTEND=noninteractive to prevent blocking prompts
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    subprocess.run(["apt-get", "upgrade", "-y", "-o", "Dpkg::Options::=--force-confold"], env=env, check=True)
    
    log_info("Installing required security and system packages...")
    packages = [
        "nginx", "certbot", "python3-certbot-nginx", "ufw", "fail2ban", 
        "unattended-upgrades", "rkhunter", "chkrootkit", "auditd", "chrony"
    ]
    run_cmd(["apt-get", "install", "-y"] + packages)
    log_success("All packages installed successfully.")

def configure_auto_updates():
    log_info("Configuring unattended-upgrades (Automatic Security Updates)...")
    
    # Reconfigure non-interactively
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    run_cmd(["dpkg-reconfigure", "-plow", "unattended-upgrades"], env=env)
    
    # Enforce basic updates
    auto_upgrades_path = "/etc/apt/apt.conf.d/20auto-upgrades"
    auto_upgrades_content = (
        'APT::Periodic::Update-Package-Lists "1";\n'
        'APT::Periodic::Unattended-Upgrade "1";\n'
        'APT::Periodic::AutocleanInterval "7";\n'
    )
    with open(auto_upgrades_path, "w") as f:
        f.write(auto_upgrades_content)
        
    log_success("Automatic security updates enabled.")

def configure_sysctl_hardening():
    log_info("Applying sysctl kernel security hardening configurations...")
    params = {
        # IP Spoofing protection
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.conf.default.rp_filter": "1",
        # Ignore ICMP redirects
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv6.conf.all.accept_redirects": "0",
        # Ignore send redirects
        "net.ipv4.conf.all.send_redirects": "0",
        # Disable source packet routing
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv6.conf.all.accept_source_route": "0",
        # Log Martians
        "net.ipv4.conf.all.log_martians": "1",
        # Ignore ICMP ping requests (Optional, but increases obscurity)
        "net.ipv4.icmp_echo_ignore_all": "1",
        # Enable TCP SYN Cookie Protection (anti-DOS)
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv4.tcp_max_syn_backlog": "2048",
        "net.ipv4.tcp_synack_retries": "2",
        "net.ipv4.tcp_syn_retries": "5",
        
        # --- Advanced Hardening ---
        "kernel.randomize_va_space": "2",  # ASLR enabled
        "fs.suid_dumpable": "0",            # Disable setuid core dumps
        "net.core.bpf_jit_harden": "2"     # JIT hardening
    }
    update_sysctl(params)
    log_success("Kernel parameters hardened.")

def configure_shared_memory():
    log_info("Hardening shared memory /dev/shm...")
    fstab_path = "/etc/fstab"
    backup_file(fstab_path)
    
    with open(fstab_path, "r") as f:
        lines = f.read().splitlines()
        
    shm_exists = False
    updated_lines = []
    
    for line in lines:
        if re.search(r"\s+/dev/shm\s+", line):
            # Replace existing shm line with secure mount options
            updated_lines.append("tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0")
            shm_exists = True
        else:
            updated_lines.append(line)
            
    if not shm_exists:
        updated_lines.append("tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0")
        
    with open(fstab_path, "w") as f:
        f.write("\n".join(updated_lines) + "\n")
        
    # Remount /dev/shm to apply changes instantly
    try:
        run_cmd(["mount", "-o", "remount", "/dev/shm"], check=False)
        log_success("Shared memory hardened.")
    except Exception as e:
        log_warning(f"Could not remount /dev/shm immediately (requires reboot): {e}")

def create_sudo_user(username, ssh_key_input):
    log_info(f"Checking if user '{username}' exists...")
    res = subprocess.run(["id", username], capture_output=True)
    if res.returncode == 0:
        log_warning(f"User '{username}' already exists. Skipping user creation.")
    else:
        log_info(f"Creating user '{username}'...")
        # Create user with a locked password (only public key login allowed)
        run_cmd(["useradd", "-m", "-s", "/bin/bash", "-G", "sudo", username])
        # Lock user password to disable password login entirely for this account
        run_cmd(["passwd", "-l", username])
        log_success(f"User '{username}' created and added to sudo group.")
        
    # Determine the actual key string (in case a path was provided)
    key_str = ssh_key_input
    if os.path.exists(os.path.expanduser(ssh_key_input)):
        with open(os.path.expanduser(ssh_key_input), "r") as f:
            key_str = f.read().strip()
            
    # Setup SSH folder for user
    user_home = os.path.expanduser(f"~{username}")
    ssh_dir = os.path.join(user_home, ".ssh")
    auth_keys_path = os.path.join(ssh_dir, "authorized_keys")
    
    if not os.path.exists(ssh_dir):
        os.makedirs(ssh_dir, mode=0o700)
        
    with open(auth_keys_path, "w") as f:
        f.write(key_str + "\n")
        
    os.chmod(auth_keys_path, 0o600)
    
    # Resolve UID and GID for ownership assignment
    import pwd
    user_info = pwd.getpwnam(username)
    uid, gid = user_info.pw_uid, user_info.pw_gid
    
    os.chown(ssh_dir, uid, gid)
    os.chown(auth_keys_path, uid, gid)
    log_success(f"SSH authorized keys provisioned for user '{username}'.")
    
    # Configure passwordless sudo for convenience & safe setup verification
    sudoers_d_file = f"/etc/sudoers.d/{username}"
    if not os.path.exists(sudoers_d_file):
        with open(sudoers_d_file, "w") as f:
            f.write(f"{username} ALL=(ALL) NOPASSWD:ALL\n")
        os.chmod(sudoers_d_file, 0o440)
        log_info(f"Passwordless sudo configured for '{username}' in /etc/sudoers.d/")

def configure_ssh_daemon(username, ssh_port):
    log_info("Hardening SSH Daemon config...")
    
    ssh_settings = {
        "Port": str(ssh_port),
        "PasswordAuthentication": "no",
        "PermitRootLogin": "no",
        "PermitEmptyPasswords": "no",
        "MaxAuthTries": "3",
        "X11Forwarding": "no",
        "LoginGraceTime": "30",
        "AllowUsers": username,
        "AllowAgentForwarding": "no",
        "AllowTcpForwarding": "no"
    }
    
    update_sshd_config(ssh_settings)
    
    log_info("Restarting SSH service...")
    run_cmd(["systemctl", "restart", "ssh"])
    log_success("SSH Daemon has been secured and restarted.")

def configure_fail2ban(ssh_port):
    log_info("Configuring Fail2ban...")
    local_jail_path = "/etc/fail2ban/jail.local"
    
    # Backup fail2ban configuration
    if os.path.exists(local_jail_path):
        backup_file(local_jail_path)
    else:
        # Create a fresh jail.local from jail.conf if it does not exist
        if os.path.exists("/etc/fail2ban/jail.conf"):
            shutil.copy2("/etc/fail2ban/jail.conf", local_jail_path)
            
    # Read jail.local
    with open(local_jail_path, "r") as f:
        content = f.read()
        
    # We will inject/update the [sshd] configuration
    jail_sshd_block = (
        "\n[sshd]\n"
        "enabled = true\n"
        f"port = {ssh_port}\n"
        "banaction = ufw\n"
        "filter = sshd\n"
        "logpath = /var/log/auth.log\n"
        "maxretry = 3\n"
        "bantime = 3600\n"
        "findtime = 600\n"
    )
    
    # Clean up any existing [sshd] block or append
    if "[sshd]" in content:
        # To prevent nested/duplicated configurations, we strip the old block
        content = re.sub(r"\[sshd\].*?(?=\n\[\w+\]|$)", "", content, flags=re.DOTALL)
        
    content += jail_sshd_block
    
    with open(local_jail_path, "w") as f:
        f.write(content)
        
    run_cmd(["systemctl", "enable", "fail2ban"])
    run_cmd(["systemctl", "restart", "fail2ban"])
    log_success("Fail2ban configured to watch SSH on custom port and restarted.")

def configure_ufw(ssh_port):
    log_info("Configuring UFW Firewall...")
    
    # Set default policies
    run_cmd(["ufw", "default", "deny", "incoming"])
    run_cmd(["ufw", "default", "allow", "outgoing"])
    
    # Allow web traffic
    run_cmd(["ufw", "allow", "80/tcp"])
    run_cmd(["ufw", "allow", "443/tcp"])
    
    # Allow custom SSH port with rate-limiting
    log_info(f"Adding firewall rule: Rate-limit custom SSH port {ssh_port}...")
    run_cmd(["ufw", "limit", f"{ssh_port}/tcp"])
    
    # CRITICAL: Verify UFW will allow the custom SSH port
    res = run_cmd(["ufw", "status", "numbered"], check=False)
    if str(ssh_port) not in res.stdout:
        # Double check rules list manually
        log_warning(f"Verification warning: SSH Port {ssh_port} was not found explicitly in UFW status output. Re-applying rule...")
        run_cmd(["ufw", "allow", f"{ssh_port}/tcp"])
        
    # Enable firewall
    log_info("Enabling UFW firewall...")
    run_cmd(["ufw", "--force", "enable"])
    
    # Display final firewall status
    status_res = run_cmd(["ufw", "status", "verbose"])
    print(status_res.stdout)
    log_success("Firewall configured and activated.")

def start_aux_services():
    log_info("Configuring system security services (Chrony & Auditd)...")
    run_cmd(["systemctl", "enable", "chrony"])
    run_cmd(["systemctl", "start", "chrony"])
    
    run_cmd(["systemctl", "enable", "auditd"])
    run_cmd(["systemctl", "start", "auditd"])
    
    log_info("Running quick check with chkrootkit...")
    run_cmd(["chkrootkit"], check=False)
    
    # Setup rkhunter baseline data
    log_info("Updating rkhunter file property database...")
    run_cmd(["rkhunter", "--propupd"], check=False)
    
    log_success("Chrony, Auditd, and intrusion detection baselines configured.")

# --- Main Flow ---

def main():
    check_root()
    
    print(f"\n{COLOR_SUCCESS}==============================================={COLOR_RESET}")
    print(f"{COLOR_SUCCESS}   VPS SECURITY HARDENING & SETUP WIZARD       {COLOR_RESET}")
    print(f"{COLOR_SUCCESS}==============================================={COLOR_RESET}\n")
    
    # Setup default swap size (based on RAM)
    try:
        with open("/proc/meminfo", "r") as f:
            mem_line = f.readline()
        mem_kb = int(re.search(r"\d+", mem_line).group())
        default_swap = max(2, round(mem_kb / (1024 * 1024)))
    except Exception:
        default_swap = 4
        
    # 1. Gather configuration details interactively
    print(f"\n{COLOR_MUTED}--> HOSTNAME CONFIGURATION:")
    print("    This identifies your VPS on the network and in your command line prompt.")
    print(f"    Can contain letters, numbers, and hyphens (max 63 chars).{COLOR_RESET}")
    hostname = get_input(
        "Enter new server hostname",
        default="froniqo",
        validator=validate_hostname,
        error_msg="Hostname must contain only letters, numbers, and hyphens (max 63 chars)."
    )
    
    print(f"\n{COLOR_MUTED}--> ADMIN USER CONFIGURATION:")
    print("    For security, root login is disabled. We will create a new administrator")
    print(f"    user with sudo privileges to manage this server.{COLOR_RESET}")
    username = get_input(
        "Enter username for the new sudo user",
        default="linux",
        validator=validate_username,
        error_msg="Username must start with a lowercase letter or underscore, followed by lowercase alphanumeric/hyphen/underscore (max 32 chars)."
    )
    
    print(f"\n{COLOR_MUTED}--> SSH PORT HARDENING:")
    print("    Bots continuously scan port 22. Changing the port stops automated script attacks.")
    print(f"    Choose any port from 1 to 65535 (port 62 is set as default).{COLOR_RESET}")
    ssh_port_str = get_input(
        "Enter custom SSH port number",
        default="62",
        validator=validate_ssh_port,
        error_msg="Port must be an integer between 1 and 65535, excluding standard database ports."
    )
    ssh_port = int(ssh_port_str)
    
    print(f"\n{COLOR_MUTED}--> CRYPTOGRAPHIC KEY AUTHENTICATION:")
    print("    This secures access by requiring an SSH Key instead of a weak password.")
    print("    Paste the contents of your public key (e.g. starting with 'ssh-rsa' or 'ssh-ed25519')")
    print(f"    or enter the absolute path to your public key file on this server.{COLOR_RESET}")
    ssh_key_input = get_input(
        "Enter SSH public key string OR path to key file (e.g. ~/.ssh/id_rsa.pub)",
        validator=validate_ssh_public_key,
        error_msg="Invalid SSH key string or file path. Ensure the file exists or paste a valid public key (e.g. ssh-rsa ...)."
    )
    
    print(f"\n{COLOR_MUTED}--> SWAP FILE (VIRTUAL MEMORY) CONFIGURATION:")
    print("    Swap acts as backup memory when the VPS runs out of physical RAM.")
    print(f"    Setting this prevents application crashes due to Out-Of-Memory conditions.{COLOR_RESET}")
    swap_size_str = get_input(
        "Enter swap file size in GB (0 to disable)",
        default=str(default_swap),
        validator=validate_swap_size,
        error_msg="Please enter a valid integer between 0 and 64."
    )
    swap_size_gb = int(swap_size_str)
    
    # Double check before starting execution
    print("\nConfiguration Summary:")
    print(f"  Hostname:   {hostname}")
    print(f"  Username:   {username}")
    print(f"  SSH Port:   {ssh_port}")
    print(f"  Swap Size:  {swap_size_gb} GB")
    print(f"  SSH Key:    [Valid public key or key file provided]")
    print(f"\nLog file will be saved at: {LOG_FILE}\n")
    
    print(f"\n{COLOR_MUTED}--> START HARDENING INSTALLATION:")
    print("    This will begin editing system configuration files, installing security tools,")
    print(f"    setting up firewall rules, and applying kernel policies.{COLOR_RESET}")
    confirm = input("Begin VPS hardening now? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Installation aborted by user.")
        sys.exit(0)
        
    log_info("Starting VPS security setup...")
    
    # 2. Run execution steps
    setup_hostname(hostname)
    setup_swap(swap_size_gb)
    install_packages()
    configure_auto_updates()
    configure_sysctl_hardening()
    configure_shared_memory()
    create_sudo_user(username, ssh_key_input)
    configure_ssh_daemon(username, ssh_port)
    configure_fail2ban(ssh_port)
    configure_ufw(ssh_port)
    start_aux_services()
    
    log_success("VPS security hardening steps completed successfully!")
    print(f"\n{COLOR_WARNING}-------------------------------------------------------{COLOR_RESET}")
    print(f"{COLOR_WARNING} IMPORTANT INSTRUCTIONS FOR YOUR NEXT CONNECTION:{COLOR_RESET}")
    print(f"  1. Test your SSH connection in a NEW terminal window before closing this one!")
    print(f"  2. Connection command: ssh -p {ssh_port} {username}@{hostname or '<your_vps_ip>'}")
    print(f"{COLOR_WARNING}-------------------------------------------------------{COLOR_RESET}\n")
    
    print(f"\n{COLOR_MUTED}--> REBOOT RECOMMENDED:")
    print("    A system reboot is required to activate kernel security hardening modifications,")
    print(f"    remount the secure /dev/shm partition, and load upgraded kernel modules.{COLOR_RESET}")
    reboot_choice = input("Would you like to reboot the VPS now to apply all updates? (y/n) [n]: ").strip().lower()
    if reboot_choice == 'y':
        log_info("Rebooting system now...")
        run_cmd(["reboot"])
    else:
        print("Setup complete. Please reboot the VPS manually when ready.")

if __name__ == "__main__":
    main()