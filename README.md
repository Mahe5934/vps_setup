# Automated VPS Security Hardening & Setup Wizard

A set of production-grade scripts designed to automatically secure, update, and harden a self-hosted VPS running Debian or Ubuntu.

This project rewrites and consolidates manual system hardening instructions into modular, idempotent, and validated Python and Bash scripts.

---

## 🔒 Key Security Features Implemented

* **SSH Daemon Hardening**: Configures custom SSH ports, disables root login and password authentication, restricts login to the newly created user (`AllowUsers`), and disables unused forwarding protocols.
* **Firewall Configuration (UFW)**: Reconfigures firewall policies to default-deny incoming, default-allow outgoing, opens web ports (HTTP/HTTPS), and configures rate-limiting (`ufw limit`) on the custom SSH port to prevent brute-force attempts.
* **Fail2ban Custom Jails**: Configures customized monitoring jails for the new SSH port using native UFW actions.
* **Kernel & Sysctl Security**: Hardens the Linux kernel against network attacks (spoofing, redirect ignores, SYN flooding countermeasures), enables ASLR, restricts core dumps for setuid binaries, and hardens the BPF JIT compiler.
* **Shared Memory Hardening**: Secures `/dev/shm` in `/etc/fstab` with `noexec,nosuid,nodev` flags to block runtime execution in shared memory.
* **Intrusion Detection**: Installs and sets up `rkhunter` (with properties baseline database updates), `chkrootkit`, and system auditing via `auditd`.
* **Time Synchronization**: Configures `chrony` NTP client to ensure reliable, auditable system log timestamps.
* **Idempotency & Safety**: Performs backups of all configurations prior to editing, checks root status, validates syntax using `sshd -t` before reloading SSH configuration, and runs verification checks to ensure you never get locked out.

---

## 📁 Repository Structure

```text
ProjectRoot/
│
├── tasks/
│   ├── todo.md          # Implementation checklist
│   ├── lessons.md       # Syntax lessons learned during development
│   └── review.md        # Hardening audit report
│
├── Vps_setup.py         # Secured Python Hardening Script (Interactive)
├── vps_setup.sh         # Secured Bash Hardening Script (Interactive)
└── README.md            # Project overview (this file)
```

---

## 🚀 Getting Started

Ensure you run these scripts as `root` or with `sudo` on a clean Debian/Ubuntu server. You can fetch and execute them directly from the remote repository using `curl` or `wget`.

### Option A: Python Script (Recommended)
The Python version includes robust validators for input strings and paths using Python's standard library. 

Download and run using **curl**:
```bash
curl -sSL https://raw.githubusercontent.com/Mahe5934/vps_setup/main/Vps_setup.py -o Vps_setup.py && sudo python3 Vps_setup.py
```
Or using **wget**:
```bash
wget -q https://raw.githubusercontent.com/Mahe5934/vps_setup/main/Vps_setup.py -O Vps_setup.py && sudo python3 Vps_setup.py
```

### Option B: Bash Script
The Bash version is written with strict safety flags (`set -euo pipefail`) and executes equivalent actions.

Download and run using **curl**:
```bash
curl -sSL https://raw.githubusercontent.com/Mahe5934/vps_setup/main/vps_setup.sh -o vps_setup.sh && chmod +x vps_setup.sh && sudo ./vps_setup.sh
```
Or using **wget**:
```bash
wget -q https://raw.githubusercontent.com/Mahe5934/vps_setup/main/vps_setup.sh -O vps_setup.sh && chmod +x vps_setup.sh && sudo ./vps_setup.sh
```

---

## 📝 Configuration Prompt Workflow

Upon running either script, the wizard interactively prompts for the following configurations (providing sensible defaults):
1. **Hostname**: The desired system hostname (e.g. `froniqo`).
2. **Sudo User**: The username of the new admin user.
3. **SSH Port**: The custom port for SSH daemon (e.g. `62`).
4. **SSH Public Key**: The raw public key string OR path to the public key file on the local machine.
5. **Swap Size**: Size in GB for memory swap (suggested default is based on actual system RAM).

---

## ⚠️ Important Connection Verification

1. **DO NOT CLOSE** your active terminal session where you ran the hardening script.
2. Open a **new, separate terminal** on your local machine.
3. Attempt to establish a test connection to verify that SSH key authentication and custom ports are functioning properly:
   ```bash
   ssh -p <custom_ssh_port> <username>@<your_vps_ip>
   ```
4. Once connection is verified successfully, you can safely close your initial terminal window.
5. All installation and execution steps are logged in `/var/log/vps_setup.log` for debugging purposes.
