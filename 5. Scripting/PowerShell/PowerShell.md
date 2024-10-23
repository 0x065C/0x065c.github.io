# Summary
PowerShell is a task automation framework developed by Microsoft, consisting of a command-line shell and an associated scripting language built on the .NET framework. PowerShell is designed to automate system administration tasks, such as batch processing and configuration management, making it a powerful tool for both administrators and attackers.

# Default PowerShell Locations
PowerShell is available in different directories depending on the Windows architecture:
- `C:\windows\syswow64\windowspowershell\v1.0\powershell`
- `C:\Windows\System32\WindowsPowerShell\v1.0\powershell`

# PowerShell Syntax Structure
PowerShell syntax is designed to be consistent and easy to understand, with a focus on readability. 

**General syntax structure of a PowerShell command is:**

```powershell
Verb-Noun -ParameterName <Value> -ParameterName <Value>
```

**Example:**

```powershell
Get-Process -Name "notepad"
```

This command retrieves all instances of the `notepad` process running on the system.

#### Key Elements of PowerShell Syntax

- **Cmdlets:** The core commands in PowerShell, which follow the Verb-Noun convention.
- **Parameters:** Cmdlets often accept parameters, which modify their behavior or specify input. Parameters are usually preceded by a dash (e.g., `-Name`).
- **Pipelines (`|`):** The pipeline operator passes the output of one cmdlet as input to another, allowing for complex command chaining.
- **Variables (`$`):** Variables in PowerShell are denoted by the `$` symbol. For example, `$variable = "value"` stores the string `"value"` in `$variable`.
- **Loops and Conditionals:** PowerShell supports standard programming constructs like loops (`for`, `foreach`, `while`) and conditionals (`if`, `else`, `switch`).
- **Comments:** Comments in PowerShell begin with `#` and are used to annotate scripts.

# Commands and Usage

## Basic PowerShell Cmdlets
Start by familiarizing yourself with basic PowerShell commands:

#### Get-Help
- `Get-Help` Invoking this command with the name of a command as an argument displays a help page describing various parts of a command.
- `Get-Help *`: List everything loaded
- `Get-Help process`: List everything containing "process"
- `Get-Help Get-Item -Full`: Get full help about a topic
- `Get-Help Get-Item -Examples`: List examples

#### Get-Verb
- `Get-Verb`: Running this command returns a list of verbs that most commands adhere to. The response includes a description of what these verbs do. Since most commands follow this naming convention, it sets expectations on what a command does. This helps you select the appropriate command and what to name a command, should you be creating one.

#### Get-Command
- `Get-Command`: This command retrieves a list of all commands installed on your machine.
- `Get-Command -Verb 'Get'`: Filter on a verb.
- `Get-Command -Noun U*`: Filter on a noun.
- `Get-Command -Verb Get -Noun U*`: Combine parameters.
- `Get-Command -Module <modulename>`: List commands from a specific module


## Data Manipulation

#### Get-Member
- `Get-Member`: It operates on object based output and is able to discover what object, properties and methods are available for a command.
- `<PowerShell_Command> | Get-Member`: Displays all available properties of an object.

#### Data Parsing
- `Get-Process | Select-Object -Property Name, Id`: Selects specific properties of an object or set of objects.
- `Get-Process | Sort-Object -Property CPU -Descending`: Sorts objects by property values.
- `Get-Process | Where-Object -Property CPU -GT 100`: Filters objects based on specified criteria.
- `Get-Process | ForEach-Object { $_.Kill() }`: Performs an operation on each item in a collection.

### Output Formating
- `Get-Process | Format-List`: Displays data and objects in list format
- `Get-Process | Format-List -Property *`: Displays all available properties of an object.
- `Get-Process | Format-Table`: Displays data and objects in table format
- `Get-Process | Format-Table -Property *`: Displays all available properties of an object.

#### Out-File
- `Get-Process | Out-File -FilePath "C:\temp\processes.txt"`: Sends output to a file.
- `Get-Process | Out-File -FilePath "C:\temp\processes.txt" -Append`: Appends output to a file.
- `Get-Process | Out-File -FilePath "C:\temp\processes.txt" -NoClobber`: Prevent an existing file from being overwritten.
- `Get-Process | Out-File -FilePath "C:\temp\processes" -Width <number>`: Specifies the maximum number of characters in each line of output. Any additional characters are truncated, not wrapped. Default is 80 characters.
- `Get-Process | Out-GridView`: Sends output to an interactive table in a separate window.

#### Credentials
- `-UseDefaultCredentials`: Use current session credentials
- `-Credential (Get-Credential)`:  Prompt user to input credentials.

#### Execution Policy
- `-ExecutionPolicy Bypass`:
- `Set-ExecutionPolicy RemoteSigned`: Changes the user preference for the PowerShell script execution policy.

## System and Process Management

#### General System Information
- `Get-ComputerInfo`: Full system info (OS version, hostname, architecture).
- `systeminfo`: OS info, uptime, hotfixes.
- `Get-WmiObject -Class Win32_OperatingSystem`: Detailed OS and boot time info.
- `Get-WmiObject -Class Win32_BIOS`: BIOS version and serial number.
- `Get-WmiObject -Class Win32_ComputerSystem`: System manufacturer, model, and domain.
- `Get-WmiObject -Class Win32_Processor`: CPU details (cores, clock speed).
- `Get-WmiObject -Class Win32_PhysicalMemory`: RAM capacity and speed.
- `Get-HotFix`: Lists installed updates (hotfixes).

#### Performance Information
- `Get-WmiObject -Class Win32_PerfFormattedData_PerfOS_Processor`: CPU usage per core.
- `Get-WmiObject -Class Win32_PerfFormattedData_PerfOS_Memory`: Memory usage metrics.
- `Get-WmiObject -Class Win32_PerfFormattedData_PerfDisk_PhysicalDisk`: Disk usage metrics (read/write speeds).

#### Boot and Time Information
- `Get-WmiObject -Class Win32_OperatingSystem | Select-Object LastBootUpTime`: Last boot time.
- `Get-Date`: Displays the current system date and time.
- `Get-WinEvent -FilterHashtable @{logname='System'; id=6005} | select timecreated`: Last boot and shutdown time.

## User and Group Information

#### Current and Logged-In Users
- `whoami`: Current user and domain.
- `query user`: Displays currently logged-in users.
- `qwinsta`: Lists active sessions and users.

#### User Accounts
- `Get-LocalUser`: Lists all local users.
- `Get-WmiObject -Class Win32_UserAccount`: Detailed user account info (status, expiration).

#### Group Memberships
- `Get-LocalGroup`: Lists all local groups.
- `Get-LocalGroupMember <GroupName>`: Lists members of a specific group.
- `net localgroup administrators`: Lists members of the Administrators group.
- `whoami /priv`: Displays the privileges of the current user.

## Network Information

#### Network Interfaces and Configuration
- `Get-NetIPConfiguration`: Detailed network adapter info, including IP addresses, DNS servers, gateways.
- `Get-NetIPAddress`: Lists IP addresses for all network interfaces.
- `ipconfig`: Displays IP configuration, including IPv4 and IPv6.
- `Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Select-Object MACAddress, IPAddress, DefaultIPGateway`: Lists MAC, IP, and Gateway details for network interfaces.

#### Active Connections and Listening Ports
- `netstat -ano`: Displays active connections, listening ports, and associated PIDs.
- `Get-NetTCPConnection`: Lists active TCP connections.
- `Get-NetUDPEndpoint`: Lists active UDP connections.
- `Test-NetConnection -ComputerName <hostname> -Port <port>`: Tests connectivity to a remote host and port.

#### ARP, Routing, and DNS Information
- `Get-NetNeighbor`: Displays ARP table.
- `Get-NetRoute`: Displays the current routing table.
- `Get-DnsClientServerAddress`: Lists DNS servers configured on the system.
 -`Get-Content C:\Windows\System32\drivers\etc\hosts`: Display the hosts file contents

#### Firewall and Network Shares
- `Get-NetFirewallProfile`: Lists firewall profiles and their statuses.
- `Get-NetFirewallRule`: Displays configured firewall rules.
- `Get-NetFirewallRule -Enabled True`: Get enabled firewall rules.
- `net use`: Lists network shares and mapped drives.
- `Get-SmbShare`: Lists SMB shares hosted on the system.
- `Get-SmbMapping`: Lists current SMB share mappings.

#### Wireless Network Information
- `netsh wlan show profiles`: Lists all saved wireless network profiles.
- `netsh wlan show profile name=<SSID> key=clear`: Shows details (including the cleartext key) for a specific wireless profile.

#### Remote Commands
- `Invoke-Command -ComputerName <target_ip> -ScriptBlock { Get-Process }`: Runs commands on local and remote computers.
- `Invoke-WebRequest -Uri "https://www.example.com"`: Sends an HTTP or HTTPS request to a web page or web service.
- `Invoke-RestMethod -Uri "https://api.example.com/data"`: Sends an HTTP or HTTPS request to a RESTful web service and retrieves the response.

## Process and Service Information

#### Process Enumeration
- `Get-Process`: Lists all running processes.
- `Get-Process -PID <PID_Number>`: Displays information on a specific process.
- `Get-Process | Sort-Object CPU -Descending`: Lists processes by CPU usage.
- `Start-Process -FilePath "notepad.exe"`: Starts one or more processes.
- `Stop-Process -Name "notepad"`: Stops one or more running processes.
- `Get-WmiObject -Class Win32_Process`: Retrieves process details, including parent processes and command line arguments.

#### Service Enumeration
- `Get-Service`: Lists all services and their current statuses.
- `Get-Service -Name <Service_Name>`: Displays information on a specific service.
- `Start-Service -Name "wuauserv"`: Starts a service on a system.
- `Stop-Service -Name "wuauserv"`: Stops a running service.
- `Restart-Service -Name "wuauserv"`: Restarts a service.
- `Get-WmiObject -Class Win32_Service`: Displays detailed service information, including startup type.
- `Get-Service | Where-Object { $_.Status -eq 'Running' }`: Lists all running services.

#### Environment Variables
- `Get-ChildItem Env:`: Lists all environment variables.
- `$env:<variable_name>`: Retrieves a specific environment variable value.

## Scheduled Tasks

#### Scheduled Task Enumeration
- `Get-ScheduledTask`: Lists all scheduled tasks.
- `Get-ScheduledTask -TaskName <Task_Name>`: Displays information on a specific scheduled task.
- `New-ScheduledTask -Action (New-ScheduledTaskAction -Execute "notepad.exe") -Trigger (New-ScheduledTaskTrigger -At 9AM -Daily) -TaskName "Open Notepad"`: Creates a new scheduled task on the local computer.
- `Register-ScheduledTask -TaskName "Open Notepad" -InputObject $task`: Registers a new scheduled task on the local computer.
- `schtasks /query /fo LIST /v`: Displays detailed information about scheduled tasks.
- `Get-ScheduledTask | Select-Object TaskName, State, LastRunTime, NextRunTime`: Summarizes tasks with their statuses and run times.

## Installed Software

#### Installed Programs
- `Get-WmiObject -Class Win32_Product`: Lists installed programs.
- `Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*`: Queries installed software from the registry.
- `Get-Package`: Lists installed packages (via PowerShell modules like Chocolatey).

#### Installed Drivers
- `Get-WmiObject -Class Win32_PnPSignedDriver`: Displays installed drivers and their statuses.
- `Get-WindowsDriver -Online`: Lists installed drivers for the current session.

## File System Enumeration

#### Files
- `New-Item -Path "C:\temp\newfile.txt" -ItemType "file"`:  Creates a new item (e.g., file, directory) in a container.
- `Remove-Item -Path "C:\temp\newfile.txt"`: Deletes files or directories.
- `Copy-Item -Path "C:\temp\file.txt" -Destination "C:\backup\file.txt"`: Copies an item from one location to another.
- `Move-Item -Path "C:\temp\file.txt" -Destination "C:\backup\file.txt"`: Moves an item from one location to another.
- `Rename-Item -Path "C:\temp\file.txt" -NewName "newfile.txt"`: Renames an existing item.
- `Get-Content -Path "C:\temp\file.txt"`: Retrieves the contents of a file.
- `Set-Content -Path "C:\temp\file.txt" -Value "New content"`: Writes or replaces the content of a file.
- `Add-Content -Path "C:\temp\file.txt" -Value "Additional content"`: Appends content to the end of a file.

#### Directory and File Listings
- `Get-ChildItem -Path "C:\temp"`: Retrieves the items in a specified location, such as files and directories.
- `Get-ChildItem -Path C:\ -Recurse`: Recursively lists all files and directories on C: drive.
- `Get-ChildItem -Path C:\ -Hidden -Recurse`: Lists hidden files and directories.
- `Get-ChildItem -Path C:\ -Filter *.log -Recurse`: Searches for all `.log` files.

#### Drives
- `New-PSDrive -Name "Z" -PSProvider FileSystem -Root "\\server\share"`: Creates a new drive that is mapped to a specified location.
- `Remove-PSDrive -Name "Z"`: Removes a PowerShell drive that was created with `New-PSDrive`.

#### File Permissions and Ownership
- `icacls C:\path\to\directory`: Displays permissions for a directory.
- `Get-Acl -Path C:\path\to\file`: Shows ACL (Access Control List) details for a file.
  
#### Search for Specific Files
- `Get-ChildItem -Path C:\ -Recurse -Filter "*password*"`: Searches for files with "password" in the filename.
- `Select-String -Path "C:\path\*.txt" -Pattern "<keyword>" -Recurse`: Searches for a keyword inside text files.

## Security and Privilege Escalation

#### User Privileges and Security Policies
- `whoami /priv`: Lists current user privileges.
- `net accounts`: Displays password and lockout policies.
- `secedit /export /cfg C:\policies.txt`: Exports local security policies for review.

#### Registry Keys and Persistence
- `Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`: Lists programs set to run at user login.
- `Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`: Lists programs set to run at system startup.
- `reg query HKLM\SYSTEM\CurrentControlSet\Services`: Lists services configured via the registry.

## Logging and Event Information

#### Event Logs
- `Get-WinEvent -LogName "Application" -MaxEvents 10`: Displays the last 10 events from the Application log.
- `Get-EventSubscriber`: Gets the event subscribers in the current session.
- `Get-EventLog -LogName "Security" -Newest 5`: Lists the last 5 entries from the Security log.
- `Get-EventLog -LogName "System" -EntryType Error -Newest 10`: Displays the last 10 errors from the System log.
- `$timer = New-Object Timers.Timer Register-ObjectEvent -InputObject $timer -EventName Elapsed -SourceIdentifier Timer.Elapsed`: Subscribes to an event generated by a .NET object.

#### Clearing Event Logs
- `Clear-EventLog -LogName Application`: Clears the Application event log.
- `wevtutil cl System`: Clears the System event log.

## Miscellaneous Enumeration

#### Scripting Interaction and Interface

- `$input = Read-Host -Prompt "Enter your name"`: Reads a line of input from the console.
- `Write-Host "Hello, World!" -ForegroundColor Green`: Writes customized output to the console.
- `Clear-Host`: Clears the console window.
- `Start-Sleep -Seconds 5`: Suspends the activity in a script for the specified period.

#### System Startup Programs
- `Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`: Lists startup programs for the current user.
- `Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`: Lists startup programs for the system.

# Additional Information

- **Execution Policies:** PowerShell's execution policies determine how scripts are executed. Common policies include `Restricted`, `AllSigned`, `RemoteSigned`, and `Unrestricted`. It's essential to understand these when running or developing scripts.
- **Remoting:** PowerShell supports remote management through WinRM, allowing scripts and commands to be executed on remote systems. This feature is critical for managing large environments.
- **Script Signing:** PowerShell supports script signing, which is a security feature to ensure that only scripts from trusted sources are executed. Developers can sign their scripts using certificates.
- **Profiles:** PowerShell profiles are scripts that execute when PowerShell starts. They can be used to customize the user's environment, such as loading specific modules or setting aliases.
- **Integrated Scripting Environment (ISE):** PowerShell ISE is a graphical interface for writing, testing, and debugging scripts. It includes features like syntax highlighting, auto-completion, and an integrated help system.
- **Cross-Platform Support:** PowerShell Core is a cross-platform version of PowerShell that runs on Windows, macOS, and Linux. This version brings the power of PowerShell to a broader range of environments.
- **Advanced Functions:** PowerShell supports advanced functions, which are like cmdlets but written in PowerShell script. These functions can include detailed parameter handling, support for pipeline input, and advanced error handling.
- **Use in Offensive Security:** PowerShell is commonly used in penetration testing and red team operations due to its powerful scripting capabilities and deep integration with the Windows operating system. Techniques such as living-off-the-land attacks often leverage PowerShell to execute malicious actions without dropping additional binaries on the target system.

# Resources

|**Website**|**URL**|
|-|-|
|PowerShell Module Help|https://learn.microsoft.com/en-us/powershell/module/|
|PowerShell Documentation|[https://docs.microsoft.com/en-us/powershell/](https://docs.microsoft.com/en-us/powershell/)|
|PowerShell Gallery (Modules)|[https://www.powershellgallery.com/](https://www.powershellgallery.com/)|
|PowerShell GitHub Repository|[https://github.com/PowerShell/PowerShell](https://github.com/PowerShell/PowerShell)|
|PowerShell Security Best Practices|[https://docs.microsoft.com/en-us/powershell/security/](https://docs.microsoft.com/en-us/powershell/security/)|
|SANS PowerShell Cheat Sheet|[https://www.sans.org/media/PowerShell-Cheat-Sheet.pdf](https://www.sans.org/media/PowerShell-Cheat-Sheet.pdf)|
|PowerShell Remoting Guide|[https://docs.microsoft.com/en-us/powershell/remoting/](https://docs.microsoft.com/en-us/powershell/remoting/)|
|PowerShell Core on Linux|[https://docs.microsoft.com/en-us/powershell/scripting/](https://docs.microsoft.com/en-us/powershell/scripting/)|
|Advanced PowerShell Scripting|[https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/creating-a-cmdlet](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/creating-a-cmdlet)|