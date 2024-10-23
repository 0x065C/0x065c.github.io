# System Information

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

# User and Group Information

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

# Network Information

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

#### Firewall and Network Shares
- `Get-NetFirewallProfile`: Lists firewall profiles and their statuses.
- `Get-NetFirewallRule`: Displays configured firewall rules.
- `net use`: Lists network shares and mapped drives.
- `Get-SmbShare`: Lists SMB shares hosted on the system.
- `Get-SmbMapping`: Lists current SMB share mappings.

#### Wireless Network Information
- `netsh wlan show profiles`: Lists all saved wireless network profiles.
- `netsh wlan show profile name=<SSID> key=clear`: Shows details (including the cleartext key) for a specific wireless profile.

# Process and Service Information

#### Process Enumeration
- `Get-Process`: Lists all running processes.
- `Get-Process | Sort-Object CPU -Descending`: Lists processes by CPU usage.
- `Get-WmiObject -Class Win32_Process`: Retrieves process details, including parent processes and command line arguments.

#### Service Enumeration
- `Get-Service`: Lists all services and their current statuses.
- `Get-WmiObject -Class Win32_Service`: Displays detailed service information, including startup type.
- `Get-Service | Where-Object { $_.Status -eq 'Running' }`: Lists all running services.

# File System Enumeration

#### Directory and File Listings
- `Get-ChildItem -Path C:\ -Recurse`: Recursively lists all files and directories on C: drive.
- `Get-ChildItem -Path C:\ -Hidden -Recurse`: Lists hidden files and directories.
- `Get-ChildItem -Path C:\ -Filter *.log -Recurse`: Searches for all `.log` files.
  
#### File Permissions and Ownership
- `icacls C:\path\to\directory`: Displays permissions for a directory.
- `Get-Acl -Path C:\path\to\file`: Shows ACL (Access Control List) details for a file.
  
#### Search for Specific Files
- `Get-ChildItem -Path C:\ -Recurse -Filter "*password*"`: Searches for files with "password" in the filename.
- `Select-String -Path "C:\path\*.txt" -Pattern "<keyword>" -Recurse`: Searches for a keyword inside text files.

# Scheduled Tasks

#### Scheduled Task Enumeration
- `Get-ScheduledTask`: Lists all scheduled tasks.
- `schtasks /query /fo LIST /v`: Displays detailed information about scheduled tasks.
- `Get-ScheduledTask | Select-Object TaskName, State, LastRunTime, NextRunTime`: Summarizes tasks with their statuses and run times.

# Installed Software

#### Installed Programs
- `Get-WmiObject -Class Win32_Product`: Lists installed programs.
- `Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*`: Queries installed software from the registry.
- `Get-Package`: Lists installed packages (via PowerShell modules like Chocolatey).

#### Installed Drivers
- `Get-WmiObject -Class Win32_PnPSignedDriver`: Displays installed drivers and their statuses.
- `Get-WindowsDriver -Online`: Lists installed drivers for the current session.

# Security and Privilege Escalation

#### User Privileges and Security Policies
- `whoami /priv`: Lists current user privileges.
- `net accounts`: Displays password and lockout policies.
- `secedit /export /cfg C:\policies.txt`: Exports local security policies for review.

#### Registry Keys and Persistence
- `Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`: Lists programs set to run at user login.
- `Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`: Lists programs set to run at system startup.
- `reg query HKLM\SYSTEM\CurrentControlSet\Services`: Lists services configured via the registry.

# Logging and Event Information

#### Event Logs
- `Get-WinEvent -LogName "Application" -MaxEvents 10`: Displays the last 10 events from the Application log.
- `Get-EventLog -LogName "Security" -Newest 5`: Lists the last 5 entries from the Security log.
- `Get-EventLog -LogName "System" -EntryType Error -Newest 10`: Displays the last 10 errors from the System log.

#### Clearing Event Logs
- `Clear-EventLog -LogName Application`: Clears the Application event log.
- `wevtutil cl System`: Clears the System event log.

# Miscellaneous Enumeration

#### Environment Variables
- `Get-ChildItem Env:`: Lists all environment variables.
- `$env:<variable_name>`: Retrieves a specific environment variable value.

#### System Startup Programs
- `Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`: Lists startup programs for the current user.
- `Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`: Lists startup programs for the system.