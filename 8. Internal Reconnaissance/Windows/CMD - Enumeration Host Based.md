# System Information

#### General System Information
- `systeminfo`: Displays detailed information about the system, including OS version, hostname, architecture, and hotfixes.
- `ver`: Shows the Windows version.
- `wmic os get Caption,CSDVersion,OSArchitecture,Version`: Lists the OS name, service pack, architecture, and version.
- `wmic bios get serialnumber`: Retrieves the system's BIOS serial number.
- `wmic computersystem get manufacturer,model`: Shows the manufacturer and model of the system.
- `wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors`: CPU details, including cores and logical processors.
- `wmic memorychip get capacity`: Displays installed memory (RAM).

#### Performance Information
- `tasklist`: Displays a list of currently running processes.
- `wmic cpu get loadpercentage`: Displays CPU load percentage.
- `wmic OS get FreePhysicalMemory`: Shows available physical memory in kilobytes.

#### Boot and Time Information
- `systeminfo | findstr /C:"Boot Time"`: Displays the system boot time.
- `echo %date% %time%`: Displays the current system date and time.
- `wmic path Win32_OperatingSystem get LastBootUpTime`: Shows the last boot time in a different format.

# User and Group Information

#### Current and Logged-In Users
- `whoami`: Displays the current user and their domain.
- `query user`: Shows the current logged-in users and their sessions.
- `qwinsta`: Displays active terminal sessions on the system.

#### User Accounts
- `net user`: Lists all user accounts on the system.
- `net user <username>`: Displays detailed information about a specific user account.

#### Group Memberships
- `net localgroup`: Lists all local groups.
- `net localgroup administrators`: Lists all members of the Administrators group.
- `whoami /groups`: Displays the groups that the current user is a member of.

# Network Information

#### Network Interfaces and Configuration
- `ipconfig /all`: Displays detailed network configuration, including IP addresses, MAC addresses, DNS servers, and gateways.
- `getmac`: Displays the MAC addresses for all network interfaces.
- `netsh interface ip show config`: Shows IP configuration for network interfaces.

#### Active Connections and Listening Ports
- `netstat -ano`: Displays active network connections and listening ports with their associated PIDs.
- `tasklist /svc | findstr <PID>`: Matches PIDs with processes to identify services associated with network connections.

#### ARP, Routing, and DNS Information
- `arp -a`: Displays the ARP cache of IP addresses and associated MAC addresses.
- `route print`: Displays the routing table.
- `nslookup <domain>`: Performs a DNS lookup for the given domain.

#### Firewall and Network Shares
- `netsh advfirewall show allprofiles`: Displays the status of all firewall profiles.
- `net share`: Lists all network shares on the system.
- `net use`: Lists currently connected network shares.

#### Wireless Network Information
- `netsh wlan show profiles`: Lists all saved wireless network profiles.
- `netsh wlan show profile <SSID> key=clear`: Displays details of a specific wireless profile, including the cleartext password.

# Process and Service Information

#### Process Enumeration
- `tasklist`: Lists all running processes on the system.
- `tasklist /v`: Displays detailed information about running processes, including CPU and memory usage.
- `tasklist /svc`: Lists services associated with running processes.

#### Service Enumeration
- `sc query`: Lists all services and their statuses.
- `net start`: Lists all running services.
- `sc qc <service_name>`: Displays detailed information about a specific service, including its binary path and startup type.

# File System Enumeration

#### Directory and File Listings
- `dir C:\`: Lists files and directories in the root of the C: drive.
- `dir C:\ /A:H /S`: Lists all hidden files and directories on the C: drive.
- `dir C:\ /S /P | findstr ".log"`: Searches for `.log` files in the C: drive.

#### File Permissions and Ownership
- `icacls <Path\To\FileOrDirectory>`: Displays the permissions for a specific file or directory.
- `dir /Q <Path\To\FileOrDirectory>`: Shows the owner of a file or directory.

#### Search for Specific Files
- `dir C:\ /S | findstr "password"`: Searches for files with "password" in the filename.
- `findstr /S /I "<keyword>" C:\*.txt`: Searches for a keyword inside all `.txt` files on the C: drive.



# Scheduled Tasks

#### Scheduled Task Enumeration
- `schtasks`: Lists all scheduled tasks on the system.
- `schtasks /query /fo LIST /v`: Displays detailed information about scheduled tasks, including last and next run times.

# Installed Software

#### Installed Programs
- `wmic product get name,version`: Lists installed programs along with their version numbers.
- `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall`: Queries installed software from the registry.

#### Installed Drivers
- `driverquery`: Displays a list of all installed drivers on the system.
- `driverquery /v`: Provides detailed information about installed drivers, including their modules and file paths.

# Security and Privilege Escalation

#### User Privileges and Security Policies
- `whoami /priv`: Displays the current user's privileges.
- `net accounts`: Shows password and lockout policies.
- `secedit /export /cfg C:\policies.txt`: Exports local security policies to a text file for review.

#### Registry Keys and Persistence
- `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run`: Displays programs set to run at user login.
- `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run`: Displays programs set to run at system startup.
- `reg query HKLM\SYSTEM\CurrentControlSet\Services`: Lists all services configured in the registry.

# Logging and Event Information

#### Event Logs
- `wevtutil qe Application /f:text /c:10`: Displays the last 10 events from the Application log.
- `wevtutil qe System /f:text /c:10`: Displays the last 10 events from the System log.
- `wevtutil qe Security /f:text /c:10`: Displays the last 10 events from the Security log.

#### Clearing Event Logs
- `wevtutil cl Application`: Clears the Application event log.
- `wevtutil cl System`: Clears the System event log.

# Miscellaneous Enumeration

#### Environment Variables
- `set`: Lists all environment variables.
- `echo %<variable_name>%`: Displays the value of a specific environment variable.

#### System Startup Programs
- `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run`: Lists startup programs for the current user.
- `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run`: Lists startup programs for the system.