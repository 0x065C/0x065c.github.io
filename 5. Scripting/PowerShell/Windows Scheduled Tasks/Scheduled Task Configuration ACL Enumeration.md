```powershell
# Scheduled Tasks ACL Collection Script
# - This script gathers Access Control List (ACL) details for all scheduled tasks configured on the system.
# - It saves two output files: one for all ACL information and one for filtered ACL entries matching specific access rights.
# Step1_OutputFilePath: Contains ACL information for all scheduled tasks.
# Step2_OutputFilePath: Contains ACL information only for tasks with potentially risky permissions.

# Usage:
# .\Scheduled_Task_Configuration_ACL_Enumeration.ps1



# Initialize output file paths
$Step1_OutputFilePath = "D:\Step1_Scheduled_Tasks_Configuration_ACL.txt"
$Step2_OutputFilePath = "D:\Step2_Scheduled_Tasks_Configuration_ACL_Filtered.txt"

# Ensure the output files are created/reset with UTF-8 encoding
New-Item -Path $Step1_OutputFilePath -ItemType File -Force | Out-Null
New-Item -Path $Step2_OutputFilePath -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output file
$PSDefaultParameterValues['Out-File:Width'] = 300

# Define regex patterns for matching ACL entries (e.g., FullControl, Modify, Write permissions)
$patterns = @(
    "Everyone .*Allow.*  .*FullControl.*",
    "Everyone .*Allow.*  .*Modify.*",
    "Everyone .*Allow.*  .*Write.*",
    "Everyone .*Allow.*  .*Delete.*",
    "Everyone .*Allow.*  .*TakeOwnership.*",
    "Everyone .*Allow.*  .*ChangePermissions.*",
    "NT AUTHORITY\\Authenticated Users .*Allow.*  .*FullControl.*",
    "NT AUTHORITY\\Authenticated Users .*Allow.*  .*Modify.*",
    "NT AUTHORITY\\Authenticated Users .*Allow.*  .*Write.*",
    "NT AUTHORITY\\Authenticated Users .*Allow.*  .*Delete.*",
    "NT AUTHORITY\\Authenticated Users .*Allow.*  .*TakeOwnership.*",
    "NT AUTHORITY\\Authenticated Users .*Allow.*  .*ChangePermissions.*",
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

        # Check for matches in the ACL entries based on the defined patterns
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

# End of script logging
"ACL Collection for Scheduled Tasks Completed" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8

```