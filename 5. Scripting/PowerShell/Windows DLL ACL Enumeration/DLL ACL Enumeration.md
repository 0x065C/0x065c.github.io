```powershell
# DLL ACL Information Collection Script
# - This script gathers ACL details for all DLLs loaded by currently running processes.
# - It saves two output files: one for all ACL information and one for filtered ACL entries matching specific access rights.
# Step1_OutputFilePath: Contains ACL information for all DLLs found.
# Step2_OutputFilePath: Contains ACL information only for DLLs with potentially risky permissions.

# Usage:
# .\DLL_ACL_Enumeration.ps1



# Initialize output file paths
$Step1_OutputFilePath = "D:\Step1_DLL_ACL.txt"
$Step2_OutputFilePath = "D:\Step2_DLL_ACL_Filtered.txt"

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

                    # Write the Process Name, Process ID, DLL path, and ACL details to the Step 1 output file
                    "Process Name: $($process.Name), PID: $($process.Id)" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                    "DLL Path: $cleanDLLPath" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                    $acl | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                    "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8 # Add a newline for readability

                    # Add ACL entries for matching
                    $aclEntries = $acl -split "`n"
                    $currentACL = $aclEntries | Where-Object { $_ -match ".*Allow.*" }

                    # Check for matches in the ACL entries based on the defined patterns
                    $matchingEntries = $currentACL | Where-Object { $_ -match ($patterns -join "|") }

                    # If any matching ACL entry is found, write the Process Name, Process ID, DLL, and matching ACLs to the Step 2 output file
                    if ($matchingEntries.Count -gt 0) {
                        "Process Name: $($process.Name), PID: $($process.Id)" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
                        "DLL Path: $cleanDLLPath" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
                        $matchingEntries | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
                        "`n" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8 # Add a newline for readability
                    }
                }
                catch {
                    # If an error occurs (e.g., if the DLL path doesn't exist), log it to the output file
                    "Process Name: $($process.Name), PID: $($process.Id)" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                    "Failed to retrieve ACL for DLL: $cleanDLLPath" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                    "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                }
            }
        }
    }
    catch {
        # Log any error retrieving DLLs for the process
        "Process Name: $($process.Name), PID: $($process.Id)" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        "Failed to retrieve DLLs for process" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
}

# End of script logging
"ACL Collection Completed" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
```