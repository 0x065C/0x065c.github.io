```powershell
# PATH Environment Directories ACL Collection Script
# - This script gathers ACL details for all directories listed in the $env:PATH environment variable.
# - It saves two output files: one for all ACL information and one for filtered ACL entries matching specific access rights.
# Step1_OutputFilePath: Contains ACL information for all directories in the PATH.
# Step2_OutputFilePath: Contains filtered ACL information based on specific permission patterns (e.g., FullControl, Modify).

# Usage:
# .\PATH_Directories_ACL.ps1



# Initialize output file paths
$Step1_OutputFilePath = "D:\Step1_PATH_Directories_ACL.txt"
$Step2_OutputFilePath = "D:\Step2_PATH_Directories_ACL_Filtered.txt"

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

        # Check for matches in the ACL entries based on the defined patterns
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

# End of script logging
"ACL Collection Completed" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
```