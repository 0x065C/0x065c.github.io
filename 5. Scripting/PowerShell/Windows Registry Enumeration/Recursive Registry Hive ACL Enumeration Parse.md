```powershell
# Windows Registry ACL Weak Permissions Detection Script
# This script recursively scans a specified Windows Registry hive for ACLs and checks for weak permissions.
# It outputs registry keys with potentially insecure ACLs (e.g., FullControl, Modify, Write permissions) to an output file.

# Usage:
# .\Windows_Registry_Hive_Recursive_ACL_Enumeration_Parse.ps1



# Input parameter
$path = "Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\"

# Initialize output file path
$OutputFilePath = "D:\Step2_Registry_Hive_ACL_Filtered.txt"

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $OutputFilePath -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output file
$PSDefaultParameterValues['Out-File:Width'] = 300

# Initialize search patterns for identifying weak permissions
$SearchPatterns = @(
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

# Initialize an empty array to store matching registry paths
$MatchingRegistryPaths = @()

# Recursively retrieve registry items from the specified path
$RegistryItems = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue

# Iterate over each registry item and retrieve its ACL
foreach ($RegistryItem in $RegistryItems) {
    try {
        # Retrieve the ACL for the current registry key
        $RegistryACL = Get-Acl -Path $RegistryItem.PSPath

        # Convert the ACL to a string for easier pattern matching
        $AclContentString = $RegistryACL | Format-List | Out-String -Width 300

        # Check if the ACL contains any weak permissions matching the search patterns
        foreach ($Pattern in $SearchPatterns) {
            if ($AclContentString -match $Pattern) {
                # Add the matching registry path to the array
                $MatchingRegistryPaths += $RegistryItem.PSPath
                break  # Stop checking other patterns once a match is found
            }
        }
    } catch {
        # Log error messages for issues encountered during ACL retrieval
        $ErrorMessage = $_.Exception.Message
        Write-Output "Error processing $($RegistryItem.PSPath): $ErrorMessage"
    }
}

# Write the matching registry paths to the output file
$MatchingRegistryPaths | Out-File -FilePath $OutputFilePath

# End of script logging
Write-Output "Registry ACL scan completed. Results written to: $OutputFilePath"
```