```powershell
# Service Executable ACL Information Collection Script
# - This script gathers ACL details for all service executables on the system.
# - It saves two output files: one for all ACL information and one for filtered ACL entries with specific access rights.
# Step1_OutputFilePath: Contains ACL information for all service executables found.
# Step2_OutputFilePath: Contains ACL information only for service executables with potentially risky permissions.

# Usage:
# .\Service_Executable_ACL_Enumeration.ps1



# Initialize output file paths
$Step1_OutputFilePath = "D:\Step1_Service_Executable_ACL.txt"
$Step2_OutputFilePath = "D:\Step2_Service_Executable_ACL_Filtered.txt"

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

# Query services and extract service executables and service names
$services = Get-WmiObject -Class Win32_Service

# Initialize variables to hold the current service details
$currentService = ""
$currentACL = @()

# Iterate over each service and retrieve its executable path and service name
foreach ($service in $services) {
    $serviceName = $service.Name
    $executable = $service.PathName -replace '"', ''  # Remove quotes from the executable path if present

    # Filter out invalid paths
    if (Test-Path $executable -ErrorAction SilentlyContinue) {
        try {
            # Get the ACL information for the service executable
            $acl = Get-Acl -Path $executable | Format-List | Out-String -Width 300

            # Write the service name, executable path, and ACL details to the Step 1 output file
            "Service Name: $serviceName" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
            "Executable: $executable" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
            $acl | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
            "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8 # Add a newline for readability

            # Add ACL entries for matching
            $aclEntries = $acl -split "`n"
            $currentACL = $aclEntries | Where-Object { $_ -match ".*Allow.*" }

            # Check for matches in the ACL entries based on the defined patterns
            $matchingEntries = $currentACL | Where-Object { $_ -match ($patterns -join "|") }

            # If any matching ACL entry is found, write the service name, executable, and matching ACLs to the Step 2 output file
            if ($matchingEntries.Count -gt 0) {
                "Service Name: $serviceName" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
                "Executable: $executable" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
                $matchingEntries | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
                "`n" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8 # Add a newline for readability
            }
        }
        catch {
            # If an error occurs (e.g., if the executable path doesn't exist), log it to the output file
            "Service Name: $serviceName" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
            "Failed to retrieve ACL for executable: $executable" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
            "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        }
    }
}

# End of script logging
"Service Executable ACL Collection Completed" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
```