```powershell
# Windows Registry Hive SID and Username Enumeration Script
# - This script queries the Windows Registry HKEY_USERS hive for all SIDs and attempts to translate them into corresponding NT Account names.
# - The script outputs the SID and NT Account mappings into a specified output file.
#
# Output File:
# $OutputFilePath: Contains the list of SIDs and their corresponding NT Account names.

# Usage:
# .\Registry_SID_Enumeration.ps1



# Initialize output file path
$OutputFilePath = "D:\HKEY_Users.txt"

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $OutputFilePath -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output file
$PSDefaultParameterValues['Out-File:Width'] = 300

# Initialize registry hive path for SID enumeration
$RegistryHivePath = "Microsoft.PowerShell.Core\Registry::HKEY_USERS\"

# Clear previous content of the output file to avoid appending to old data
if (Test-Path $OutputFilePath) {
    Clear-Content -Path $OutputFilePath
} else {
    # Create the output file if it doesn't exist
    New-Item -Path $OutputFilePath -ItemType File -Force
}

# Retrieve all SIDs from the HKEY_USERS registry hive
$SIDs = Get-ChildItem -Path $RegistryHivePath

# Iterate through each SID retrieved from the registry hive
foreach ($SIDEntry in $SIDs) {
    # Extract the SID from the registry key name
    $SecurityIdentifierString = $SIDEntry.PSChildName
    
    try {
        # Convert the string SID to a SecurityIdentifier object
        $SecurityIdentifier = New-Object System.Security.Principal.SecurityIdentifier($SecurityIdentifierString)
        
        # Translate the SecurityIdentifier to an NT Account name
        $NTAccount = $SecurityIdentifier.Translate([System.Security.Principal.NTAccount])
        
        # Output the SID and the corresponding NT Account name to the file
        $Output = "$SecurityIdentifierString - $($NTAccount.Value)"
        Add-Content -Path $OutputFilePath -Value $Output
    }
    catch {
        # Handle any errors that occur during translation (e.g., access denied or invalid SID)
        $ErrorOutput = "$SecurityIdentifierString - Unable to translate SID or access denied"
        Add-Content -Path $OutputFilePath -Value $ErrorOutput
    }
}
```