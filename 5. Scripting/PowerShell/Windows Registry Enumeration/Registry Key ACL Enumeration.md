```powershell
# Windows Registry ACL Query Script
# It retrieves the Access Control List (ACL) of the specified Windows Registry key
# and writes the formatted ACL information to the specified output file.

# Usage:
# .\Windows_Registry_Key_ACL_Enumeration.ps1



# Input parameter
$path = "Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\MyKey"

# Initialize output file path
$OutputFilePath = "D:\Windows_Registry_Key_Enumeration.txt"

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $OutputFilePath -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output file
$PSDefaultParameterValues['Out-File:Width'] = 300

# Retrieve the Access Control List (ACL) for the specified registry key
try {
    $RegistryACL = Get-Acl -Path $path

    # Convert the ACL to a formatted string for easier reading
    $AclFormattedString = $RegistryACL | Format-List | Out-String -Width 300

    # Write the formatted ACL to the output file in UTF8 encoding
    $AclFormattedString | Out-File -FilePath $OutputFilePath -Encoding UTF8

    Write-Host "ACL for $path has been successfully written to $OutputFilePath."
}
catch {
    Write-Host "Error retrieving ACL for $path: $_"
    exit
}
```