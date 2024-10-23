```powershell
# Windows Registry Hive ACL Query Script
# This script recursively queries a specified Windows Registry Hive for ACLs.
# It saves the collected ACLs to an output file.

# Usage:
# .\Windows_Registry_Hive_Recursive_ACL_Enumeration.ps1



# Input parameter
$path = "Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\"

# Initialize output file path
$OutputFilePath = "D:\Step1_Registry_Hive_ACL.txt"

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $OutputFilePath -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output fileWi
$PSDefaultParameterValues['Out-File:Width'] = 300

# Recursively query the registry hive for ACLs and save them to the output file
Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | 
ForEach-Object { 
    Get-Acl -Path $_.PSPath 
} | Format-List | Out-String -Width 300 | Out-File -FilePath $OutputFilePath -Encoding UTF8

# End of script logging
"Registry ACL Collection Completed" | Out-File -FilePath $OutputFilePath -Append -Encoding UTF8
```