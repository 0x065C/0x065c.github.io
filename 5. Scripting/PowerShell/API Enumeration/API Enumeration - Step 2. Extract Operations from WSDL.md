```powershell
# WSDL Operations Extraction Script
# This script loads the WSDL file from a target URL, extracts service operations, and saves them to a wordlist. It outputs the extracted operations to a specified output file.

# Usage:
# .\WSDL_Operations_Extraction.ps1



# Input parameter
$apiUrl = "https://www.example.com/Services.REST/target_service.svc?wsdl_or_singlewsdl"

# Initialize output file path
$outputFile = "D:\API_Enumeration_2_Service_Operation_Wordlist.txt" 

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $outputFile -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output file
$PSDefaultParameterValues['Out-File:Width'] = 300

# Attempt to load the WSDL file using the current user's credentials
try {
    $response = Invoke-WebRequest -Uri $apiUrl -UseDefaultCredentials -ErrorAction Stop
    [xml]$wsdl = $response.Content
    Write-Output "WSDL file loaded successfully."
} catch {
    Write-Output "Failed to load WSDL file: $_"
    exit
}

# Initialize a list to store the operations
$operations = @()

# Extract operations from the WSDL
$wsdl.definitions.portType.operation | ForEach-Object {
    $operationName = $_.name
    $operations += $operationName
}

# Output the operations to the wordlist file
$operations | Out-File -FilePath $outputFile -Encoding UTF8

# Log completion of the operation extraction process
Write-Output "Operations have been extracted and saved to $outputFile"
```