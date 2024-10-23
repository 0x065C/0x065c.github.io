```powershell
# REST API Invocation Script
# This script sends GET requests to the specified REST API endpoints using the current user's credentials.
# The script captures the API responses and saves them to output files for further analysis.

# Usage:
# .\REST_API_Invocation.ps1



# Input parameter
$apiUrl1 = "https://www.example.com/Services.REST/target_service.svc/operation_name_here"

# Initialize output file path
$outputFilePath = "D:\Operation_Name_Response.txt"

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $outputFilePath -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output file
$PSDefaultParameterValues['Out-File:Width'] = 300

# Prepare the HTTP request for the first API
try {
    # Invoke the REST API using the user's default credentials
    $response1 = Invoke-WebRequest -Uri $apiUrl1 -Method GET -UseDefaultCredentials
    # Output the response to verify the data
    Write-Output "Service responded successfully." | Out-File -FilePath $outputFilePath -Append
    $response1.Content | Out-File -FilePath $outputFilePath -Append
    Write-Output "Response has been saved to $outputFilePath"
} catch {
    # Handle errors and output to the file
    $errorMsg1 = "An error occurred: $_"
    Write-Output $errorMsg1 | Out-File -FilePath $outputFilePath -Append
    Write-Output "Error details have been saved to $outputFilePath"
}
```