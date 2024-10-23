```powershell
# REST API Request Script
# This script sends a request to a REST .svc endpoint with specified HTTP headers and body payload.
# It outputs the response to a file and handles any potential errors during the request.

# Usage:
# .\REST_API_Request.ps1



# Define the target URL and REST action
$apiUrl = "https://www.example.com/target.svc/Operation_Name"

# Define the output file path
$outputFile = "D:\REST_Action_Request.txt"

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $outputFile -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output file
$PSDefaultParameterValues['Out-File:Width'] = 300

# Prepare the HTTP headers (modify as needed)
$headers = @{
    "Content-Type" = "application/json"
    # Additional headers can be added here if required
}

# Define the body payload (adjust parameters as needed for POST requests)
$body = @{
    "InjectionPayload" = "<payload>"   # Modify this with appropriate parameters
}

# Convert the body to JSON format if needed
$bodyJson = $body | ConvertTo-Json

# Send the REST request using the appropriate HTTP method
try {
    $response = Invoke-WebRequest -Uri $apiUrl -Method POST -Headers $headers -Body $bodyJson -UseDefaultCredentials
    
    # Output the response content to the specified output file
    $response.Content | Out-File -FilePath $outputFile -Encoding UTF8
    Write-Host "Response has been saved to $outputFile"
} catch {
    # Handle any errors during the request and output the exception message
    Write-Host "Error: $($_.Exception.Message)"
}
```