```powershell
# REST API Enumeration Script
# This script sends REST requests to a list of operations (provided in a wordlist) using various HTTP methods.
# It constructs requests from a base URL and captures the responses for each combination of operation and method.
# The responses are saved to an output file for further analysis.

# Usage:
# .\REST_API_Enumeration.ps1



# Define the base URL for the target .svc endpoint
$baseUrl = "https://www.example.com/Services.REST/target.svc"

# Define the path to the external wordlist file (each operation on a new line)
$operationPath = "C:\path\to\operation_file.txt"

# Define the output file path
$outputFile = "C:\path\to\output_file.txt"

# Define the HTTP methods to loop through (excluding DELETE)
$httpMethods = @("GET", "POST", "PUT", "PATCH", "OPTIONS")

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $outputFile -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output file
$PSDefaultParameterValues['Out-File:Width'] = 300

# Read the operations from the external wordlist file
try {
    $operations = Get-Content -Path $operationPath -ErrorAction Stop
} catch {
    Write-Output "Failed to read wordlist file: $_"
    exit
}

# Initialize a variable to store the response data
$responseData = ""

# Loop through each operation
foreach ($operation in $operations) {
    # Loop through each HTTP method
    foreach ($method in $httpMethods) {
        # Construct the full URL
        $url = "$baseUrl/$operation"
        
        # Attempt the request using the current user's credentials
        try {
            $response = Invoke-WebRequest -Uri $url -UseDefaultCredentials -Method $method -ErrorAction Stop
            $statusCode = $response.StatusCode
            $statusDescription = $response.StatusDescription
            $responseBody = $response.Content
        } catch {
            $statusCode = "Error"
            $statusDescription = $_.Exception.Message
            $responseBody = ""
        }

        # Organize the output for this operation and method
        $responseData += "Operation: $operation`r`n"
        $responseData += "HTTP Method: $method`r`n"
        $responseData += "URL: $url`r`n"
        $responseData += "Status Code: $statusCode`r`n"
        $responseData += "Status Description: $statusDescription`r`n"
        $responseData += "Response:`r`n$responseBody`r`n"
        $responseData += "--------------------------------------------`r`n"
    }
}

# Write the organized responses to the output file
$responseData | Out-File -FilePath $outputFile -Encoding UTF8

Write-Output "REST requests have been sent for each HTTP method and responses saved to $outputFile"
```