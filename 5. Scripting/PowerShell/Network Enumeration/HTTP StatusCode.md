```powershell
# Simple HTTP Request Script
# This script sends an HTTP request to a target URL and retrieves the response status code using the current user's credentials.
# It outputs the HTTP status code for the specified URL.

# Usage:
# .\Simple_HTTP_Request.ps1



# Hardcoded input parameters
$uri = "https://www.example.com"  # The target URL for the HTTP request

# Send HTTP request using the current user's credentials
try {
    # Attempt to send a request to the target URL
    $response = Invoke-WebRequest -Uri $uri -UseDefaultCredentials -ErrorAction Stop
    
    # Output the status code received from the server
    $statusCode = $response.StatusCode
    Write-Output "The request to $uri returned status code: $statusCode"
} catch {
    # Handle errors by displaying the exception message
    $errorMessage = $_.Exception.Message
    Write-Output "Failed to send request to $uri: $errorMessage"
}

```