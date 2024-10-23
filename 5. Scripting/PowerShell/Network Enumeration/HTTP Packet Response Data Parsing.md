# 1. Automate TLS Configuration Based on Environment
Manually configuring the TLS version may not always be necessary or ideal. We can automate this step by checking the available security protocols on the system and enabling only the necessary ones. This ensures compatibility while avoiding redundant configuration.

#### Improved TLS Setup
```powershell
# Automatically configure the highest available security protocol for the current system
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor `
    [Net.SecurityProtocolType]::Tls12 -bor `
    [Net.SecurityProtocolType]::Tls11 -bor `
    [Net.SecurityProtocolType]::Tls
```

This will automatically apply the correct TLS protocols without manual intervention, ensuring modern and secure communications.

# 2. Create a Flexible PowerShell Script Template for Web Requests
Instead of manually copying and editing commands from the browser’s network inspector, you can streamline the process by creating a flexible PowerShell script template that you can reuse for multiple requests, with built-in flexibility for extracting different fields dynamically.

#### Improved Web Request Process
1. **Automate Input for URL and Headers:** Allow the script to take dynamic input for the URL and headers, so you don't need to copy/paste from the browser each time.
2. **Parameterize the Extraction Process:** Allow the user to specify which fields to extract without having to modify the script multiple times.
3. **Improved Error Handling:** Handle different HTTP status codes (4xx, 5xx) gracefully with meaningful error messages.

#### Enhanced Script

```powershell
# Enhanced REST API Request and Data Extraction Script
# This script dynamically sends an HTTP request to a target URL, handles different status codes, 
# and extracts the specified fields from the response.

param (
    [string]$uri = "https://www.example.com",  # Default target URL (can be overridden)
    [string]$method = "GET",                   # Default HTTP method (can be overridden)
    [string[]]$fieldsToExtract,                # Fields to extract from the JSON response
    [switch]$useDefaultCredentials = $true     # Use default credentials if needed
)

# Ensure TLS 1.2 or higher is used
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor `
    [Net.SecurityProtocolType]::Tls11 -bor `
    [Net.SecurityProtocolType]::Tls

# Function to send the request
function Send-Request {
    param (
        [string]$uri,
        [string]$method,
        [bool]$useDefaultCredentials
    )
    
    try {
        if ($useDefaultCredentials) {
            $response = Invoke-RestMethod -Uri $uri -Method $method -UseDefaultCredentials -ErrorAction Stop
        } else {
            $response = Invoke-RestMethod -Uri $uri -Method $method -ErrorAction Stop
        }
        return $response
    } catch {
        Write-Output "Failed to retrieve data: $($_.Exception.Message)"
        return $null
    }
}

# Function to extract fields from the JSON response
function Extract-Fields {
    param (
        [object]$response,
        [string[]]$fieldsToExtract
    )
    
    if ($null -eq $response) {
        Write-Output "No response to process."
        return
    }
    
    foreach ($field in $fieldsToExtract) {
        try {
            # Use Select-Object to extract the field dynamically
            $extractedValue = $response | Select-Object -ExpandProperty $field -ErrorAction Stop
            Write-Output "$field: $extractedValue"
        } catch {
            Write-Output "Failed to extract field '$field': $_"
        }
    }
}

# Main Execution

# Send the request and get the response
$response = Send-Request -uri $uri -method $method -useDefaultCredentials:$useDefaultCredentials

# Extract specified fields
if ($fieldsToExtract) {
    Extract-Fields -response $response -fieldsToExtract $fieldsToExtract
} else {
    Write-Output "Response received:"
    $response | ConvertTo-Json -Depth 5
}
```

# 3. Streamlined Workflow
Using this improved script, you now only need to run the script with the parameters as needed:

```powershell
.\Enhanced_HTTP_Request.ps1 -uri "https://api.example.com/data" -method "GET" -fieldsToExtract "user", "details.email"
```

- **No Need to Manually Edit Each Time:** Instead of manually copying requests from the browser’s network inspector, you can specify the URL and fields in the script.
- **Multiple HTTP Methods Supported:** You can change the HTTP method (GET, POST, PUT, PATCH, etc.) dynamically when calling the script.

# 4. Automated Response Parsing
If the API response returns structured data (JSON, XML), the script uses `ConvertTo-Json` or `ConvertTo-Xml` to format the output neatly. You can also drill down into deeper structures by modifying the `-fieldsToExtract` parameter without modifying the script itself.

# 5. Support for Complex and Nested JSON
The script handles nested fields automatically. If you want to extract a deeply nested property, you can pass it as a dot-separated field in the `fieldsToExtract` array.

**Example:**
If the JSON response looks like this:
```json
{
    "user": {
        "name": "John Doe",
        "details": {
            "email": "john@example.com"
        }
    }
}
```

You can extract the email like this:
```powershell
.\Enhanced_HTTP_Request.ps1 -uri "https://api.example.com/data" -fieldsToExtract "user.details.email"
```

# 6. Export Data Automatically
To make it more flexible, you can modify the script to automatically export data into CSV or JSON files:

```powershell
$response | Export-Csv -Path "C:\output.csv" -NoTypeInformation
```

Or, convert the entire response to JSON:
```powershell
$response | ConvertTo-Json | Out-File -FilePath "C:\output.json"
```

# Final Workflow
1. **Set Security Protocol:** Automatically configure the security protocol to ensure the highest available version is used.
2. **Send Request:** Automate sending an HTTP request using the target URL and method, with optional credentials.
3. **Extract Fields:** Use dynamic field extraction, so you don’t need to manually modify the script for each request.
4. **Enhanced Error Handling:** Get detailed error messages and handle network issues effectively.
5. **Automated Export:** Optionally export results to CSV or JSON for further analysis.