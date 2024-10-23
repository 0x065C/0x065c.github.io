```powershell
# WSDL and REST API Enumeration Script
# This script loads the WSDL file from a target URL, extracts operations and messages, and sends REST requests to the service endpoints.
# It outputs the parsed WSDL data, operations, and REST responses to output files.

# Usage:
# .\API_Enumeration.ps1



# Input parameter
$baseUrl = "https://www.example.com/Services.REST/target_service.svc"

# Initialize output file paths
$parsedOutputFile = "D:\API_Enumeration_1_WSDL_Parse.txt"
$operationOutputFile = "D:\API_Enumeration_2_Service_Operation_Wordlist.txt"  
$finalOutputFile = "D:\API_Enumeration_3_REST_Responses.txt"

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $parsedOutputFile -ItemType File -Force | Out-Null
New-Item -Path $operationOutputFile -ItemType File -Force | Out-Null
New-Item -Path $finalOutputFile -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output files
$PSDefaultParameterValues['Out-File:Width'] = 300

# Define the full URL for the WSDL file
$apiUrl = $baseUrl + "?wsdl"

# Attempt to load the WSDL file using the current user's credentials
try {
    $response = Invoke-WebRequest -Uri $apiUrl -UseDefaultCredentials -ErrorAction Stop
    [xml]$wsdl = $response.Content
    Write-Output "WSDL file loaded successfully."
} catch {
    Write-Output "Failed to load WSDL file: $_"
    exit
}

# Step 1: Parse the WSDL and extract services, operations, and messages
$parsedData = ""

# Extract and organize services
$parsedData += "Services`r`n"
$parsedData += "========`r`n"
foreach ($service in $wsdl.definitions.service) {
    $serviceName = $service.name
    $parsedData += "Service Name: $serviceName`r`n"
    foreach ($port in $service.port) {
        $portName = $port.name
        $binding = $port.binding
        $address = $port.address.location
        $parsedData += "  Port: $portName`r`n"
        $parsedData += "    Binding: $binding`r`n"
        $parsedData += "    Address: $address`r`n"
    }
    $parsedData += "`r`n"
}

# Extract and organize port types and operations
$parsedData += "Port Types and Operations`r`n"
$parsedData += "=========================`r`n"
$operations = @() # Initialize a list to store the operations
foreach ($portType in $wsdl.definitions.portType) {
    $portTypeName = $portType.name
    $parsedData += "Port Type: $portTypeName`r`n"
    foreach ($operation in $portType.operation) {
        $operationName = $operation.name
        $operations += $operationName # Add operation to the wordlist
        $inputMessage = $operation.input.message
        $outputMessage = $operation.output.message
        $parsedData += "  Operation: $operationName`r`n"
        $parsedData += "    Input Message: $inputMessage`r`n"
        $parsedData += "    Output Message: $outputMessage`r`n"
    }
    $parsedData += "`r`n"
}

# Extract and organize messages
$parsedData += "Messages`r`n"
$parsedData += "==========`r`n"
foreach ($message in $wsdl.definitions.message) {
    $messageName = $message.name
    $parsedData += "Message Name: $messageName`r`n"
    foreach ($part in $message.part) {
        $partName = $part.name
        $element = $part.element
        $parsedData += "  Part Name: $partName, Element: $element`r`n"
    }
    $parsedData += "`r`n"
}

# Output the parsed data to a file
$parsedData | Out-File -FilePath $parsedOutputFile -Encoding UTF8
Write-Output "Parsed WSDL data has been saved to $parsedOutputFile"

# Output the operations to the wordlist file
$operations | Out-File -FilePath $operationOutputFile -Encoding UTF8
Write-Output "Operations have been extracted and saved to $operationOutputFile"

# Step 2: Use the generated wordlist to send REST requests to the service

# Define the HTTP methods to loop through (excluding DELETE)
$httpMethods = @("GET", "POST", "PUT", "PATCH", "OPTIONS")

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
$responseData | Out-File -FilePath $finalOutputFile -Encoding UTF8

Write-Output "REST requests have been sent for each HTTP method and responses saved to $finalOutputFile"
```


Some services may return with a `System.NullReferenceException: Object reference not set to an instance of an object` meaning the HTTP Request successfully executed and the service/operation attempted to retrieve the response data but the value was null. Rerunning the query at a later time may generate a full response depending on the system (example: running the request at peak operation hours vs running at low-traffic hours).


Some services may return with a `System.Exception: Authorization failed. If the environment details are not provided, then the user must have 'Super User' rights.`. Meaning the request may or may not have successfully executed, but was stopped due to request parameters not matching expecting input. Capture legitimate traffic and copy/paste the body of the packet into the request to validate.
