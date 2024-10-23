```powershell
# WSDL File Parsing Script
# This script loads the WSDL file from a specified URL, extracts services, port types, operations, and messages, and saves the parsed data to an output file.

# Usage:
# .\WSDL_Parsing.ps1



# Input parameter
$apiUrl = "https://www.example.com/Services.REST/target_service.svc?wsdl_or_singlewsdl"

# Initialize output file path
$outputFile = "D:\API_Enumeration_1_WSDL_Parse.txt"

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $outputFile -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output file
$PSDefaultParameterValues['Out-File:Width'] = 300

# Attempt to load the WSDL file using the current user's credentials
try {
    $response = Invoke-WebRequest -Uri $apiUrl -UseDefaultCredentials
    if ($response.StatusCode -eq 200) {
        [xml]$wsdl = $response.Content
        Write-Output "WSDL file loaded successfully."
    } else {
        Write-Output "Failed to load WSDL file. Status code: $($response.StatusCode)"
        exit
    }
} catch {
    Write-Output "Error loading WSDL file: $_"
    exit
}

# Initialize a string to store the parsed data
$parsedData = ""

# Step 1: Extract and organize services
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

# Step 2: Extract and organize port types and operations
$parsedData += "Port Types and Operations`r`n"
$parsedData += "=========================`r`n"
foreach ($portType in $wsdl.definitions.portType) {
    $portTypeName = $portType.name
    $parsedData += "Port Type: $portTypeName`r`n"
    foreach ($operation in $portType.operation) {
        $operationName = $operation.name
        $inputMessage = $operation.input.message
        $outputMessage = $operation.output.message
        $parsedData += "  Operation: $operationName`r`n"
        $parsedData += "    Input Message: $inputMessage`r`n"
        $parsedData += "    Output Message: $outputMessage`r`n"
    }
    $parsedData += "`r`n"
}

# Step 3: Extract and organize messages
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
$parsedData | Out-File -FilePath $outputFile -Encoding UTF8

# End of script logging
Write-Output "Parsed WSDL data has been saved to $outputFile"
```