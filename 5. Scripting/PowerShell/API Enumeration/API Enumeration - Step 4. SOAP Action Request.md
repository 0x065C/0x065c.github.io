```powershell
# SOAP API Request Script
# This script sends a SOAP request to a .svc endpoint with a specified SOAP action and body payload.
# It outputs the response to a file and handles any potential errors during the request.

# Usage:
# .\SOAP_API_Request.ps1



# Define the target SOAP URL and SOAPAction
$soapUrl = "https://www.example.com/Services.REST/target_service.svc"
$soapAction = "http://example.com/Services.REST/target_service/Operation_Name"

# Define the output file path
$outputFile = "D:\SOAP_Action_Request.txt"

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $outputFile -ItemType File -Force | Out-Null

# Prepare the SOAP request body (replace with the correct XML structure for your SOAP API)
$soapBody = @"
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <Operation_Name xmlns="http://example.com/Services.REST/target_service">
      <Parameter1>Value1</Parameter1>
      <Parameter2>Value2</Parameter2>
      <!-- Add more parameters as needed -->
    </Operation_Name>
  </s:Body>
</s:Envelope>
"@

# Prepare the HTTP headers for the SOAP request
$headers = @{
    "Content-Type" = "text/xml; charset=utf-8"
    "SOAPAction" = $soapAction
}

# Send the SOAP request using POST method
try {
    $response = Invoke-WebRequest -Uri $soapUrl -Method POST -Headers $headers -Body $soapBody -UseDefaultCredentials

    # Output the response content to the specified output file
    $response.Content | Out-File -FilePath $outputFile -Encoding UTF8
    Write-Host "SOAP response has been saved to $outputFile"
} catch {
    # Handle any errors during the request and output the exception message
    Write-Host "Error: $($_.Exception.Message)"
}
```