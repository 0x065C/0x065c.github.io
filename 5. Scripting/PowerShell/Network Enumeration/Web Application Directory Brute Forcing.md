```powershell
# Web Application Directory Brute Forcing Script with Hardcoded Fuzzing Position
# This script will perform brute forcing on the specified fuzzing position within the target URL using the provided wordlist.

# Usage:
# .\WebApplicationDirectoryDiscovery.ps1



# Input parameters
$target_url = "http://example.com/<FUZZ>"   # Target URL containing the <FUZZ> placeholder for fuzzing
$wordlist_path = "D:\wordlist.txt"          # Path to the wordlist file (list of directories or subdomains)

# Initialize output file path
$OutputFilePath = "D:\BruteForce_Results.txt"

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $OutputFilePath -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output file
$PSDefaultParameterValues['Out-File:Width'] = 300

# Function to send HTTP requests and check for valid responses
function Test-URL {
    param (
        [string]$url
    )

    try {
        # Send a HEAD request to check if the directory or subdomain exists
        $response = Invoke-WebRequest -Uri $url -Method Head -ErrorAction Stop
        return $response.StatusCode -eq 200
    } catch {
        # Return false for any exceptions (likely a 404 or the resource doesn't exist)
        return $false
    }
}

# Load the wordlist
if (Test-Path $wordlist_path) {
    $fuzz_words = Get-Content -Path $wordlist_path
} else {
    # Exit if the wordlist file does not exist
    Add-Content -Path $OutputFilePath -Value "Wordlist file not found: $wordlist_path"
    Add-Content -Path $OutputFilePath -Value "`n"
    exit
}

# Check if the target URL contains the <FUZZ> placeholder
if ($target_url -notlike "*<FUZZ>*") {
    Write-Host "The target URL must contain the <FUZZ> placeholder."
    exit
}

# Write header to the output file
"Target URL: $target_url" | Out-File -FilePath $OutputFilePath -Append -Encoding UTF8
"Brute-forcing fuzzing position using wordlist: $wordlist_path" | Out-File -FilePath $OutputFilePath -Append -Encoding UTF8
"`n" | Out-File -FilePath $OutputFilePath -Append -Encoding UTF8

# Iterate over each word in the wordlist
foreach ($fuzz_word in $fuzz_words) {
    # Replace the <FUZZ> placeholder in the URL with the current fuzz word
    $fuzzed_url = $target_url -replace "<FUZZ>", $fuzz_word
    
    # Check if the fuzzed URL exists
    if (Test-URL -url $fuzzed_url) {
        # If the URL is valid, log the result
        $logEntry = "FOUND: $fuzzed_url"
        Add-Content -Path $OutputFilePath -Value $logEntry
        Add-Content -Path $OutputFilePath -Value "`n"
    }
}

# Log the end of the brute force
Add-Content -Path $OutputFilePath -Value "Brute force completed."
Add-Content -Path $OutputFilePath -Value "`n"
```