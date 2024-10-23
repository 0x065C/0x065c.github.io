```powershell
# Splunk Enumeration Script
# - This script enumerates Splunk-related information such as installation directories, configuration files, services, registry keys, and event logs.
# Step1_OutputFilePath: Contains detailed information for all enumerated components.

# Usage:
# .\Splunk_Enumeration.ps1


# Initialize output file paths
$Step1_OutputFilePath = "D:\Splunk_Enumeration.txt"

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $Step1_OutputFilePath -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output file
$PSDefaultParameterValues['Out-File:Width'] = 300

function Add-Separation {
    "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
}

# Enumerate Splunk Installation Directories
Write-Output "Enumerating Splunk installation directories..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
try {
    $splunkPaths = @(
        "C:\Program Files\Splunk",
        "C:\Program Files\SplunkUniversalForwarder",
        "C:\Program Files (x86)\Splunk",
        "C:\Program Files (x86)\SplunkUniversalForwarder"
    )
    foreach ($path in $splunkPaths) {
        if (Test-Path $path) {
            Write-Output "Found Splunk directory: $path" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        }
    }
} catch {
    Write-Output "Failed to check Splunk installation directories." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} Add-Separation

# Enumerate Splunk Configuration Files
Write-Output "Enumerating Splunk configuration files (inputs.conf, outputs.conf, props.conf)..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
try {
    foreach ($path in $splunkPaths) {
        if (Test-Path $path) {
            $configFiles = Get-ChildItem -Path $path -Recurse -Filter "*.conf"
            foreach ($file in $configFiles) {
                if ($file.Name -match "inputs.conf|outputs.conf|props.conf") {
                    Write-Output "Found configuration file: $($file.FullName)" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                    Write-Output "Contents of $($file.FullName):" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                    Get-Content -Path $file.FullName -ErrorAction Stop | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                }
            }
        }
    }
} catch {
    Write-Output "Failed to enumerate Splunk configuration files." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} Add-Separation

# Enumerate Monitored Data Inputs from inputs.conf
Write-Output "Enumerating data inputs from inputs.conf..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
try {
    foreach ($path in $splunkPaths) {
        $inputsConfPath = Join-Path -Path $path -ChildPath "etc\system\local\inputs.conf"
        if (Test-Path $inputsConfPath) {
            Write-Output "Found inputs.conf: $inputsConfPath" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
            Write-Output "Contents of inputs.conf:" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
            Get-Content -Path $inputsConfPath -ErrorAction Stop | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        }
    }
} catch {
    Write-Output "Failed to enumerate data inputs from inputs.conf." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} Add-Separation

# Enumerate Splunk HTTP Event Collectors (HEC)
Write-Output "Checking for HTTP Event Collectors (HEC) in inputs.conf..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
try {
    foreach ($path in $splunkPaths) {
        $inputsConfPath = Join-Path -Path $path -ChildPath "etc\system\local\inputs.conf"
        if (Test-Path $inputsConfPath) {
            $hecConfig = Get-Content -Path $inputsConfPath -ErrorAction Stop | Select-String -Pattern "\[http://|hec\]"
            if ($hecConfig) {
                Write-Output "HTTP Event Collector (HEC) found in inputs.conf:" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
                $hecConfig | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
            }
        }
    }
} catch {
    Write-Output "Failed to check for HTTP Event Collectors (HEC)." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} Add-Separation

# Enumerate Forwarder Configuration
Write-Output "Enumerating Splunk forwarder configurations (outputs.conf)..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
try {
    foreach ($path in $splunkPaths) {
        $outputsConfPath = Join-Path -Path $path -ChildPath "etc\system\local\outputs.conf"
        if (Test-Path $outputsConfPath) {
            Write-Output "Found outputs.conf: $outputsConfPath" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
            Write-Output "Contents of outputs.conf:" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
            Get-Content -Path $outputsConfPath -ErrorAction Stop | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        }
    }
} catch {
    Write-Output "Failed to enumerate forwarder configurations from outputs.conf." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} Add-Separation

# Search for Splunk Event Logs
Write-Output "Searching for Splunk-related event logs..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
try {
    $splunkLogs = Get-WinEvent -ListLog * | Where-Object { $_.LogName -match "Splunk" }
    if ($splunkLogs) {
        foreach ($log in $splunkLogs) {
            Write-Output "Found Splunk event log: $($log.LogName)" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        }
    } else {
        Write-Output "No Splunk-related event logs found." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
} catch {
    Write-Output "Failed to enumerate Splunk-related event logs." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} Add-Separation

# End of script logging
"Splunk enumeration complete." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
```