```powershell
# Host-based Defense Enumeration Script
# - This script collects information about various host-based defenses including antivirus, Windows Defender, firewall, security software, audit policies, and network-based defenses.
# Step1_OutputFilePath: Contains detailed information for all enumerated defenses.

# Usage:
# .\Host_Defense_Enumeration.ps1


# Initialize output file paths
$Step1_OutputFilePath = "D:\Host_Defense_Enumeration.txt"

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $Step1_OutputFilePath -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output file
$PSDefaultParameterValues['Out-File:Width'] = 300

function Add-Separation {
    "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
}

# Enumerate User Rights Assignment (related to logon and audit rights) (Requires Administrator Privileges)
Write-Output "Enumerating User Rights Assignment (Requires Administrator Privileges)..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        secedit /export /cfg $env:TEMP\secpol.cfg
        Select-String -Path $env:TEMP\secpol.cfg -Pattern "Se*Logon*|SeAudit*" | ForEach-Object { $_.Line } | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    } catch {
        Write-Output "Failed to retrieve user rights assignment." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
} else {
    Write-Output "Insufficient privileges to retrieve user rights assignment." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
}

# Enumerate Antivirus Products Installed
Write-Output "Enumerating installed antivirus products..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct | Select-Object displayName, productState, pathToSignedProductExe, pathToSignedReportingExe | Format-Table -AutoSize | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8

# Check for Any Security Products Installed (Using Registry)
Write-Output "Checking for security products in registry..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'
Get-ChildItem -Path $regPath | Get-ItemProperty | Where-Object { $_.DisplayName -match 'antivirus|security|defender|firewall' } | Select-Object DisplayName, Publisher, InstallLocation | Format-Table -AutoSize | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8

# Enumerate Security-Related Services
Write-Output "Enumerating security-related services..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
Get-Service | Where-Object { $_.DisplayName -match 'antivirus|security|firewall|defender' } | Select-Object DisplayName, Status, Name | Format-Table -AutoSize | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8

# Enumerate Splunk Installation Directories
Write-Output "Enumerating Splunk installation directories..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
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
    }
} else {
    Write-Output "Insufficient privileges to retrieve Splunk installation directories." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
}

# Enumerate Splunk Configuration Files
Write-Output "Enumerating Splunk configuration files (inputs.conf, outputs.conf, props.conf)..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
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
    }
} else {
    Write-Output "Insufficient privileges to enumerate Splunk configuration files." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
}

# Enumerate Monitored Data Inputs from inputs.conf
Write-Output "Enumerating data inputs from inputs.conf..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
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
    }
} else {
    Write-Output "Insufficient privileges to enumerate data inputs from inputs.conf." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
}

# Enumerate Splunk HTTP Event Collectors (HEC)
Write-Output "Checking for HTTP Event Collectors (HEC) in inputs.conf..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
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
    }
} else {
    Write-Output "Insufficient privileges to check for HTTP Event Collectors (HEC)." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
}

# Enumerate Forwarder Configuration
Write-Output "Enumerating Splunk forwarder configurations (outputs.conf)..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
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
    }
} else {
    Write-Output "Insufficient privileges to enumerate forwarder configurations." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
}

# Search for Splunk Event Logs
Write-Output "Searching for Splunk-related event logs..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
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
    }
} else {
    Write-Output "Insufficient privileges to search for Splunk-related event logs." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} Add-Separation

# Enumerate Symantec Installation Directories
Write-Output "Enumerating Symantec installation directories (Requires Administrator Privileges)..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        $symantecPaths = @(
            "C:\Program Files\Symantec",
            "C:\Program Files\Symantec Endpoint Protection",
            "C:\Program Files (x86)\Symantec",
            "C:\Program Files (x86)\Symantec Endpoint Protection"
        )
        foreach ($path in $symantecPaths) {
            if (Test-Path $path) {
                Write-Output "Found Symantec directory: $path" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
            }
        }
    } catch {
        Write-Output "Failed to check Symantec installation directories." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
} else {
    Write-Output "Insufficient privileges to retrieve Symantec installation directories." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
}

# Enumerate Symantec Services
Write-Output "Enumerating Symantec-related services (Requires Administrator Privileges)..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        $symantecServices = Get-Service | Where-Object { $_.DisplayName -match "Symantec|SEP|Endpoint Protection" }
        if ($symantecServices) {
            foreach ($service in $symantecServices) {
                Write-Output "Found Symantec service: $($service.DisplayName) (Status: $($service.Status))" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
            }
        } else {
            Write-Output "No Symantec-related services found." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        }
    } catch {
        Write-Output "Failed to enumerate Symantec services." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
} else {
    Write-Output "Insufficient privileges to retrieve Symantec services." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
}

# Enumerate Symantec Processes
Write-Output "Enumerating Symantec processes..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
try {
    $symantecProcesses = Get-Process | Where-Object { $_.Name -match "symantec|sep|smc" }
    if ($symantecProcesses) {
        foreach ($process in $symantecProcesses) {
            Write-Output "Found Symantec process: $($process.Name) (ID: $($process.Id))" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        }
    } else {
        Write-Output "No Symantec processes found." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
} catch {
    Write-Output "Failed to enumerate Symantec processes." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
}

# Enumerate Symantec Registry Keys
Write-Output "Enumerating Symantec-related registry keys (Requires Administrator Privileges)..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        $symantecRegPaths = @(
            "HKLM:\SOFTWARE\Symantec",
            "HKLM:\SOFTWARE\WOW6432Node\Symantec",
            "HKLM:\SYSTEM\CurrentControlSet\Services\SepMasterService",
            "HKLM:\SYSTEM\CurrentControlSet\Services\Symantec Endpoint Protection"
        )
        foreach ($regPath in $symantecRegPaths) {
            if (Test-Path $regPath) {
                Write-Output "Found Symantec registry key: $regPath" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
            }
        }
    } catch {
        Write-Output "Failed to enumerate Symantec registry keys." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
} else {
    Write-Output "Insufficient privileges to retrieve Symantec registry keys." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
}

# Search for Symantec Event Logs
Write-Output "Searching for Symantec-related event logs..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
try {
    $symantecLogs = Get-WinEvent -ListLog * | Where-Object { $_.LogName -match "Symantec|SEP|Endpoint Protection" }
    if ($symantecLogs) {
        foreach ($log in $symantecLogs) {
            Write-Output "Found Symantec event log: $($log.LogName)" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        }
    } else {
        Write-Output "No Symantec-related event logs found." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
} catch {
    Write-Output "Failed to enumerate Symantec-related event logs." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} Add-Separation

# Enumerate Windows Defender Status
Write-Output "Enumerating Windows Defender status..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
try {
    $DefenderStatus = Get-MpComputerStatus
    Write-Output "Windows Defender Status:" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    "Antivirus Enabled: $($DefenderStatus.AntivirusEnabled)" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    "Real-Time Protection Enabled: $($DefenderStatus.RealTimeProtectionEnabled)" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    "Behavior Monitor Enabled: $($DefenderStatus.BehaviorMonitorEnabled)" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    "Antispyware Enabled: $($DefenderStatus.AntispywareEnabled)" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} catch {
    Write-Output "Windows Defender is not available or access is denied." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
}

# Enumerate Windows Defender Antivirus Exclusions
Write-Output "Enumerating Windows Defender antivirus exclusions (Requires Administrator Privileges)..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
try {
    $Exclusions = Get-MpPreference
    Write-Output "File Exclusions:" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    $Exclusions.ExclusionPath | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    Write-Output "Process Exclusions:" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    $Exclusions.ExclusionProcess | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    Write-Output "Extension Exclusions:" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    $Exclusions.ExclusionExtension | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    Write-Output "IP Address Exclusions:" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    $Exclusions.ExclusionIpAddress | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    Write-Output "Temporary Path Exclusions:" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    $Exclusions.ExclusionTemporaryPath | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} catch {
    Write-Output "Failed to retrieve Windows Defender antivirus exclusions." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} Add-Separation

# Enumerate Event 5007 Logs Related to Windows Defender Exclusions
Write-Output "Enumerating Windows Defender configuration change events (Event ID 5007) - Exclusions..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
try {
    $logName = "Microsoft-Windows-Windows Defender/Operational"
    $eventID = 5007
    $events = Get-WinEvent -LogName $logName | Where-Object { $_.Id -eq $eventID }
    $exclusionEvents = $events | Where-Object { $_.Message -match "Exclusions" }

    # Define patterns for different types of exclusions
    $patterns = @{
        'File Exclusions' = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\[^\s]+"
        'Process Exclusions' = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes\\[^\s]+"
        'Extension Exclusions' = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions\\[^\s]+"
        'IP Address Exclusions' = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\IpAddresses\\[^\s]+"
        'Temporary Path Exclusions' = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\TemporaryPaths\\[^\s]+"
    }

    foreach ($type in $patterns.Keys) {
        $pattern = $patterns[$type]
        $exclusionEvents | ForEach-Object {
            if ($_.Message -match $pattern) {
                Write-Output "Detected $type Change: $($matches[0])" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
            }
        }
    }
} catch {
    Write-Output "Failed to retrieve Event 5007 logs." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} Add-Separation

# Check for Audit Policies (Requires Administrator Privileges)
Write-Output "Enumerating audit policies (Requires Administrator Privileges)..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        AuditPol /get /category:* | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    } catch {
        Write-Output "Failed to retrieve audit policies." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
} else {
    Write-Output "Insufficient privileges to retrieve audit policies." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} Add-Separation

# Enumerate ASR (Attack Surface Reduction) Rules
Write-Output "Enumerating Attack Surface Reduction (ASR) rules..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
try {
    $ASRRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
    Write-Output "ASR Rules:" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    $ASRRules | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} catch {
    Write-Output "ASR rules not available or access is denied." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} Add-Separation

# Enumerate BitLocker Status (Requires Administrator Privileges)
Write-Output "Enumerating BitLocker status (Requires Administrator Privileges)..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, LockStatus | Format-Table -AutoSize | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    } catch {
        Write-Output "Failed to retrieve BitLocker status." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
} else {
    Write-Output "Insufficient privileges to retrieve BitLocker status." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} Add-Separation

# Display System Restore Status (Requires Administrator Privileges)
Write-Output "Enumerating System Restore status (Requires Administrator Privileges)..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        (Get-ComputerRestorePoint | Select-Object -Last 1) | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    } catch {
        Write-Output "Failed to retrieve system restore status." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
} else {
    Write-Output "Insufficient privileges to retrieve system restore status." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
} Add-Separation

# Enumerate Network-Based Defenses
Write-Output "Enumerating network-based defenses..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8

# Enumerate Network Adapters and Their Status
Write-Output "Enumerating network adapters and their status..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
ipconfig -all | Format-Table -AutoSize | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8

# Enumerate Active Network Connections
Write-Output "Enumerating active network connections..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
Get-NetTCPConnection | Format-Table -AutoSize | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8

# Enumerate Network Shares
Write-Output "Enumerating network shares..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
Get-SmbShare | Format-Table -AutoSize | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8

# Enumerate Windows Firewall Status
Write-Output "Enumerating Windows Firewall status..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules | Format-Table -AutoSize | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8

# Enumerate Windows Firewall Rules
Write-Output "Enumerating Windows Firewall rules..." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
Get-NetFirewallRule | Out-String | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8

# End of script logging
"Host and network-based defense enumeration complete." | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
```