# Ping a Single IP
```powershell
ping <target_ip> -n <number of packets>
```

```powershell
Test-Connection -ComputerName <target_ip> -Count <number_of_pings> -BufferSize <buffer_size> -Delay <delay_in_seconds>
```

```powershell
Test-NetConnection -ComputerName <target_ip>
```

# Ping Sweep
```powershell
$ping = New-Object System.Net.Networkinformation.Ping
1..254 | % { $ping.send("10.9.15.$_") | select address, status }
```

# Custom Ping Sweep Script
```powershell
# Ping Sweep Script
# This script will perform a ping sweep on all subnets attached to the local machine and log active hosts and their hostnames.

# Usage: 
# .\PingSweep.ps1



# Initialize output file path
$OutputFilePath = "D:\PingSweep_Results.txt"

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $OutputFilePath -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output file
$PSDefaultParameterValues['Out-File:Width'] = 300

# Set the ICMP timeout period (in milliseconds)
$icmpTimeout = 1000

# Function to check ICMP response using Ping.exe
function Test-PingHost {
    param (
        [string]$IPAddress,
        [int]$Timeout
    )
    $pingResult = Test-Connection -ComputerName $IPAddress -Count 1 -Quiet
    return $pingResult
}

# Function to perform DNS resolution
function Resolve-Hostname {
    param (
        [string]$IPAddress
    )
    try {
        $dnsResult = Resolve-DnsName -Name $IPAddress -ErrorAction Stop
        return $dnsResult.NameHost
    } catch {
        return "Unknown"
    }
}

# Function to get all local IP subnets, including DHCP and static addresses
function Get-LocalSubnets {
    # Get all IPv4 addresses excluding loopback (127.0.0.1)
    $localIPs = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" }

    $subnets = @()

    foreach ($ip in $localIPs) {
        # Extract the first three octets for subnet calculation (assume /24)
        $subnet = $ip.IPAddress.Substring(0, $ip.IPAddress.LastIndexOf("."))
        if (-not ($subnets -contains $subnet)) {
            $subnets += $subnet
        }
    }

    return $subnets
}

# Get the list of subnets for all interfaces on the local machine
$subnets = Get-LocalSubnets

# Iterate over each subnet
foreach ($subnet in $subnets) {
    # Define the IP range (e.g., 192.168.50.0/24)
    $ipRange = 1..254

    $totalIPs = $ipRange.Count
    $currentIP = 0

    # Iterate over each IP address in the range
    foreach ($i in $ipRange) {
        $ip = "$subnet.$i"
        $currentIP++

        # Check if the IP responds to ping with a short timeout
        if (Test-PingHost -IPAddress $ip -Timeout $icmpTimeout) {
            try {
                # Resolve hostname if ping is successful
                $hostname = Resolve-Hostname -IPAddress $ip

                # Log the IP and hostname to the output file
                $logEntry = "IP: $ip - Hostname: $hostname"
                Add-Content -Path $OutputFilePath -Value $logEntry
                Add-Content -Path $OutputFilePath -Value "`n" # Add a newline for readability
            } catch {
                # If DNS resolution fails, log as unknown
                Add-Content -Path $OutputFilePath -Value "IP: $ip - Hostname: Unknown"
                Add-Content -Path $OutputFilePath -Value "`n"
            }
        }
    }
}

# Log the end of the scan
Add-Content -Path $OutputFilePath -Value "Ping sweep completed."
Add-Content -Path $OutputFilePath -Value "`n"
```