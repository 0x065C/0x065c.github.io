# Check a Port on a Single IP
```powershell
Test-NetConnection -Port 80 10.10.10.10
```

# Check a List of Ports on a Single IP
```powershell
80,443,8080 | % { echo ((New-Object Net.Sockets.TcpClient).Connect("10.10.10.10", $_)) "Port $_ is open!" } 2>$null
```

# Check a Range of Ports
```powershell
1..1024 | % { echo ((New-Object Net.Sockets.TcpClient).Connect("10.10.10.10", $_)) "TCP port $_ is open" } 2>$null
```

# Scan Multiple IPs for Specific Ports
```powershell
"10.10.10.10","10.10.10.11" | % { $a = $_; write-host "[INFO] Testing $_ ..."; 80,443,445,8080 | % { echo ((New-Object Net.Sockets.TcpClient).Connect("$a", $_)) "$a : $_ is open!" } 2>$null }
```

# Custom Port Scan Script
```powershell
# Port Scanner Script
# This script will perform scans on the specified port range on the given target IP and outputs the results to a file.

# Usage:
# .\PortScan.ps1



# Input parameters
$target_ip = "192.168.1.100"     # Target IP address or hostname
$start_port = 1                  # Start of the port range
$end_port = 1000                 # End of the port range

# Initialize output file path
$OutputFilePath = "D:\PortScan_Results.txt"

# Ensure the output file is created/reset with UTF-8 encoding
New-Item -Path $OutputFilePath -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output file
$PSDefaultParameterValues['Out-File:Width'] = 300

# Function to check if a port is open
function Test-Port {
    param (
        [string]$target_ip,
        [int]$port
    )
    
    try {
        # Try to establish a TCP connection to the port
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($target_ip, $port)
        $tcpClient.Close()
        return $true
    } catch {
        return $false
    }
}

# Validate the input range
if ($start_port -gt $end_port) {
    Write-Host "Invalid port range: Start port is greater than end port."
    exit
}

# Write header to the output file
"Target IP: $target_ip" | Out-File -FilePath $OutputFilePath -Append -Encoding UTF8
"Scanning ports $start_port to $end_port" | Out-File -FilePath $OutputFilePath -Append -Encoding UTF8
"`n" | Out-File -FilePath $OutputFilePath -Append -Encoding UTF8

# Loop through the port range
for ($port = $start_port; $port -le $end_port; $port++) {
    if (Test-Port -target_ip $target_ip -port $port) {
        # If the port is open, write the result to the output file
        "Port $port is OPEN" | Out-File -FilePath $OutputFilePath -Append -Encoding UTF8
    } else {
        # Write closed port information to the output file
        "Port $port is CLOSED" | Out-File -FilePath $OutputFilePath -Append -Encoding UTF8
    }
}

# Append completion message to the output file
"Port scan on $target_ip completed." | Out-File -FilePath $OutputFilePath -Append -Encoding UTF8
"`n" | Out-File -FilePath $OutputFilePath -Append -Encoding UTF8
```