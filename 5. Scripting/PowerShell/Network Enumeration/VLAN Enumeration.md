```powershell
# PowerShell script to identify and enumerate VLANs on the network
# Note: Requires SNMP community strings for querying switches

# Initialize output file paths
$Step1_OutputFilePath = "D:\Step1_VLAN_Information.txt"
$Step2_OutputFilePath = "D:\Step2_Network_Adapters.txt"

# Ensure the output files are created/reset with UTF-8 encoding
New-Item -Path $Step1_OutputFilePath -ItemType File -Force | Out-Null
New-Item -Path $Step2_OutputFilePath -ItemType File -Force | Out-Null

# Set a large width to prevent line wrapping in the output file
$PSDefaultParameterValues['Out-File:Width'] = 300

# Define the SNMP community string and list of switches to query
$communityString = "public"  # Replace with the actual SNMP community string
$switches = @("<switch_ip1>", "<switch_ip2>")  # Replace with actual switch IPs

# Function to perform an SNMP query
function Get-SNMPv2Value {
    param (
        [string]$ip,
        [string]$oid
    )
    try {
        $snmpResult = snmpget -v 2c -c $communityString $ip $oid 2>&1
        return $snmpResult
    }
    catch {
        Write-Error "Failed to query SNMP on $ip with OID $oid"
    }
}

# OIDs for VLAN information (depending on switch vendor, OIDs may vary)
$vlanOid = "1.3.6.1.2.1.17.7.1.4.3.1.1"  # Common OID for VLAN IDs on some switches

# Enumerate VLANs on each switch
foreach ($switch in $switches) {
    Write-Output "Querying VLAN information from switch: $switch"
    $vlanInfo = Get-SNMPv2Value -ip $switch -oid $vlanOid
    if ($vlanInfo) {
        "Switch: $switch" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        "VLAN Information:" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        $vlanInfo | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
    else {
        "No VLAN information retrieved from switch: $switch" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
        "`n" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
    }
}

# Enumerate network adapters on domain machines
$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

foreach ($computer in $computers) {
    try {
        $networkAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $computer -ErrorAction Stop | Where-Object { $_.IPEnabled -eq $true }
        foreach ($adapter in $networkAdapters) {
            "Computer: $computer" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
            "Description: $($adapter.Description)" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
            "MAC Address: $($adapter.MACAddress)" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
            "IP Address: $($adapter.IPAddress)" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
            "Subnet: $($adapter.IPSubnet)" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
            "----------------------------------------" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
            "`n" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
        }
    }
    catch {
        "Failed to get network adapter information from $computer" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
        "`n" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
    }
}

# End of script logging
"VLAN Enumeration Completed" | Out-File -FilePath $Step1_OutputFilePath -Append -Encoding UTF8
"Network Adapter Enumeration Completed" | Out-File -FilePath $Step2_OutputFilePath -Append -Encoding UTF8
```