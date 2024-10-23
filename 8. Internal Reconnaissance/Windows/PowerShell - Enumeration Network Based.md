# IP Address and Network Configuration

#### Basic IP Configuration
- `ipconfig`: Display basic IP configuration (IP, subnet mask, gateway).
- `ipconfig /all`: Detailed IP configuration, including MAC, DHCP, and DNS info.
- `Get-NetIPAddress`: Get all IP addresses configured on the system.
- `Get-NetIPConfiguration`: Retrieve configuration details of all network interfaces.
- `Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $True }`: Show detailed info for enabled network interfaces.

#### Adapter Information
- `Get-NetAdapter`: List all network adapters and their current status.
- `Get-NetAdapter | Select-Object Name, Status, MACAddress, LinkSpeed`: Show status, MAC address, and link speed.
- `Get-NetAdapterAdvancedProperty -Name <adapter_name>`: Show advanced properties of a specific adapter.
- `Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.NetEnabled -eq $True }`: List network adapters enabled for network traffic.

#### MAC Address Information
- `Get-NetAdapter | Select-Object Name, MacAddress`: Show MAC addresses for all network interfaces.
- `Get-WmiObject -Class Win32_NetworkAdapter`: Retrieve detailed MAC address and adapter info.

#### Network Profiles
- `Get-NetConnectionProfile`: Display network profile details (Public, Private, Domain) for all network interfaces.
- `Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq 'Public' }`: List interfaces categorized under the 'Public' profile.

# Routing Table and Gateway Information

#### Routing Table
- `route print`: Display the current routing table.
- `Get-NetRoute`: Retrieve detailed routing table via PowerShell.
- `Get-WmiObject -Class Win32_IP4RouteTable`: Retrieve IPv4 routing table from WMI.
  
#### Default Gateway
- `Get-NetIPConfiguration | Select-Object -ExpandProperty IPv4DefaultGateway`: Show default gateway for each interface.
- `Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.DefaultIPGateway }`: Show default gateways configured on active interfaces.

# DNS Enumeration

#### DNS Server Information
- `ipconfig /displaydns`: Display the DNS cache, showing recently resolved hostnames.
- `Get-DnsClientServerAddress`: Show DNS servers configured for each network interface.
- `Get-NetIPConfiguration | Select-Object -ExpandProperty DnsServerAddresses`: Display DNS server addresses used by the host.
- `Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Select-Object DNSHostName, DNSDomain, DNSServerSearchOrder`: Show DNS hostname, domain, and DNS server addresses.

#### DNS Resolution
- `Resolve-DnsName <hostname>`: Resolve a DNS name and get the corresponding IP addresses.
- `Resolve-DnsName <hostname> -Server <dns_server>`: Perform DNS resolution using a specific DNS server.
- `nslookup <hostname>`: Query the DNS for details about a specific hostname.
- `Get-DnsClientCache`: Retrieve the local DNS client cache.

# Active Connections and Listening Ports

#### Active Network Connections
- `netstat -an`: List all active connections and listening ports.
- `netstat -ano`: Display active connections and associated process IDs (PIDs).
- `Get-NetTCPConnection`: Display detailed info on active TCP connections (local/remote addresses, ports, state).
- `Get-NetUDPEndpoint`: List all active UDP connections and listening UDP ports.

#### Listening Ports
- `netstat -ano | findstr LISTEN`: List all actively listening TCP ports and their associated PIDs.
- `Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }`: Show all listening TCP ports.

#### Detailed Netstat Information
- `netstat -s`: Show detailed statistics for network protocols, including TCP, UDP, ICMP.
- `netstat -r`: Show the routing table alongside active connections.

# Firewall and Security Settings

#### Firewall Profile Information
- `Get-NetFirewallProfile`: Display firewall settings for Domain, Private, and Public profiles.
- `Get-NetFirewallProfile | Select-Object -Property Profile, Enabled, DefaultInboundAction, DefaultOutboundAction`: Show default inbound/outbound policies for each firewall profile.
- `netsh advfirewall show allprofiles`: Display firewall configuration for all profiles.

#### Firewall Rules
- `Get-NetFirewallRule`: List all configured firewall rules.
- `Get-NetFirewallRule -DisplayName "<rule_name>"`: Display detailed information about a specific firewall rule.
- `Get-NetFirewallPortFilter`: List firewall rules that filter specific ports.
- `Get-NetFirewallAddressFilter`: Show firewall rules that apply to specific IP addresses.

#### Firewall Configuration
- `netsh advfirewall firewall show rule name=all verbose`: Display all firewall rules with detailed information.
- `Get-NetFirewallRule | Where-Object { $_.Enabled -eq $True }`: List only the enabled firewall rules.

#### Open Ports and Firewall Settings
- `Get-NetFirewallPortFilter | Select-Object LocalPort, Protocol`: Show which ports are allowed or blocked by firewall rules.
- `netsh advfirewall firewall show rule name=all`: Show all firewall rules, including port-based filtering rules.

# ARP Cache and Neighbor Information

#### ARP Cache
- `arp -a`: Display the ARP cache, mapping IP addresses to MAC addresses.
- `Get-NetNeighbor`: Show detailed information from the ARP cache, including IP and MAC address mappings.
- `Get-NetNeighbor | Where-Object { $_.State -eq 'Reachable' }`: List only ARP entries that are currently reachable.

# Wireless Network Enumeration

#### Wi-Fi Profiles and Network Information
- `netsh wlan show profiles`: Display all saved wireless network profiles on the system.
- `netsh wlan show interfaces`: Show detailed info about the active wireless network interface, including connected SSID, signal strength, and security.
- `netsh wlan show networks mode=bssid`: Display nearby wireless networks (SSID, signal strength, channel).

#### Wireless Network Security Information
- `netsh wlan show profile <profile_name> key=clear`: Display detailed information about a wireless network profile, including the saved password (if applicable).
- `netsh wlan export profile key=clear folder=<path>`: Export the Wi-Fi profile details, including the password, to a file.

# Neighboring Hosts and Network Discovery

#### ICMP Ping and Connectivity Testing
- `Test-Connection <hostname_or_IP>`: Perform a ping test to a specified host.
- `Test-Connection <hostname_or_IP> -Count 4`: Ping a host 4 times and display the results.
- `Test-NetConnection <hostname_or_IP>`: Test network connectivity to a remote host, including TCP port testing.
- `tracert <hostname_or_IP>`: Perform a traceroute to identify the path taken to reach a remote host.
- `traceroute <hostname_or_IP>`: Alternative traceroute syntax (available in some environments).

#### Port Scanning
- `Test-NetConnection -ComputerName <hostname_or_IP> -Port <port>`: Check if a specific port is open on a remote host.
- `Test-Port -IPAddress <hostname_or_IP> -Port <port>`: Custom port-scanning function to test open ports on a remote host.

# SMB and Network Shares

#### Enumerate Local Shares
- `Get-SmbShare`: List all SMB shares on the local system.
- `Get-WmiObject -Query "Select * from Win32_Share"`: Retrieve network shares using WMI.
- `net share`: Display the current shared resources on the local machine.

#### Enumerate Remote Shares
- `net view \\<target_host>`: View shared resources on a remote host.
- `Get-SmbSession`: List active SMB sessions, showing which users have connected.
- `Get-SmbOpenFile`: Show open files that are accessed through SMB on the system.

#### Mounting and Managing Network Drives
- `net use <drive_letter> \\<target_host>\<share>`: Map a network drive to a remote SMB share.
- `Get-PSDrive -PSProvider FileSystem`: List all file system drives, including mounted network shares.
- `net use`: Display all active network connections and mapped drives.

# Network Services Enumeration

#### DHCP Information
- `Get-WmiObject -Query "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE DHCPEnabled = 'TRUE'"`: Display detailed DHCP configuration.
- `ipconfig /all | findstr /i "DHCP"`: Show the DHCP lease information for each adapter.
- `Get-DhcpServerv4Scope`: Retrieve DHCP scope information (requires DHCP module).

#### NetBIOS Information
- `nbtstat -A <target_IP>`: Query the NetBIOS name table for

 a remote host by its IP address.
- `nbtstat -n`: Show the NetBIOS name table for the local machine.
- `nbtstat -s`: Display active NetBIOS sessions and their status.

#### SNMP Enumeration (If Enabled)
- `Get-WmiObject -Namespace root\cimv2 -Query "Select * from Win32_Service where name='SNMP'": Check if SNMP service is enabled and running.
- `snmpwalk -v 2c -c public <target_IP>`: Use SNMPWalk (external tool) to enumerate SNMP data from a remote host.

# Proxy and Web Proxy Configuration

#### Proxy Configuration
- `Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"`: Show proxy settings from the registry.
- `netsh winhttp show proxy`: Display the current proxy configuration for WinHTTP.
- `Get-WmiObject -Namespace root\cimv2 -Query "SELECT * FROM Win32_Proxy"`: Show proxy settings using WMI.

# Network Diagnostics and Performance

#### Network Statistics and Throughput
- `Get-NetAdapterStatistics`: Display traffic statistics for each network adapter (packets sent/received, errors).
- `netstat -e`: Display Ethernet statistics, including bytes and packets sent/received.
- `netstat -s`: Show statistics for all network protocols (TCP, UDP, ICMP, etc.).

#### Interface Bandwidth Utilization
- `Get-NetAdapter | Get-NetAdapterStatistics`: Display detailed statistics, including bytes sent/received, errors, and discard rates.
- `Get-NetAdapter | Select-Object Name, LinkSpeed`: Display link speed for all network interfaces.
