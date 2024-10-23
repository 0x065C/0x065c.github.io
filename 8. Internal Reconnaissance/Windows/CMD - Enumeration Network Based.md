# IP Address and Network Configuration

#### Basic IP Configuration
- `ipconfig`: Display basic IP configuration (IP, subnet mask, gateway).
- `ipconfig /all`: Detailed IP configuration, including MAC, DHCP, and DNS info.
- `netsh interface ip show config`: Show IP configuration for all network interfaces.

#### Adapter Information
- `wmic nic get Name,NetConnectionID,MACAddress`: Lists all network adapters with their names, connection IDs, and MAC addresses.
- `getmac`: Displays MAC addresses and associated network adapters.
- `netsh interface show interface`: Lists all network interfaces and their statuses.

# Routing Table and Gateway Information

#### Routing Table
- `route print`: Display the current routing table.
- `netstat -r`: Display the routing table along with active connections.

#### Default Gateway
- `ipconfig | findstr /i "Gateway"`: Display the default gateway for each interface.

# DNS Enumeration

#### DNS Server Information
- `ipconfig /displaydns`: Display the DNS cache, showing recently resolved hostnames.
- `nslookup`: Interactive DNS query tool to resolve hostnames.
- `nslookup <hostname>`: Query DNS for a specific hostname.
- `ipconfig /flushdns`: Clear the DNS cache.

#### DNS Resolution
- `nslookup <hostname>`: Perform a DNS query to resolve the IP address for a hostname.
- `ping <hostname>`: Resolve the hostname to an IP address and ping the destination.

# Active Connections and Listening Ports

#### Active Network Connections
- `netstat -an`: List all active network connections and listening ports.
- `netstat -ano`: Display active connections with associated process IDs (PIDs).
- `netstat -b`: Display connections along with the executable responsible for the connection.

#### Listening Ports
- `netstat -an | findstr LISTENING`: Show all listening ports.

#### Detailed Netstat Information
- `netstat -s`: Display detailed statistics for network protocols, including TCP, UDP, ICMP.
- `netstat -e`: Show Ethernet statistics, including bytes sent and received.

# Firewall and Security Settings

#### Firewall Profile Information
- `netsh advfirewall show allprofiles`: Display the status of all firewall profiles (Domain, Private, Public).
- `netsh advfirewall show currentprofile`: Show the currently active firewall profile.

#### Firewall Rules
- `netsh advfirewall firewall show rule name=all`: List all configured firewall rules.
- `netsh advfirewall firewall show rule name="<rule_name>"`: Show details of a specific firewall rule.

#### Firewall Configuration
- `netsh advfirewall firewall show rule name=all`: Display all firewall rules with detailed information.

# ARP Cache and Neighbor Information

#### ARP Cache
- `arp -a`: Display the ARP cache, mapping IP addresses to MAC addresses.
  
# Wireless Network Enumeration

#### Wi-Fi Profiles and Network Information
- `netsh wlan show profiles`: Display all saved wireless network profiles on the system.
- `netsh wlan show interfaces`: Show detailed info about the active wireless network interface.
- `netsh wlan show networks mode=bssid`: Display nearby wireless networks with SSIDs and signal strengths.

#### Wireless Network Security Information
- `netsh wlan show profile <profile_name> key=clear`: Display the saved password for a wireless profile in clear text.

# Neighboring Hosts and Network Discovery

#### ICMP Ping and Connectivity Testing
- `ping <hostname_or_IP>`: Ping a host to check connectivity.
- `tracert <hostname_or_IP>`: Perform a traceroute to a host, showing the path and hops taken.

# SMB and Network Shares

#### Enumerate Local Shares
- `net share`: Display shared resources on the local machine.

#### Enumerate Remote Shares
- `net view \\<target_host>`: Display shared resources on a remote host.

#### Mounting and Managing Network Drives
- `net use <drive_letter> \\<target_host>\<share>`: Map a network drive to a remote SMB share.
- `net use`: List all active network connections and mapped drives.

# Network Services Enumeration

#### DHCP Information
- `ipconfig /all`: Show DHCP configuration details for each network adapter.

#### NetBIOS Information
- `nbtstat -A <target_IP>`: Display the NetBIOS name table for a remote host by its IP address.
- `nbtstat -n`: Show the NetBIOS name table for the local machine.

# Proxy and Web Proxy Configuration

#### Proxy Configuration
- `netsh winhttp show proxy`: Display the current proxy configuration.

# Network Diagnostics and Performance

#### Network Statistics and Throughput
- `netstat -e`: Display Ethernet statistics including bytes sent and received.
- `netstat -s`: Show statistics for all network protocols (TCP, UDP, ICMP, etc.).