# Network Enumeration

#### Network Interfaces and Configuration
- `ifconfig | ip a`: Display all network interfaces and their IP configurations.
- `ip link show`: Show the status of network interfaces (up, down, etc.).
- `nmcli device status`: List all network devices and their states (useful for NetworkManager).
- `nmcli connection show`: Show active and available network connections managed by NetworkManager.
- `cat /etc/network/interfaces`: View network interface configurations (Debian-based).
- `cat /etc/sysconfig/network-scripts/ifcfg-*`: View network interface configurations (RHEL-based).
- `resolvectl status`: Display DNS resolver configuration.
- `cat /etc/resolv.conf`: Show current DNS server configuration.

#### Active Network Connections
- `netstat -tulnp`: List all active listening ports along with the associated process.
- `ss -tulwn`: Similar to `netstat`, but shows sockets and open ports with faster performance.
- `lsof -i`: List open files and the associated network connections.
- `ss -an`: Display all active TCP and UDP connections.
- `netstat -an | grep ESTABLISHED`: Show all active network connections.
- `cat /proc/net/tcp | grep <target_ip>`: View details of specific TCP connections.
- `cat /proc/net/udp | grep <target_ip>`: View details of specific UDP connections.
- `netstat -r`: Display the system's routing table.

#### Firewall Configuration and Status
- `iptables -L`: Display all current iptables rules.
- `iptables -t nat -L`: Show NAT table rules.
- `iptables-save`: Export the current iptables rules for later analysis.
- `ufw status verbose`: Display UFW (Uncomplicated Firewall) status and rules (if applicable).
- `firewall-cmd --list-all`: Show active firewalld rules and zones (CentOS/RHEL/Fedora).
- `firewalld-cmd --list-ports`: List all open ports allowed by firewalld.

#### ARP and Neighbor Discovery
- `arp -a`: Display the ARP cache, showing local IP-to-MAC address mappings.
- `ip neigh`: Show neighbor table entries (ARP equivalent).
- `cat /proc/net/arp`: Access the ARP cache from the proc file system.
- `ip n`: Another way to display the ARP table (useful for verifying address mappings).
  
#### Routing Information
- `ip route show`: Display the routing table.
- `route -n`: Display the network routing table.
- `traceroute <target_ip>`: Trace the route packets take to reach a target host.
- `mtr <target_ip>`: A real-time network diagnostic tool combining traceroute and ping.
- `cat /etc/iproute2/rt_tables`: View custom routing tables.

# Advanced Network Enumeration

#### DNS Resolution and Lookup
- `nslookup <domain>`: Perform a simple DNS lookup for a domain.
- `dig <domain>`: Retrieve DNS records (A, MX, NS, etc.) for a specific domain.
- `dig +short <domain>`: Perform a short DNS lookup, returning only the answer.
- `dig -x <ip_address>`: Perform reverse DNS lookup.
- `host <domain>`: A simple DNS resolution utility that can look up forward and reverse DNS entries.
- `cat /etc/hosts`: View static IP-to-hostname mappings.
  
#### Wireless Network Information
- `iwconfig`: Display wireless network information (SSID, signal strength, etc.).
- `nmcli dev wifi list`: Show available Wi-Fi networks using NetworkManager.
- `airmon-ng`: Enable monitor mode for wireless interfaces (if installed).
- `airodump-ng <interface>`: Capture wireless packets for analysis (useful for sniffing Wi-Fi traffic).
  
#### Packet Capture and Analysis
- `tcpdump -i <interface>`: Start capturing packets on a specific interface.
- `tcpdump -i <interface> -w <output_file.pcap>`: Capture network traffic to a .pcap file for later analysis.
- `tcpdump -nn`: Disable hostname and service resolution in packet capture.
- `tcpdump -v`: Increase the verbosity level of packet output.
- `tshark`: Command-line tool for packet analysis (Wireshark’s command-line counterpart).
- `tshark -i <interface> -w <file.pcap>`: Capture traffic to a pcap file using TShark.
  
#### Service and Port Scanning
- `nmap -sT -Pn <target_ip>`: TCP connect scan of a target, skipping host discovery.
- `nmap -sS <target_ip>`: Perform a stealth SYN scan on the target.
- `nmap -p- <target_ip>`: Scan all 65,535 ports on the target.
- `nmap -O <target_ip>`: Attempt to detect the operating system of the target.
- `nmap -sV <target_ip>`: Perform version detection on open ports.
- `nmap --script=vuln <target_ip>`: Run vulnerability scanning scripts on the target.
- `nmap -sP <subnet>`: Ping sweep a subnet to identify live hosts.

# Network Service Enumeration

#### SSH Enumeration
- `ssh -v <user>@<target_ip>`: Verbose SSH connection attempt.
- `ssh-keyscan <target_ip>`: Gather SSH host keys from the target for analysis.
- `grep -i 'sshd' /etc/services`: Verify the SSH service and port in `/etc/services`.
- `lsof -i :22`: Identify the process using port 22 (SSH).

#### FTP Enumeration
- `ftp <target_ip>`: Basic FTP connection to a target.
- `nc <target_ip> 21`: Use Netcat to interact with the FTP service on port 21.
- `telnet <target_ip> 21`: Use Telnet to connect and test the FTP service.

#### Web Server Enumeration
- `curl -I <target_ip>`: Fetch HTTP headers from the target’s web server.
- `curl -v <target_ip>`: Perform a verbose HTTP request, showing all headers and response details.
- `wget --spider <target_ip>`: Perform a non-recursive retrieval, verifying if a URL exists.
- `nikto -h <target_ip>`: Scan a web server for vulnerabilities.
- `whatweb <target_ip>`: Identify web technologies used by the target server.

#### SMB Enumeration
- `smbclient -L //<target_ip>/`: List shares on an SMB server.
- `smbmap -H <target_ip>`: Enumerate shares and accessible files on a target SMB server.
- `enum4linux <target_ip>`: Comprehensive SMB enumeration for Linux systems.
- `rpcclient -U "" <target_ip>`: Connect to an SMB server to run SMB commands interactively.

#### NFS Enumeration
- `showmount -e <target_ip>`: Show exported file systems on the target (NFS server).
- `mount -t nfs <target_ip>:/<export> /mnt`: Mount an NFS export locally for further analysis.

#### LDAP Enumeration
- `ldapsearch -x -h <target_ip>`: Perform an anonymous LDAP search on the target.
- `ldapsearch -x -b "dc=example,dc=com" "(objectclass=*)"`: Perform a base search using LDAP.
  
#### MySQL Enumeration
- `mysql -h <target_ip> -u root -p`: Attempt to log in to a MySQL server.
- `mysqladmin -h <target_ip> -u root status`: Get the status of the MySQL server.
  
#### PostgreSQL Enumeration
- `psql -h <target_ip> -U postgres`: Connect to the PostgreSQL server using the `psql` client.
- `pg_isready -h <target_ip>`: Check if the PostgreSQL service is up and running.

# SNMP & VoIP Enumeration

#### SNMP Enumeration
- `snmpwalk -v 2c -c public <target_ip>`: Retrieve SNMP information from the target.
- `snmpget -v 2c -c public <target_ip> <OID>`: Query a specific OID (Object Identifier) from the target.
- `snmp-check <target_ip>`: Perform an SNMP enumeration check (requires snmp-check tool).
- `onesixtyone -c community.txt -i ips.txt`: SNMP community string brute-force.
- `snmp-check <target_ip>`: SNMPv2/v3 enumeration on the target.
- `snmpwalk -c public -v 2c <target_ip> .1.3.6.1.2.1.1`: Walk the SNMP MIB (Management Information Base).

#### VoIP Enumeration
- `svmap <target_ip>`: Scan for SIP servers.
- `sipvicious <target_ip>`: Use the SIPVicious toolkit for VoIP enumeration and vulnerability scanning.
  
# Advanced Network Discovery

#### ICMP and Ping Discovery
- `ping <target_ip>`: Send ICMP echo requests to check if the target is up.
- `ping -c 4 <target_ip>`: Send 4 ICMP echo requests.
- `fping -a -g <subnet>`: Fast ping sweep across a subnet to discover live hosts.
- `hping3 -S <target_ip> -p 80`: Send SYN packets to port 80 on the target.
  
#### NetBIOS Enumeration
- `nbtscan <subnet>`: Perform NetBIOS name table scan for a subnet.
- `nmblookup -A <target_ip>`: Query the NetBIOS name service for a target IP.
  
# VPN and Proxy Configuration Discovery

#### VPN Configuration
- `cat /etc/openvpn/*.conf`: View OpenVPN configuration files.
- `grep vpn /var/log/syslog`: Search logs for VPN-related events and connections.

#### Proxy Configuration
- `env | grep -i proxy`: Check for proxy environment variables.
- `cat /etc/environment | grep -i proxy`: View proxy settings from system-wide configuration.