# Summary 
Active reconnaissance is the process of gathering information about a target by directly interacting with its systems, networks, or services. Unlike passive reconnaissance, which relies on indirect methods that don't touch the target, active reconnaissance involves actions that could potentially be detected by the target organization. This phase is crucial for obtaining detailed, actionable data that can lead to successful exploitation during a penetration test or red team operation.

Active reconnaissance can be divided into several key techniques:

1. **Network Scanning**
2. **Port Scanning**
3. **Service Enumeration**
4. **Operating System Fingerprinting**
5. **Banner Grabbing**
6. **Vulnerability Scanning**
7. **Web Application Enumeration**
8. **SMB and NetBIOS Enumeration**
9. **SNMP Enumeration**
10. **Wireless Network Scanning**

# Network Scanning

Network scanning is the process of identifying active hosts within a target network. This is typically the first step in active reconnaissance and helps the penetration tester map out the network.

#### Host Discovery
- **Purpose:** Identify live hosts on the network.
- **Tools:**
  - `Nmap`: A versatile network scanning tool.
  - `Ping`: A simple utility to check the reachability of a host.
- **Command Examples:**
  - **Nmap Ping Sweep:**
    ```bash
    nmap -sn <target_ip_range>
    ```
    - **Example:**
      ```bash
      nmap -sn 192.168.1.0/24
      ```
  - **Ping:**
    ```bash
    ping -c 4 <target_ip>
    ```
    - **Example:**
      ```bash
      ping -c 4 192.168.1.1
      ```

#### ARP Scanning
- **Purpose:** Identify live hosts on a local network using Address Resolution Protocol (ARP).
- **Tools:**
  - `arp-scan`: A command-line tool for ARP scanning.
- **Command Example:**
  ```bash
  sudo arp-scan --localnet
  ```
  - **Example:**
    ```bash
    sudo arp-scan --localnet
    ```

#### ICMP Scanning
- **Purpose:** Identify live hosts using Internet Control Message Protocol (ICMP) echo requests (ping).
- **Tools:**
  - `Nmap`
- **Command Example:**
  ```bash
  nmap -PE <target_ip_range>
  ```
  - **Example:**
    ```bash
    nmap -PE 192.168.1.0/24
    ```

# Port Scanning

Port scanning is the process of identifying open ports on a target system. Each open port represents a potential entry point for an attacker, as it indicates that a service is listening for connections.

#### Full TCP Port Scan
- **Purpose:** Identify all open TCP ports on a target system. This method is thorough but can be time-consuming.
- **Tools:**
  - `Nmap`
- **Command Example:**
  ```bash
  nmap -p- <target_ip>
  ```
  - **Example:**
    ```bash
    nmap -p- 192.168.1.1
    ```

#### SYN Scan (Half-Open Scan)
- **Purpose:** Perform a faster, stealthier scan by only sending SYN packets and analyzing responses without completing the TCP handshake. This method is often referred to as a "stealth scan."
- **Tools:**
  - `Nmap`
- **Command Example:**
  ```bash
  nmap -sS <target_ip>
  ```
  - **Example:**
    ```bash
    nmap -sS 192.168.1.1
    ```

#### UDP Scan
- **Purpose:** Identify open UDP ports on a target system. UDP scanning is slower and less reliable than TCP scanning because of the lack of a three-way handshake in UDP communications.
- **Tools:**
  - `Nmap`
- **Command Example:**
  ```bash
  nmap -sU <target_ip>
  ```
  - **Example:**
    ```bash
    nmap -sU 192.168.1.1
    ```

#### Version Detection
- **Purpose:** Identify the version of the service running on an open port. This helps in determining specific vulnerabilities associated with the service.
- **Tools:**
  - `Nmap`
- **Command Example:**
  ```bash
  nmap -sV <target_ip> -p <target_port>
  ```
  - **Example:**
    ```bash
    nmap -sV 192.168.1.1 -p 80
    ```

# Service Enumeration

Service enumeration involves gathering detailed information about the services running on the open ports identified during port scanning. This includes the service type, version, and sometimes even configuration details.

#### Banner Grabbing
- **Purpose:** Capture banners that are typically returned by services when a connection is established. Banners often contain useful information such as the software version and OS.
- **Tools:**
  - `Telnet`
  - `Netcat`
  - `Nmap`
- **Command Examples:**
  - **Netcat:**
    ```bash
    nc -v <target_ip> <target_port>
    ```
    - **Example:**
      ```bash
      nc -v 192.168.1.1 80
      ```
  - **Telnet:**
    ```bash
    telnet <target_ip> <target_port>
    ```
    - **Example:**
      ```bash
      telnet 192.168.1.1 80
      ```

#### Detailed Service Enumeration
- **Purpose:** Gather detailed information about a specific service to identify vulnerabilities or misconfigurations.
- **Tools:**
  - `Nmap` with specific scripts
  - `enum4linux`: A tool for enumerating information from Windows systems via SMB.
- **Command Example:**
  ```bash
  nmap --script smb-enum-shares.nse,smb-enum-users.nse -p 445 <target_ip>
  ```
  - **Example:**
    ```bash
    nmap --script smb-enum-shares.nse,smb-enum-users.nse -p 445 192.168.1.1
    ```

# Operating System Fingerprinting

Operating system fingerprinting is the process of determining the operating system running on a target host. This information is crucial for tailoring attacks to specific vulnerabilities associated with that OS.

#### Active OS Fingerprinting
- **Purpose:** Identify the target’s operating system based on TCP/IP stack characteristics.
- **Tools:**
  - `Nmap`
- **Command Example:**
  ```bash
  nmap -O <target_ip>
  ```
  - **Example:**
    ```bash
    nmap -O 192.168.1.1
    ```

#### TCP/IP Stack Fingerprinting
- **Purpose:** Gather information about the OS by analyzing how it responds to specific network probes.
- **Tools:**
  - `Xprobe2`: A tool specifically designed for OS fingerprinting using active probes.
- **Command Example:**
  ```bash
  xprobe2 <target_ip>
  ```
  - **Example:**
    ```bash
    xprobe2 192.168.1.1
    ```

# Banner Grabbing

Banner grabbing, though already mentioned in service enumeration, is an essential technique in active reconnaissance. It involves connecting to a service to retrieve the initial information provided by the service (the "banner"), which often includes software version and other details.

#### HTTP Banner Grabbing
- **Purpose:** Retrieve HTTP banners from web servers to identify the server type and version.
- **Tools:**
  - `Curl`
  - `Netcat`
- **Command Example:**
  - **Curl:**
    ```bash
    curl -I <target_url>
    ```
    - **Example:**
      ```bash
      curl -I http://example.com
      ```
  - **Netcat:**
    ```bash
    echo -e "HEAD / HTTP/1.1\r\nHost: <target_domain>\r\n\r\n" | nc <target_ip> <target_port>
    ```
    - **Example:**
      ```bash
      echo -e "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n" | nc 192.168.1.1 80
      ```

# Vulnerability Scanning

Vulnerability scanning is the process of automatically identifying known vulnerabilities within the target systems and services. This step is often performed after the initial reconnaissance to focus on specific areas of interest.

#### Automated Vulnerability Scanning
- **Purpose:** Identify known vulnerabilities in the target’s systems or applications.
- **Tools:**
  - `Nessus`
  - `OpenVAS`
- **Command Example:**
  - **Nessus CLI Example:** (Start a scan, though usually managed via GUI)
    ```bash
    nessuscli scan --start <scan_id>
    ```
  - **OpenVAS Scan Command:**
    ```bash
    omp -u <username> -w <password> -h <host> -p <port> -S -iX <scan_config

_id>
    ```

#### Specific Vulnerability Checks
- **Purpose:** Manually test for specific vulnerabilities that are of particular interest or are not covered by automated scanners.
- **Tools:**
  - `Nmap` scripts
  - `Metasploit`
- **Command Example with Nmap Script:**
  ```bash
  nmap --script http-vuln-cve2017-5638.nse -p 80 <target_ip>
  ```
  - **Example:**
    ```bash
    nmap --script http-vuln-cve2017-5638.nse -p 80 192.168.1.1
    ```

# Web Application Enumeration

Web application enumeration focuses on identifying and mapping out web-based services and applications that may be vulnerable to various attacks.

#### Web Application Scanning
- **Purpose:** Identify web applications running on the target and test for common vulnerabilities.
- **Tools:**
  - `Nikto`: A web server scanner that detects various vulnerabilities.
  - `Burp Suite`: A comprehensive web vulnerability scanner.
- **Command Example:**
  - **Nikto:**
    ```bash
    nikto -h <target_url>
    ```
    - **Example:**
      ```bash
      nikto -h http://example.com
      ```

#### Directory and File Enumeration
- **Purpose:** Identify hidden or unlisted directories and files within a web application.
- **Tools:**
  - `Dirb`: A web content scanner.
  - `Gobuster`: A tool for brute-forcing directories and files.
- **Command Example:**
  - **Gobuster:**
    ```bash
    gobuster dir -u <target_url> -w <wordlist>
    ```
    - **Example:**
      ```bash
      gobuster dir -u http://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
      ```

# SMB and NetBIOS Enumeration

SMB (Server Message Block) and NetBIOS are protocols used primarily in Windows environments. Enumerating SMB and NetBIOS can provide valuable information about the target network, such as shared resources, user accounts, and open sessions.

#### SMB Enumeration
- **Purpose:** Gather information about shared resources, users, and services running on SMB.
- **Tools:**
  - `enum4linux`: A tool for SMB enumeration.
  - `smbclient`: A command-line tool for accessing SMB/CIFS resources.
- **Command Example:**
  - **enum4linux:**
    ```bash
    enum4linux -a <target_ip>
    ```
    - **Example:**
      ```bash
      enum4linux -a 192.168.1.1
      ```

#### NetBIOS Enumeration
- **Purpose:** Discover NetBIOS names, shares, and services on the target network.
- **Tools:**
  - `nbtscan`: A tool for scanning NetBIOS name servers.
  - `nmblookup`: A tool to lookup NetBIOS names.
- **Command Example:**
  - **nbtscan:**
    ```bash
    nbtscan <target_ip_range>
    ```
    - **Example:**
      ```bash
      nbtscan 192.168.1.0/24
      ```

# SNMP Enumeration

Simple Network Management Protocol (SNMP) is used for managing devices on IP networks. Enumerating SNMP can reveal a lot about the target network, including network infrastructure, running services, and system configurations.

#### SNMP Walk
- **Purpose:** Query an SNMP-enabled device to retrieve a large amount of information, such as system details, network interfaces, and running processes.
- **Tools:**
  - `snmpwalk`: A command-line tool to retrieve data from an SNMP-enabled device.
- **Command Example:**
  ```bash
  snmpwalk -v 2c -c public <target_ip>
  ```
  - **Example:**
    ```bash
    snmpwalk -v 2c -c public 192.168.1.1
    ```

#### SNMP Enumeration
- **Purpose:** Identify SNMP-enabled devices and gather information about their configurations and services.
- **Tools:**
  - `onesixtyone`: An SNMP scanner.
- **Command Example:**
  ```bash
  onesixtyone -c public <target_ip>
  ```
  - **Example:**
    ```bash
    onesixtyone -c public 192.168.1.1
    ```

# Wireless Network Scanning

Wireless network scanning involves identifying wireless access points, clients, and potential vulnerabilities in the wireless network.

#### Wireless Access Point Discovery
- **Purpose:** Identify wireless access points and their configurations.
- **Tools:**
  - `Airodump-ng`: A tool for capturing wireless network traffic.
- **Command Example:**
  ```bash
  airodump-ng <wireless_interface>
  ```
  - **Example:**
    ```bash
    airodump-ng wlan0
    ```

#### Wireless Client Enumeration
- **Purpose:** Identify clients connected to a wireless network.
- **Tools:**
  - `Airodump-ng`
- **Command Example:**
  ```bash
  airodump-ng --bssid <target_bssid> --channel <channel> --write <output_file> <wireless_interface>
  ```
  - **Example:**
    ```bash
    airodump-ng --bssid 00:11:22:33:44:55 --channel 6 --write capture wlan0
    ```
