# Index
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]

# Nmap

Nmap (Network Mapper) is one of the most powerful and versatile network scanning tools used in penetration testing, network inventory, security auditing, and vulnerability scanning. This ultimate edition provides a comprehensive overview of Nmap’s commands, detailed explanations, and advanced usage scenarios.

## Basic Syntax
```bash
nmap [Scan Type(s)] [Options] <target_ip>/<target_range>
```

## Core Options
- `-sS`: SYN scan (stealth scan, half-open scan).
- `-sT`: TCP connect scan (complete connection).
- `-sU`: UDP scan.
- `-sP` / `-sn`: Ping scan (host discovery only).
- `-O`: OS detection.
- `-sV`: Version detection for services.
- `-A`: Aggressive scan, includes OS detection, version detection, and traceroute.
- `-p <port_range>`: Specify target ports or ranges.
- `-T0` to `-T5`: Timing options, with `T0` being slowest/stealthiest and `T5` being fastest.
- `-v`: Verbose mode.
- `-vv`: Very verbose mode.
- `-Pn`: Skip host discovery, assume all hosts are online.
- `-F`: Fast scan, scans only top 100 ports.
- `-r`: Scan ports in sequential order (default is random).
- `--open`: Show only open ports.
- `-iL <input_file>`: Read targets from a file.
- `-oN`/`-oX`/`-oG`: Output in normal, XML, or grepable formats respectively.
- `-n`: Disable DNS resolution.
- `-R`: Always resolve DNS.

# Commands and Use Cases

#### Target Specification

1. **Scan Single IP**:
	```bash
	nmap 192.168.1.1
	```
2. **Scan Specific IPs**:
	```bash
	nmap 192.168.1.1 192.168.2.1
	```
3. **Scan IP Range**:
	```bash
	nmap 192.168.1.1-254
	```
4. **Scan a Domain**:
	```bash
	nmap scanme.nmap.org
	```
5. **Scan Using CIDR Notation**:
	```
	nmap 192.168.1.0/24
	```
6. **Scan Targets From a File**:
	```bash
	nmap -iL targets.txt
	```
7. **Scan 100 Random Hosts**:
	```bash
	nmap -iR 100
	```
8. **Exclude Listed Hosts**:
	```bash
	nmap –exclude 192.168.1.1
	```

#### Scan Techniques

1. **TCP SYN Port Scan**: Default scan setting
	```bash
	nmap 192.168.1.1 -sS
	```
2. **TCP Connect Port Scan**: Default without root privilege
	```bash
	nmap 192.168.1.1 -sT
	```
3. **UDP Port Scan**:
	```bash
	nmap 192.168.1.1 -sU
	```
4. **TCP ACK Port Scan**:
	```bash
	nmap 192.168.1.1 -sA
	```
5. **TCP FIN Port Scan**:
	```bash
	nmap 192.168.1.1 -sF
	```
6. **TCP Window Port Scan**:
	```bash
	nmap 192.168.1.1 -sW
	```
7. **TCP Maimon Port Scan**:
	```bash
	nmap 192.168.1.1 -sM
	```

#### Host Discovery

1. **No scan. List Targets Only**:
	```bash
	nmap 192.168.1.1-3 -sL
	```
2. **Disable Port Scanning. Host Discovery Only.**:
	```bash
	nmap 192.168.1.1/24 -sn
	```
3. **Disable Host Discovery. Port Scan Only**:
	```bash
	nmap 192.168.1.1-5 -Pn
	```
4. **TCP SYN Discovery on Port X**: Port 80 by default
	```bash
	nmap 192.168.1.1-5 -PS22-25,80
	```
5. **TCP ACK Discovery on Port X**: Port 80 by default
	```bash
	nmap 192.168.1.1-5 -PA22-25,80
	```
6. **UDP Discovery on Port X**: Port 40125 by default
	```bash
	nmap 192.168.1.1-5 -PU53
	```
7. **ARP Discovery on Local Network**:
	```bash
	nmap 192.168.1.1-1/24 -PR
	```
8. **Never Do DNS resolution**:
	```bash
	nmap 192.168.1.1 -n
	```

#### Port Specification

1. **Port Scan for Port X**:
	```bash
	nmap 192.168.1.1 -p 21
	```
2. **Port Range**:
	```bash
	nmap 192.168.1.1 -p 21-100
	```
3. **Port Scan multiple TCP and UDP ports**:
	```bash
	nmap 192.168.1.1 -p U:53,T:21-25,80
	```
4. **Port Scan All Ports**:
	```bash
	nmap 192.168.1.1 -p-
	```
5. **Port Scan from Service Name**:
	```bash
	nmap 192.168.1.1 -p http,https
	```
6. **Fast Port Scan (100 ports)**:
	```bash
	nmap 192.168.1.1 -F
	```
7. **Port Scan the Top X Ports**:
	```bash
	nmap 192.168.1.1 –top-ports 2000
	```
8. **Leaving Off Initial Port in Range**: Makes the scan start at port 1
	```bash
	nmap 192.168.1.1 -p-65535
	```
9. **Leaving Off End Port in Range**: Makes the scan go through to port 65535
	```bash
	nmap 192.168.1.1 -p0-
	```

#### Service and Version Detection

1. **Attempts to determine the version of the service running on port**:
	```bash
	nmap 192.168.1.1 -sV
	```
2. **Intensity level 0 to 9**: Higher number increases possibility of correctness.
	```bash
	nmap 192.168.1.1 -sV –version-intensity 8
	```
3. **Enable light mode**: Lower possibility of correctness. Faster.
	```bash
	nmap 192.168.1.1 -sV –version-light
	```
4. **Enable intensity level 9**: Higher possibility of correctness. Slower.
	```bash
	nmap 192.168.1.1 -sV –version-all
	```
5. **Enable OS Detection, Version Detection, Script Scanning, and Traceroute**:
	```bash
	nmap 192.168.1.1 -A
	```

#### OS Detection

1. **Remote OS Detection using TCP/IP Stack Fingerprinting**:
	```bash
	nmap 192.168.1.1 -O
	```
2. **If at least one open and one closed TCP port are not found it will not try OS detection against host**:
	```bash
	nmap 192.168.1.1 -O –osscan-limit
	```
3. **Makes Nmap guess more aggressively**:
	```bash
	nmap 192.168.1.1 -O –osscan-guess
	```
4. **Set the maximum number x of OS detection tries against a target**:
	```bash
	nmap 192.168.1.1 -O –max-os-tries 1
	```
5. **Enable OS Detection, Version Detection, Script Scanning, and Traceroute**:
	```bash
	nmap 192.168.1.1 -A
	```

#### Timing and Performance

1. **Paranoid (0) Intrusion Detection System Evasion**:
	```bash
	nmap 192.168.1.1 -T0
	```
1. **Sneaky (1) Intrusion Detection System Evasion**:
	```bash
	nmap 192.168.1.1 -T1
	```
1. **Polite (2)**: Slows down the scan to use less bandwidth and use less target machine resources.
	```bash
	nmap 192.168.1.1 -T2
	```
1. **Normal (3)**: Default
	```bash
	nmap 192.168.1.1 -T3
	```
1. **Aggressive (4)**: Speed scans; assumes you are on a reasonably fast and reliable network**
	```bash
	nmap 192.168.1.1 -T4
	```
1. **Insane (5)**: Speed scan; assumes you are on an extraordinarily fast network**
	```bash
	nmap 192.168.1.1 -T5
	```

#### Timing and Performance Switches

1. **Give Up on Target After X Seconds**:
	```bash
	–host-timeout <time> - 1s; 4m; 2h
	```
2. **Specifies Probe Round Trip Time**:
	```bash
	–min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time> - 1s; 4m; 2h
	```
3. **Parallel Host Scan Group Sizes**:
	```bash
	–min-hostgroup/max-hostgroup <size<size> - 50; 1024	
	```
4. **Probe Parallelization**:
	```bash
	–min-parallelism/max-parallelism <numprobes> - 10; 1
	```
5. **Specify Maximum Number of Port Scan Probe Retransmissions**:
```bash
–max-retries <tries> - 3
```
6. **Send Packets No Slower Than X Per Second**:
	```bash
	–min-rate <number> - 100
	```
7. **Send Packets No Faster Than X Per Second**:
	```bash
	–max-rate <number> - 100
	```

#### NSE Scripts
**[Nmap NSE Scripts](https://nmap.org/nsedoc/scripts/)**

1. **Update Script Database**:
	```bash
	nmap --script-updatedb
	```
2. **Scan with Default NSE scripts**: Considered useful for discovery and safe.
	```bash
	nmap 192.168.1.1 -sC
	```
3. **Scan with default NSE Scripts**: Considered useful for discovery and safe.
	```bash
	nmap 192.168.1.1 –script default
	```
4. **Scan with a Single Script**: Example banner
	```bash
	nmap 192.168.1.1 –script=banner
	```
5. **Scan with a Wildcard**: Example http
	```bash
	nmap 192.168.1.1 –script=http*
	```
6. **Scan with Multiple Scripts**: Example http and banner
	```bash
	nmap 192.168.1.1 –script=http,banner
	```
7. **Scan Default, but Remove Intrusive Scripts**:
	```bash
	nmap 192.168.1.1 –script “not intrusive”
	```
8. **NSE Script with Arguments**:
	```bash
	nmap –script snmp-sysdescr –script-args snmpcommunity=admin 192.168.1.1
	```
9. **Search Scripts**: 
	```bash
	find / -type f -name <protocol>* 2>/dev/null | grep scripts
	```
10. **Script Trace**:
	```bash
	nmap 192.168.1.1 –script=http* --script-trace
	```

#### NSE Script Examples

1. **HTTP Site Map Generator**:
	```bash
	nmap -Pn –script=http-sitemap-generator scanme.nmap.org
	```
2. **Fast Search for Random Web Servers**:
	```bash
	nmap -n -Pn -p 80 –open -sV -vvv –script banner,http-title -iR 1000
	```
3. **Brute Forces DNS Hostnames, Guessing Subdomains**:
	```bash
	nmap -Pn –script=dns-brute domain.com
	```
4. **Safe SMB Scripts to Run**:
	```bash
	nmap -n -Pn -vv -O -sV –script smb-enum*,smb-ls,smb-mbenum,smb-os-discovery,smb-s*,smb-vuln*,smbv2* -vv 192.168.1.1
	```
5. **Whois Query**:
	```bash
	nmap –script whois* domain.com
	```
6. **Detect Cross Site Scripting Vulnerabilities**:
	```bash
	nmap -p80 –script http-unsafe-output-escaping scanme.nmap.org
	```
7. **Check for SQL Injections**:
	```bash
	nmap -p80 –script http-sql-injection scanme.nmap.org
	```
8. **Display Progress of NSE Scripts**:
	```bash
	nmap -p80 --script http-sql-injection --script-trace scanme.nmap.org
	```

#### Defense Evasion and Spoofing

1. **Use Tiny fragmented IP Packets**: Harder for packet filters
	```bash
	nmap 192.168.1.1 -f
	```
2. **Set Offset Size**:
	```bash
	nmap 192.168.1.1 –mtu 32
	```
3. **Send Scans from Spoofed IPs**:
	```bash
	nmap -D decoy-ip1,decoy-ip2,your-own-ip,decoy-ip3,decoy-ip4 remote-host-ip
	nmap -D 192.168.1.101,192.168.1.102,192.168.1.103,192.168.1.23 192.168.1.1
	```
4. **Using Randomly Produced IPs**: Above Example Alternative 
	```bash
	nmap -D RND:5 192.168.1.1
	```
5. **Scans Target from a Specified IP Address**:
	```bash
	nmap 192.168.1.1 -S 192.168.1.254
	```
6. **Above example**: Scan Facebook from Microsoft (`-e eth0 -Pn` may be required)
	```bash
	nmap -S www.microsoft.com www.facebook.com
	```
7. **Use Given Source Port Number**:
	```bash
	nmap -g 53 192.168.1.1
	```
8. **Relay Connections Through HTTP/SOCKS4 Proxies**:
	```bash
	nmap –proxies http://192.168.1.1:8080, http://192.168.1.2:8080 192.168.1.1
	```
9. **Appends Random Data to Sent Packets**:
	```bash
	nmap –data-length 200 192.168.1.1
	```
10. **Example IDS Evasion Command**:
	```bash
	nmap -f -t 0 -n -Pn –data-length 200 -D 192.168.1.101,192.168.1.102,192.168.1.103,192.168.1.23 192.168.1.1
	```

#### Output

1. **Normal Output to the File `normal.file`**:
	```
	nmap 192.168.1.1 -oN normal.file
	```
2. **XML Output to File `xml.file`**:
	```
	nmap 192.168.1.1 -oX xml.file
	```
3. **Grepable Output to File `grep.file`**:
	```
	nmap 192.168.1.1 -oG grep.file
	```
4. **Output to All Three Formats**:
	```
	nmap 192.168.1.1 -oA results
	```
5. **Grepable output to screen**: `-oN -`, `-oX –` also usable
	```
	nmap 192.168.1.1 -oG
	```
6. **Append a Scan to a Previous Scan File**:
	```
	nmap 192.168.1.1 -oN file.file –append-output
	```
7. **Increase Verbosity Level**: Use `-vv` or more for greater effect.
	```
	nmap 192.168.1.1 -v
	```
8. **Increase Debugging Level**: Use `-dd` or more for greater effect.
	```
	nmap 192.168.1.1 -d
	```
9. **Display the Reason a Port is in a Particular State**: Same output as `-vv`.
	```
	nmap 192.168.1.1 –reason
	```
10. **Only Show Open/Possibly Open Ports**:
	```
	nmap 192.168.1.1 –open
	```
11. **Show All Packets Sent/Received**:
	```
	nmap 192.168.1.1 -T4 –packet-trace
	```
12. **Shows the Host Interfaces and Routes**:
	```
	–iflist
	```
13. **Resume a Scan**:
	```
	nmap –resume results.file
	```

#### Output Examples

1. **Scan for Web Servers and Grep to Show Which IPs are Running Web Servers**:
	```bash
	nmap -p80 -sV -oG – –open 192.168.1.1/24 | grep open
	```
2. **Generate List of IPs with Live Hosts**:
	```bash
	nmap -iR 10 -n -oX out.xml | grep “Nmap” | cut -d ” ” -f5 > live-hosts.txt
	```
3. **Append IP to the List of IPs with Live Hosts**:
	```bash
	nmap -iR 10 -n -oX out2.xml | grep “Nmap” | cut -d ” ” -f5 >> live-hosts.txt
	```
4. **Compare Output from Nmap Using NDiff**:
	```bash
	ndiff scanl.xml scan2.xml
	```
5. **Convert Nmap XML Files to HTML Files**:
	```bash
	xsltproc nmap.xml -o nmap.html
	```
6. **Reverse Sorted List of How Often Ports Turn Up**:
	```bash
	grep ” open ” results.nmap | sed -r ‘s/ +/ /g’ | sort | uniq -c | sort -rn | less
	```

#### Miscellaneous Nmap Flags

1. **Enable IPv6 Scanning**:
	```bash
	nmap -6 2607:f0d0:1002:51::4
	```
2. **Nmap Help Screen**:
	```bash
	nmap -h
	```
3. **Specify Interface**:
	```bash
	-e tun0
	```

#### Other Useful Nmap Commands

1. **Discovery Only on Ports X; No Port Scan**:
	```bash
	nmap -iR 10 -PS22-25,80,113,1050,35000 -v -sn
	```
2. **ARP Discovery Only on Local Network; No Port Scan**:
	```bash
	nmap 192.168.1.1-1/24 -PR -sn -vv
	```
3. **Traceroute to Random Targets; No Port Scan**:
	```bash
	nmap -iR 10 -sn -traceroute
	```
4. **Query the Internal for Hosts; List Targets Only**:
	```bash
	nmap 192.168.1.1-50 -sL –dns-server 192.168.1.1
	```


# Additional Information

#### File Structure
Nmap scripts are stored under `/usr/share/nmap/scripts/`. You can add custom scripts to this directory to extend Nmap's functionality.

- **Custom Script Example**:
	```bash
	-- Simple custom Nmap script example
	description = [[
	  Simple script to check HTTP status
	]]
	
	categories = {"discovery"}
	
	hostrule = function(host)
	  return host.port == 80
	end
	
	action = function(host)
	  local result = nmap.fetchurl("http://" .. host.ip)
	  return result
	end
	```

- **To run the custom script**:
	```bash
	nmap --script <path_to_script> <target_ip>
	```

#### Integration with Other Tools
Nmap can be integrated with various other tools for enhanced functionality.

##### Integration with Metasploit
- You can import Nmap scan results into Metasploit.
	```bash
	db_nmap -sS <target_ip>
	```

##### Integration with Nessus
- You can export Nmap scan results and import them into Nessus for further vulnerability analysis.
	```****
	nmap -oX nmap_results.xml <target_ip>
	# Import nmap_results.xml into Nessus
	```

#### Firewall and IDS/IPS Evasion with Nmap
Nmap gives us many different ways to bypass firewalls rules and IDS/IPS. These methods include the fragmentation of packets, the use of decoys, and others that we will discuss in this section.

##### Firewalls
A firewall is a security measure against unauthorized connection attempts from external networks. Every firewall security system is based on a software component that monitors network traffic between the firewall and incoming data connections and decides how to handle the connection based on the rules that have been set. It checks whether individual network packets are being passed, ignored, or blocked. This mechanism is designed to prevent unwanted connections that could be potentially dangerous.

##### IDS/IPS
Like the firewall, the intrusion detection system (IDS) and intrusion prevention system (IPS) are also software-based components. IDS scans the network for potential attacks, analyzes them, and reports any detected attacks. IPS complements IDS by taking specific defensive measures if a potential attack should have been detected. The analysis of such attacks is based on pattern matching and signatures. If specific patterns are detected, such as a service detection scan, IPS may prevent the pending connection attempts.

#### Determine Firewalls and Their Rules
We already know that when a port is shown as filtered, it can have several reasons. In most cases, firewalls have certain rules set to handle specific connections. The packets can either be dropped, or rejected. The dropped packets are ignored, and no response is returned from the host. This is different for rejected packets that are returned with an RST flag. These packets contain different types of ICMP error codes or contain nothing at all. Such errors can be:
	- Net Unreachable
	- Net Prohibited
	- Host Unreachable
	- Host Prohibited
	- Port Unreachable
	- Proto Unreachable

Nmap's TCP ACK scan (`-sA`) method is much harder to filter for firewalls and IDS/IPS systems than regular SYN (`-sS`) or Connect scans (`-sT`) because they only send a TCP packet with only the ACK flag. When a port is closed or open, the host must respond with an RST flag. Unlike outgoing connections, all connection attempts (with the SYN flag) from external networks are usually blocked by firewalls. However, the packets with the ACK flag are often passed by the firewall because the firewall cannot determine whether the connection was first established from the external network or the internal network.

If we look at these scans, we will see how the results differ.

- **SYN-Scan**:
	```bash
	sudo nmap 10.129.2.28 -p 21,22,25 -sS -Pn -n --disable-arp-ping --packet-trace
	
	Starting Nmap 7.80 ( [https://nmap.org](https://nmap.org) ) at 2020-06-21 14:56 CEST
	SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:22 S ttl=53 id=22412 iplen=44  seq=4092255222 win=1024 <mss 1460>
	SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:25 S ttl=50 id=62291 iplen=44  seq=4092255222 win=1024 <mss 1460>
	SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:21 S ttl=58 id=38696 iplen=44  seq=4092255222 win=1024 <mss 1460>
	RCVD (0.0329s) ICMP [10.129.2.28 > 10.10.14.2 Port 21 unreachable (type=3/code=3) ] IP [ttl=64 id=40884 iplen=72 ]
	RCVD (0.0341s) TCP 10.129.2.28:22 > 10.10.14.2:57347 SA ttl=64 id=0 iplen=44  seq=1153454414 win=64240 <mss 1460>
	RCVD (1.0386s) TCP 10.129.2.28:22 > 10.10.14.2:57347 SA ttl=64 id=0 iplen=44  seq=1153454414 win=64240 <mss 1460>
	SENT (1.1366s) TCP 10.10.14.2:57348 > 10.129.2.28:25 S ttl=44 id=6796 iplen=44  seq=4092320759 win=1024 <mss 1460>
	Nmap scan report for 10.129.2.28
	Host is up (0.0053s latency).
	
	PORT   STATE    SERVICE
	21/tcp filtered ftp
	22/tcp open     ssh
	25/tcp filtered smtp
	MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
	
	Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds
	```

- **ACK-Scan**:
	```bash
	sudo nmap 10.129.2.28 -p 21,22,25 -sA -Pn -n --disable-arp-ping --packet-trace
	
	Starting Nmap 7.80 ( [https://nmap.org](https://nmap.org) ) at 2020-06-21 14:57 CEST
	SENT (0.0422s) TCP 10.10.14.2:49343 > 10.129.2.28:21 A ttl=49 id=12381 iplen=40  seq=0 win=1024
	SENT (0.0423s) TCP 10.10.14.2:49343 > 10.129.2.28:22 A ttl=41 id=5146 iplen=40  seq=0 win=1024
	SENT (0.0423s) TCP 10.10.14.2:49343 > 10.129.2.28:25 A ttl=49 id=5800 iplen=40  seq=0 win=1024
	RCVD (0.1252s) ICMP [10.129.2.28 > 10.10.14.2 Port 21 unreachable (type=3/code=3) ] IP [ttl=64 id=55628 iplen=68 ]
	RCVD (0.1268s) TCP 10.129.2.28:22 > 10.10.14.2:49343 R ttl=64 id=0 iplen=40  seq=1660784500 win=0
	SENT (1.3837s) TCP 10.10.14.2:49344 > 10.129.2.28:25 A ttl=59 id=21915 iplen=40  seq=0 win=1024
	Nmap scan report for 10.129.2.28
	Host is up (0.083s latency).
	
	PORT   STATE      SERVICE
	21/tcp filtered   ftp
	22/tcp unfiltered ssh
	25/tcp filtered   smtp
	MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
	
	Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
	```

Please pay attention to the RCVD packets and its set flag we receive from our target. With the SYN scan (`-sS`) our target tries to establish the TCP connection by sending a packet back with the SYN-ACK (SA) flags set and with the ACK scan (`-sA`) we get the RST flag because TCP port 22 is open. For the TCP port 25, we do not receive any packets back, which indicates that the packets will be dropped.

#### Detect IDS/IPS
Unlike firewalls and their rules, the detection of IDS/IPS systems is much more difficult because these are passive traffic monitoring systems. IDS systems examine all connections between hosts. If the IDS finds packets containing the defined contents or specifications, the administrator is notified and takes appropriate action in the worst case.

IPS systems take measures configured by the administrator independently to prevent potential attacks automatically. It is essential to know that IDS and IPS are different applications and that IPS serves as a complement to IDS.

Several virtual private servers (VPS) with different IP addresses are recommended to determine whether such systems are on the target network during a penetration test. If the administrator detects such a potential attack on the target network, the first step is to block the IP address from which the potential attack comes. As a result, we will no longer be able to access the network using that IP address, and our Internet Service Provider (ISP) will be contacted and blocked from all access to the Internet.

IDS systems alone are usually there to help administrators detect potential attacks on their network. They can then decide how to handle such connections. We can trigger certain security measures from an administrator, for example, by aggressively scanning a single port and its service. Based on whether specific security measures are taken, we can detect if the network has some monitoring applications or not.

One method to determine whether such IPS system is present in the target network is to scan from a single host (VPS). If at any time this host is blocked and has no access to the target network, we know that the administrator has taken some security measures. Accordingly, we can continue our penetration test with another VPS.

Consequently, we know that we need to be quieter with our scans and, in the best case, disguise all interactions with the target network and its services.

#### Decoys
There are cases in which administrators block specific subnets from different regions in principle. This prevents any access to the target network. Another example is when IPS should block us. For this reason, the Decoy scanning method (`-D`) is the right choice. With this method, Nmap generates various random IP addresses inserted into the IP header to disguise the origin of the packet sent. With this method, we can generate random (`RND`) a specific number (for example: 5) of IP addresses separated by a colon (`:`). Our real IP address is then randomly placed between the generated IP addresses. In the next example, our real IP address is therefore placed in the second position. Another critical point is that the decoys must be alive. Otherwise, the service on the target may be unreachable due to SYN-flooding security mechanisms.

- **Scan by Using Decoys**:
	```bash
	sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
	
	Starting Nmap 7.80 ( [https://nmap.org](https://nmap.org) ) at 2020-06-21 16:14 CEST
	SENT (0.0378s) TCP 102.52.161.59:59289 > 10.129.2.28:80 S ttl=42 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
	SENT (0.0378s) TCP 10.10.14.2:59289 > 10.129.2.28:80 S ttl=59 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
	SENT (0.0379s) TCP 210.120.38.29:59289 > 10.129.2.28:80 S ttl=37 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
	SENT (0.0379s) TCP 191.6.64.171:59289 > 10.129.2.28:80 S ttl=38 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
	SENT (0.0379s) TCP 184.178.194.209:59289 > 10.129.2.28:80 S ttl=39 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
	SENT (0.0379s) TCP 43.21.121.33:59289 > 10.129.2.28:80 S ttl=55 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
	RCVD (0.1370s) TCP 10.129.2.28:80 > 10.10.14.2:59289 SA ttl=64 id=0 iplen=44  seq=4056111701 win=64240 <mss 1460>
	Nmap scan report for 10.129.2.28
	Host is up (0.099s latency).
	
	PORT   STATE SERVICE
	80/tcp open  http
	MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
	
	Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
	```

The spoofed packets are often filtered out by ISPs and routers, even though they come from the same network range. Therefore, we can also specify our VPS servers' IP addresses and use them in combination with "IP ID" manipulation in the IP headers to scan the target.

Another scenario would be that only individual subnets would not have access to the server's specific services. So we can also manually specify the source IP address (`-S`) to test if we get better results with this one. Decoys can be used for SYN, ACK, ICMP scans, and OS detection scans. So let us look at such an example and determine which operating system it is most likely to be.

#### Testing Firewall Rule

```bash
sudo nmap 10.129.2.28 -n -Pn -p445 -O

Starting Nmap 7.80 ( [https://nmap.org](https://nmap.org) ) at 2020-06-22 01:23 CEST
Nmap scan report for 10.129.2.28
Host is up (0.032s latency).

PORT    STATE    SERVICE
445/tcp filtered microsoft-ds
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
Too many fingerprints match this host to give specific OS details
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at [https://nmap.org/submit/](https://nmap.org/submit/) .
Nmap done: 1 IP address (1 host up) scanned in 3.14 seconds
```

#### Scan by Using Different Source IP

```bash
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0

Starting Nmap 7.80 ( [https://nmap.org](https://nmap.org) ) at 2020-06-22 01:16 CEST
Nmap scan report for 10.129.2.28
Host is up (0.010s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 3.2 - 4.9 (96%), Linux 2.6.32 - 3.10 (96%), Linux 3.4 - 3.10 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Synology DiskStation Manager 5.2-5644 (94%), Linux 2.6.32 - 2.6.35 (94%), Linux 2.6.32 - 3.5 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at [https://nmap.org/submit/](https://nmap.org/submit/) .
Nmap done: 1 IP address (1 host up) scanned in 4.11 seconds
```

#### DNS Proxying
By default, Nmap performs a reverse DNS resolution unless otherwise specified to find more important information about our target. These DNS queries are also passed in most cases because the given web server is supposed to be found and visited. The DNS queries are made over the UDP port 53. The TCP port 53 was previously only used for the so-called "Zone transfers" between the DNS servers or data transfer larger than 512 bytes. More and more, this is changing due to IPv6 and DNSSEC expansions. These changes cause many DNS requests to be made via TCP port 53.

However, Nmap still gives us a way to specify DNS servers ourselves (`--dns-server ns, ns`). This method could be fundamental to us if we are in a demilitarized zone (DMZ). The company's DNS servers are usually more trusted than those from the Internet. So, for example, we could use them to interact with the hosts of the internal network. As another example, we can use TCP port 53 as a source port (`--source-port`) for our scans. If the administrator uses the firewall to control this port and does not filter IDS/IPS properly, our TCP packets will be trusted and passed through.

- **SYN-Scan of a Filtered Port**:
	```bash
	sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace
	
	Starting Nmap 7.80 ( [https://nmap.org](https://nmap.org) ) at 2020-06-21 22:50 CEST
	SENT (0.0417s) TCP 10.10.14.2:33436 > 10.129.2.28:50000 S ttl=41 id=21939 iplen=44  seq=736533153 win=1024 <mss 1460>
	SENT (1.0481s) TCP 10.10.14.2:33437 > 10.129.2.28:50000 S ttl=46 id=6446 iplen=44  seq=736598688 win=1024 <mss 1460>
	Nmap scan report for 10.129.2.28
	Host is up.
	
	PORT      STATE    SERVICE
	50000/tcp filtered ibm-db2
	
	Nmap done: 1 IP address (1 host up) scanned in 2.06 seconds
	```

- **SYN-Scan From DNS Port**:
	```bash
	sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
	
	SENT (0.0482s) TCP 10.10.14.2:53 > 10.129.2.28:50000 S ttl=58 id=27470 iplen=44  seq=4003923435 win=1024 <mss 1460>
	RCVD (0.0608s) TCP 10.129.2.28:50000 > 10.10.14.2:53 SA ttl=64 id=0 iplen=44  seq=540635485 win=64240 <mss 1460>
	Nmap scan report for 10.129.2.28
	Host is up (0.013s latency).
	
	PORT      STATE SERVICE
	50000/tcp open  ibm-db2
	
	MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
	Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds
	```

Now that we have found out that the firewall accepts TCP port 53, it is very likely that IDS/IPS filters might also be configured much weaker than others. We can test this by trying to connect to this port by using Netcat.

- **Connect To The Filtered Port**:
	```bash
	ncat -nv --source-port 53 10.129.2.28 50000
	
	Ncat: Version 7.80 ( [https://nmap.org/ncat](https://nmap.org/ncat) )
	Ncat: Connected to 10.129.2.28:50000.
	220 ProFTPd
	```

[https://isc.sans.edu/diary/NMAP+without+NMAP+Port+Testing+and+Scanning+with+PowerShell/29202/](https://isc.sans.edu/diary/NMAP+without+NMAP+Port+Testing+and+Scanning+with+PowerShell/29202/)

# Resources

|**Name**|**URL**|
|---|---|
|Nmap Documentation|https://nmap.org/book/man.html|
|NSE Script Repository|https://nmap.org/nsedoc/|
|Nmap Cheat Sheet by SANS|https://www.sans.org/tools/nmap-cheat-sheet/|
|Nmap Scripting Engine (NSE) Tutorial|https://nmap.org/book/nse-usage.html|
|Common Nmap Use Cases|https://www.hackingarticles.in/comprehensive-guide-on-nmap-scan-for-pentesters/|
|Nmap Official Download|https://nmap.org/download.html|
|Advanced Nmap Techniques|https://www.offensive-security.com/metasploit-unleashed/nmap/|
|Bypassing Firewalls with Nmap|https://null-byte.wonderhowto.com/how-to/bypass-firewalls-ids-with-nmap-0175782/|
|Penetration Testing with Nmap|https://www.pentest-standard.org/index.php/Network_Information_Gathering|
|Defensive Techniques Against Nmap Scans|https://securitytrails.com/blog/nmap-scan|