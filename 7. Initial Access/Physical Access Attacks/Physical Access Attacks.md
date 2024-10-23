# BIOS/UEFI Access and Manipulation
This technique focuses on exploiting or bypassing the BIOS/UEFI (Basic Input/Output System or Unified Extensible Firmware Interface) to manipulate the machine's boot process.

- **Objective:**
	- Bypass security features such as boot order restrictions, Secure Boot, or even BIOS passwords to gain control of the system.
  
- **Execution:**
	1. Access BIOS/UEFI:
	   - Restart the system and press the necessary key (e.g., `F2`, `Delete`, `Esc`, `F10`) to enter the BIOS/UEFI configuration.
	   
	2. Disable Security Features:
	   - Disable Secure Boot (which ensures that only signed OS boots) to allow unsigned media to boot (e.g., Kali Linux).
	   - If the system has a BIOS password, you can:
	     - Try default passwords based on the motherboard manufacturer.
	     - Physically reset the CMOS by removing the battery or using a jumper.
	
	3. Change Boot Order:
	   - Adjust the boot sequence to prioritize booting from a USB drive or external media.
	
	4. Persistence:
	   - For more advanced attacks, you could flash malicious BIOS firmware to gain long-term persistence.

# Boot from External Media
This technique allows the attacker to boot the machine from a USB or CD containing a live operating system or forensic tools.

- **Objective:**
	- Boot into a clean operating system environment to bypass the native OS's security, directly access files, and execute further attacks.

- **Execution:**
	1. Prepare External Media:
	   - Create a bootable USB stick using tools like Rufus or `dd` with a penetration testing distribution like Kali Linux, Parrot OS, or Tails.
	
	   Example:
	   ```
	   dd if=<Path\To\ISO> of=/dev/sdX bs=4M
	   ```
	
	2. Boot from USB:
	   - Insert the USB into the target machine, change the boot order to prioritize USB boot, and boot into the live OS.
	
	3. Execute Attacks:
	   - Mount local storage to access sensitive files.
	   - Reset passwords on the local OS using tools like `chntpw` (for Windows).
	   - Use built-in tools like `metasploit`, `nmap`, `hydra`, or `john` to scan, brute-force, or exploit vulnerabilities.

# Installing Virtual Machines
Once physical access is achieved, an attacker can install and run a virtual machine (VM) on the target host. The VM runs as a separate OS, providing the attacker with a sandboxed environment to conduct further attacks.

- **Objective:**
	- Use the host's resources without disrupting its normal operation, allowing for covert exploitation or data exfiltration.

- **Execution:**
	1. Install a Virtualization Platform:
	   - Install virtualization software such as VirtualBox or VMware on the target machine.
	
	2. Set Up the Virtual Machine:
	   - Install a VM running an OS like Kali Linux or Parrot OS.
	   - Configure the VM with network interfaces that allow it to communicate either locally or externally.
	
	3. Conduct Attacks:
	   - Launch internal network attacks (e.g., ARP spoofing, sniffing).
	   - Use the VM to bypass restrictions on the main OS by interacting with the host machine’s file system or devices.

# USB Hard Drive
This attack involves using a USB external hard drive to quickly transfer large volumes of data from the target machine or to upload malicious files.

- **Objective:**
	- Perform rapid data exfiltration or transfer attack tools and payloads onto the machine.

- **Execution:**
	1. Connect USB Hard Drive:
	   - Insert a USB hard drive into the target system.
	   
	2. Exfiltrate Data:
	   - Use tools like `rsync` or `robocopy` to quickly copy sensitive files to the external drive:
	     - Linux:
	       ```
	       rsync -av /target/directory /media/usbdrive
	       ```
	     - Windows:
	       ```
	       robocopy C:\sensitive_data D:\ /E
	       ```
	
	3. Transfer Malicious Files:
	   - Upload exploit payloads, backdoors, or scripts onto the target machine for further exploitation.

# USB Tethering
USB tethering allows the attacker to connect their smartphone to the target machine via USB to share the phone’s mobile network connection or interact with the target’s network. This method can be used for data exfiltration or to set up a covert internet connection.

- **Objective:**
	- Use the mobile device to set up a covert internet connection or to bypass network restrictions on the target machine.

- **Execution:**
	1. Enable USB Tethering:
	   - Connect your phone to the target machine via USB and enable USB tethering on the phone.
	   - The target machine will use the phone’s mobile network connection to route traffic.
	   
	2. **Conduct Exploitation:**
	   - Use the mobile internet connection to:
	     - Download tools and exploits.
	     - Upload exfiltrated data to a remote server or cloud storage.
	     - Establish a reverse shell back to a remote control server.

# USB Wi-Fi Adapter
This technique involves plugging in a USB Wi-Fi adapter to connect the target machine to a rogue Wi-Fi network under the attacker's control.

- **Objective:**
	- Connect the target system to an attacker's rogue Wi-Fi network for data interception or direct exploitation.

- **Execution:**
	1. **Insert USB Wi-Fi Adapter:**
	   - Connect a USB Wi-Fi adapter to the target machine, allowing it to interface with wireless networks.
	
	2. **Connect to Rogue Network:**
	   - Connect the target machine to a malicious Wi-Fi network controlled by the attacker. This could be achieved using tools like Wi-Fi Pineapple.
	
	3. **Launch Network Attacks:**
	   - Once the target is connected, conduct attacks such as:
	     - Man-in-the-Middle (MITM): Intercept traffic using tools like `Ettercap` or `Wireshark`.
	     - DNS Spoofing/Poisoning: Redirect traffic to malicious websites.
	     - Credential Harvesting: Capture login credentials or sensitive information passed over the network.

# Ethernet Tethering
This method involves tethering the target machine’s Ethernet connection to another device (such as a smartphone, laptop, or rogue device) to either route traffic through it or to control the target's network access.

- **Objective:**
	- Route traffic through a device controlled by the attacker to monitor or manipulate the target’s network activity.

- **Execution:**
	1. **Tether Ethernet Cable:**
	   - Disconnect the target machine from the legitimate network and insert a rogue device (e.g., a Raspberry Pi or LAN Turtle) between the Ethernet cable and the target machine.
	
	2. **Route Traffic via Attacker Device:**
	   - Configure the rogue device to act as a bridge or gateway. The device can:
	     - Forward traffic to the legitimate network while logging or manipulating it.
	     - Divert traffic to the attacker's machine for further inspection.
	   
	3. **Conduct Network Attacks:**
	   - Launch attacks such as:
	     - Traffic sniffing: Capture sensitive data passing through the Ethernet connection using `tcpdump` or `Wireshark`.
	     - MITM attacks: Modify or inject malicious traffic into the data stream.
	
	   Example using `tcpdump`:
	   ```
	   tcpdump -i eth0 -w /media/external_drive/traffic.pcap
	   ```