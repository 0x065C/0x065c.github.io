# Index
- [[Methodology]]
	- [[Physical Access Methodology]]
	- [[Linux Methodology]]
	- [[Windows Methodology]]
	- [[Web Application Methodology]]
	- [[Cloud Methodology]]

# BIOS/UEFI Access and Manipulation
- [ ] **Access BIOS/UEFI Settings:** - Ensure the machine allows boot-level access through BIOS/UEFI. This may involve rebooting the system and pressing a specific key (e.g., F2, Del, ESC).
- [ ] **Password Bypass Techniques:** - If the BIOS/UEFI is password-protected, consider using methods such as:
	  - CMOS battery removal.
	  - Reset jumpers on the motherboard.
	  - Default passwords for specific BIOS/UEFI manufacturers.
- [ ] **Change Boot Order:** - Modify the boot sequence to prioritize external devices like USB drives or CD/DVD drives.
- [ ] **Enable/Disable Secure Boot:** - Secure Boot can prevent booting from unsigned OS kernels. Disable it to allow booting from custom media.
- [ ] **Disable TPM (Trusted Platform Module):** - Disabling TPM can weaken hardware-backed security protections, such as BitLocker in Windows environments.

# Boot from External Media
- [ ] **Create Bootable USB Media:** - Use tools like `Rufus` or `dd` to create a bootable USB drive with an OS like Kali Linux or Windows PE.
- [ ] **Live CD/USB Attacks:** - Boot from external media to access the system without authentication. This allows file system access, password resetting, or full OS installation.
- [ ] **Bypass Disk Encryption (Cold Boot Attack):** - Conduct cold boot attacks to retrieve encryption keys by exploiting the vulnerability in DRAM data retention after power off.

# USB Hard Drive
- [ ] **Install Persistent Malware:** - Deploy a payload or implant on a USB hard drive that runs automatically when plugged in (via autorun.inf or scheduled tasks).
- [ ] **USB Drive for Data Exfiltration:** - Use USB hard drives to quickly transfer large volumes of data from a compromised machine.
- [ ] **USB Rubber Ducky:** - Deploy a USB Rubber Ducky (or similar device) for keystroke injection, executing a pre-programmed payload as soon as it is plugged into the target machine.

# USB Tethering
- [ ] **Enable USB Tethering on Mobile Device:** - Tether a mobile device to the target machine via USB to access an alternate internet connection or act as a network bridge.
- [ ] **Bypass Network Restrictions:** - Use USB tethering to bypass corporate firewalls or filtering by routing the machine’s traffic through the mobile device.

# Ethernet Tethering
- [ ] **Establish an Ethernet Bridge:** - Connect an Ethernet cable between the target machine and a secondary device (such as a laptop or rogue device) to capture network traffic or redirect it through a controlled interface.
- [ ] **Network Traffic Redirection:** - Configure IP forwarding and use network address translation (NAT) or ARP spoofing to redirect the machine’s network traffic through an attacker-controlled device.

# USB Wi-Fi Adapter
- [ ] **Install Malicious Wi-Fi Adapter:** - Connect a rogue Wi-Fi adapter to the target machine to capture wireless traffic or reroute data through a malicious access point (AP).
- [ ] **Wireless Network Snooping:** - Use tools like `aircrack-ng` or `Wireshark` to sniff wireless traffic from nearby access points or perform Man-in-the-Middle (MitM) attacks.
- [ ] **Enable Monitor Mode:** - Enable monitor mode on a USB Wi-Fi adapter to capture wireless traffic.

# Installing Virtual Machines
- [ ] **Deploy Virtual Machine on Target System:** - If physical access allows login, install and deploy a hypervisor (e.g., VirtualBox, VMware) and set up a malicious virtual machine to gain long-term access.
- [ ] **Virtual Machine Configuration:** - Ensure the virtual machine is stealthy by configuring it to use minimal resources and hide its presence.
- [ ] **Network Bridging:** - Use network bridging on the VM to mirror or proxy traffic through the host’s network interface.

# Additional Physical Access Techniques
- [ ] **Keylogger Installation:** - Install a hardware keylogger between the target keyboard and the computer to capture keystrokes for credentials or sensitive information.
- [ ] **BIOS Flashing/Rootkits:** - Flash the BIOS/UEFI with a modified version containing a rootkit to maintain persistent access to the system, even after OS reinstalls.