You can connect the laptop and the desktop by setting up an ad-hoc wireless network or using a method called Wi-Fi Direct. This will allow the two devices to communicate with each other wirelessly. Here’s a step-by-step guide to setting up these connections based on your configuration.

# Option 1: Ad-hoc Wireless Network Setup

An ad-hoc network is a peer-to-peer wireless network where two or more devices communicate directly without needing a wireless access point (like a router).

#### Steps for Ad-hoc Wireless Network

1. Laptop Configuration (Windows/Linux/Mac):
   - On your laptop (which has a wireless NIC), create an ad-hoc network:
     - Windows: 
       - Open Control Panel -> Network and Sharing Center.
       - Click on Set up a new connection or network.
       - Choose Set up a wireless ad-hoc (computer-to-computer) network.
       - Assign a network name and a security type (WEP/WPA2, etc.).
       - Once the network is set up, your laptop will begin broadcasting the ad-hoc network.
     - Linux (Using Network Manager GUI):
       - Open your network settings.
       - Go to the Wi-Fi section and select Create New Wi-Fi Network.
       - Set the mode to Ad-hoc and configure the network name and security settings.
     - macOS:
       - Open System Preferences -> Network.
       - Click Wi-Fi and then click Create Network.
       - Set up the network name, channel, and encryption.

2. Desktop Configuration (Windows/Linux):
   - Once the laptop is broadcasting the ad-hoc network, connect your desktop with the USB wireless adapter to this network.
     - Open the Wi-Fi settings on your desktop.
     - Find the ad-hoc network created by the laptop and connect using the provided credentials.
   
3. IP Address Configuration:
   - If the devices do not automatically assign IP addresses, you can set static IPs:
     - Laptop: IP `192.168.1.1`, Subnet Mask `255.255.255.0`
     - Desktop: IP `192.168.1.2`, Subnet Mask `255.255.255.0`
   - Set the Default Gateway to the laptop’s IP (`192.168.1.1`) if you plan to share internet access.

4. Verify the Connection:
   - Once both computers are connected to the ad-hoc network, you can test the connection by pinging one device from the other:
     ```bash
     ping <other_computer_ip>
     ```

5. File Sharing (Optional):
   - If you need to share files, enable File Sharing on both devices and configure shared folders.
   - On Windows, this can be done via Control Panel -> Network and Sharing Center -> Advanced sharing settings.

# Option 2: Wi-Fi Direct

Wi-Fi Direct allows devices to connect directly without needing a router. This is somewhat similar to ad-hoc networking but tends to be more streamlined.

#### Steps for Wi-Fi Direct

1. Check for Wi-Fi Direct Support:
   - On Windows 10/11, many modern laptops and desktops support Wi-Fi Direct natively. You can check this by opening Command Prompt and typing:
     ```bash
     ipconfig /all
     ```
     Look for a Microsoft Wi-Fi Direct Virtual Adapter.

2. Enable Wi-Fi Direct on the Laptop:
   - Open Settings -> Devices -> Bluetooth & other devices.
   - Click Add Bluetooth or other device, then select Wi-Fi Direct.
   - The laptop will start broadcasting a Wi-Fi Direct signal.

3. Connect the Desktop:
   - On the desktop, search for available Wi-Fi networks. The laptop should appear as a Wi-Fi Direct connection.
   - Select the network and enter any credentials if required.

4. IP Configuration and Testing:
   - As with ad-hoc networking, if IP addresses are not automatically assigned, manually set static IPs.
   - Ping the other device to verify connectivity.

# Option 3: Internet Connection Sharing (ICS)

If you want to share the internet connection from your laptop to the desktop, you can use Internet Connection Sharing (ICS) on the laptop.

#### Steps for ICS
1. Laptop Configuration:
   - Open Control Panel -> Network and Sharing Center -> Change adapter settings.
   - Right-click on the Wi-Fi connection (assuming your laptop is connected to the internet) and go to Properties.
   - Under the Sharing tab, check the box for Allow other network users to connect through this computer’s Internet connection.
   - Select your wireless ad-hoc connection as the one to share with.
   
2. Connect the Desktop:
   - Now, connect the desktop to the ad-hoc network you’ve set up on the laptop.
   - The desktop will gain internet access through the shared connection.