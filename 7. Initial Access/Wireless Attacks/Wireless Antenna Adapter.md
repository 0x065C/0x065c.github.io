To enable and configure the ALFA AWUS036NEH 802.11n USB Adapter (note: this adapter supports the 802.11b/g/n standards rather than 802.11a) on a Windows 10 host, you need to ensure that the driver is installed correctly, and the adapter is properly recognized by the operating system. Here's a step-by-step guide to achieve this:

# Step 1: Connect the ALFA AWUS036NEH to the Windows 10 Host
1. Physically connect the AWUS036NEH adapter to one of your USB ports.
2. Wait for Windows 10 to automatically detect the device. If drivers are already available on your system, Windows may install them automatically. 

# Step 2: Install the Correct Drivers
Windows may not always have the latest or correct drivers. You should manually install the official drivers to ensure proper functionality. Follow these steps to download and install them:

1. Download the Driver:
   - Visit the [ALFA Network website](https://www.alfa.com.tw/) or use the CD that comes with the device.
   - Search for the model "AWUS036NEH" and download the appropriate drivers for Windows 10.
   
2. Install the Driver:
   - Extract the downloaded driver package (if it comes in a zip file).
   - Navigate to the extracted folder, locate the `setup.exe` file or the appropriate installer, and run the installation.
   - Follow the on-screen instructions to complete the installation.

3. Verify Installation:
   - After installation, go to Device Manager (press `Windows + X` and select Device Manager).
   - Expand the Network adapters section and check for Realtek RTL8188RU Wireless LAN 802.11n (this is the chipset used in the AWUS036NEH).
   - If the device shows up without any warnings or errors, the driver has been installed successfully.

# Step 3: Configure the Adapter for Use
Once the adapter is installed and recognized, you need to configure it to connect to a wireless network:

1. Open the Network and Sharing Center:
   - Click on the network icon in the system tray (bottom-right of the screen) and select Network & Internet settings.
   - Select Wi-Fi from the left-hand pane.

2. Select the Wireless Network:
   - Under Wi-Fi settings, your ALFA adapter should now detect the available wireless networks.
   - Select the desired wireless network and enter the password if required.

3. Check the Connection:
   - Once connected, you can check your connection status from the Network & Sharing Center or by simply clicking the network icon in the system tray.

# Step 4: Troubleshooting Tips
If you're encountering issues or the adapter isn't working correctly, try the following:

- Driver Issues: If the adapter doesn't appear in Device Manager or has a yellow exclamation mark, uninstall the current driver by right-clicking it in Device Manager and selecting Uninstall Device. Then, reboot and reinstall the driver.
  
- USB Port Issues: Make sure you're using a working USB port, preferably a USB 2.0 port. The AWUS036NEH is a USB 2.0 device, and some older systems may have trouble with USB 3.0 ports.

- Windows Update: Ensure Windows 10 is fully updated by going to Settings > Update & Security > Windows Update and installing any pending updates.

- Power Management Settings: Sometimes Windows may disable USB devices to save power. To prevent this, open Device Manager, locate the adapter, right-click, and select Properties. Go to the Power Management tab and uncheck the option for Allow the computer to turn off this device to save power.

- Network Issues: If the network signal is weak or the adapter isn't detecting nearby networks, try moving closer to your wireless access point or ensure that there are no strong sources of interference nearby.

Once properly configured, your ALFA AWUS036NEH USB Adapter should be able to operate in long-range modes, making it a great tool for both everyday use and Wi-Fi auditing tasks.