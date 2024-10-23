# Creating a Portable Windows 11/10 USB drive with Hasleo WinToUSB.

Step 1. Connect the USB drive to the computer, download, install and run Hasleo WinToUSB and then click "Windows To Go USB".

![Click Windows To Go creator](https://www.easyuefi.com/wintousb/images/en/click-windows-to-go-usb.png)

Step 2. Click "Select installation source", then click "Browse image file" and select the image file (ISO、WIM、VHD(X)、DBI) from the open dialog box as installation source, or choose a CD/DVD drive with a Windows installation DVD inserted as the installation source. You can also [clone the currently running Windows to a USB drive as portable Windows](https://www.easyuefi.com/wintousb/resource/clone-windows-10-to-usb-drive.html) by selecting "Current Windows OS" as the installation source.

![Select installation source for Windows To Go](https://www.easyuefi.com/wintousb/images/en/wintogo-win11/pro/select-installation-source.png)

* **Tips:** DBI is the extension of the backup image file produced by [Hasleo Backup Suite](https://www.easyuefi.com/backup-software/backup-suite-free.html).

Step 3. Hasleo WinToUSB scans for and lists installable operating systems, select the edition of Windows you want to install.

![Select Windows edition](https://www.easyuefi.com/wintousb/images/en/wintogo-win11/pro/select-windows-edition.png)

Step 4. Click "Select destination drive" and select the destination drive from the pop-up drive list. If the drive is not correctly recognized by Hasleo WinToUSB, you can click the ![refresh drive list](https://www.easyuefi.com/wintousb/images/refresh.png) button for the program to recognize the drive.

![Select destination drive](https://www.easyuefi.com/wintousb/images/en/wintogo-win11/pro/select-destination-drive.png)

Step 5. Choose the partition scheme and installation mode you want to use, and you can specify additional drivers or enable BitLocker to encrypt the Windows To Go USB drive according to your needs, then click "Proceed".

![Select partition scheme and installation mode](https://www.easyuefi.com/wintousb/images/en/wintogo-win11/pro/select-partition-scheme-and-installation-mode.png)

* **Tips:**

1. For more detailed information about "Partition scheme", "Installation mode" and "Enable BitLocker", please refer to: [How to create portable Windows 11/10/8/7 from an ISO, WIM, ESD, SWM or VHD(X) file?](https://www.easyuefi.com/wintousb/faq/en-US/How-to-use-WinToUSB-ISO-To-USB.html)
2. If you choose "Keep the existing partition scheme", you need to manually prepare the partitions on the USB drive before this step, and [here](https://www.easyuefi.com/wintousb/resource/manually-prepare-the-partitions-for-windows-to-go.html) is the user guide on how to manually prepare partitions for Windows To Go.

Step 6. After clicking "Proceed", a pop-up will appear asking you if you want to format it to continue, click "Yes" if you are sure.

![The drive needs to be formatted prompt](https://www.easyuefi.com/wintousb/images/en/wintogo-win11/pro/drive-will-be-formatted-warning.png)

Step 7. After clicking "Yes", WinToUSB begins installing Windows to the destination drive.

![installing Windows to USB](https://www.easyuefi.com/wintousb/images/en/wintogo-win11/pro/installing-windows-to-usb.png)

Step 8. The installation will take some time, please be patient.

#### Boot and run Windows 11/10 from the portable Windows 11/10 USB drive.

BIOS settings allow you to run a boot sequence from a floppy drive, a hard drive, a CD-ROM drive or an external device. To boot portable Windows from a USB drive, you need to enter the BIOS and change the boot sequence to set the USB drive as the first boot priority.

Step 1. After the installation is complete, restart the computer, press the appropriate key to boot into BIOS. Different motherboards and computer manufacturers use different keys to enter the BIOS. Usually, when the computer starts, you will be prompted to enter the key to enter BIOS, but the prompts are usually displayed for a short time and you may not be able to see it clearly. Below we list the keys used by popular brands of motherboards and computers to get into BIOS.

![keys to enter BIOS](https://www.easyuefi.com/wintousb/images/resource/keys-to-enter-bios.png)

Step 2. After successfully entering the BIOS, change BIOS to boot from the portable Windows 11/10 USB drive.

![change BIOS to boot from USB](https://www.easyuefi.com/wintousb/images/en_US/installation-bios-boot-from-usb.png)

Step 3. Windows 11/10 normal installation starts up and you have to complete all the installation steps. After that, you can install programs, copy files, etc.

![Windows normal installation](https://www.easyuefi.com/wintousb/images/en_US/installation-windows-normal-installation.png)
