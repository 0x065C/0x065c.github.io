A `.vhdx` file is a Hyper-V virtual hard disk format used to store the contents of a virtual machine's hard drive. To extract or mount the contents of a `.vhdx` file using native tools in Windows and Linux, there are specific approaches. Below are detailed step-by-step instructions for both operating systems.

---

# Windows: Mounting `.vhdx` using Native Tools

## Method 1: Mount via Disk Management

1. Open Disk Management:
   - Press `Win + X` and select Disk Management, or search for Create and format hard disk partitions in the Start menu.

2. Mount the `.vhdx` File:
   - In Disk Management, click on Action in the menu, then select Attach VHD.
   - A dialog box will appear. Click Browse and navigate to the location of the `.vhdx` file.
   - Once you’ve selected the `.vhdx` file, ensure the checkbox for Read-only is unchecked if you want to make changes to the disk, or checked if you only want to view the contents.

3. Access the Mounted Disk:
   - After the `.vhdx` file is mounted, it will appear as a new drive in File Explorer. You can access, copy, and manipulate the files just like any other drive.

4. Dismount the `.vhdx` File:
   - Once you are done, you can dismount it. In Disk Management, right-click the disk that corresponds to the `.vhdx` and select Detach VHD.

---

## Method 2: Mount via PowerShell

PowerShell also provides a way to mount and work with `.vhdx` files. Here's a deep dive into the process.

1. Open PowerShell as Administrator:
   - Search for `PowerShell`, right-click it, and choose Run as Administrator.

2. Mount the `.vhdx` File:
   Use the `Mount-VHD` cmdlet to mount the `.vhdx` file.

   ```powershell
   Mount-VHD -Path "<Path\To\File.vhdx>"
   ```

   For example:

   ```powershell
   Mount-VHD -Path "C:\VirtualDisks\mydisk.vhdx"
   ```

3. Verify the Mounted Drive:
   You can use the `Get-Disk` or `Get-VHD` cmdlet to verify if the `.vhdx` is successfully mounted.

   ```powershell
   Get-Disk
   ```

   Or to get more specific details:

   ```powershell
   Get-VHD -Path "<Path\To\File.vhdx>"
   ```

4. List Mounted Volumes:
   After mounting, you can use the following to list the volumes:

   ```powershell
   Get-Volume
   ```

5. Unmount the `.vhdx` File:
   Once done, you can unmount the `.vhdx` by running:

   ```powershell
   Dismount-VHD -Path "<Path\To\File.vhdx>"
   ```

---

## Method 3: Using Hyper-V Manager

1. Open Hyper-V Manager:
   - Search for and open Hyper-V Manager.
   
2. Create a Virtual Machine:
   - If needed, create a new virtual machine and select the `.vhdx` file as its virtual hard disk.
   
3. Access the `.vhdx` File:
   - Once the virtual machine is up and running, you can access the `.vhdx` contents through the virtual machine itself.

---

# Linux: Mounting `.vhdx` Files using Native Tools

Linux does not natively support `.vhdx` files, but you can use tools like `qemu-nbd` to mount the virtual hard disk. Below is a deep dive into the process.

## Method 1: Using `qemu-nbd` to Mount a `.vhdx` File

1. Install Required Packages:
   You need to install the `qemu-utils` package, which includes the `qemu-nbd` tool for interacting with Network Block Devices (NBD).

   On Debian/Ubuntu-based distributions:
   
   ```bash
   sudo apt update
   sudo apt install qemu-utils
   ```

   On CentOS/RHEL-based distributions:
   
   ```bash
   sudo yum install qemu-img
   ```

2. Load the NBD Kernel Module:
   Before mounting the `.vhdx` file, load the NBD kernel module:

   ```bash
   sudo modprobe nbd max_part=8
   ```

   The `max_part=8` option defines the number of partitions you can have.

3. Connect the `.vhdx` to the NBD Device:
   Use `qemu-nbd` to connect the `.vhdx` file to a network block device (e.g., `/dev/nbd0`).

   ```bash
   sudo qemu-nbd -c /dev/nbd0 <Path\To\File.vhdx>
   ```

   For example:

   ```bash
   sudo qemu-nbd -c /dev/nbd0 /home/user/disks/mydisk.vhdx
   ```

4. Check the Partitions:
   Use `fdisk` or `parted` to list the partitions:

   ```bash
   sudo fdisk -l /dev/nbd0
   ```

   Or:

   ```bash
   sudo parted /dev/nbd0 print
   ```

5. Mount the Partitions:
   Once you’ve identified the partitions, you can mount them. For example, if the partition you want is `/dev/nbd0p1`:

   ```bash
   sudo mount /dev/nbd0p1 /mnt
   ```

   Now, the contents of the `.vhdx` file should be accessible at `/mnt`.

6. Unmount and Disconnect:
   After you’re done, unmount the partitions and disconnect the NBD device.

   ```bash
   sudo umount /mnt
   sudo qemu-nbd -d /dev/nbd0
   ```

---

## Method 2: Convert `.vhdx` to a Supported Format (Optional)

If working with `.vhdx` directly is not feasible, you can convert it to a format natively supported by Linux, such as `.qcow2` or `.raw`.

1. Convert `.vhdx` to `.raw` or `.qcow2`:
   Use the `qemu-img` tool to convert the `.vhdx` file.

   ```bash
   qemu-img convert -f vhdx -O raw <Path\To\File.vhdx> <Path\To\Outfile.raw>
   ```

   Or, to convert to `.qcow2`:

   ```bash
   qemu-img convert -f vhdx -O qcow2 <Path\To\File.vhdx> <Path\To\Outfile.qcow2>
   ```

2. Mount the Converted File:
   If converted to a `.raw` file, you can directly mount it using the `losetup` command.

   ```bash
   sudo losetup -fP <Path\To\Outfile.raw>
   ```

   This will associate the image with a loopback device. Then, check the loop device:

   ```bash
   sudo losetup -l
   ```

3. Mount the Loop Device:
   Now, mount the partition:

   ```bash
   sudo mount /dev/loop0p1 /mnt
   ```

4. Unmount:
   When finished, unmount the drive and detach the loopback device:

   ```bash
   sudo umount /mnt
   sudo losetup -d /dev/loop0
   ```