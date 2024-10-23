# Overview: Importing PowerShell Modules

PowerShell modules are packages that contain PowerShell functions, cmdlets, scripts, or assemblies. Modules allow you to extend the capabilities of PowerShell by adding new functionality and features, making them crucial for tasks ranging from system administration to automation. In this guide, you’ll learn how to import and manage PowerShell modules.

# What Is a PowerShell Module?

A module is a collection of related scripts, cmdlets, functions, or resources organized into a single package. There are different types of modules:
- **Script modules:** Contain PowerShell functions or scripts.
- **Binary modules:** Contain compiled code in .NET assemblies (.dll files).
- **Manifest modules:** Provide metadata and dependencies.
- **DSC Resource modules:** Provide Desired State Configuration (DSC) resources.

# Managing Module Locations

PowerShell stores modules in predefined locations that it searches when you use `Import-Module`. Common locations include:
- **User-specific location:**  
  `C:\Users\<UserName>\Documents\WindowsPowerShell\Modules`
  
- **System-wide location:**  
  `C:\Program Files\WindowsPowerShell\Modules`

You can also create and store custom modules in these directories for easy use.

# Download PowerShell Module

[https://www.powershellgallery.com/](https://www.powershellgallery.com/)


## Step 1: Identify Install Path
Determine the path for your PowerShell modules by running the command:

```powershell
$Env:PSModulePath
```

   - Use the first path for a specific user account.
   - Use the second path for all users on the computer.
   - Avoid using the third path as it’s reserved for built-in Windows modules.

## Step 2: List Available Modules

Before importing a module, you can list all available modules on your system with the following command:

```powershell
Get-Module -ListAvailable
```

This will display all modules installed on your system, both those that are currently loaded and those that are available for loading.

---

## Step 3: Download the Module
Download the module and copy it to the chosen path from step 1. For instance, to make it available for all users, copy it to `C:\Program Files\WindowsPowerShell\Modules`.
    - Verify the module availability by running `Get-Module -ListAvailable`.
---

## Step 4: Installing a Module (If Needed)

If the desired module isn't installed on your system, you can install it from the PowerShell Gallery or other repositories.

### Example: Install a Module from PowerShell Gallery

```powershell
Install-Module -Name <module_name>
```

Replace `<module_name>` with the name of the module you wish to install. You may be prompted for permission if the module requires additional privileges.

---

## Step 5: Importing a Module

After installing or verifying that a module is available, you can import it into your current session to make its commands and functions available.

```powershell
Import-Module -Name <module_name>
```

---

## Step 6: Verify Module Import

To check whether a module has been successfully imported, use the following command:

```powershell
Get-Module
```

This will show all the modules currently loaded in your session. If the desired module appears in the list, it has been imported correctly.

---

## Step 7: List Module Commands

To see what commands a module contains, run:

```powershell
Get-Command -Module <module_name>
```

---

## Step 8: Remove a Module (If Needed)

If you no longer need the module in your current session, you can unload it with:

```powershell
Remove-Module -Name <module_name>
```

This will remove the module from the session but won’t uninstall it from your system. You can re-import it in future sessions as needed.

---

## Auto-Loading Modules

Starting from PowerShell 3.0, modules are automatically imported when you first use a cmdlet from that module. This is a handy feature, but you can manually disable auto-loading if needed.

To manually disable auto-loading of modules:

```powershell
$PSModuleAutoLoadingPreference = "None"
```

To re-enable auto-loading, set it back to `"All"`:

```powershell
$PSModuleAutoLoadingPreference = "All"
```

---

## Example: Full Workflow

Here’s an example of how you would work with a module from installation to usage.

1. **Install the module** (if needed):
   ```powershell
   Install-Module -Name Posh-SSH
   ```

2. **Import the module:**
   ```powershell
   Import-Module -Name Posh-SSH
   ```

3. **Verify the module is imported:**
   ```powershell
   Get-Module
   ```

4. **List the available cmdlets:**
   ```powershell
   Get-Command -Module Posh-SSH
   ```

5. **Use a cmdlet from the module:**
   ```powershell
   New-SSHSession -ComputerName <target_ip> -Credential (Get-Credential)
   ```

6. **Remove the module** (optional):
   ```powershell
   Remove-Module -Name Posh-SSH
   ```