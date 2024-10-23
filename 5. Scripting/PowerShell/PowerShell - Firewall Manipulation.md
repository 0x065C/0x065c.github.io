**Display All Firewall Rules:**

```powershell
Get-NetFirewallRule
```

**Get Enabled Firewall Rules:**

```powershell
Get-NetFirewallRule -Enabled True
```

**List Firewall Rules:**

```powershell
netsh advfirewall firewall dump
# or 
netsh firewall show state
netsh firewall show config
```

**Add Firewall Rule - Inbound Connection:**

```powershell
netsh advfirewall firewall add rule name="Red Cell Inbound" dir=in action=allow remoteip=<attack_ip> protocol=any
```

**Add Firewall Rule - Outbound Connection:**

```powershell
netsh advfirewall firewall add rule name="Red Cell Outbound" dir=out action=allow remoteip=<attack_ip> protocol=any
```

**Delete Firewall Rule:**

```powershell
netsh advfirewall firewall delete rule name="<rule_name>" 
```

**Disable Firewall:**

```powershell
# Disable Firewall via cmd
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"  /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Disable Firewall via Powershell
powershell.exe -ExecutionPolicy Bypass -command 'Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value'`

# Disable Firewall on any windows using native command
netsh firewall set opmode disable
netsh Advfirewall set allprofiles state off
```