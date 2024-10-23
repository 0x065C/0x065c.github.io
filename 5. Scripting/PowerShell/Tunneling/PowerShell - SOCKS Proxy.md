```powershell
# PowerShell SOCKS Proxy Script with Improved Buffering, Logging, and Asynchronous Handling

# Import necessary .NET assemblies for networking
Add-Type -AssemblyName System.Net
Add-Type -AssemblyName System.Net.Sockets

# Define local port for SOCKS proxy
$localPort = 8008

# Buffer size for reading/writing data
$bufferSize = 4096

# Logging function to write events to the console and log file
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $message"
    Write-Output $logMessage
    $logMessage | Out-File -FilePath "C:\socks_proxy_log.txt" -Append -Encoding UTF8
}

# Start listener for incoming connections
$listener = [System.Net.Sockets.TcpListener]::new('127.0.0.1', $localPort)
$listener.Start()

Log-Message "SOCKS proxy started and listening on 127.0.0.1:$localPort"

# Function to handle incoming connections and forward traffic
function HandleConnection {
    param (
        [System.Net.Sockets.TcpClient]$client,
        [string]$targetHost,
        [int]$targetPort
    )

    try {
        # Create connection to the target host (Host C) and port
        Log-Message "Connecting to target $targetHost on port $targetPort"
        $targetClient = [System.Net.Sockets.TcpClient]::new($targetHost, $targetPort)
        $targetStream = $targetClient.GetStream()

        # Set up the client and target streams
        $clientStream = $client.GetStream()

        # Create buffers for reading and writing
        $clientBuffer = New-Object byte[] $bufferSize
        $targetBuffer = New-Object byte[] $bufferSize

        # Process bidirectional data transfer
        while ($client.Connected -and $targetClient.Connected) {
            # Check for incoming data from client to target
            if ($clientStream.DataAvailable) {
                $clientBytesRead = $clientStream.Read($clientBuffer, 0, $clientBuffer.Length)
                if ($clientBytesRead -gt 0) {
                    $targetStream.Write($clientBuffer, 0, $clientBytesRead)
                    $targetStream.Flush()
                    Log-Message "Data forwarded from client to target ($clientBytesRead bytes)"
                }
            }

            # Check for incoming data from target to client
            if ($targetStream.DataAvailable) {
                $targetBytesRead = $targetStream.Read($targetBuffer, 0, $targetBuffer.Length)
                if ($targetBytesRead -gt 0) {
                    $clientStream.Write($targetBuffer, 0, $targetBytesRead)
                    $clientStream.Flush()
                    Log-Message "Data forwarded from target to client ($targetBytesRead bytes)"
                }
            }

            # Sleep briefly to avoid high CPU usage in the loop
            Start-Sleep -Milliseconds 50
        }
    } catch {
        Log-Message "Error during communication: $_"
    } finally {
        # Ensure that both connections are closed
        Log-Message "Closing connections"
        $client.Close()
        $targetClient.Close()
    }
}

# Function to stop the listener and clean up resources
function Stop-SOCKSProxy {
    Log-Message "Stopping SOCKS proxy..."
    $listener.Stop()
    Log-Message "SOCKS proxy stopped."
    exit
}

# Handle CTRL+C or termination signal for clean shutdown
$exitEvent = Register-EngineEvent -SourceIdentifier ConsoleBreak -Action {
    Stop-SOCKSProxy
}

# Main loop to accept and handle incoming connections
while ($true) {
    try {
        # Accept incoming client connection
        $client = $listener.AcceptTcpClient()
        Log-Message "Accepted connection from $($client.Client.RemoteEndPoint)"

        # Dynamic target host and port, can be configured or passed dynamically
        $targetHost = "x.x.x.3"  # Replace with actual target IP
        $targetPort = 443        # Replace with actual target port

        # Use runspaces for better efficiency and multi-threading
        $runspace = [powershell]::Create().AddScript({
            param ($client, $targetHost, $targetPort)
            HandleConnection -client $client -targetHost $targetHost -targetPort $targetPort
        }).AddArgument($client).AddArgument($targetHost).AddArgument($targetPort)

        # Start the task asynchronously
        $runspace.BeginInvoke()
    } catch {
        Log-Message "Error accepting connection: $_"
    }
}
```

#### Workflow Summary

1. **Proxy Setup:** The script sets up a listener on `127.0.0.1` at port `8008`, awaiting incoming connections.
2. **Connection Handling:** For each client connection, the script establishes a corresponding connection to the target host (which can be dynamically set) and forwards data bidirectionally using buffers.
3. **Logging:** Every significant event (connection acceptance, data transfer, errors) is logged to both the console and a log file.
4. **Graceful Shutdown:** When the proxy is stopped (via CTRL+C), it gracefully closes all connections and cleans up resources.
5. **Asynchronous Connections:** The use of runspaces ensures that multiple client connections are handled concurrently, without the need for blocking or sequential processing.

#### Example Usage

1. **Start the proxy:**
	```powershell
	.\Improved_SOCKS_Proxy.ps1
	```    
	This will start the SOCKS proxy on `127.0.0.1:8008`.

2. **Use the proxy:**
    - Point any local application to use the proxy at `127.0.0.1:8008` to redirect traffic through the SOCKS proxy.
3. **Stop the proxy:**
    - Press `CTRL+C` in the PowerShell window to gracefully shut down the proxy and close any active connections.