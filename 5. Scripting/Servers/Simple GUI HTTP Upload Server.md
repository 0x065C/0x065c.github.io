# Step 1: Create a folder and open a terminal from that directory. 

# Step 2: Create a file named `index.html` with the following content:

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Simple File Upload</title>
    <style>
        /* Basic styling for the page */
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }
        h1 {
            margin-bottom: 20px;
        }
        #uploadForm {
            margin-bottom: 20px;
        }
        #fileInput {
            margin-right: 10px;
        }
        #uploadButton {
            cursor: pointer;
        }
        #responseMessage {
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <h1>Simple File Upload</h1>
    <form id="uploadForm">
        <input type="file" id="fileInput" name="file" accept=".txt,.pdf,.jpg,.png" required>
        <button type="button" id="uploadButton">Upload</button>
    </form>
    <div id="responseMessage"></div>
		    
    <script>
	    // JavaScript code for handling file upload
        document.getElementById('uploadButton').addEventListener('click', function(event) {
            var fileInput = document.getElementById('fileInput');
            var file = fileInput.files[0];
            if (file) {
                var formData = new FormData();
                formData.append('file', file, file.name); // Append the file with its name
                var xhr = new XMLHttpRequest();
                xhr.open('POST', '/upload', true); // Ensure that the URL matches the server endpoint
                xhr.setRequestHeader('file', file.name); // Set the 'file' header with the file name
                xhr.onload = function() {
                    if (xhr.status === 200) {
                        document.getElementById('responseMessage').textContent = xhr.responseText;
                        fileInput.value = ''; // Clear the file input field after upload
                    } else {
                        console.error('Upload failed with status ' + xhr.status);
                    }
                };
                xhr.send(formData);
					
                // Debug: Print the file name being uploaded
                console.log('Uploading file:', file.name);
            } else {
                alert('Please select a file to upload.');
            }
        });
    </script>
</body>
</html>
```

# Step 3: Create a file named `server.py` with the following content:

```
import http.server
import shutil
import os

# Define the request handler class
class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
   # Override the do_POST method to handle POST requests
    def do_POST(self):
        try:
            # Get the length of the content
            content_length = int(self.headers['Content-Length'])
            # Get the file name from the 'file' form field
            filename = self.headers['file']
            # Get the destination directory for file upload
            upload_dir = os.path.join(os.getcwd(), 'uploads')
            # Create the 'uploads' directory if it doesn't exist
            os.makedirs(upload_dir, exist_ok=True)
            # Get the destination path for file upload
            destination = os.path.join(upload_dir, filename)
            # Read the content from the request
            with open(destination, 'wb') as f:
                # Copy the content to the destination file
                shutil.copyfileobj(self.rfile, f)
            # Respond with a success message
            self.send_response(200)
            self.end_headers()
            self.wfile.write("File uploaded successfully".encode())
        except Exception as e:
            # If an error occurs, respond with an error message
            print("Error uploading file:", e)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Error uploading file: {str(e)}".encode())

# Define the server address and port
server_address = ('', 8000)

# Create and start the HTTP server
httpd = http.server.HTTPServer(server_address, SimpleHTTPRequestHandler)
print('Server running at localhost:8000...')
httpd.serve_forever()
```

# Step 4: Make server.py file executable 

```
sudo chmod +x server.py 
```

# Step 5: Run server.py

```
python3 server.py
```


• Now, you can access the HTML file using a web browser by navigating to `http[:]//<public_ip>:8000` 
• This will display the upload form. Users can now select a file using the file input field and click the "Upload" button to submit the form and upload the file to the server.
• To view uploaded files, navigate to `http[:]//<public_ip>:8000/uploads`
