# Summary
Word list generation is a critical technique used in the context of password attacks, particularly for brute force and dictionary attacks. This technique involves creating a comprehensive list of potential passwords that can be used to systematically guess the password for a given account or service. Typical use cases include penetration testing, ethical hacking, and security assessments to identify weak or common passwords. The process involves combining common words, phrases, and patterns to generate potential password lists, leveraging various tools and methodologies to create effective and extensive word lists.

# How Word List Generation Works

1. **Identify Target Information:** Gather information about the target, such as usernames, common phrases, and other relevant data that might influence password choices.
2. **Select a Word List Generator:** Choose a tool or script that will be used for generating the word list. Popular tools include `Crunch`, `Cewl`, and `John the Ripper`.
3. **Define Parameters:** Set the parameters for the word list, such as length, character sets, and patterns. This can include lowercase letters, uppercase letters, numbers, and special characters.
4. **Combine Words and Patterns:** Use the tool to combine words and patterns to create potential passwords. This can involve permutations, concatenations, and substitutions to expand the list.
5. **Refine the List:** Remove duplicates and irrelevant entries to create a focused and efficient word list.
6. **Test the Word List:** Use the generated word list in password cracking tools to test its effectiveness against the target system.

# Types of Word List Generation

1. **Static Word Lists:** Precompiled lists that are commonly used for quick tests. Examples include the `rockyou.txt` and `darkc0de.lst`.    
    - **Use Case:** Initial testing phase to quickly identify weak passwords.
    - **Example:** `rockyou.txt` contains millions of passwords leaked from real-world databases.

2. **Dynamic Word Lists:** Custom-generated lists based on specific parameters and patterns.    
    - **Use Case:** Targeted attacks where specific characteristics of the target are known.
    - **Example:** Using `Crunch` to generate a list with specific length and character set:

```
crunch 8 12 abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 -o wordlist.txt
```

3. **Contextual Word Lists:** Lists generated from context-specific data, such as words from a website or social media profiles.    
    - **Use Case:** Phishing and social engineering attacks where target-specific data can be leveraged.
    - **Example:** Using `Cewl` to scrape words from a target website:

```
cewl http://example.com -m 5 -w wordlist.txt
```

# Word List Generation Discovery

#### Automated Discovery

1. **Crunch:** A tool for generating word lists with specific parameters.    
    - **Features:** Customizable length, character set, and patterns.
    - **Usage:**

```
crunch 8 12 abcdefghijklmnopqrstuvwxyz -o wordlist.txt
```

2. **Cewl:** A tool for creating custom word lists by scraping websites.    
    - **Features:** Extracts words from HTML, customizable minimum word length.
    - **Usage:**

```
cewl http://example.com -m 5 -w wordlist.txt
```

3. **John the Ripper:** A popular password cracking tool that includes a word list generation feature.    
    - **Features:** Customizable rules for wordlist generation.
    - **Usage:**

```
john --wordlist=rockyou.txt --rules --stdout > wordlist.txt
```


#### Manual Discovery

1. **Website Analysis:** Manually extract keywords from target websites, social media profiles, and other public sources.    
    - **Techniques:** Look for common phrases, names, and patterns relevant to the target.

2. **Common Password Patterns:** Create lists based on common patterns such as `SeasonYear`, `CompanyName123`, etc.    
    - **Techniques:** Use knowledge of common password construction methods.

3. **User Information:** Leverage known information about the target, such as birthdates, favorite sports teams, etc.    
    - **Techniques:** Combine personal data with common patterns.

# Word List Generation Payloads

#### Crafting Payloads

1. **Custom Patterns:** Define specific patterns that reflect likely password choices.    
    - **Example:** Creating a pattern for dates of birth and common suffixes:

```
crunch 8 8 -t 199%%%%% -o wordlist.txt
```

2. **Context-Specific Words:** Extract words from target-specific data sources like websites and documents.    
    - **Example:** Using `Cewl` to scrape words from a target's social media profile:

```
cewl http://socialmedia.com/targetprofile -m 5 -w wordlist.txt
```

#### Example of Context-Specific Payloads

1. **Targeted Word Lists:** Creating a list based on a target company's name and common suffixes.    
    - **Example:** Combining a company name with common password patterns:

```
crunch 8 12 -t CompanyName%% -o wordlist.txt
```

2. **Personalized Word Lists:** Generating passwords based on personal information.    
    - **Example:** Using a combination of a target's birth year and favorite sports team:

```
crunch 8 10 -t 1990Team%% -o wordlist.txt
```

# Password Mutation
Password mutation in the context of wordlist generation for password attacks refers to the process of systematically altering a base set of passwords to create new variants. This increases the chances of successfully cracking passwords by accounting for common modifications that users often apply to their passwords. These mutations can include changes such as appending numbers, substituting characters, changing case, or adding special characters.

#### Techniques for Password Mutation

1. **Character Substitution:**    
    - Replace common characters with similar-looking symbols or numbers.
    - Example: `password` becomes `p@ssw0rd`, `pa$$w0rd`, `p4ssw0rd`.

2. **Case Variation:**    
    - Change the case of characters to account for case sensitivity.
    - Example: `password` becomes `Password`, `PASSWORD`, `pAsswOrd`.

3. **Append and Prepend:**    
    - Add numbers, years, or special characters at the beginning or end of the password.
    - Example: `password` becomes `password123`, `123password`, `password!`, `!password`.

4. **Leet Speak (1337 5p34k):**    
    - Convert characters into leet speak.
    - Example: `password` becomes `p@55w0rd`.

5. **Reversal and Duplication:**    
    - Reverse the order of characters or duplicate certain parts.
    - Example: `password` becomes `drowssap`, `passwordpassword`.

6. **Insertion:**    
    - Insert characters or strings at various positions within the password.
    - Example: `password` becomes `pa$$word`, `passw0rd`.

#### Tools for Password Mutation
Several tools can automate the process of password mutation. Some of the commonly used ones are:

1. **John the Ripper:**    
    - John the Ripper (JtR) includes a rules engine that allows for complex password mutations.
    - Rules can be defined in the `john.conf` file to specify the types of mutations.
    - Syntax example: 

```
john --wordlist=wordlist.txt --rules --stdout > mutated_wordlist.txt
```

2. **Hashcat:**    
    - Hashcat also supports rule-based password mutations with its `.rule` files.
    - Syntax example:

```
hashcat -r rules/best64.rule -a 0 wordlist.txt -o mutated_wordlist.txt
```

   - Sample rule to append digits:

```
$1
$2
$3
```

- This appends `1`, `2`, `3` to each word in the wordlist.

3. **CeWL and CUPP:**    
    - CeWL (Custom Word List generator) and CUPP (Common User Passwords Profiler) can generate targeted wordlists based on user information and mutate them.
    - Example with CUPP:

```
cupp -i
```

- Interactive mode lets you input user information and generate a wordlist.

#### Example Workflow

1. **Generate a Base Wordlist:** Use a tool like CeWL to generate a wordlist from a target website:

```
cewl <target_url> -w base_wordlist.txt
```

2. **Mutate the Wordlist:** Use John the Ripper to apply rules and generate mutated passwords:

```
john --wordlist=base_wordlist.txt --rules --stdout > mutated_wordlist.txt
```

3. **Use the Mutated Wordlist in an Attack:** Use Hashcat to perform a dictionary attack with the mutated wordlist:

```
hashcat -m 0 <hashes.txt> mutated_wordlist.txt
```

#### Custom Rules in John the Ripper
You can create custom rules in `john.conf` to define specific mutations. For example:

```
[List.Rules:Custom]
:
-c Az"password"           # Change to "password"
-c "password"             # Change to "password"
Az"[0-9]"                 # Append digits 0-9
```

Running John with custom rules:

```
john --wordlist=base_wordlist.txt --rules=Custom --stdout > custom_mutated_wordlist.txt
```

# Bypassing Defenses

1. **Frequency Analysis:** Identify and use common patterns and sequences that might bypass simple filtering mechanisms.    
    - **Example:** Adjusting the word list to include common substitutions like `@` for `a`, `3` for `e`, etc.

```
sed 's/a/@/g; s/e/3/g' original_wordlist.txt > modified_wordlist.txt
```

2. **Encoding Variations:** Use different encoding techniques to evade detection.    
    - **Example:** Base64 encoding passwords:

```
echo -n 'password' | base64
```

3. **Length and Complexity Adjustments:** Generate passwords with varying lengths and complexities to test different policy constraints.    
    - **Example:** Using `Crunch` to create lists with a range of lengths:

```
crunch 8 16 abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 -o wordlist.txt
```

# Word List Generation Mitigation Strategies

1. **Enforce Strong Password Policies:** Implement and enforce policies that require complex, unique passwords.
    - **Example:** Requiring a minimum length of 12 characters with a mix of uppercase, lowercase, numbers, and special characters.

2. **Rate Limiting:** Limit the number of login attempts to reduce the effectiveness of brute force attacks.    
    - **Example:** Implementing rate limiting in web application configurations:

```
<Location "/login">
  SetEnvIf Request_URI "^/login$" LOGIN_ATTEMPTS
  <Limit POST>
    Order Deny,Allow
    Deny from env=LOGIN_ATTEMPTS
    Allow from all
  </Limit>
</Location>
```

3. **Multi-Factor Authentication (MFA):** Require additional authentication factors beyond just passwords.    
    - **Example:** Implementing MFA in authentication flows.
4. **Account Lockout Policies:** Lock accounts after a certain number of failed login attempts.    
    - **Example:** Configuring account lockout settings in Active Directory:

```
Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 -LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00
```

5. **User Education:** Educate users about the importance of strong passwords and the risks of password reuse.

# Resources

|**Website**|**URL**|
|-|-|
|Crunch|https://sourceforge.net/projects/crunch-wordlist/|
|Cewl|https://digi.ninja/projects/cewl.php|
|John the Ripper|https://www.openwall.com/john/|
|rockyou.txt|[https://github.com/praetorian-inc/Hob0Rules/blob/master/wordlists/rockyou.txt](https://github.com/praetorian-inc/Hob0Rules/blob/master/wordlists/rockyou.txt)|
|darkc0de.lst|[https://github.com/danielmiessler/SecLists/blob/master/Passwords/darkc0de.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/darkc0de.txt)|
|OWASP Password Cracking Resources|https://owasp.org/www-project-password-cracking/|