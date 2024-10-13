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
11- nmap -sC -sV -p- -O -v -A -T4 192.168.9.0/24
12- nmap -p 22 -sV 192.168.0.0/24 (Identify version of OpenSSH)

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
1- NetBios enum using windows- 
in cmd type- nbtstat -a 10.10.10.10 (-a displays NEtBIOS name table)
2- NetBios enum using nmap- 
nmap -sV -v --script nbstat.nse 10.10.10.16
3- SNMP enum using nmap-  
nmap -sU -p 161 10.10.10.10 (-p 161 is port for SNMP)--> Check if port is open
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
