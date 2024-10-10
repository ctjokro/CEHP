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
