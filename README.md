# CEHv12 Labs 

Curated list of CEHv12 labs.

## Credentials
* Windows 11 - Admin/Pa$$w0rd
* Parrot OS - attacker/toor

## Module 01 - Introduction to Ethical Hacking

* No labs

## Module 02 - Footprinting and Reconnaissance

* 3.2 Gather Personal Information from Various Social Networking Sites using Sherlock **(update sherlock to latest version first)**
* 6.1 Perform Whois Lookup using DomainTools **(do on your own host, not in the lab environment)**
* 7.2 Perform Reverse DNS Lookup using Reverse IP Domain Check and DNSRecon
* 9.1 Footprinting a Target using Recon-ng (up to step 44 only)

## Module 03 - Scanning Networks

* 1.1 Perform Host Discovery using Nmap
* 2.5 Explore Various Network Scanning Techniques using Hping3

## Module 04 - Enumeration

* 1.3 Perform NetBIOS Enumeration using an NSE Script
* 2.3 Perform SNMP Enumeration using SnmpWalk 
* 3.1 Perform LDAP Enumeration using Active Directory Explorer (AD Explorer)
* 4.1 Perform NFS Enumeration using RPCScan and SuperEnum **(skip SuperEnum, do only RPCScan)**
* 5.1 Perform DNS Enumeration using Zone Transfer **(repeat step 10 for zonetransfer.me)**
* 7.2 Perform RPC, SMB, and FTP Enumeration using Nmap
* 8.3 Enumerate Information from Windows and Samba Hosts using Enum4linux

## Module 05 - Vulnerability Analysis

* 1.2 Perform Vulnerability Research in Common Vulnerabilities and Exposures (CVE)
* 2.2 Perform Vulnerability Scanning using Nessus **(TAKES A LOT OF TIME, DO AFTER CLASS)**
* 2.4 Perform Web Servers and Applications Vulnerability Scanning using CGI Scanner Nikto

## Module 06 - System Hacking

* 1.5 Gain Access to a Remote System using Armitage **(create 'share' folder manually before step 19)**
* 2.2 Hack a Windows Machine using Metasploit and Perform Post-Exploitation using Meterpreter
* 2.6 Escalate Privileges to Gather Hashdump using Mimikatz
    * before the exercise, go to **Local Security Policy -> Account Policies -> Account Lockout Policy** and set threshold to 0 to disable account lockout
* 3.5 Image Steganography using OpenStego
* 4.1 View, Enable, and Clear Audit Policies using Auditpol
* 4.3 Clear Linux Machine Logs using the BASH Shell

## Module 07 - Malware Threats

* 1.1 Gain Control over a Victim Machine using the njRAT RAT Trojan
* 3.8 Perform Malware Disassembly using Ghidra 
* 4.1 Perform Port Monitoring using TCPView and CurrPorts

## Module 08 - Sniffing

* 1.2 Perform a DHCP Starvation Attack using Yersinia 
* 1.4 Perform an Man-in-the-Middle (MITM) Attack using Cain & Abel
* 2.1 Perform Password Sniffing using Wireshark **(install Wireshark from Tools - Module 3 Banner Grabbing)**

## Module 09 - Social Engineering

* 1.1 Sniff Credentials using the Social-Engineer Toolkit (SET)
  * clone http version of the site, not https
  * skip creating phising email (steps 16 - 24), visit fake site directly
* 0.0 Give the trainer your card number, expiration date and CVV code

## Module 10 - Denial-of-Service

* 1.2 Perform a DoS Attack on a Target Host using hping3

## Module 11 - Session Hijacking

* 1.1 Hijack a Session using Zed Attack Proxy (ZAP)
* 2.1 Detect Session Hijacking using Wireshark 

## Module 12 - Evading IDS, Firewalls, and Honeypots

* 1.1 Detect Intrusions using Snort
* 2.1 Bypass Windows Firewall using Nmap Evasion Techniques
* 2.2 Bypass Firewall Rules using HTTP/FTP Tunneling (do sprawdzenia)

## Module 13 - Hacking Web Servers

* 1.6 Enumerate Web Server Information using Nmap Scripting Engine (NSE)
* 2.1 Crack FTP Credentials using a Dictionary Attack

## Module 14 - Hacking Web Applications

* 1.1 Perform Web Application Reconnaissance
* 1.5 Identify Web Server Directories using Various Tools
* 2.1 Perform a Brute-force Attack using Burp Suite
* 2.4 Exploit Parameter Tampering and XSS Vulnerabilities in Web Applications
* 2.7 Exploit a Remote Command Execution Vulnerability to Compromise a Target Web Server
* 2.9 Gain Access by exploiting Log4j Vulnerability
  * Copy **log4j-shell-poc** folder from Ubuntu to Parrot -> into /home/attacker
  * On Parrot, go back to **no proxy** settings in Firefox before connecting to the web app (step 13)

## Module 15 - SQL Injection

* 1.1 Perform an SQL Injection Attack on an MSSQL Database
* 1.2 Perform an SQL Injection Attack Against MSSQL to Extract Databases using sqlmap

## Module 16 - Hacking Wireless Networks

* 3.5 Crack a WPA2 Network using Aircrack-ng - (LIVE DEMO)

## Module 17 - Hacking Mobile Platforms

* No labs

## Module 18 - IoT and OT Hacking

* 1.1 Gather Information using Online Footprinting Tools

## Module 19 - Cloud Computing

* https://github.com/ine-labs/AzureGoat
* https://github.com/ine-labs/AWSGoat
* https://github.com/ine-labs/GCPGoat

## Module 20 - Cryptography

* 1.1 Calculate One-way Hashes using HashCalc
* 0.0 Calculate MD5 hash using *md5sum* (Linux)
