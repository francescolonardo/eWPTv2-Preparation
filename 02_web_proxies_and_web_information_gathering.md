# Web Proxies and Web Information Gathering

Testing and modifying web requests being sent to web servers or web applications make up the majority of Web Application Penetration Testing. In order to intercept and modify the requests being sent between browsers and web applications we need to utilize Web Proxies. Web Proxies like Burp Suite and OWASP ZAP play a vital role in web application penetration testing and are pivotal in identifying and exploiting vulnerabilities in web applications. Web Proxies make the process of intercepting and replaying web requests much more efficient. As a result, web proxies are considered among the most important tools for any web app pentester.

This course will introduce you to web proxies like Burp Suite and OWASP ZAP and will cover the process of utilizing these web proxies in order to identify and exploit common vulnerabilities or misconfigurations in web applications. The goal of this course is to get you comfortable with using both Burp Suite and OWASP ZAP for web app pentesting.

---

## Course Introduction

### Course Topic Overview

- Introduction to Web Proxies
- Introduction to Burp Suite and OWASP ZAP
- Configuring the Burp Suite Proxy
- Burp Suite Dashboard and UI
- Burp Suite Target, Intruder, Sequencer, Repeater and Decoder
- Configuring the OWASP ZAP Proxy and Browser Certificate
- OWASP ZAP Dashboard and UI
- Crawling and Spidering with OWASP ZAP
- OWASP ZAP Target Context
- Directory Enumeration with Burp Suite and OWASP ZAP
- Attacking HTTP Forms with Burp Suite and OWASP ZAP

### Prerequisites

- Basic familiarity with HTTP/HTTPS
- Basic familiarity with Linux

### Learning Objectives

- You will get an introduction to what web proxies are and how they are used for web app pentesting.
- You will get an introduction to Burp Suite and OWASP ZAP.
- You will learn how to setup and configure Burp Suite and OWASP ZAP.
- You will get an understanding of the various features and capabilities of both Burp Suite and OWASP ZAP.
- You will learn how to actively and passively scan, crawl and spider web applications with Burp Suite and OWASP ZAP.
- You will learn how to perform common web application assessments and attacks like attacking HTTP login forms with Burp Suite and OWASP ZAP.

---
---

## 


---
---

## Tools and Frameworks

- []()

- []()

- []()

- []()

- [BuiltWith](https://builtwith.com/)
	BuiltWith is a web site profiler tool. Upon looking up a page, BuiltWith returns a list all the technologies in use on that page that it can find.
	BuiltWith covers 108,425+ internet technologies which include analytics, advertising, hosting, CMS and many more. See how the internet technology usage changes on a weekly basis.

- [Wappalyzer](https://www.wappalyzer.com/)
	Identify technologies on websites.
	Find out the technology stack of any website. Create lists of websites that use certain technologies, with company and contact details. Use our tools for lead generation, market analysis and competitor research.

- [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
	Next generation web scanner.
	WhatWeb identifies websites. Its goal is to answer the question, "What is that Website?". WhatWeb recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices. WhatWeb has over 1800 plugins, each to recognise something different. WhatWeb also identifies version numbers, email addresses, account IDs, web framework modules, SQL errors, and more.
	WhatWeb can be stealthy and fast, or thorough but slow. WhatWeb supports an aggression level to control the trade off between speed and reliability. When you visit a website in your browser, the transaction includes many hints of what web technologies are powering that website. Sometimes a single webpage visit contains enough information to identify a website but when it does not, WhatWeb can interrogate the website further. The default level of aggression, called 'stealthy', is the fastest and requires only one HTTP request of a website. This is suitable for scanning public websites. More aggressive modes were developed for use in penetration tests.
	Most WhatWeb plugins are thorough and recognise a range of cues from subtle to obvious. For example, most WordPress websites can be identified by the meta HTML tag, e.g. `<meta name="generator" content="WordPress X.Y.Z">`, but a minority of WordPress websites remove this identifying tag but this does not thwart WhatWeb. The WordPress WhatWeb plugin has over 15 tests, which include checking the favicon, default installation files, login pages, and checking for `/wp-content/` within relative links.

- [WAFW00F](https://github.com/EnableSecurity/wafw00f)
	WAFW00F allows one to identify and fingerprint Web Application Firewall (WAF) products protecting a website.
	To do its magic, WAFW00F does the following:
	- Sends a _normal_ HTTP request and analyses the response; this identifies a number of WAF solutions.
	- If that is not successful, it sends a number of (potentially malicious) HTTP requests and uses simple logic to deduce which WAF it is.
	- If that is also not successful, it analyses the responses previously returned and uses another simple algorithm to guess if a WAF or security solution is actively responding to our attacks.

- [HTTrack Website Copier](https://www.httrack.com/)
	HTTrack Website Copier, copy websites to your computer.
	_HTTrack_ is an _offline browser_ utility, allowing you to download a World Wide website from the Internet to a local directory, building recursively all directories, getting html, images, and other files from the server to your computer.
	_HTTrack_ arranges the original site's relative link-structure. Simply open a page of the "mirrored" website in your browser, and you can browse the site from link to link, as if you were viewing it online.

- [EyeWitness](https://github.com/RedSiege/EyeWitness)
	EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible.

- [Burp Suite]()

- [OWASP ZAP]()

- [DNSRecon](https://github.com/darkoperator/dnsrecon)
	DNSRecon is a Python port of a Ruby script that I wrote to learn the language and about DNS in early 2007. This time I wanted to learn about Python and extend the functionality of the original tool and in the process re-learn how DNS works and how could it be used in the process of a security assessment and network troubleshooting.
	This script provides the ability to perform:
	- Check all NS Records for Zone Transfers.
	- Enumerate General DNS Records for a given Domain (MX, SOA, NS, A, AAAA, SPF and TXT).
	- Perform common SRV Record Enumeration.
	- Top Level Domain (TLD) Expansion.
	- Check for Wildcard Resolution.
	- Brute Force subdomain and host A and AAAA records given a domain and a wordlist.
	- Perform a PTR Record lookup for a given IP Range or CIDR.
	- Check a DNS Server Cached records for A, AAAA and CNAME Records provided a list of host records in a text file to check.

- [dnsenum](https://github.com/fwaeytens/dnsenum)
	dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous IP blocks.

- [Sublist3r](https://github.com/aboul3la/Sublist3r)
	Fast subdomains enumeration tool for penetration testers.
	Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google, Yahoo, Bing, Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft, Virustotal, ThreatCrowd, DNSdumpster and ReverseDNS. [subbrute](https://github.com/TheRook/subbrute) was integrated with Sublist3r to increase the possibility of finding more subdomains using bruteforce with an improved wordlist. The credit goes to TheRook who is the author of subbrute.

- [Fierce](https://github.com/mschwager/fierce)
	A DNS reconnaissance tool for locating non-contiguous IP space.
	Fierce is a semi-lightweight scanner that helps locate non-contiguous IP space and hostnames against specified domains. It's really meant as a pre-cursor to nmap, unicornscan, nessus, nikto, etc, since all of those require that you already know what IP space you are looking for. This does not perform exploitation and does not scan the whole internet indiscriminately. It is meant specifically to locate likely targets both inside and outside a corporate network. Because it uses DNS primarily you will often find mis-configured networks that leak internal address space. That's especially useful in targeted malware.

- [Nikto](https://github.com/sullo/nikto)
	Nikto web server scanner.
	Nikto is a free software command-line vulnerability scanner that scans web servers for dangerous files or CGIs, outdated server software and other problems.

- [Gobuster](https://github.com/OJ/gobuster)
	Directory/File, DNS and VHost busting tool written in Go.
	Gobuster is a tool used to brute-force:
	- URIs (directories and files) in web sites
	- DNS subdomains (with wildcard support)
	- Virtual Host names on target web servers
	- Open Amazon S3 buckets
	- Open Google Cloud buckets
	- TFTP servers.

- [OWASP Amass](https://github.com/owasp-amass/amass)
	In-depth attack surface mapping and asset discovery.
	The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.

---

## Resources and References

- [DNSDumpster](https://dnsdumpster.com/)
- [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database)
- [Wayback Machine](https://web.archive.org/)

---
---
