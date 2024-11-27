# File and Resource Attacks

In the ever-evolving landscape of web application security, it's essential to stay ahead of the curve when it comes to protecting your web applications from potential threats. This comprehensive course delves deep into the critical aspects of file upload, directory traversal, Local File Inclusion (LFI), and Remote File Inclusion (RFI) vulnerabilities. This course is designed for cybersecurity professionals, web application penetration testers, and anyone interested in web application security testing. It focuses on file and resource-based vulnerabilities commonly encountered in modern web applications. It will also give you practical knowledge and hands-on experience in identifying, exploiting, and mitigating vulnerabilities related to file and resource handling in web applications.

This course will start by introducing you to Arbitrary File Upload vulnerabilities and will teach you how to identify and exploit these vulnerabilities for remote code execution (RCE). You will also get an introduction to Directory Traversal vulnerabilities, and you will get an insight into what causes Directory Traversal vulnerabilities and how they can be identified and exploited. The course will then close off by covering inclusion vulnerabilities, specifically Local File Inclusion (LFI) and Remote File Inclusion (RFI).

---

## Course Introduction

### Course Topic Overview

- Introduction to Arbitrary File Upload Vulnerabilities
- Bypassing File Upload Extension Filters
- Bypassing PHPx Blacklists
- Introduction to Directory/Path Traversal Vulnerabilities
- Identifying and Exploiting Directory/Path Traversal Vulnerabilities
- Introduction to LFI and RFI Vulnerabilities
- Identifying and Exploiting LFI and RFI Vulnerabilities

### Prerequisites

- Basic familiarity with HTTP/HTTPS
- Basic familiarity with Linux

### Learning Objectives

- You will have an understanding of what File Upload, Directory Traversal, LFI and RFI vulnerabilities are and how to identify them.
- You will have the ability to bypass file upload filters and blacklists for RCE.
- How will be able to exploit Directory Traversal vulnerabilities.
- You will have the ability to identify and exploit LFI vulnerabilities.
- You will have the ability to identify and exploit RFI vulnerabilities.

---
---

## Arbitrary File Upload Vulnerabilities

### Exploiting Basic File Upload Vulnerabilities

#### Lab Environment

**Vulnerable Apache IV**

Apache is probably the most popular web server on the World Wide Web with millions of deployments! In this series of challenges, we hope to explore how attackers can exploit webapps running on Apache  arising due to server misconfigurations and/or application vulnerabilities. Take a look at the scenario below.

The target server has not been properly secured against arbitrary file upload and execution vulnerability.

**Objective**: Your objective is to upload a web shell, execute arbitrary commands on the server and retrieve the flag!

#### Lab Solution

``:
```

```

``:
```

```

``:
```

```

### Bypassing File Upload Extension Filters

#### Lab Environment

**Vulnerable Nginx II**

Nginx, even though young by World Wide Web years, is as popular as Apache today. In this series of challenges, we hope to explore how attackers can exploit webapps running on Nginx  arising due to server misconfigurations and/or application vulnerabilities. Take a look at the scenario below.

The web portal only allows the user to upload files with restricted extensions i.e. jpg, png etc. But a misconfiguration in PHP configuration file (php.ini) allows PHP code execution for uploaded files.

**Objective:** Your objective is to upload a web shell, execute arbitrary commands on the server and retrieve the flag!

#### Lab Solution

``:
```

```

``:
```

```

``:
```

```

### Bypassing PHPx Blacklists

#### Lab Environment

**Vulnerable Apache V**

Apache is probably the most popular web server on the World Wide Web with millions of deployments! In this series of challenges, we hope to explore how attackers can exploit webapps running on Apache  arising due to server misconfigurations and/or application vulnerabilities. Take a look at the scenario below.

The target server has not been properly secured against arbitrary file upload and execution vulnerability. The administrator has used a blacklisting approach but forgotten to add other executable file extensions to this list. This example also proves why blacklisting is not considered a good security measure.

**Objective**: Your objective is to upload a web shell, execute arbitrary commands on the server and retrieve the flag!

#### Lab Solution

``:
```

```

``:
```

```

``:
```

```

### WordPress wpStoreCart File Upload

#### Lab Environment

**Vulnerable Apache IV**

The attacker might not have any user level access to the web application. However, this does not mean that the application cannot be compromised remotely. File Upload vulnerabilities could be triggered even by unauthenticated users.

In the exercise below, the attacker is unauthenticated to the web application and needs to find a file upload attack to eventually run arbitrary commands on the server.

A version of WordPress wpStoreCart Plugin is vulnerable to a file upload attack.

**Objective**: Your task is to find and exploit this vulnerability.

#### Lab Solution

``:
```

```

``:
```

```

``:
```

```

---

## Directory/Path Traversal

### Directory Traversal Basics

#### Lab Environment

**Directory Traversal**

[OWASP Top 10](https://owasp.org/www-project-top-ten/) is an awareness document, which outlines the most critical security risks to web applications. Pentesting is performed according to the OWASP TOP 10 standard to reduce/mitigate the security risks.

In the exercise, we will focus on [OWASP A5: Broken Access Control](https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control) flaws and we will take a look at how to exploit the vulnerability on the [bWAPP](http://www.itsecgames.com/) web application.

**Objective**: Leverage the directory traversal vulnerability and find more information about the system. 

Instructions: 
- This lab is dedicated to you! No other users are on this network :)
- Once you start the lab, you will have access to a Kali GUI instance.
- Your Kali instance has an interface with IP address `192.X.Y.2`. Run `ip addr` to know the values of X and Y.
- Do not attack the gateway located at IP address `192.X.Y.1`.

#### Lab Solution

``:
```

```

``:
```

```

``:
```

```

### OpenEMR Directory Traversal

#### Lab Environment

**OpenEMR Arbitrary File Read**

An attacker might get administrative access to a web application. However, this does not automatically mean that the web server can be compromised. In cases where a SaaS application is made available to users, it is routine to give each user admin access to his own instance of the web application e.g. a managed hosted Wordpress site. In such scenario, the attacker who will begin accessing the application as a managed administrative user will have to figure out how to exploit the administrative interface to get a shell on the server. In some cases, it might be possible to do privilege escalation as well.

In the exercise below, the attacker has administrative access to the web application and needs to find a directory traversal attack to access restricted information (i.e. files listing) about the server.

[OpenEMR](https://www.open-emr.org/) is a popular open source electronic health records and medical practice management solution developed in PHP.  
OpenEMR (5.0.1.3) is vulnerable to a Directory Traversal documented in `CVE-2018-15140`.

The following username and passwords may be used to explore the application and/or find a vulnerability which might require authenticated access:
- Username: "admin"
- Password: "password"

**Objective**: Your task is to find and exploit this vulnerability.  

#### Lab Solution

``:
```

```

``:
```

```

``:
```

```

---

## Local File Inclusion (LFI)

### Local File Inclusion Basics

#### Lab Environment

**Local File Inclusion**

[OWASP Top 10](https://owasp.org/www-project-top-ten/) is an awareness document, which outlines the most critical security risks to web applications. Pentesting is performed according to the OWASP TOP 10 standard to reduce/mitigate the security risks.

In the exercise, we will focus on [OWASP A5: Broken Access Control](https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control) flaws and we will take a look at how to exploit the vulnerability on the [bWAPP](http://www.itsecgames.com/) web application.

**Objective**: Leverage the Local File Inclusion vulnerability and read system files from the target machine. 

Instructions: 
- This lab is dedicated to you! No other users are on this network :)
- Once you start the lab, you will have access to a Kali GUI instance.
- Your Kali instance has an interface with IP address `192.X.Y.2`. Run `ip addr` to know the values of X and Y.
- Do not attack the gateway located at IP address `192.X.Y.1`.

#### Lab Solution

``:
```

```

``:
```

```

``:
```

```

#### Lab Environment

**WordPress IMDb Widget**

The attacker might not have any user level access to the web application. However, this does not mean that the application cannot be compromised remotely. Local File Inclusion could be triggered even by unauthenticated users.

In the exercise below, the attacker is unauthenticated to the web application and needs to find an local file inclusion attack on it.

A version of WordPress IMDb Profile Widget Plugin is vulnerable to a local file inclusion attack.

**Objective**: Your task is to find and exploit this vulnerability.

#### Lab Solution

``:
```

```

``:
```

```

``:
```

```

---

## Remote File Inclusion (RFI)

### Remote File Inclusion Basics

#### Lab Environment

**Remote File Inclusion I**

[OWASP Top 10](https://owasp.org/www-project-top-ten/) is an awareness document, which outlines the most critical security risks to web applications. Pentesting is performed according to the OWASP TOP 10 standard to reduce/mitigate the security risks.

In the exercise, we will focus on [OWASP A5: Broken Access Control](https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control) flaws and we will take a look at how to exploit the vulnerability on the [Mutillidae](https://github.com/webpwnized/mutillidae) web application.

**Objective**: Leverage the Remote File Inclusion vulnerability and perform an XSS attack on the web application.

Instructions: 
- This lab is dedicated to you! No other users are on this network :)
- Once you start the lab, you will have access to a Kali GUI instance.
- Your Kali instance has an interface with IP address `192.X.Y.2`. Run `ip addr` to know the values of X and Y.
- Do not attack the gateway located at IP address `192.X.Y.1`.

#### Lab Solution

``:
```

```

``:
```

```

``:
```

```

---
---
