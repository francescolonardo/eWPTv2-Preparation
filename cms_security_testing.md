# CMS Security Testing

In the world of modern, ever-evolving web applications, Content Management Systems (CMS) are the backbone of countless websites, with WordPress being one of the most widely used Content Management Systems. However, the ubiquity of WordPress also makes it a prime target for cyberattacks given its market share. This course is designed to equip security professionals, web application pentesters, and developers with the skills and knowledge needed to identify, assess, exploit and mitigate security vulnerabilities in WordPress websites.

This course will start off by introducing you to the CMS Security Testing process and will provide you with a comprehensive methodology that you can use as a guide to thoroughly test CMSs for common vulnerabilities and misconfigurations. This course will then introduce you to WordPress and will outline the process of performing information gathering and enumeration on a WordPress site both manually and automatically. The information obtained from this enumeration phase will set the stage for the next phases set to follow.
You will then learn how to put to use the information gathered in the enumeration phase by learning how to perform a vulnerability scan on a WordPress site in order to identify vulnerabilities in themes and plugins. Armed with this knowledge, you will then learn how to exploit vulnerabilities identified in themes and plugins. This course also covers the process of performing various types of authentication attacks that will involve enumerating user accounts on a WordPress site, and will demonstrate how to utilize these usernames to perform a brute force attack to obtain valid login credentials.

---

## Course Introduction

### Course Topic Overview

- Content Management Systems (CMS) Security Testing Methodology
- WordPress Security Testing Methodology
- WordPress Information Gathering and Enumeration
- WordPress Vulnerability Scanning
- WordPress Authentication Attacks
- WordPress Plugin Exploitation
- WordPress Black-Box Penetration Testing

### Prerequisites

- Basic familiarity with HTTP/HTTPS
- Basic familiarity with Linux
- Basic familiarity with OWASP ZAP/Burp Suite
- Basic familiarity with Vulnerabilities like XSS, SQLi, etc.

### Learning Objectives

- You will have an understanding as to what CMSs are, how they work and what they are used for.
+ You will have a solid understanding of how to methodologically perform a web app pentest on WordPress.
- You will have the ability to perform passive and active information gathering and enumeration on WordPress using both manual and automated techniques.
- You will be able to identify vulnerabilities in plugins and themes on WordPress sites both manually and automatically.
- You will be able to effectively use WPScan to automate information gathering and enumeration, identify vulnerabilities and perform brute-force attacks against WordPress sites.
- You will have a solid understanding of how to methodologically perform a web app pentest on WordPress.
- You will be able to perform authentication attacks like brute forcing WordPress login forms to obtain valid credentials.
- You will have the ability to identify and exploit vulnerabilities in WordPress themes and plugins.

---
---

[WordPress](https://wordpress.org/) is a free and open source full-featured CMS for hosting blogs and web portals. It is based on PHP and MySQL. It is one of the most popular CMS.

## Information Gathering and Enumeration

### WordPress Version Enumeration

#### Lab Environment

**WordPress AdRotate**

The attacker might not have any user level access to the web application. However, this does not mean that the application cannot be compromised remotely. SQL Injection vulnerabilities could be triggered even by unauthenticated users.

In the exercise below, the attacker is unauthenticated to the web application and needs to find an SQL Injection attack on it.

<u>A version of WordPress AdRotate Plugin is vulnerable to an SQL injection attack</u>.

**Objective**: Your task is to find and exploit this vulnerability.

#### Lab Solution

![Lab - ](./assets/cms_security_testing_lab_.png)

``:
```

```

``:
```

```

``:
```

```

### Enumerating WordPress Users, Plugins and Themes

#### Lab Environment

**WordPress RCE**

The attacker might not have any user level access to the web application. However, this does not mean that the application cannot be attacked remotely. User Enumeration vulnerabilities could be triggered even by unauthenticated users.

In the exercise below, <u>the attacker is not authenticated to the web application and needs to find a user enumeration attack to gain information about the users</u>.

<u>WordPress (4.7.1) is vulnerable to User Enumeration documented in CVE-2017-5487</u>.

**Objective**: Your task is to find and exploit this vulnerability.

#### Lab Solution

![Lab - ](./assets/cms_security_testing_lab_.png)

``:
```

```

``:
```

```

``:
```

```

### Enumerating Hidden Files and Sensitive Information

#### Lab Environment

**WordPress Security Audit Log plugin Sensitive Information Disclosure**

The attacker might not have any user level access to the web application. However, this does not mean that the application cannot be attacked remotely. Sensitive Information Disclosure vulnerabilities could be triggered even by unauthenticated users.

In the exercise below, <u>the attacker is unauthenticated to the web application and needs to find a sensitive information disclosure attack to access sensitive information from the server</u>.

<u>WordPress Security Audit Log plugin (3.1.1) is vulnerable to a Sensitive Information Disclosure documented in CVE-2018-8719</u>.

**Objective**: Your task is to find and exploit this vulnerability.  

#### Lab Solution

![Lab - ](./assets/cms_security_testing_lab_.png)

``:
```

```

``:
```

```

``:
```

```

### WordPress Enumeration with Nmap NSE Scripts

#### Lab Solution

![Lab - ](./assets/cms_security_testing_lab_.png)

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

## Vulnerability Scanning

### WordPress Vulnerability Scanning with WPScan

#### Lab Environment

**WordPress Symposium plugin SQL Injection**

The attacker might not have any user level access to the web application. However, this does not mean that the application cannot be compromised remotely. SQL Injection vulnerabilities could be triggered even by unauthenticated users.

In the exercise below, <u>the attacker is unauthenticated to the web application and needs to find a SQL injection attack to access restricted information from the portal</u>.

<u>WordPress Symposium (15.1) is vulnerable to SQL Injection in CVE-2015-6522</u>.

**Objective**: Your mission is to find and exploit this vulnerability.

#### Lab Solution

![Lab - ](./assets/cms_security_testing_lab_.png)

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

## Authentication Attacks

### WordPress Brute-Force Attacks

#### Lab Environment

**WordPress Plugin**

An attacker might get administrative access to a web application. However, this does not automatically mean that the web server can be compromised. In cases where a SaaS application is made available to users, it is routine to give each user admin access to his own instance of the web application (e.g. a managed hosted Wordpress site). In such scenario, the attacker who will begin accessing the application as a managed administrative user will have to figure out how to exploit the administrative interface to get a shell on the server. In some cases, it might be possible to do privilege escalation as well.

In the exercise below, <u>the attacker has administrative access to the web application and needs to find a file upload attack to eventually run arbitrary commands on the server</u>.

<u>WordPress has a plugin which is vulnerable to a file upload attack</u>.

The following username and passwords may be used to explore the application and/or find a vulnerability which might require authenticated access:
- Username: "pentester"
- Password: "password1".

**Objective**: Your task is to find and exploit this vulnerability.

#### Lab Solution

![Lab - ](./assets/cms_security_testing_lab_.png)

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

## Exploiting Vulnerabilities

### WP Plugin - Arbitrary File Upload Vulnerability

#### Lab Solution

![Lab - ](./assets/cms_security_testing_lab_.png)

``:
```

```

``:
```

```

``:
```

```

### WP Plugin - Stored XSS Vulnerability (CVE-2020-9371)

#### Lab Environment

**WordPress Appointment Booking Calendar Stored XSS**

In this exercise, the attacker has admin access already so there is nothing more to be done. However, looks like the <u>admin access does lead to an XSS attack</u>. So you can try to find this XSS as a purely academic exercise.

<u>WordPress Appointment Booking Calendar plugin (before 1.3.35) is vulnerable to Stored Cross-Site Scripting documented in CVE-2020-9371</u>.

The following username and passwords may be used to explore the application and/or find a vulnerability which might require authenticated access:
- Username: "admin"
- Password: "password1".

**Objective**: Your task is to find and exploit this vulnerability.

#### Lab Solution

![Lab - ](./assets/cms_security_testing_lab_.png)

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

## WordPress Black-Box Pentest

### WordPress Black-Box Pentest

#### Lab Environment

**Exploiting WordPress**

In this lab, you will learn how to perform a dictionary attack to get admin access on a WordPress-based website and gain shell access on the target machine by exploiting a vulnerable WordPress plugin.

In this lab environment, the user will get access to a Kali GUI instance. The WordPress web application can be accessed using the tools installed on Kali on `http://demo.ine.local`.

**Objective:** Gain admin access on the WordPress website. Also obtain a shell on the target machine and get the flag file from the target machine.

Dictionary attack wordlist: `/root/Desktop/wordlists/100-common-passwords.txt`.

#### Lab Solution

![Lab - ](./assets/cms_security_testing_lab_.png)

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
