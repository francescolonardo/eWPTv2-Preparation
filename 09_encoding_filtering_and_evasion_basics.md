# Encoding, Filtering and Evasion Basics

In the ever evolving  world of cybersecurity, web applications continue to be prime targets for cyberattacks. To effectively attack and defend against these threats and vulnerabilities, you need to go beyond the basics of standard web application penetration testing.

This course is designed to take your web app penetration testing expertise to the next level by focusing on three essential aspects of web application security testing that frequently get overlooked: encoding, filtering, and evasion. In order to understand how to analyze and assess a web applications for vulnerabilities, you need to understand how web application developers implement encoding, input filtering and security mechanisms like WAFs (Web Application Firewalls) for improved security.
This course will start off by introducing you to the practice of characterset encoding, URL encoding, HTML encoding and Base64 encoding and will explain how and why these encoding techniques are utilized in web applications. You will then be introduced to the process of server-side and client-side input filtering, where you will get a tacit understanding of the different types of input filtering techniques used to prevent vulnerabilities like XSS, SQL Injection and command injection. The course will then outline how these filtering techniques can be bypassed through manual and automated techniques. Finally, this course will introduce you to WAFs (Web Application Firewalls), Proxies and server-side IDSs (Intrusion Detection Systems). You will learn about how they work, how they can be identified and how they can be bypassed.

---

## Course Introduction

### Course Topic Overview

- Charset Encoding
- HTML Encoding
- URL Encoding
- Base64 Encoding
- Bypassing Client-Side Filters
- Bypassing Server-Side Filters
- Web Application Firewalls (WAF) and Proxies
- Evading WAFs, Proxies and IDSs

### Prerequisites

- Basic familiarity with HTTP/HTTPS
- Basic familiarity with OWASP ZAP/Burp Suite
- Basic familiarity with Javascript

### Learning Objectives

- You will have a good understanding of the importance of encoding on the web and its importance in the functionality of web applications.
- You will have a solid understanding of what content and input filtering is, how and why filtering is implemented in web applications and how server-side and client-side filters can be bypassed.
- You will have a functional understanding of what Web Application Firewalls (WAF) are, how they work and how they differ from traditional proxies.
- You will have a solid understanding of the most common forms of encoding on the web, how they work and how why they are implemented (HTML encoding, URL Encoding and Base64 encoding).
- You will have the ability to detect and bypass common client-side and server-side filters (XSS filters, command injection filters etc).
- You will be able to bypass/evade rudimentary forms of protection/filtering imposed by proxies/WAFs.

---
---

## Encoding

### Charset Encoding

#### Lab Solution

![Lab - Charset Encoding](./assets/encoding_filtering_and_evasion_basics_lab_.png)

``:
```

```

``:
```

```

``:
```

```

### HTML Encoding

#### Lab Solution

![Lab - HTML Encoding](./assets/encoding_filtering_and_evasion_basics_lab_.png)

``:
```

```

``:
```

```

``:
```

```

### URL Encoding

#### Lab Solution

![Lab - URL Encoding](./assets/encoding_filtering_and_evasion_basics_lab_.png)

``:
```

```

``:
```

```

``:
```

```

### Base64 Encoding

#### Lab Solution

![Lab - ](./assets/encoding_filtering_and_evasion_basics_lab_.png)

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

## Filtering

### Bypassing Client-Side Filters

#### Lab Environment

**Mutillidae 2**

[Mutillidae 2](https://www.owasp.org/index.php/OWASP_Mutillidae_2_Project) is a deliberately vulnerable web application created by Jeremy Druin and currently maintained by [OWASP](https://www.owasp.org/). It is licensed under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html).

You can download Mutillidae 2 locally and install it in a virtual machine. We are providing an online version to save you time and pain of having to do that.

The following username and password may be used to explore the application:
- User: "samurai"
- Password: "samurai".

#### Lab Solution

![Lab - Mutillidae 2](./assets/encoding_filtering_and_evasion_basics_lab_.png)

``:
```

```

``:
```

```

``:
```

```

### Bypassing Server-Side Filters

#### Lab Environment

**Damn Vulnerable Web Application**

[Damn Vulnerable Web Application (DVWA](http://www.dvwa.co.uk/)) is a deliberately vulnerable web application created by Ryan Dewhurst. It is licensed under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html).

You can download DVWA locally and install it in a virtual machine. We are providing an online version to save you the time and pain of having to do that. 

The following username and password may be used to explore the application:
- User: "admin"
- Password: "password".

#### Lab Solution

![Lab - Damn Vulnerable Web Application](./assets/encoding_filtering_and_evasion_basics_lab_.png)

``:
```

```

``:
```

```

``:
```

```

### Bypassing XSS Filters In Chamilo LMS

#### Lab Environment

**Chamilo LMS**

The attacker might not have any user level access to the web application. However, this does not mean that the application cannot be used to attack other users. Reflected Cross Site Scripting could be triggered even by unauthenticated users.

In the exercise below, <u>the attacker is not authenticated to the web application and needs to find a reflected XSS attack on it</u>.

<u>A version of Chamilo LMS is vulnerable to a reflected XSS attack</u>.

**Objective**: Your task is to find and exploit this vulnerability.

#### Lab Solution

![Lab - Chamilo LMS](./assets/encoding_filtering_and_evasion_basics_lab_.png)

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

## Evasion

### Bypassing Squid Proxy - Browser Based Restrictions

#### Lab Environment

**Squid: Browser Based Restriction**

[Squid](http://www.squid-cache.org/) is a caching web proxy. The target machine as described below is running squid proxy. The proxy is configured only to serve requests coming from a specific web browser (i.e. Firefox). A web portal is running on the target machine. This portal is reachable only via the proxy.

**Objective**: You have to figure out a way to access the web portal and retrieve the flag!

Instructions: 
- This lab is dedicated to you! No other users are on this network :)
- Once you start the lab, you will have access to a root terminal of a Kali instance
- Your Kali has an interface with IP address `192.X.Y.Z`. Run `ip addr` to know the values of X and Y.
- The Target machine should be located at the IP address `192.X.Y.3`.
- Do not attack the gateway located at IP address `192.X.Y.1`.
- `postgresql` is not running by default so `Metasploit` may give you an error about this when starting.

#### Lab Solution

![Lab - Squid: Browser Based Restriction](./assets/encoding_filtering_and_evasion_basics_lab_.png)

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
