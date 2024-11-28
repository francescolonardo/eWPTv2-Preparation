# Web Service Security Testing

In the complex world of web applications, web services play a pivotal role in enabling the seamless exchange of data and functionality between applications over the internet. Web services, particularly those built using the SOAP (Simple Object Access Protocol) framework, have become essential components of modern web applications. However, the convenience they offer comes with inherent security challenges that demand expert attention.

In this course you will uncover the core principles of web application service security testing with a specialized focus on SOAP-based web services. This course will dive deep into the world of web services, the backbone of modern applications, enabling seamless data exchange and functionality sharing across the digital landscape.
It will explore the critical security vulnerabilities that threaten these services, including SQL Injection, Command Injection and Cross-Site Scripting (XSS). This course will provide you with hands-on experience in identifying, assessing, and exploiting these vulnerabilities and will equip you with essential skills required to test web applications and their underlying SOAP-based web services in an ever-evolving cyber threat landscape.

---

## Course Introduction

### Course Topic Overview

- Introduction to Web Services
- Web Service Implementations
- WSDL Language Fundamentals
- Web Service Security Testing
- SOAP Web Service Security Testing

### Prerequisites

- Basic familiarity with HTTP/HTTPS
- Basic familiarity with OWASP ZAP/Burp Suite

### Learning Objectives

- You will have a solid understanding of what web services are, how they work and how they differ from traditional APIs and web applications.
- You will have an understanding of the different types of Web Service implementations (XML-RPC, SOAP, REST etc) and how they work.
- You will have an understanding of the WSDL language and how it is used to describe the functionality of web services.
- You will have an understanding of how to methodologically test a SOAP based web service for common vulnerabilities.
- You will be able to find and identify WSDL files to discover methods and operations pertinent to the web service.
- You will be able to invoke hidden methods and test web services for common vulnerabilities like SQL injection and command injection.

---
---

## Testing SOAP-based Web Service

### WSDL Disclosure and Method Enumeration

#### Lab Environment

In this lab, you will learn to attack SOAP-based web services. More specifically, you would enumerate the WSDL file to discover and invoke hidden methods, bypass SOAP body restriction and perform SQL and command injection attacks on the provided web service.

- WSDL Enumeration
- Invoking hidden methods
- Bypass SOAP body restrictions
- SQL Injection
- Command Injection

In this lab environment, the user will get access to a Kali GUI instance. A slightly modified instance of the `Mutillidae` web application can be accessed using the tools installed on Kali at `http://demo.ine.local`.

**Objective**: Perform the following attacks on the provided SOAP-based web service and collect all three flags:
- `flag1` and `flag2` would be retrieved by invoking the hidden methods.  
- `flag3` would be invoked from the server file system after exploiting the command injection vulnerability.

**Web Services - WSDL Enumeration**

#### Lab Solution

![Lab - ](./assets/web_service_security_testing_lab_.png)

``:
```

```

``:
```

```

``:
```

```

### Invoking Hidden Methods

#### Lab Environment

**Web Services - Invoking hidden methods**

#### Lab Solution

![Lab - Web Services: Invoking hidden methods](./assets/web_service_security_testing_lab_.png)

``:
```

```

``:
```

```

``:
```

```

## Testing for SQL Injection

#### Lab Environment

**Web Services - SQL Injection**

#### Lab Solution

![Lab - Web Services: SQL Injection](./assets/web_service_security_testing_lab_.png)

``:
```

```

``:
```

```

``:
```

```

## Testing for Command Injection

#### Lab Environment

**Web Services - Command Injection**

#### Lab Solution

![Lab - Web Services: Command Injection](./assets/web_service_security_testing_lab_.png)

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
