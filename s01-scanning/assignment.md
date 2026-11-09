# Scanning & Vulnerability Assessment

## Session 01

**Course:** Digital Forensics & Cyber Security  
**Platform:** VMware  
**Lab Environment:** Kali Linux and Metasploitable 2  
**Target:** `192.168.17.128`

---

## 1. Objective

The objective of this practical work was to perform network scanning and vulnerability assessment against a Metasploitable 2 virtual machine using Kali Linux.

The assessment focused on identifying active hosts, open ports, running services, service versions, and security weaknesses. The findings were then classified using CVE, CVSS and CWE concepts where applicable.

All testing was performed in a controlled VMware laboratory environment for educational purposes.

---

## 2. Tools Used

The following tools were used during the assessment:

- Kali Linux
- Nmap
- Netdiscover
- IP Scanner
- Metasploitable 2
- VMware

---

## 3. Initial Service Scan

The following command was used to identify open ports and service versions:

```bash
nmap -sV 192.168.17.128
```

The scan identified several exposed services on the Metasploitable 2 machine, including:

```text
21/tcp   open  ftp       vsftpd 2.3.4
22/tcp   open  ssh       OpenSSH 4.7p1 Debian 8ubuntu1
23/tcp   open  telnet    Linux telnetd
25/tcp   open  smtp      Postfix smtpd
53/tcp   open  domain    ISC BIND 9.4.2
80/tcp   open  http      Apache httpd 2.2.8
139/tcp  open  netbios-ssn Samba
445/tcp  open  netbios-ssn Samba
513/tcp  open  login     rlogind
3306/tcp open  mysql     MySQL 5.0.51a-3ubuntu5
5432/tcp open  postgresql PostgreSQL
5900/tcp open  vnc       VNC
8180/tcp open  http      Apache Tomcat
```

Version detection was important because it provided specific service and version information that could be used for vulnerability research. The handout describes `nmap -sV` as the point where a basic port scan becomes useful for vulnerability assessment.

**Evidence:** Screenshot of the initial Nmap service/version scan.

---

# 4. Task A — Three Findings

## Finding 1 — Anonymous FTP Access

### Title

Anonymous FTP Access Enabled

### Severity

Medium — security misconfiguration

### Affected Asset

`192.168.17.128:21/tcp`

### Identifiers

- Service: FTP
- Finding: Anonymous FTP login allowed
- CWE: Configuration-related weakness; no specific CWE is asserted for this laboratory finding

### Description

The FTP service on the Metasploitable 2 machine allows anonymous login.

The following command was used to verify the configuration:

```bash
nmap -p21 --script ftp-anon,ftp-syst 192.168.17.128
```

The scan reported:

```text
21/tcp open ftp
ftp-anon: Anonymous FTP login allowed (FTP code 230)
```

This indicates that an FTP client can authenticate using the anonymous account without a normal user password.

### Evidence

Nmap FTP enumeration showed that anonymous FTP login was allowed.

**Evidence:** Screenshot of:

```bash
nmap -p21 --script ftp-anon,ftp-syst 192.168.17.128
```

### Proof of Concept

The Nmap `ftp-anon` script successfully detected anonymous FTP access without requiring exploitation.

### Impact

Anonymous FTP can allow unauthorized users to access files that should not be publicly available. Depending on the server configuration, anonymous users may also be able to upload files.

### Remediation

Disable anonymous FTP access unless it is specifically required. If anonymous access is necessary, restrict the directories and permissions available to anonymous users and prevent write access where it is not required.

### References

- Nmap FTP enumeration script documentation
- Metasploitable 2 laboratory environment

---

## Finding 2 — Exposed PHP Information Page

### Title

PHP Information Page Exposed

### Severity

Low to Medium — information disclosure

### Affected Asset

`192.168.17.128:80/tcp`

### Identifiers

- Service: HTTP
- Finding: `/phpinfo.php` exposed
- CWE: CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor

### Description

HTTP enumeration identified an accessible PHP information page on the target.

The following command was used:

```bash
nmap -p80 --script http-enum 192.168.17.128
```

The scan identified:

```text
/phpinfo.php: Possible information file
```

A PHP information page can expose technical details about the server environment, PHP configuration, installed modules and other system information.

CWE-200 describes exposure of sensitive information to an unauthorized actor. MITRE also lists a `phpinfo()` example under CWE-200.

### Evidence

Nmap HTTP enumeration identified `/phpinfo.php`.

**Evidence:** Screenshot of:

```bash
nmap -p80 --script http-enum 192.168.17.128
```

### Proof of Concept

The Nmap HTTP enumeration script identified the PHP information page without requiring exploitation.

### Impact

Exposed configuration information can help an attacker understand the target environment and identify additional attack opportunities.

### Remediation

Remove unnecessary diagnostic files such as `phpinfo.php` from production systems. If the page is required for administration, access should be restricted to authorized administrators.

### References

- MITRE CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- Nmap HTTP enumeration documentation

---

## Finding 3 — vsftpd 2.3.4 Vulnerability

### Title

vsftpd 2.3.4 Backdoor Vulnerability

### Severity

Critical — CVSS 9.8

### Affected Asset

`192.168.17.128:21/tcp`

### Identifiers

- CVE: CVE-2011-2523
- CWE: CWE-78 — OS Command Injection
- CPE: `cpe:/a:vsftpd:vsftpd:2.3.4`

### Description

The FTP service was identified as **vsftpd 2.3.4**.

The following command was used:

```bash
nmap -sV -p21 192.168.17.128
```

The result identified:

```text
21/tcp open ftp vsftpd 2.3.4
```

The handout uses CVE-2011-2523 as the worked vulnerability example and maps it to CWE-78. The handout gives the CVSS 3.1 score as 9.8 Critical with the vector:

```text
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```



### Evidence

Nmap service/version detection identified `vsftpd 2.3.4`.

**Evidence:** Screenshot of:

```bash
nmap -sV -p21 192.168.17.128
```

### Proof of Concept

The vulnerability was documented based on the identified vulnerable service version. No exploitation was required for this assignment.

### Impact

A vulnerable vsftpd 2.3.4 installation can allow an attacker to obtain unauthorized command execution on the affected system.

### Remediation

Upgrade or replace the vulnerable vsftpd version with a supported and patched release. The FTP service should also be restricted to the minimum network access required.

### References

- CVE-2011-2523
- CWE-78 — OS Command Injection
- Digital Forensics & Cyber Security Bootcamp Day 2 Handout

---

# 5. Task B — Additional Scanning and Vulnerability Assessment

For Task B, I selected:

- **B1 — Host Discovery**
- **B4 — CWE Classification**

---

## 5.1 B1 — Host Discovery Using Three Tools

The objective of this task was to identify active hosts on the laboratory network using Nmap, Netdiscover and IP Scanner.

The network scanned was:

```text
192.168.17.0/24
```

The Metasploitable 2 target was:

```text
192.168.17.128
```

### Method 1 — Nmap

The following command was used:

```bash
nmap -sn 192.168.17.0/24
```

The `-sn` option performs host discovery without performing a port scan.

The scan identified active hosts on the laboratory network, including the Metasploitable 2 machine at:

```text
192.168.17.128
```

**Evidence:** Screenshot of the Nmap host discovery output.

---

### Method 2 — Netdiscover

The following command was used:

```bash
sudo netdiscover -r 192.168.17.0/24
```

Netdiscover uses ARP-based discovery to identify systems on the local network. It can display information such as IP addresses and MAC addresses.

The Metasploitable 2 system was identified at:

```text
192.168.17.128
```

**Evidence:** Screenshot of the Netdiscover output.

---

### Method 3 — IP Scanner

IP Scanner was used to scan:

```text
192.168.17.0/24
```

The scan identified the Metasploitable 2 machine at:

```text
192.168.17.128
```

**Evidence:** Screenshot of the IP Scanner results.

---

### Comparison of Results

The three tools perform host discovery using different approaches and interfaces. Nmap provides a flexible command-line method for discovering active hosts, while Netdiscover is useful for ARP-based discovery on a local network. IP Scanner provides a graphical interface that makes discovered systems easier to review visually.

Small differences can occur between tools because discovery methods, response timing and network configuration can affect the results. In this laboratory environment, the important result was that the Metasploitable 2 target at `192.168.17.128` was identified as an active host. This confirmed that the target was reachable before continuing with service enumeration and vulnerability assessment.

---

# 5.2 B4 — CWE Classification

The purpose of this task was to identify the CWE classification associated with three different security weaknesses identified during the assessment.

CVE identifies a specific vulnerability, while CWE describes the general class of weakness. The handout specifically uses **CWE-78** for the vsftpd 2.3.4 vulnerability.

---

## Vulnerability 1 — vsftpd 2.3.4

**CVE:** CVE-2011-2523  
**CWE:** CWE-78 — OS Command Injection

The service scan identified:

```text
21/tcp open ftp vsftpd 2.3.4
```

CWE-78 describes OS command injection, where externally influenced input can result in operating-system command execution.

The remediation for this type of weakness focuses on removing the vulnerable software version, applying security updates and preventing unsafe input from reaching operating-system command execution.

The handout identifies CVE-2011-2523 as the worked example and maps it to CWE-78.

---

## Vulnerability 2 — Exposed `/phpinfo.php`

**Finding:** Exposed PHP information page  
**CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor

The HTTP enumeration scan identified:

```text
/phpinfo.php: Possible information file
```

CWE-200 describes exposure of sensitive information to an unauthorized actor. MITRE's CWE-200 page includes an example where `phpinfo()` reveals system configuration to a web user.

The remediation is different from the vsftpd finding because the main issue is information exposure rather than command execution. The unnecessary PHP information page should be removed or access should be restricted to authorized administrators.

---

## Vulnerability 3 — Telnet Service

**Service:** Telnet  
**Port:** 23/tcp  
**CWE:** CWE-319 — Cleartext Transmission of Sensitive Information

The following command was used to verify the Telnet service:

```bash
nmap -sV -p23 192.168.17.128
```

The result showed:

```text
23/tcp open telnet Linux telnetd
```

This confirms that the Telnet service is running on TCP port 23.

CWE-319 describes transmission of sensitive or security-critical information in cleartext over a communication channel that can be monitored by unauthorized actors.

The remediation is different from the previous findings because this is a protocol/security-design issue. Telnet should normally be disabled and replaced with an encrypted remote-access protocol such as SSH.

---

## CWE Classification Comparison

| Finding | CWE | Weakness Class | Main Remediation |
|---|---|---|---|
| vsftpd 2.3.4 / CVE-2011-2523 | CWE-78 | OS Command Injection | Patch or replace the vulnerable software |
| Exposed `/phpinfo.php` | CWE-200 | Information Exposure | Remove the diagnostic page or restrict access |
| Telnet service | CWE-319 | Cleartext Transmission of Sensitive Information | Disable Telnet and use an encrypted protocol such as SSH |

These findings demonstrate why CWE classification is useful during vulnerability assessment. The three weaknesses have different causes and therefore require different remediation strategies. The vsftpd issue involves command execution, the PHP information page involves information exposure, and the Telnet service represents an insecure cleartext communication protocol.

---

# 6. Conclusion

The assessment demonstrated the basic workflow of network scanning and vulnerability assessment using Kali Linux and Metasploitable 2.

Host discovery was performed using Nmap, Netdiscover and IP Scanner. Service enumeration was then performed using Nmap version detection to identify open services and their versions.

Three security findings were documented: anonymous FTP access, an exposed PHP information page and the vulnerable vsftpd 2.3.4 service. The additional CWE exercise showed how different security weaknesses can require different remediation approaches.

The work was performed in a controlled VMware laboratory environment using the intentionally vulnerable Metasploitable 2 virtual machine.

---

# 7. Evidence

The following screenshots are included as evidence for the practical work:

1. Nmap initial service/version scan.
2. Nmap anonymous FTP enumeration.
3. Nmap HTTP enumeration showing `/phpinfo.php`.
4. Nmap vsftpd 2.3.4 service detection.
5. Nmap host discovery using `nmap -sn`.
6. Netdiscover host discovery.
7. IP Scanner host discovery.
8. Nmap Telnet service detection showing `23/tcp open telnet Linux telnetd`.

All commands were executed against the Metasploitable 2 laboratory target:

```text
192.168.17.128
```

All testing was performed in a controlled environment for educational purposes.
