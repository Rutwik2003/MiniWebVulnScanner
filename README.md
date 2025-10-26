# MiniWebVulnScanner

A lightweight, educational web vulnerability scanner built with Python and Flask. This tool demonstrates basic security testing techniques for **SQL Injection (SQLi)**, **Cross-Site Scripting (XSS)**, **Command Injection**, **Path Traversal**, **LDAP Injection**, and **XML External Entity (XXE)** vulnerabilities.

## ⚠️ Ethical Use Warning
**This tool is for educational purposes only. Only scan websites you own or have explicit permission to test. Unauthorized security testing is illegal.**

## Features
- Simple web interface for entering target URLs
- Automatic form and parameter discovery
- **6 Vulnerability Types Detected:**
  - ✅ SQL Injection (SQLi) - Error-based detection
  - ✅ Reflected Cross-Site Scripting (XSS)
  - ✅ Command Injection - OS command execution
  - ✅ Path Traversal - Directory/file access
  - ✅ LDAP Injection - LDAP query manipulation
  - ✅ XML External Entity (XXE) - XML parser exploitation
- Clear vulnerability reporting with remediation tips
- **📄 OWASP ZAP-style HTML report generation**
- **🎯 Built-in list of free vulnerable testing websites**

## Requirements
- Python 3.10 or higher
- Flask, Requests, BeautifulSoup4 (see requirements.txt)

## Quick Setup

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the application:**
   ```bash
   flask --app app run
   ```
   Or simply:
   ```bash
   python app.py
   ```

3. **Access the scanner:**
   Open your browser and go to: `http://127.0.0.1:5000`

## Key Features

### 📄 Professional Report Generation
After scanning, click the "Generate Report" button to download a comprehensive HTML report similar to OWASP ZAP reports, featuring:
- Executive summary with risk assessment
- Vulnerability breakdown by type
- Detailed findings with payloads and evidence
- Remediation recommendations
- OWASP resource links

### 🎯 Free Testing Websites
Click "View Free Testing Sites" on the home page to access:
- Online vulnerable platforms (no setup required)
- Local Docker-based testing environments
- CTF and advanced learning platforms
- Setup instructions and recommendations

## Testing
For safe testing, use intentionally vulnerable applications like:
- **DVWA** (Damn Vulnerable Web Application)
- **bWAPP**
- **WebGoat**

Never test on production sites without authorization!

## How It Works
1. Enter a target URL in the web interface
2. The scanner crawls the page to find forms and parameters
3. Non-destructive payloads are injected into each input field for 6 vulnerability types
4. Responses are analyzed for vulnerability indicators
5. Results are displayed with vulnerability type and remediation advice

## Payloads Used
- **SQLi**: `' OR 1=1 --`, `' OR '1'='1`, etc. (error-based detection)
- **XSS**: `<script>alert('XSS')</script>`, `<img src=x onerror=...>` (reflection-based)
- **Command Injection**: `; whoami`, `| whoami`, `$(whoami)` (output-based)
- **Path Traversal**: `../../../etc/passwd`, `..\..\windows\win.ini` (content-based)
- **LDAP Injection**: `*)(uid=*))(|(uid=*`, `admin*` (error-based)
- **XXE**: XML payloads with external entities (content-based)

## License
MIT License - Use responsibly and ethically.
