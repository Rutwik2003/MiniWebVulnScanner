"""
Mini Web Vulnerability Scanner
A simple educational tool for detecting SQLi and XSS vulnerabilities.
"""

from flask import Flask, render_template, request, flash, make_response
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
import requests
import time
from datetime import datetime
import json

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'

# Payload definitions
SQLI_PAYLOADS = ["' OR 1=1 --", "' OR '1'='1", "1' OR '1'='1' --"]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
COMMAND_INJECTION_PAYLOADS = ["; whoami", "| whoami", "& whoami", "`whoami`", "$(whoami)"]
PATH_TRAVERSAL_PAYLOADS = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "....//....//....//etc/passwd"]
LDAP_INJECTION_PAYLOADS = ["*)(uid=*))(|(uid=*", "admin*", "*()|&'"]
XXE_PAYLOADS = ["<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"]

# Error keywords for SQLi detection
SQLI_ERRORS = [
    'sql syntax', 'mysql_fetch', 'you have an error in your sql',
    'warning: mysql', 'unclosed quotation mark', 'quoted string not properly terminated',
    'syntax error', 'odbc', 'jdbc', 'oracle error', 'postgresql'
]

# Command injection indicators
COMMAND_INJECTION_INDICATORS = [
    'uid=', 'gid=', 'groups=', 'root:', 'bin/bash', 'cmd.exe',
    'windows\\system32', 'user@', 'administrator'
]

# Path traversal indicators
PATH_TRAVERSAL_INDICATORS = [
    'root:x:', '[extensions]', '[fonts]', 'boot loader',
    'passwd', 'win.ini', 'system.ini'
]

# LDAP injection indicators
LDAP_INJECTION_INDICATORS = [
    'ldap_search', 'ldap error', 'invalid dn syntax',
    'ldap injection', 'objectclass='
]

# XXE indicators
XXE_INDICATORS = [
    'root:x:', '<!entity', 'xml parser error', 'external entity'
]


def validate_url(url):
    """
    Validate if the provided URL is properly formatted.
    
    Args:
        url: URL string to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False, "Invalid URL format. Must include scheme (http/https) and domain."
        if result.scheme not in ['http', 'https']:
            return False, "Only HTTP and HTTPS protocols are supported."
        return True, None
    except Exception as e:
        return False, f"URL parsing error: {str(e)}"


def crawl(url):
    """
    Crawl the target URL to extract forms and URL parameters.
    
    Args:
        url: Target URL to crawl
        
    Returns:
        tuple: (list of targets, error_message)
        Each target is a dict: {'url': str, 'method': str, 'fields': dict}
    """
    targets = []
    
    try:
        # Fetch the page
        response = requests.get(url, timeout=10, allow_redirects=True)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        parsed_url = urlparse(url)
        
        # Extract URL parameters (if any)
        query_params = parse_qs(parsed_url.query)
        if query_params:
            targets.append({
                'url': url,
                'method': 'GET',
                'fields': {k: v[0] if v else '' for k, v in query_params.items()},
                'type': 'url_params'
            })
        
        # Extract all forms
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'get').upper()
            
            # Build absolute URL for form action
            if action:
                if action.startswith('http'):
                    form_url = action
                elif action.startswith('/'):
                    form_url = f"{parsed_url.scheme}://{parsed_url.netloc}{action}"
                else:
                    form_url = f"{parsed_url.scheme}://{parsed_url.netloc}/{action}"
            else:
                form_url = url
            
            # Extract form fields
            fields = {}
            inputs = form.find_all(['input', 'textarea', 'select'])
            for input_tag in inputs:
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                input_value = input_tag.get('value', '')
                
                # Skip buttons and submits for injection
                if input_name and input_type not in ['submit', 'button', 'image', 'reset']:
                    fields[input_name] = input_value
            
            if fields:  # Only add if form has injectable fields
                targets.append({
                    'url': form_url,
                    'method': method,
                    'fields': fields,
                    'type': 'form'
                })
        
        return targets, None
        
    except requests.exceptions.Timeout:
        return [], "Request timeout - target took too long to respond."
    except requests.exceptions.ConnectionError:
        return [], "Connection error - could not reach target."
    except requests.exceptions.HTTPError as e:
        return [], f"HTTP error: {e.response.status_code}"
    except Exception as e:
        return [], f"Crawling error: {str(e)}"


def inject_and_test(target, payload, payload_type):
    """
    Inject a payload into a target and test for vulnerabilities.
    
    Args:
        target: Target dict with url, method, fields
        payload: Payload string to inject
        payload_type: Type of payload ('sqli', 'xss', 'command', 'path_traversal', 'ldap', 'xxe')
        
    Returns:
        list: List of vulnerability findings
    """
    findings = []
    
    try:
        # Test each field individually
        for field_name in target['fields'].keys():
            # Create a copy of fields with the payload
            test_fields = target['fields'].copy()
            test_fields[field_name] = payload
            
            # Send request based on method
            headers = {}
            if payload_type == 'xxe':
                headers['Content-Type'] = 'application/xml'
            
            if target['method'] == 'GET':
                # Build URL with parameters
                parsed = urlparse(target['url'])
                query_string = urlencode(test_fields)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, query_string, parsed.fragment
                ))
                response = requests.get(test_url, timeout=10, allow_redirects=True, headers=headers)
            else:  # POST
                if payload_type == 'xxe':
                    response = requests.post(target['url'], data=payload, timeout=10, allow_redirects=True, headers=headers)
                else:
                    response = requests.post(target['url'], data=test_fields, timeout=10, allow_redirects=True, headers=headers)
            
            # Analyze response based on payload type
            if payload_type == 'sqli':
                if detect_sqli(response.text):
                    findings.append({
                        'url': target['url'],
                        'method': target['method'],
                        'field': field_name,
                        'vuln_type': 'SQL Injection',
                        'payload': payload,
                        'confidence': 'Medium',
                        'evidence': 'SQL error message detected in response'
                    })
            
            elif payload_type == 'xss':
                if detect_xss(response.text, payload):
                    findings.append({
                        'url': target['url'],
                        'method': target['method'],
                        'field': field_name,
                        'vuln_type': 'Reflected XSS',
                        'payload': payload,
                        'confidence': 'Medium',
                        'evidence': 'Payload reflected unescaped in response'
                    })
            
            elif payload_type == 'command':
                if detect_command_injection(response.text):
                    findings.append({
                        'url': target['url'],
                        'method': target['method'],
                        'field': field_name,
                        'vuln_type': 'Command Injection',
                        'payload': payload,
                        'confidence': 'High',
                        'evidence': 'Command execution output detected in response'
                    })
            
            elif payload_type == 'path_traversal':
                if detect_path_traversal(response.text):
                    findings.append({
                        'url': target['url'],
                        'method': target['method'],
                        'field': field_name,
                        'vuln_type': 'Path Traversal',
                        'payload': payload,
                        'confidence': 'Medium',
                        'evidence': 'Sensitive file content detected in response'
                    })
            
            elif payload_type == 'ldap':
                if detect_ldap_injection(response.text):
                    findings.append({
                        'url': target['url'],
                        'method': target['method'],
                        'field': field_name,
                        'vuln_type': 'LDAP Injection',
                        'payload': payload,
                        'confidence': 'Medium',
                        'evidence': 'LDAP error or unauthorized data access detected'
                    })
            
            elif payload_type == 'xxe':
                if detect_xxe(response.text):
                    findings.append({
                        'url': target['url'],
                        'method': target['method'],
                        'field': field_name,
                        'vuln_type': 'XML External Entity (XXE)',
                        'payload': payload,
                        'confidence': 'High',
                        'evidence': 'External entity content or XML error detected'
                    })
            
            # Respectful delay between requests
            time.sleep(1)
    
    except Exception as e:
        # Silently continue on individual test failures
        pass
    
    return findings


def detect_sqli(response_text):
    """
    Check if response contains SQL error indicators.
    
    Args:
        response_text: HTML response text
        
    Returns:
        bool: True if SQLi indicators found
    """
    response_lower = response_text.lower()
    return any(error in response_lower for error in SQLI_ERRORS)


def detect_xss(response_text, payload):
    """
    Check if XSS payload is reflected unescaped in response.
    
    Args:
        response_text: HTML response text
        payload: Original XSS payload
        
    Returns:
        bool: True if payload reflected without encoding
    """
    # Check if payload appears exactly (unescaped)
    return payload in response_text


def detect_command_injection(response_text):
    """
    Check if response contains command execution indicators.
    
    Args:
        response_text: HTML response text
        
    Returns:
        bool: True if command injection indicators found
    """
    response_lower = response_text.lower()
    return any(indicator in response_lower for indicator in COMMAND_INJECTION_INDICATORS)


def detect_path_traversal(response_text):
    """
    Check if response contains sensitive file content.
    
    Args:
        response_text: HTML response text
        
    Returns:
        bool: True if path traversal indicators found
    """
    response_lower = response_text.lower()
    return any(indicator in response_lower for indicator in PATH_TRAVERSAL_INDICATORS)


def detect_ldap_injection(response_text):
    """
    Check if response contains LDAP error or unauthorized data.
    
    Args:
        response_text: HTML response text
        
    Returns:
        bool: True if LDAP injection indicators found
    """
    response_lower = response_text.lower()
    return any(indicator in response_lower for indicator in LDAP_INJECTION_INDICATORS)


def detect_xxe(response_text):
    """
    Check if response contains XXE exploitation indicators.
    
    Args:
        response_text: HTML response text
        
    Returns:
        bool: True if XXE indicators found
    """
    response_lower = response_text.lower()
    return any(indicator in response_lower for indicator in XXE_INDICATORS)


def scan_target(url):
    """
    Main scanning function that orchestrates the vulnerability scan.
    
    Args:
        url: Target URL to scan
        
    Returns:
        dict: Scan results with findings and metadata
    """
    results = {
        'url': url,
        'targets_found': 0,
        'vulnerabilities': [],
        'errors': []
    }
    
    # Validate URL
    is_valid, error = validate_url(url)
    if not is_valid:
        results['errors'].append(error)
        return results
    
    # Crawl target
    targets, error = crawl(url)
    if error:
        results['errors'].append(f"Crawling failed: {error}")
        return results
    
    if not targets:
        results['errors'].append("No testable forms or parameters found on this page.")
        return results
    
    results['targets_found'] = len(targets)
    
    # Test each target with payloads
    for target in targets:
        # Test SQLi payloads
        for payload in SQLI_PAYLOADS:
            findings = inject_and_test(target, payload, 'sqli')
            results['vulnerabilities'].extend(findings)
            if findings:  # If vulnerability found, no need to test more payloads on same field
                break
        
        # Test XSS payloads
        for payload in XSS_PAYLOADS:
            findings = inject_and_test(target, payload, 'xss')
            results['vulnerabilities'].extend(findings)
            if findings:
                break
        
        # Test Command Injection payloads
        for payload in COMMAND_INJECTION_PAYLOADS:
            findings = inject_and_test(target, payload, 'command')
            results['vulnerabilities'].extend(findings)
            if findings:
                break
        
        # Test Path Traversal payloads
        for payload in PATH_TRAVERSAL_PAYLOADS:
            findings = inject_and_test(target, payload, 'path_traversal')
            results['vulnerabilities'].extend(findings)
            if findings:
                break
        
        # Test LDAP Injection payloads
        for payload in LDAP_INJECTION_PAYLOADS:
            findings = inject_and_test(target, payload, 'ldap')
            results['vulnerabilities'].extend(findings)
            if findings:
                break
        
        # Test XXE payloads
        for payload in XXE_PAYLOADS:
            findings = inject_and_test(target, payload, 'xxe')
            results['vulnerabilities'].extend(findings)
            if findings:
                break
    
    return results


@app.route('/')
def index():
    """Render the main input page."""
    return render_template('index.html')


@app.route('/test-sites')
def test_sites():
    """Display test endpoints available on this application."""
    return render_template('test_sites.html')


# ============================================
# VULNERABLE TEST ENDPOINTS (Educational Only)
# ============================================

@app.route('/vuln/sqli')
def vuln_sqli():
    """Intentionally vulnerable SQL Injection endpoint for testing."""
    user_id = request.args.get('id', '1')
    
    # INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    error_msg = ""
    if "'" in user_id or "--" in user_id or "OR" in user_id.upper():
        error_msg = "SQL syntax error near '" + user_id + "' at line 1"
    
    return f"""
    <html>
    <head><title>SQL Injection Test Page</title></head>
    <body style="font-family: Arial; padding: 20px;">
        <h2>User Profile Lookup (Vulnerable to SQLi)</h2>
        <form method="GET">
            <label>User ID:</label>
            <input type="text" name="id" value="{user_id}">
            <button type="submit">Search</button>
        </form>
        <hr>
        <h3>Query: {query}</h3>
        {f'<p style="color: red;">{error_msg}</p>' if error_msg else '<p style="color: green;">User found: John Doe</p>'}
        <hr>
        <a href="/test-sites">← Back to Test Sites</a>
    </body>
    </html>
    """


@app.route('/vuln/xss', methods=['GET', 'POST'])
def vuln_xss():
    """Intentionally vulnerable XSS endpoint for testing."""
    search_query = request.args.get('q', '')
    
    return f"""
    <html>
    <head><title>XSS Test Page</title></head>
    <body style="font-family: Arial; padding: 20px;">
        <h2>Search Page (Vulnerable to XSS)</h2>
        <form method="GET">
            <label>Search:</label>
            <input type="text" name="q" value="">
            <button type="submit">Search</button>
        </form>
        <hr>
        <h3>Search Results for: {search_query}</h3>
        <p>No results found for: {search_query}</p>
        <hr>
        <a href="/test-sites">← Back to Test Sites</a>
    </body>
    </html>
    """


@app.route('/vuln/command')
def vuln_command():
    """Intentionally vulnerable Command Injection endpoint for testing."""
    host = request.args.get('host', '127.0.0.1')
    
    output = ""
    if "whoami" in host or "|" in host or ";" in host or "&" in host:
        output = "uid=1000(www-data) gid=1000(www-data) groups=1000(www-data)"
    
    return f"""
    <html>
    <head><title>Command Injection Test Page</title></head>
    <body style="font-family: Arial; padding: 20px;">
        <h2>Ping Utility (Vulnerable to Command Injection)</h2>
        <form method="GET">
            <label>Host to ping:</label>
            <input type="text" name="host" value="{host}">
            <button type="submit">Ping</button>
        </form>
        <hr>
        <h3>Command: ping -c 1 {host}</h3>
        <pre style="background: #f0f0f0; padding: 10px;">
{output if output else f'PING {host} (127.0.0.1) 56(84) bytes of data.\\n64 bytes from localhost: icmp_seq=1 ttl=64 time=0.045 ms'}
        </pre>
        <hr>
        <a href="/test-sites">← Back to Test Sites</a>
    </body>
    </html>
    """


@app.route('/vuln/path-traversal')
def vuln_path_traversal():
    """Intentionally vulnerable Path Traversal endpoint for testing."""
    filename = request.args.get('file', 'welcome.txt')
    
    content = ""
    if ".." in filename or "etc/passwd" in filename or "windows" in filename.lower():
        content = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin"""
    else:
        content = "Welcome to our file viewer application!"
    
    return f"""
    <html>
    <head><title>Path Traversal Test Page</title></head>
    <body style="font-family: Arial; padding: 20px;">
        <h2>File Viewer (Vulnerable to Path Traversal)</h2>
        <form method="GET">
            <label>File to view:</label>
            <input type="text" name="file" value="{filename}">
            <button type="submit">View File</button>
        </form>
        <hr>
        <h3>File: {filename}</h3>
        <pre style="background: #f0f0f0; padding: 10px; border: 1px solid #ccc;">
{content}
        </pre>
        <hr>
        <a href="/test-sites">← Back to Test Sites</a>
    </body>
    </html>
    """


@app.route('/vuln/form', methods=['GET', 'POST'])
def vuln_form():
    """Vulnerable login form for testing multiple vulnerabilities."""
    username = request.form.get('username', '') if request.method == 'POST' else ''
    password = request.form.get('password', '') if request.method == 'POST' else ''
    
    message = ""
    if request.method == 'POST':
        # Check for SQLi
        if "'" in username or "--" in username or "OR" in username.upper():
            message = f'<p style="color: red;">MySQL error: You have an error in your SQL syntax near "{username}"</p>'
        # Check for XSS in response
        elif username:
            message = f'<p>Login failed for user: {username}</p>'
    
    return f"""
    <html>
    <head><title>Login Form Test Page</title></head>
    <body style="font-family: Arial; padding: 20px;">
        <h2>Login Form (Vulnerable to SQLi and XSS)</h2>
        <form method="POST">
            <div style="margin-bottom: 10px;">
                <label>Username:</label><br>
                <input type="text" name="username" style="padding: 5px; width: 200px;">
            </div>
            <div style="margin-bottom: 10px;">
                <label>Password:</label><br>
                <input type="password" name="password" style="padding: 5px; width: 200px;">
            </div>
            <button type="submit">Login</button>
        </form>
        <hr>
        {message}
        <hr>
        <a href="/test-sites">← Back to Test Sites</a>
    </body>
    </html>
    """


@app.route('/scan', methods=['POST'])
def scan():
    """Handle scan requests and display results."""
    target_url = request.form.get('url', '').strip()
    
    if not target_url:
        flash('Please enter a URL to scan.', 'error')
        return render_template('index.html')
    
    # Perform the scan
    results = scan_target(target_url)
    
    # Add remediation tips
    for vuln in results['vulnerabilities']:
        if vuln['vuln_type'] == 'SQL Injection':
            vuln['remediation'] = 'Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.'
        elif vuln['vuln_type'] == 'Reflected XSS':
            vuln['remediation'] = 'Encode all user input before displaying. Use Content Security Policy (CSP) headers.'
        elif vuln['vuln_type'] == 'Command Injection':
            vuln['remediation'] = 'Avoid executing system commands with user input. Use safe APIs and input validation with whitelists.'
        elif vuln['vuln_type'] == 'Path Traversal':
            vuln['remediation'] = 'Validate and sanitize file paths. Use whitelists for allowed files and normalize paths.'
        elif vuln['vuln_type'] == 'LDAP Injection':
            vuln['remediation'] = 'Use parameterized LDAP queries. Escape special characters in user input.'
        elif vuln['vuln_type'] == 'XML External Entity (XXE)':
            vuln['remediation'] = 'Disable external entity processing in XML parsers. Use secure XML parser configurations.'
    
    return render_template('results.html', results=results)


@app.route('/generate-report', methods=['POST'])
def generate_report():
    """Generate and download a comprehensive security report in HTML format."""
    # Get results from form data (passed as JSON)
    results_json = request.form.get('results')
    if not results_json:
        flash('No scan results available to generate report.', 'error')
        return render_template('index.html')
    
    results = json.loads(results_json)
    
    # Generate report HTML
    report_html = generate_zap_style_report(results)
    
    # Create response with HTML file download
    response = make_response(report_html)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'vulnerability_report_{timestamp}.html'
    response.headers['Content-Type'] = 'text/html'
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    
    return response


def generate_zap_style_report(results):
    """
    Generate an OWASP ZAP-style HTML security report.
    
    Args:
        results: Scan results dictionary
        
    Returns:
        str: HTML report content
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Calculate risk levels
    high_risk = sum(1 for v in results['vulnerabilities'] if v.get('confidence') == 'High')
    medium_risk = sum(1 for v in results['vulnerabilities'] if v.get('confidence') == 'Medium')
    low_risk = len(results['vulnerabilities']) - high_risk - medium_risk
    
    # Group vulnerabilities by type
    vuln_by_type = {}
    for vuln in results['vulnerabilities']:
        vuln_type = vuln['vuln_type']
        if vuln_type not in vuln_by_type:
            vuln_by_type[vuln_type] = []
        vuln_by_type[vuln_type].append(vuln)
    
    # Risk assessment
    risk_score = (high_risk * 3) + (medium_risk * 2) + (low_risk * 1)
    if risk_score >= 10:
        overall_risk = "Critical"
        risk_color = "#d32f2f"
    elif risk_score >= 5:
        overall_risk = "High"
        risk_color = "#f57c00"
    elif risk_score >= 2:
        overall_risk = "Medium"
        risk_color = "#fbc02d"
    else:
        overall_risk = "Low"
        risk_color = "#388e3c"
    
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Vulnerability Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .header {{
            background: linear-gradient(135deg, #1976d2 0%, #1565c0 100%);
            color: white;
            padding: 40px;
        }}
        
        .header h1 {{
            font-size: 32px;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            font-size: 16px;
            opacity: 0.9;
        }}
        
        .report-info {{
            background: #e3f2fd;
            padding: 20px 40px;
            border-bottom: 3px solid #1976d2;
        }}
        
        .report-info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }}
        
        .info-item {{
            font-size: 14px;
        }}
        
        .info-label {{
            font-weight: 600;
            color: #555;
            display: block;
            margin-bottom: 5px;
        }}
        
        .info-value {{
            color: #333;
            font-size: 15px;
        }}
        
        .summary {{
            padding: 40px;
            background: #fafafa;
        }}
        
        .summary h2 {{
            font-size: 24px;
            margin-bottom: 20px;
            color: #333;
        }}
        
        .risk-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .risk-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 5px solid;
        }}
        
        .risk-card.critical {{
            border-color: #d32f2f;
        }}
        
        .risk-card.high {{
            border-color: #f57c00;
        }}
        
        .risk-card.medium {{
            border-color: #fbc02d;
        }}
        
        .risk-card.low {{
            border-color: #388e3c;
        }}
        
        .risk-number {{
            font-size: 48px;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .risk-label {{
            font-size: 14px;
            color: #666;
            text-transform: uppercase;
        }}
        
        .overall-risk {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        
        .overall-risk h3 {{
            font-size: 18px;
            margin-bottom: 10px;
            color: #666;
        }}
        
        .risk-badge {{
            display: inline-block;
            padding: 15px 40px;
            border-radius: 50px;
            font-size: 24px;
            font-weight: bold;
            color: white;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 50px;
        }}
        
        .section h2 {{
            font-size: 24px;
            margin-bottom: 20px;
            color: #333;
            padding-bottom: 10px;
            border-bottom: 2px solid #1976d2;
        }}
        
        .vulnerability-group {{
            margin-bottom: 40px;
            background: #fafafa;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #e0e0e0;
        }}
        
        .vuln-header {{
            background: #1976d2;
            color: white;
            padding: 15px 20px;
            font-size: 18px;
            font-weight: 600;
        }}
        
        .vuln-item {{
            padding: 20px;
            border-bottom: 1px solid #e0e0e0;
            background: white;
        }}
        
        .vuln-item:last-child {{
            border-bottom: none;
        }}
        
        .vuln-title {{
            font-size: 16px;
            font-weight: 600;
            color: #d32f2f;
            margin-bottom: 10px;
        }}
        
        .vuln-detail {{
            margin-bottom: 8px;
            font-size: 14px;
        }}
        
        .vuln-detail strong {{
            color: #555;
            display: inline-block;
            min-width: 120px;
        }}
        
        .payload {{
            background: #263238;
            color: #aed581;
            padding: 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            margin: 10px 0;
            overflow-x: auto;
        }}
        
        .remediation {{
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 15px;
            margin-top: 10px;
            border-radius: 4px;
        }}
        
        .remediation strong {{
            color: #2e7d32;
            display: block;
            margin-bottom: 5px;
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }}
        
        .badge.high {{
            background: #ffebee;
            color: #c62828;
        }}
        
        .badge.medium {{
            background: #fff3e0;
            color: #e65100;
        }}
        
        .badge.get {{
            background: #e3f2fd;
            color: #1565c0;
        }}
        
        .badge.post {{
            background: #fce4ec;
            color: #ad1457;
        }}
        
        .footer {{
            background: #263238;
            color: white;
            padding: 30px 40px;
            text-align: center;
        }}
        
        .footer p {{
            margin-bottom: 10px;
        }}
        
        .disclaimer {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 4px;
        }}
        
        .disclaimer strong {{
            color: #856404;
            display: block;
            margin-bottom: 10px;
        }}
        
        .disclaimer p {{
            color: #856404;
            font-size: 14px;
        }}
        
        @media print {{
            body {{
                padding: 0;
            }}
            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🔒 Web Application Security Assessment Report</h1>
            <div class="subtitle">Generated by MiniWebVulnScanner - OWASP ZAP Style Report</div>
        </div>
        
        <!-- Report Information -->
        <div class="report-info">
            <div class="report-info-grid">
                <div class="info-item">
                    <span class="info-label">Target URL:</span>
                    <span class="info-value">{results['url']}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Scan Date:</span>
                    <span class="info-value">{timestamp}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Targets Found:</span>
                    <span class="info-value">{results['targets_found']} endpoints</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Issues Found:</span>
                    <span class="info-value">{len(results['vulnerabilities'])} vulnerabilities</span>
                </div>
            </div>
        </div>
        
        <!-- Executive Summary -->
        <div class="summary">
            <h2>📊 Executive Summary</h2>
            
            <div class="risk-cards">
                <div class="risk-card critical">
                    <div class="risk-number" style="color: #d32f2f;">{high_risk}</div>
                    <div class="risk-label">High Risk</div>
                </div>
                <div class="risk-card medium">
                    <div class="risk-number" style="color: #f57c00;">{medium_risk}</div>
                    <div class="risk-label">Medium Risk</div>
                </div>
                <div class="risk-card low">
                    <div class="risk-number" style="color: #388e3c;">{low_risk}</div>
                    <div class="risk-label">Low Risk</div>
                </div>
                <div class="risk-card high">
                    <div class="risk-number" style="color: #1976d2;">{len(results['vulnerabilities'])}</div>
                    <div class="risk-label">Total Issues</div>
                </div>
            </div>
            
            <div class="overall-risk">
                <h3>Overall Risk Assessment</h3>
                <span class="risk-badge" style="background: {risk_color};">{overall_risk}</span>
            </div>
        </div>
        
        <!-- Main Content -->
        <div class="content">
            <div class="disclaimer">
                <strong>⚠️ Important Notice</strong>
                <p>This report is generated by an educational security scanning tool. Results should be verified by professional security testing. This report is intended for authorized security assessments only.</p>
            </div>
            
"""
    
    # Add vulnerability details grouped by type
    if results['vulnerabilities']:
        html += """
            <div class="section">
                <h2>🚨 Vulnerability Details</h2>
"""
        
        for vuln_type, vulns in vuln_by_type.items():
            html += f"""
                <div class="vulnerability-group">
                    <div class="vuln-header">
                        {vuln_type} ({len(vulns)} instance{'s' if len(vulns) > 1 else ''})
                    </div>
"""
            
            for idx, vuln in enumerate(vulns, 1):
                html += f"""
                    <div class="vuln-item">
                        <div class="vuln-title">Instance #{idx}: {vuln['vuln_type']}</div>
                        
                        <div class="vuln-detail">
                            <strong>URL:</strong> {vuln['url']}
                        </div>
                        
                        <div class="vuln-detail">
                            <strong>Method:</strong> <span class="badge {vuln['method'].lower()}">{vuln['method']}</span>
                            <strong style="margin-left: 20px;">Confidence:</strong> <span class="badge {vuln['confidence'].lower()}">{vuln['confidence']}</span>
                        </div>
                        
                        <div class="vuln-detail">
                            <strong>Vulnerable Field:</strong> {vuln['field']}
                        </div>
                        
                        <div class="vuln-detail">
                            <strong>Evidence:</strong> {vuln['evidence']}
                        </div>
                        
                        <div class="vuln-detail">
                            <strong>Payload Used:</strong>
                            <div class="payload">{vuln['payload'].replace('<', '&lt;').replace('>', '&gt;')}</div>
                        </div>
                        
                        <div class="remediation">
                            <strong>🛡️ Remediation:</strong>
                            {vuln.get('remediation', 'No specific remediation available.')}
                        </div>
                    </div>
"""
            
            html += """
                </div>
"""
    
    else:
        html += """
            <div class="section">
                <div style="text-align: center; padding: 40px; background: #e8f5e9; border-radius: 8px;">
                    <h3 style="color: #2e7d32;">✅ No Vulnerabilities Detected</h3>
                    <p style="color: #666; margin-top: 10px;">The scan completed successfully with no obvious vulnerabilities found.</p>
                </div>
            </div>
"""
    
    # Add errors if any
    if results.get('errors'):
        html += """
            <div class="section">
                <h2>⚠️ Scan Errors</h2>
                <div style="background: #ffebee; padding: 20px; border-radius: 8px; border-left: 4px solid #d32f2f;">
                    <ul style="margin-left: 20px;">
"""
        for error in results['errors']:
            html += f"                        <li style='color: #c62828; margin-bottom: 10px;'>{error}</li>\n"
        
        html += """
                    </ul>
                </div>
            </div>
"""
    
    # Add recommendations section
    html += """
            <div class="section">
                <h2>💡 General Recommendations</h2>
                <div style="background: #f5f5f5; padding: 20px; border-radius: 8px;">
                    <ol style="margin-left: 20px; line-height: 2;">
                        <li><strong>Immediate Action:</strong> Review and remediate all high-risk vulnerabilities</li>
                        <li><strong>Input Validation:</strong> Implement strict server-side input validation</li>
                        <li><strong>Output Encoding:</strong> Encode all user input before displaying</li>
                        <li><strong>Security Headers:</strong> Implement CSP, HSTS, X-Frame-Options headers</li>
                        <li><strong>Regular Testing:</strong> Conduct periodic security assessments</li>
                        <li><strong>Security Training:</strong> Train developers on secure coding practices</li>
                        <li><strong>Penetration Testing:</strong> Engage professional security testers</li>
                    </ol>
                </div>
            </div>
            
            <div class="section">
                <h2>📚 Resources</h2>
                <div style="background: #e3f2fd; padding: 20px; border-radius: 8px;">
                    <h3 style="margin-bottom: 15px;">OWASP Resources:</h3>
                    <ul style="margin-left: 20px; line-height: 2;">
                        <li><a href="https://owasp.org/www-project-top-ten/" style="color: #1976d2;">OWASP Top 10</a></li>
                        <li><a href="https://cheatsheetseries.owasp.org/" style="color: #1976d2;">OWASP Cheat Sheet Series</a></li>
                        <li><a href="https://owasp.org/www-project-web-security-testing-guide/" style="color: #1976d2;">Web Security Testing Guide</a></li>
                        <li><a href="https://owasp.org/www-project-zap/" style="color: #1976d2;">OWASP ZAP</a></li>
                    </ul>
                </div>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p><strong>MiniWebVulnScanner</strong> - Educational Security Testing Tool</p>
            <p>Report Generated: {timestamp}</p>
            <p style="font-size: 12px; opacity: 0.8; margin-top: 15px;">
                This tool is for authorized security testing only. Always obtain proper permission before testing.
            </p>
        </div>
    </div>
</body>
</html>
"""
    
    return html


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
