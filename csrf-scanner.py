#!/usr/bin/env python3
# CSRF Scanner v3.0 - With PoC Generation & Active Testing
# by RostamiSec

import requests
from bs4 import BeautifulSoup
import sys
from urllib.parse import urljoin

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'

def print_banner():
    """ یک بنر زیبا برای شروع برنامه چاپ می‌کند """
    print(f"{Colors.RED}")
    print("   ______ ____   _____ ____                    ")
    print("  / ____// __ \\ / ___// __ \\                   ")
    print(" / /    / /_/ / \\__ \\/ /_/ /                   ")
    print("/ /___ / _, _/ ___/ / _, _/                    ")
    print("\\____//_/ |_| /____//_/ |_|   Scanner v3.0      ")
    print("              By RostamiSec                   ")
    print(f"{Colors.NC}")

def generate_poc(form, base_url, test_param_name):
    """ برای یک فرم آسیب‌پذیر، یک فایل PoC.html تولید می‌کند """
    action = form.get('action', '#')
    method = form.get('method', 'get').upper()
    full_action_url = urljoin(base_url, action)

    poc_html = f"""
<html>
  <body>
    <h2>CSRF PoC for form targeting: {full_action_url}</h2>
    <p>This PoC will attempt to submit '{test_param_name}' with the value 'CSRF_SUCCESS'</p>
    <form action="{full_action_url}" method="{method}">
"""
    
    inputs = form.find_all('input')
    for input_tag in inputs:
        name = input_tag.get('name')
        value = 'CSRF_SUCCESS' if name == test_param_name else input_tag.get('value', '')
        input_type = input_tag.get('type', 'text')
        if name and input_tag.get('type') != 'submit':
             poc_html += f'      <input type="hidden" name="{name}" value="{value}" />\n'

    poc_html += """
      <input type="submit" value="Submit request" />
    </form>
    <script>
      // document.forms[0].submit();
    </script>
  </body>
</html>
"""
    return poc_html

def main():
    print_banner()

    target_url = input(f"{Colors.YELLOW}[?] Enter the target URL: {Colors.NC}")
    if not target_url:
        print(f"\n{Colors.RED}[!] Error: URL cannot be empty. Exiting.{Colors.NC}")
        sys.exit(1)

    cookie_string = input(f"{Colors.YELLOW}[?] Enter the cookie string: {Colors.NC}")
    if not cookie_string:
        print(f"\n{Colors.RED}[!] Error: Cookie must be provided for authenticated scanning. Exiting.{Colors.NC}")
        sys.exit(1)

    session = requests.Session()
    headers = {'Cookie': cookie_string, 'User-Agent': 'RostamiSec-CSRF-Scanner/3.0'}
    
    print(f"\n{Colors.BLUE}==================================================={Colors.NC}")
    print(f"{Colors.GREEN}[+] Scanning target: {Colors.YELLOW}{target_url}{Colors.NC}")
    print(f"{Colors.BLUE}==================================================={Colors.NC}\n")

    try:
        response = session.get(target_url, headers=headers, timeout=15)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        if not forms:
            print(f"{Colors.YELLOW}[i] No forms found on this page.{Colors.NC}")
            return

        print(f"[i] Found {len(forms)} form(s). Analyzing each one:\n")
        
        for i, form in enumerate(forms, 1):
            has_csrf_token = any(inp.get('name', '').lower() in ['csrf_token', 'csrf-token', 'xsrf_token', 'authenticity_token', '_token', 'nonce', 'user_token'] for inp in form.find_all('input'))
            
            action = form.get('action', '#')
            method = form.get('method', 'get').upper()

            print(f"{Colors.YELLOW}---------- Form #{i} Details (Action: {action}, Method: {method}) ----------{Colors.NC}")

            if has_csrf_token:
                print(f"  {Colors.GREEN}[-] Status: Found a potential CSRF token. Likely protected.{Colors.NC}\n")
            else:
                print(f"  {Colors.RED}[!] Status: NO CSRF token found. Attempting active test...{Colors.NC}")
                
                # --- تست فعال فرم ---
                test_input = form.find('input', {'type': 'text'})
                if not test_input:
                    test_input = form.find('textarea')
                
                if test_input and test_input.get('name'):
                    test_param_name = test_input.get('name')
                    test_data = {inp.get('name'): 'CSRF_TEST' for inp in form.find_all(['input', 'textarea']) if inp.get('name')}
                    
                    full_action_url = urljoin(target_url, action)
                    
                    try:
                        if method == 'POST':
                            test_response = session.post(full_action_url, headers=headers, data=test_data, allow_redirects=True)
                        else:
                            test_response = session.get(full_action_url, headers=headers, params=test_data, allow_redirects=True)
                        
                        if 'CSRF_TEST' in test_response.text:
                            print(f"  {Colors.RED}[!!!] VULNERABILITY CONFIRMED: Form submitted successfully and test data was reflected!{Colors.NC}")
                            poc_code = generate_poc(form, target_url, test_param_name)
                            poc_filename = f"csrf_poc_form_{i}_{test_param_name}.html"
                            with open(poc_filename, "w") as f:
                                f.write(poc_code)
                            print(f"  {Colors.YELLOW}[+] PoC file generated: {poc_filename}{Colors.NC}\n")
                        else:
                            print(f"  {Colors.YELLOW}[?] Form submitted, but test data not found in response. Manual verification needed.{Colors.NC}\n")
                    except requests.RequestException as e_submit:
                        print(f"  {Colors.RED}[!] Failed to submit form: {e_submit}{Colors.NC}\n")
                else:
                    print(f"  {Colors.YELLOW}[?] Could not find a text input to test submission automatically.{Colors.NC}\n")

    except requests.RequestException as e_get:
        print(f"{Colors.RED}[!] Error: Could not connect to the URL. Details: {e_get}{Colors.NC}")

if __name__ == "__main__":
    main()
