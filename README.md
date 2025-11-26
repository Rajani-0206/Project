# Project
In this project, I tried to develop a vulnerability scanner that can scan XSS, SQLi and CSRF security compromise vulnerabilities. Python 3 was used to build this scanner along with few open libraries that were available like, requests and BeautifulSoup.
The code used was tested on https://example.com, a free site for testing for coders etc. The scanner when checked upon the mentioned website by modifying the site by some SQL injection it gave a warning when the command test sql injection was given. Without any vulnerabilities the output is just the function and website name, while with a vulnerability there's an output like, vulnerability in SQLi detected. The projet along a snap of output is uploaded in this repository. The code used is as follows:
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re

visited_links = set()
forms_scanned = set()


# ------------------------------------
# 1. CRAWLER
# ------------------------------------
def crawl_website(url='https://example.com', max_depth=2, depth=0):
    if depth > max_depth or url in visited_links:
        return

    print(f"[+] Crawling: {url}")
    visited_links.add(url='https://example.com')

    try:
        response = requests.get(url='https://example.com', timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception as e:
        print(f"[-] Failed to crawl {url}: {e}")
        return

    for link in soup.find_all("a", href=True):
        full_url = urljoin(url, link['href'])
        if urlparse(full_url).netloc == urlparse(url='https://example.com').netloc:
            crawl_website(full_url, max_depth, depth+1)


# ------------------------------------
# 2. FORM EXTRACTOR
# ------------------------------------
def get_forms(url):
    try:
        response = requests.get(url='https://example.com', timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")
    except:
        return []


# ------------------------------------
# 3. XSS SCANNER
# ------------------------------------
def test_xss(url='https://example.com'):
    print("\n=== XSS TESTING ===")
    payload = "<script>alert(1)</script>"
    forms = get_forms(url='https://example.com')
    vulnerable = False

    for form in forms:
        form_details = {}
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")

        target = urljoin(url, action)
        data = {}

        for input_tag in inputs:
            name = input_tag.get("name")
            data[name] = payload

        print(f"[+] Testing form: {target}")

        try:
            if method == "post":
                res = requests.post(target, data=data)
            else:
                res = requests.get(target, params=data)

            if payload in res.text:
                vulnerable = True
                print(f"[!!] XSS VULNERABILITY FOUND at {target}")
        except:
            continue

    if not vulnerable:
        print("[✓] No XSS vulnerabilities found.")
    return vulnerable


# ------------------------------------
# 4. SQL INJECTION SCANNER
# ------------------------------------
def test_sql_injection(url):
    print("\n=== SQLi TESTING ===")
    payloads = ["' OR '1'='1", '" OR "1"="1"', "' OR 1=1 --", "' OR 'a'='a'"]
    forms = get_forms(url='https://example.com')
    vulnerable = False

    for form in forms:
        inputs = form.find_all("input")
        action = form.get("action")
        method = form.get("method", "get").lower()
        target = urljoin(url, action)

        for payload in payloads:
            print(f"[+] Testing SQL payload: {payload}")

            data = {}
            for input_field in inputs:
                name = input_field.get("name")
                data[name] = payload

            try:
                if method == "post":
                    res = requests.post(target, data=data)
                else:
                    res = requests.get(target, params=data)

                if re.search(r"sql|mysql|syntax|error|warning", res.text.lower()):
                    vulnerable = True
                    print(f"[!!] SQL Injection VULNERABILITY FOUND at {target}")
                    break
            except:
                continue

    if not vulnerable:
        print("[✓] No SQL injection vulnerabilities found.")
    return vulnerable


# ------------------------------------
# 5. CSRF DETECTOR
# ------------------------------------
def check_csrf(url='https://example.com'):
    print("\n=== CSRF TESTING ===")
    forms = get_forms(url='https://example.com')
    vulnerable = False

    for form in forms:
        inputs = form.find_all("input")
        csrf_present = any("csrf" in (i.get("name") or "").lower() for i in inputs)

        if not csrf_present:
            print(f"[!!] CSRF vulnerability: Form missing CSRF token at {url}")
            vulnerable = True

    if not vulnerable:
        print("[✓] Forms contain CSRF protection.")
    return vulnerable


# ------------------------------------
# 6. MAIN MENU
# ------------------------------------
def main():
    print("""
===========================================
   WEB APPLICATION VULNERABILITY SCANNER
===========================================
1. Crawl website
2. Scan for XSS
3. Scan for SQL Injection
4. Scan for CSRF
5. Full Scan (Recommended)
===========================================
""")

    url = input("Enter target URL: ")

    choice = input("\nChoose option: ")

    if choice == "1":
        crawl_website(url='https://example.com')
    elif choice == "2":
        test_xss(url='https://example.com')
    elif choice == "3":
        test_sql_injection(url='https://example.com')
    elif choice == "4":
        check_csrf(url='https://example.com')
    elif choice == "5":
        crawl_website(url='https://example.com')
        test_xss(url='https://example.com')
        test_sql_injection(url='https://example.com')
        check_csrf(url='https://example.com')
    else:
        print("Invalid option.")


if _name_ == "main":
    main()

After this for the final output the following commands:
crawl_website [to enter the website and get it's internal links for testing]
test_xss [to check for cross site vulnerabilities]
test_sql_injection [to check for SQL injection]
check_csrf [to check for csrf security compromise]
A final output is the obtained. This is a very basic prototype of the vulnerability scanner and can be developed further to test other vulnerabilities too.
