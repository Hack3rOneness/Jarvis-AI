#!/usr/bin/env python3                               
import requests
import threading                                     
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
import argparse                                       
class MassVulnScanner:
    def __init__(self, domains_file, threads=50, output="vuln_report.json"):
        self.domains = []
        self.results = []
        self.threads = threads
        self.output = output
        self.session = requests.Session()
        self.load_domains(domains_file)
                                                          
    def load_domains(self, file):
        with open(file, 'r') as f:                                
          self.domains = [line.strip() for line in f if line.strip()]                                            
          print(f"[+] Loaded {len(self.domains)} domains")

    def check_ssl(self, domain):
        """SSL/TLS vulnerabilities"""
        try:
            resp = requests.get(f"https://{domain}", timeout=5, verify=False)
            issues = []
            if resp.status_code == 200:
                # Check for HTTP (HSTS missing)
                http_resp = requests.get(f"http://{domain}", timeout=5)
                if http_resp.status_code == 200:
                    issues.append("HTTP accessible - HSTS missing")

            # TODO: Add SSL Labs API check
            return {"ssl": issues, "cvss": 5.3 if issues else 0}
        except:
            return {"ssl": [], "cvss": 0}

    def check_xss(self, domain):
        """Reflected XSS via parameter fuzzing"""
        payloads = ["<script>alert(1)</script>", "'\"><script>alert(1)</script>", "javascript:alert(1)"]
        paths = ["/search?q=", "/?q=", "/search.php?q="]

        for path in paths[:2]:  # Limit for speed
            test_url = urljoin(f"https://{domain}", path)
            for payload in payloads:
                try:
                    resp = self.session.get(test_url + payload, timeout=5)
                    if payload in resp.text:
                        return {"xss": "Reflected XSS confirmed", "cvss": 6.1, "payload": payload, "url": test_url + payload}
                except:
                    pass
        return {"xss": None, "cvss": 0}

    def check_open_redirect(self, domain):
        """Open redirect testing"""
        payloads = ["//google.com", "/%09//google.com", "javascript:alert(1)"]
        paths = ["/redirect?url=", "/?redirect=", "/login?redirect="]

        for path in paths:
            test_url = urljoin(f"https://{domain}", path)
            for payload in payloads:
                try:
                    resp = self.session.get(test_url + payload, timeout=5, allow_redirects=False)
                    if resp.status_code in [301, 302, 307, 308] and "google.com" in resp.headers.get('Location', ''):
                        return {"open_redirect": True, "cvss": 6.1, "url": test_url + payload}
                except:
                    pass
        return {"open_redirect": False, "cvss": 0}

    def check_sql_injection(self, domain):
        """SQLi error-based detection"""
        payloads = ["' OR 1=1--", "' UNION SELECT NULL--", "1' AND 1=1--"]
        paths = ["/?id=", "/user?id=", "/product.php?id="]

        for path in paths:
            test_url = urljoin(f"https://{domain}", path)
            for payload in payloads:
                try:
                    resp = self.session.get(test_url + payload, timeout=5)
                    if any(err in resp.text.lower() for err in ["mysql", "sql syntax", "ora-", "postgresql"]):
                        return {"sqli": "Potential SQLi", "cvss": 8.8, "payload": payload, "url": test_url + payload}
                except:
                    pass
        return {"sqli": None, "cvss": 0}

    def check_subdomain_takeover(self, domain):
        """Check common dangling DNS records"""
        takeover_hosts = ["app", "api", "staging", "dev", "beta"]
        for host in takeover_hosts:
            test_domain = f"{host}.{domain}"
            try:
                resp = requests.get(f"https://{test_domain}", timeout=5)
                if "github.io" in resp.text or "herokudns" in resp.text:
                    return {"subdomain_takeover": test_domain, "cvss": 9.1}
            except:
                pass
        return {"subdomain_takeover": None, "cvss": 0}

    def check_cors(self, domain):
        """CORS misconfiguration"""
        test_url = f"https://{domain}"
        headers = {'Origin': 'https://evil.com'}
        try:
            resp = self.session.get(test_url, headers=headers, timeout=5)
            cors = resp.headers.get('Access-Control-Allow-Origin')
            if cors and ('*' in cors or 'evil.com' not in cors):
                return {"cors": f"Misconfig: {cors}", "cvss": 5.9}
        except:
            pass
        return {"cors": None, "cvss": 0}

    def scan_domain(self, domain):
        """Full scan for single domain"""
        print(f"[*] Scanning {domain}...")
        results = {
            "domain": domain,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": [],
            "total_cvss": 0
        }

        # Run all checks in parallel
        checks = [
            self.check_ssl(domain),
            self.check_xss(domain),
            self.check_open_redirect(domain),
            self.check_sql_injection(domain),
            self.check_subdomain_takeover(domain),
            self.check_cors(domain)
        ]

        for check in checks:
            for vuln, details in check.items():
                if vuln != "cvss" and details:
                    results["vulnerabilities"].append({vuln: details})
                    results["total_cvss"] += check["cvss"]

        self.results.append(results)
        print(f"[+] {domain}: {len(results['vulnerabilities'])} vulns (CVSS: {results['total_cvss']:.1f})")
        return results

    def run(self):
        """Execute mass scan"""
        print(f"[*] Starting mass scan: {len(self.domains)} domains, {self.threads} threads")
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.scan_domain, domain) for domain in self.domains]
            for future in as_completed(futures):
                future.result()

        # Save results
        with open(self.output, 'w') as f:
            json.dump(self.results, f, indent=2)

        elapsed = time.time() - start_time
        print(f"\n[+] Scan complete: {self.output} ({elapsed:.1f}s)")
        self.print_summary()

    def print_summary(self):
        """Console summary"""
        critical = [r for r in self.results if r['total_cvss'] >= 7]
        print(f"\nSUMMARY:")
        print(f"Critical (CVSS 7+): {len(critical)}")
        print(f"Medium/High: {len([r for r in self.results if 4 <= r['total_cvss'] < 7])}")
        print(f"Total vulns: {sum(len(r['vulnerabilities']) for r in self.results)}")

        if critical:
            print("\nTOP CRITICAL:")
            for result in sorted(critical, key=lambda x: x['total_cvss'], reverse=True)[:5]:
                print(f"  {result['domain']} (CVSS {result['total_cvss']:.1f}): {result['vulnerabilities']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("domains_file", help="File with one domain per line")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("-o", "--output", default="vuln_report.json", help="Output file")
    args = parser.parse_args()

    scanner = MassVulnScanner(args.domains_file, args.threads, args.output)
    scanner.run()
