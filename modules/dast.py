import urllib.parse
import requests
from concurrent.futures import ThreadPoolExecutor

SENSITIVE_PATHS = [
    {"path": "/.git/HEAD", "indicator": "ref: refs/", "severity": "CRITICAL", "name": "Exposed Git Repository"},
    {"path": "/.env", "indicator": "DB_", "severity": "CRITICAL", "name": "Exposed Environment Configuration File"},
    {"path": "/phpinfo.php", "indicator": "PHP Version", "severity": "HIGH", "name": "Exposed phpinfo() Diagnostic Page"},
    {"path": "/robots.txt", "indicator": "Disallow:", "severity": "INFO", "name": "Robots.txt Discovered"},
    {"path": "/.DS_Store", "indicator": "\x00\x00\x00\x01Bud1", "severity": "MEDIUM", "name": "Exposed macOS .DS_Store File"},
    {"path": "/backup.zip", "indicator": "PK\x03\x04", "severity": "HIGH", "name": "Exposed Archive Backup File"},
    {"path": "/swagger-ui.html", "indicator": "swagger", "severity": "LOW", "name": "Exposed Swagger API Documentation"},
    {"path": "/admin/", "indicator": "login", "severity": "LOW", "name": "Administrative Login Portal Discovered"}
]

REQUIRED_HEADERS = [
    {
        "header": "Content-Security-Policy",
        "severity": "MEDIUM",
        "description": "Protects against Cross-Site Scripting (XSS) and data injection attacks."
    },
    {
        "header": "Strict-Transport-Security",
        "severity": "MEDIUM",
        "description": "Enforces secure HTTPS connections and defends against SSL stripping."
    },
    {
        "header": "X-Frame-Options",
        "severity": "LOW",
        "description": "Defends against UI redress attacks (Clickjacking)."
    },
    {
        "header": "X-Content-Type-Options",
        "severity": "LOW",
        "description": "Prevents MIME-type sniffing."
    },
    {
        "header": "Referrer-Policy",
        "severity": "LOW",
        "description": "Controls how much referrer information is included with requests."
    }
]

class DASTScanner:
    """Head 2: Dynamic Application Security Testing & Web Recon"""
    def __init__(self, timeout=5, user_agent=None):
        self.timeout = timeout
        self.headers = {
            "User-Agent": user_agent or "Cerberus-Security-Auditor/1.0 (+https://github.com/phantom/cerberus)"
        }

    def _normalize_url(self, url):
        if not url.startswith("http://") and not url.startswith("https://"):
            return "https://" + url
        return url

    def scan(self, target_url):
        target = self._normalize_url(target_url)
        findings = []
        server_info = {}

        try:
            resp = requests.get(target, headers=self.headers, timeout=self.timeout, verify=False)
            server_info["status_code"] = resp.status_code
            server_info["url"] = resp.url
            server_info["server"] = resp.headers.get("Server", "Undisclosed")
            server_info["powered_by"] = resp.headers.get("X-Powered-By", "Undisclosed")
        except Exception as e:
            return {
                "target": target,
                "error": f"Failed to connect to target: {str(e)}",
                "findings": []
            }

        # 1. Information Disclosure in Headers
        if server_info["server"] != "Undisclosed":
            findings.append({
                "type": "Information Disclosure",
                "name": f"Server Banner Disclosed: {server_info['server']}",
                "severity": "LOW",
                "description": "The web server discloses its software name and version in HTTP response headers.",
                "remediation": "Configure web server (e.g. ServerTokens Prod, server_tokens off) to mask banner."
            })

        if server_info["powered_by"] != "Undisclosed":
            findings.append({
                "type": "Information Disclosure",
                "name": f"X-Powered-By Header Disclosed: {server_info['powered_by']}",
                "severity": "LOW",
                "description": "Backend runtime technology is disclosed via HTTP header.",
                "remediation": "Remove the X-Powered-By header from the application configuration."
            })

        # 2. Security Headers Check
        for req_header in REQUIRED_HEADERS:
            h_name = req_header["header"]
            if h_name not in resp.headers:
                findings.append({
                    "type": "Missing Security Header",
                    "name": f"Missing Header: {h_name}",
                    "severity": req_header["severity"],
                    "description": req_header["description"],
                    "remediation": f"Configure the web server or application middleware to return '{h_name}'."
                })

        # 3. CORS Misconfiguration Check
        try:
            cors_headers = {**self.headers, "Origin": "https://evil-attacker.com"}
            cors_resp = requests.get(target, headers=cors_headers, timeout=self.timeout, verify=False)
            acao = cors_resp.headers.get("Access-Control-Allow-Origin")
            acac = cors_resp.headers.get("Access-Control-Allow-Credentials")

            if acao == "https://evil-attacker.com" and acac == "true":
                findings.append({
                    "type": "CORS Misconfiguration",
                    "name": "Overly Permissive CORS with Credentials",
                    "severity": "HIGH",
                    "description": "The server reflects arbitrary origins and allows credentials, enabling CSRF/data theft.",
                    "remediation": "Enforce a strict whitelist of trusted origins and avoid reflecting untrusted Origin headers."
                })
            elif acao == "*":
                findings.append({
                    "type": "CORS Misconfiguration",
                    "name": "Wildcard Access-Control-Allow-Origin (*)",
                    "severity": "INFO",
                    "description": "The resource is globally readable across all origins.",
                    "remediation": "If the resource contains sensitive data, restrict CORS to specific domains."
                })
        except Exception:
            pass

        # 4. Probing for Sensitive Exposed Files
        base_parsed = urllib.parse.urlparse(target)
        base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

        def check_sensitive_path(item):
            check_url = base_origin + item["path"]
            try:
                r = requests.get(check_url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=False)
                if r.status_code == 200:
                    if item["indicator"] in r.text or item["indicator"] in str(r.content):
                        return {
                            "type": "Exposed Sensitive File",
                            "name": f"{item['name']} ({item['path']})",
                            "severity": item["severity"],
                            "description": f"Accessible sensitive file detected at {check_url} with HTTP 200.",
                            "remediation": f"Block public web server access to {item['path']} or remove the file immediately."
                        }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=5) as executor:
            results = executor.map(check_sensitive_path, SENSITIVE_PATHS)
            for res in results:
                if res:
                    findings.append(res)

        return {
            "target": target,
            "server_info": server_info,
            "findings_count": len(findings),
            "findings": findings
        }
