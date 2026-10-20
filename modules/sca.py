import json
import re
from pathlib import Path
import requests

# Built-in offline CVE signatures for critical dependencies
OFFLINE_VULN_DB = {
    "lodash": [
        {"version_lt": "4.17.21", "cve": "CVE-2021-23337", "severity": "HIGH", "desc": "Command Injection in template function", "fix": ">= 4.17.21"}
    ],
    "phpmailer/phpmailer": [
        {"version_lt": "6.5.0", "cve": "CVE-2021-3603", "severity": "CRITICAL", "desc": "Object Injection via Phar deserialization", "fix": ">= 6.5.0"}
    ],
    "django": [
        {"version_lt": "3.2.13", "cve": "CVE-2022-28346", "severity": "CRITICAL", "desc": "SQL Injection in QuerySet.annotate(), aggregate(), and extra()", "fix": ">= 3.2.13"}
    ],
    "requests": [
        {"version_lt": "2.31.0", "cve": "CVE-2023-32681", "severity": "MEDIUM", "desc": "Unintended leak of Proxy-Authorization header", "fix": ">= 2.31.0"}
    ],
    "express": [
        {"version_lt": "4.19.2", "cve": "CVE-2024-29041", "severity": "MEDIUM", "desc": "Open Redirect via malformed URLs", "fix": ">= 4.19.2"}
    ]
}

class SCAScanner:
    """Head 3: Software Composition Analysis (Supply Chain CVE Scanner)"""
    def __init__(self, use_online_api=True, timeout=5):
        self.use_online_api = use_online_api
        self.timeout = timeout
        self.osv_url = "https://api.osv.dev/v1/query"

    def _parse_requirements_txt(self, path):
        deps = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:[=><~]{1,2}\s*([0-9a-zA-Z\.\-]+))?", line)
                    if m:
                        pkg = m.group(1).lower()
                        ver = m.group(2) or "latest"
                        deps.append({"ecosystem": "PyPI", "package": pkg, "version": ver, "source": str(path)})
        except Exception:
            pass
        return deps

    def _parse_package_json(self, path):
        deps = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for pkg, ver in all_deps.items():
                    clean_ver = re.sub(r"[^0-9\.]", "", ver)
                    deps.append({"ecosystem": "npm", "package": pkg.lower(), "version": clean_ver or ver, "source": str(path)})
        except Exception:
            pass
        return deps

    def _parse_composer_json(self, path):
        deps = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                all_deps = {**data.get("require", {}), **data.get("require-dev", {})}
                for pkg, ver in all_deps.items():
                    if pkg.lower() == "php":
                        continue
                    clean_ver = re.sub(r"[^0-9\.]", "", ver)
                    deps.append({"ecosystem": "Packagist", "package": pkg.lower(), "version": clean_ver or ver, "source": str(path)})
        except Exception:
            pass
        return deps

    def _query_osv_api(self, ecosystem, package, version):
        if not self.use_online_api or version in ["latest", "*", ""]:
            return []

        payload = {
            "version": version,
            "package": {
                "name": package,
                "ecosystem": ecosystem
            }
        }
        try:
            r = requests.post(self.osv_url, json=payload, timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                vulns = data.get("vulns", [])
                results = []
                for v in vulns:
                    aliases = v.get("aliases", [])
                    cve = next((a for a in aliases if a.startswith("CVE-")), v.get("id"))
                    results.append({
                        "cve": cve,
                        "severity": "HIGH",
                        "desc": v.get("summary", "Known security vulnerability in dependency."),
                        "fix": "Upgrade to latest patched version."
                    })
                return results
        except Exception:
            pass
        return []

    def scan(self, target_path):
        target = Path(target_path)
        manifests = []

        if target.is_file():
            manifests.append(target)
        else:
            manifests.extend(list(target.rglob("requirements.txt")))
            manifests.extend(list(target.rglob("package.json")))
            manifests.extend(list(target.rglob("composer.json")))

        parsed_deps = []
        for m in manifests:
            if "node_modules" in str(m) or "vendor" in str(m) or ".venv" in str(m):
                continue
            if m.name == "requirements.txt":
                parsed_deps.extend(self._parse_requirements_txt(m))
            elif m.name == "package.json":
                parsed_deps.extend(self._parse_package_json(m))
            elif m.name == "composer.json":
                parsed_deps.extend(self._parse_composer_json(m))

        findings = []
        for dep in parsed_deps:
            pkg = dep["package"]
            ver = dep["version"]

            # 1. Offline Signature Check
            if pkg in OFFLINE_VULN_DB:
                for rule in OFFLINE_VULN_DB[pkg]:
                    findings.append({
                        "package": pkg,
                        "ecosystem": dep["ecosystem"],
                        "installed_version": ver,
                        "cve": rule["cve"],
                        "severity": rule["severity"],
                        "description": rule["desc"],
                        "remediation": f"Upgrade '{pkg}' to {rule['fix']}",
                        "manifest": dep["source"]
                    })
            else:
                # 2. Online OSV API Check
                api_vulns = self._query_osv_api(dep["ecosystem"], pkg, ver)
                for v in api_vulns:
                    findings.append({
                        "package": pkg,
                        "ecosystem": dep["ecosystem"],
                        "installed_version": ver,
                        "cve": v["cve"],
                        "severity": v["severity"],
                        "description": v["desc"],
                        "remediation": v["fix"],
                        "manifest": dep["source"]
                    })

        return {
            "target": str(target.resolve()),
            "manifests_found": len(manifests),
            "dependencies_analyzed": len(parsed_deps),
            "findings_count": len(findings),
            "findings": findings
        }
