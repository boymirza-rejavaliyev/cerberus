import os
import re
import json
from pathlib import Path

DEFAULT_EXTENSIONS = {
    ".php", ".py", ".js", ".ts", ".jsx", ".tsx",
    ".go", ".java", ".rb", ".env", ".yml", ".yaml", ".json"
}

IGNORE_DIRS = {
    ".git", "node_modules", "vendor", "__pycache__", ".venv",
    "venv", ".idea", ".vscode", "dist", "build", "coverage"
}

class SASTScanner:
    """Head 1: Static Application Security Testing (Source Code Auditor)"""
    def __init__(self, rules_path=None):
        if rules_path is None:
            rules_path = Path(__file__).parent.parent / "rules" / "sast_rules.json"
        
        self.rules = self._load_rules(rules_path)

    def _load_rules(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            return []

    def scan(self, target_path):
        target = Path(target_path)
        findings = []

        if not target.exists():
            return {"error": f"Target path '{target_path}' does not exist.", "findings": []}

        files_to_scan = []
        if target.is_file():
            files_to_scan.append(target)
        else:
            for root, dirs, files in os.walk(target):
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
                for file in files:
                    file_path = Path(root) / file
                    if file_path.suffix.lower() in DEFAULT_EXTENSIONS or file.startswith(".env"):
                        files_to_scan.append(file_path)

        for file_path in files_to_scan:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                content = "".join(lines)
                for rule in self.rules:
                    regex = re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE)
                    
                    for line_idx, line in enumerate(lines, start=1):
                        match = regex.search(line)
                        if match:
                            start_context = max(0, line_idx - 2)
                            end_context = min(len(lines), line_idx + 1)
                            snippet = "".join(lines[start_context:end_context]).strip()

                            findings.append({
                                "rule_id": rule["id"],
                                "rule_name": rule["name"],
                                "severity": rule["severity"],
                                "category": rule["category"],
                                "file": str(file_path),
                                "line": line_idx,
                                "matched_line": line.strip(),
                                "snippet": snippet,
                                "description": rule["description"],
                                "remediation": rule["remediation"]
                            })
            except Exception:
                continue

        return {
            "target": str(target.resolve()),
            "files_scanned": len(files_to_scan),
            "findings_count": len(findings),
            "findings": findings
        }
