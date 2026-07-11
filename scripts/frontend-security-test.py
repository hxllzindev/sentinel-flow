#!/usr/bin/env python3
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "src" / "SentinelFlow.Api" / "wwwroot"


class FrontendSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (FRONTEND / "index.html").read_text(encoding="utf-8")
        cls.script = (FRONTEND / "app.js").read_text(encoding="utf-8")
        cls.all_text = cls.html + "\n" + cls.script

    def test_no_free_text_ingest_or_governance_forms(self):
        for value in ["ingest-report", "exception-reason", "exception-control", "role-select", "ingest-dialog", "exception-dialog", "request-exception-button"]:
            self.assertNotIn(value, self.all_text)

    def test_no_html_sinks_or_persistent_storage(self):
        for value in ["innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "localStorage", "sessionStorage"]:
            self.assertNotIn(value, self.script)

    def test_no_raw_repository_finding_or_exception_fields(self):
        for value in ["run.branch", "run.commit", "run.author", "run.project.name", "finding.title", "finding.location", "finding.owner", "exception.reason", "exception.compensatingControl", "exception.requestedBy", "exception.approvedBy"]:
            self.assertNotIn(value, self.script)

    def test_frontend_performs_read_only_requests(self):
        self.assertNotRegex(self.script, r'method:\s*["\'](?:POST|PUT|PATCH|DELETE)')
        self.assertNotIn("X-Demo-Role", self.script)

    def test_common_secret_patterns_are_absent(self):
        patterns = [r"AKIA[0-9A-Z]{16}", r"AIza[0-9A-Za-z_-]{30,}", r"sk-[A-Za-z0-9_-]{20,}", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"]
        for pattern in patterns:
            self.assertIsNone(re.search(pattern, self.all_text))


if __name__ == "__main__":
    unittest.main()
