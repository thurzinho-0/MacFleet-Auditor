"""
Testes unitários dos parsers e do motor de conformidade (rodam em qualquer SO).
    python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config  # noqa: E402
from collectors import security, system  # noqa: E402
from engine import compliance  # noqa: E402

SWU_MODERN = """Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: macOS Sequoia 15.6.1-24G90
\tTitle: macOS Sequoia 15.6.1, Version: 15.6.1, Size: 1650221KiB, Recommended: YES, Action: restart,
* Label: Command Line Tools for Xcode-16.4
\tTitle: Command Line Tools for Xcode, Version: 16.4, Size: 751000KiB, Recommended: YES,
"""


class TestSecurityParsers(unittest.TestCase):
    def test_filevault(self):
        self.assertEqual(security.parse_filevault_status("FileVault is On.")["state"], "on")
        self.assertFalse(security.parse_filevault_status("FileVault is Off.")["enabled"])
        enc = security.parse_filevault_status("Encryption in progress: Percent completed = 42.3")
        self.assertEqual((enc["state"], enc["progress_percent"]), ("encrypting", 42.3))
        self.assertTrue(security.parse_filevault_status(
            "FileVault is Off, but will be enabled after the next restart.")["deferred_enablement_pending"])

    def test_firewall(self):
        self.assertEqual(security.parse_firewall_globalstate("Firewall is enabled. (State = 1)"), 1)
        self.assertEqual(security.parse_firewall_globalstate("Firewall is disabled. (State = 0)"), 0)
        self.assertTrue(security.parse_on_off("Firewall stealth mode is on"))
        self.assertFalse(security.parse_on_off("Stealth mode disabled"))

    def test_gatekeeper_sip(self):
        self.assertTrue(security.parse_gatekeeper("assessments enabled"))
        self.assertFalse(security.parse_gatekeeper("assessments disabled"))
        self.assertEqual(security.parse_sip_status(
            "System Integrity Protection status: enabled.")["state"], "enabled")
        self.assertEqual(security.parse_sip_status(
            "System Integrity Protection status: unknown (Custom Configuration).")["state"], "custom")

    def test_softwareupdate(self):
        updates = security.parse_softwareupdate_list(SWU_MODERN)
        self.assertEqual(len(updates), 2)
        self.assertEqual(updates[0]["title"], "macOS Sequoia 15.6.1")
        self.assertTrue(updates[0]["restart_required"])
        summary = security._summarize_updates(updates, config.SECURITY_UPDATE_KEYWORDS)
        self.assertEqual((summary["pending_total"], summary["pending_security"]), (2, 1))

    def test_softwareupdate_legacy(self):
        out = "   * Safari12.1-12.1\n\tSafari (12.1), 63000K [recommended]\n"
        updates = security.parse_softwareupdate_list(out)
        self.assertEqual(len(updates), 1)
        self.assertTrue(updates[0]["recommended"])


class TestSystemParsers(unittest.TestCase):
    def test_sw_vers(self):
        data = system.parse_sw_vers("ProductName:\tmacOS\nProductVersion:\t15.6.1\nBuildVersion:\t24G90\n")
        self.assertEqual(data["product_version"], "15.6.1")

    def test_hardware_json(self):
        hw = system.parse_hardware_json('{"SPHardwareDataType":[{"serial_number":"ABC123","chip_type":"Apple M2"}]}')
        self.assertEqual((hw["serial_number"], hw["chip"]), ("ABC123", "Apple M2"))

    def test_boottime(self):
        self.assertEqual(system.parse_boottime("{ sec = 1729500000, usec = 1 } Mon Oct 21"), 1729500000)


class TestComplianceEngine(unittest.TestCase):
    def _data(self, free_percent=40.0, fv="on", pending=0):
        ok = {"collection_status": "ok"}
        return {
            "security": {
                "filevault": dict(ok, state=fv, enabled=fv == "on"),
                "firewall": dict(ok, enabled=True, stealth_mode=True),
                "gatekeeper": dict(ok, enabled=True),
                "sip": dict(ok, state="enabled", enabled=True),
                "software_updates": dict(ok, pending_total=pending, pending_security=pending),
            },
            "system": {
                "storage": dict(ok, free_percent=free_percent),
                "os": dict(ok, product_version="26.0"),
                "user": dict(ok, is_admin=False),
            },
        }

    def _status(self, evaluation, rule_id):
        return next(r["status"] for r in evaluation["results"] if r["id"] == rule_id)

    def test_all_pass(self):
        ev = compliance.evaluate(self._data(), config.POLICY)
        self.assertEqual(ev["summary"]["overall_status"], "COMPLIANT")

    def test_disk_thresholds(self):
        self.assertEqual(self._status(compliance.evaluate(self._data(15.0), config.POLICY), "OPS-001"), "WARNING")
        self.assertEqual(self._status(compliance.evaluate(self._data(9.0), config.POLICY), "OPS-001"), "FAIL")

    def test_filevault_fail_and_updates(self):
        ev = compliance.evaluate(self._data(fv="off", pending=2), config.POLICY)
        self.assertEqual(self._status(ev, "SEC-001"), "FAIL")
        self.assertEqual(self._status(ev, "SEC-006"), "FAIL")
        self.assertEqual(self._status(ev, "SEC-007"), "WARNING")
        self.assertIn("SEC-001", ev["summary"]["critical_failures"])

    def test_skipped_and_error(self):
        data = self._data()
        data["security"]["software_updates"] = {"collection_status": "skipped", "reason": "skip"}
        data["security"]["gatekeeper"] = {"collection_status": "error", "error": "boom", "enabled": None}
        ev = compliance.evaluate(data, config.POLICY)
        self.assertEqual(self._status(ev, "SEC-006"), "SKIPPED")
        self.assertEqual(self._status(ev, "SEC-004"), "WARNING")

    def test_version_compare(self):
        self.assertEqual(compliance.compare_versions("14.6.1", "15.0"), -1)
        self.assertEqual(compliance.compare_versions("26.0", "15.0"), 1)


class TestHtmlReporter(unittest.TestCase):
    def test_script_injection_is_escaped(self):
        from reporters import html_reporter
        report = {"compliance_results": [], "metadata": {"hostname": "</script><script>alert(1)</script><!--"}}
        html = html_reporter.render_dashboard(report)
        data = html.split('<script id="report-data" type="application/json">', 1)[1].split("</script>", 1)[0]
        self.assertNotIn("<script>", data)
        import json
        self.assertEqual(json.loads(data)["metadata"]["hostname"], "</script><script>alert(1)</script><!--")


if __name__ == "__main__":
    unittest.main()
