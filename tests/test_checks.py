"""Unit tests for APKScope. Run with:  python -m unittest discover tests"""

import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from apkscope_core.checks import risk_score, run_checks  # noqa: E402
from apkscope_core.killswitch import KillSwitch  # noqa: E402
from apkscope_core.loader import LoadError, load_target  # noqa: E402
from apkscope_core.safety import is_within_scope  # noqa: E402

SAMPLES = os.path.join(ROOT, "samples")
VULN = os.path.join(SAMPLES, "AndroidManifest_vulnerable.xml")
SECURE = os.path.join(SAMPLES, "AndroidManifest_secure.xml")


def ids(findings):
    return {f.check_id for f in findings}


class TestVulnerableSample(unittest.TestCase):
    def setUp(self):
        self.manifest = load_target(VULN)
        self.findings, self.completed, self.aborted = run_checks(self.manifest)

    def test_metadata(self):
        self.assertEqual(self.manifest.package, "com.example.vulnnotes")
        self.assertEqual(self.manifest.min_sdk, 16)
        self.assertEqual(self.manifest.target_sdk, 22)

    def test_expected_findings(self):
        for check_id in ("APK-001", "APK-003", "APK-004", "APK-006",
                         "APK-007", "APK-008", "APK-009", "APK-011"):
            self.assertIn(check_id, ids(self.findings))

    def test_launcher_activity_not_flagged(self):
        components = {f.component for f in self.findings}
        self.assertNotIn(".MainActivity", components)
        self.assertNotIn(".SettingsActivity", components)

    def test_implicit_export_detected(self):
        components = {f.component for f in self.findings}
        self.assertIn(".DeepLinkActivity", components)   # intent-filter, no exported attr
        self.assertIn(".NotesProvider", components)      # exported provider, no permission
        self.assertIn(".SmsReceiver", components)

    def test_weak_permission_guard(self):
        sync = [f for f in self.findings if f.component == ".SyncService"]
        self.assertEqual(sync[0].severity, "Low")

    def test_findings_sorted_by_severity(self):
        order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
        values = [order[f.severity] for f in self.findings]
        self.assertEqual(values, sorted(values))

    def test_risk_score(self):
        score, rating = risk_score(self.findings)
        self.assertGreaterEqual(score, 80)
        self.assertEqual(rating, "CRITICAL")


class TestSecureSample(unittest.TestCase):
    def test_no_false_positives(self):
        findings, _, _ = run_checks(load_target(SECURE))
        self.assertEqual(findings, [])
        self.assertEqual(risk_score(findings), (0, "LOW"))


class TestSafety(unittest.TestCase):
    def test_scope(self):
        self.assertTrue(is_within_scope(VULN, SAMPLES))
        self.assertFalse(is_within_scope(VULN, os.path.join(ROOT, "tests")))
        self.assertFalse(is_within_scope(os.path.join(SAMPLES, "..", "apkscope.py"), SAMPLES))

    def test_killswitch_keeps_partial_results(self):
        ks = KillSwitch()
        ks.triggered = True
        findings, completed, aborted = run_checks(load_target(VULN), ks)
        self.assertTrue(aborted)
        self.assertEqual(completed, [])

    def test_bad_inputs(self):
        with self.assertRaises(LoadError):
            load_target(os.path.join(SAMPLES, "does_not_exist.apk"))
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as fh:
            fh.write("<not-a-manifest/>")
        try:
            with self.assertRaises(LoadError):
                load_target(fh.name)
        finally:
            os.remove(fh.name)


if __name__ == "__main__":
    unittest.main()
