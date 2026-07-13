from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    """Load a Python module from a repository path for unittest coverage."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ClassificationTests(unittest.TestCase):
    """Exercise malware type and campaign classification paths."""

    @classmethod
    def setUpClass(cls):
        """Load classifier and ValleyRAT detector modules once for the test class."""
        cls.classify_sample = load_module("classify_sample", ROOT / "classifiers" / "classify_sample.py")
        cls.valleyrat = load_module("valleyrat_detect", ROOT / "malware" / "valleyrat" / "detect.py")

    def make_zip(self, members: dict[str, bytes]) -> bytes:
        """Create an in-memory ZIP archive from member names and bytes."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        return buffer.getvalue()

    def test_valleyrat_vvas_bundle_detection(self):
        """Detect the DLL side-loading vvaS bundle campaign from structure."""
        data = self.make_zip({"chgport.exe": b"MZhost", "LoggerCollector.dll": b"MZdll", "vvaS.bin": b"shell"})
        result = self.valleyrat.detect(data, Path("sample.zip"))
        self.assertTrue(result["matched"])
        self.assertEqual(result["campaigns"][0]["campaign_type"], "dll_sideload_vvas_bundle")

    def test_unknown_non_zip(self):
        """Return an unknown low-confidence result when no detector matches."""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.bin"
            out = Path(tmp) / "out.json"
            sample.write_bytes(b"not a zip")
            result = self.classify_sample.classify(sample, ROOT / "registry" / "malware_types.json")
            self.assertEqual(result["malware_type"], "unknown")
            self.assertEqual(result["campaign_type"], "unknown")
            self.assertFalse(out.exists())

    def test_explicit_malware_type_unmatched(self):
        """Record an explicit malware type without inventing a campaign match."""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.bin"
            sample.write_bytes(b"not a zip")
            result = self.classify_sample.classify(sample, ROOT / "registry" / "malware_types.json", "valleyrat")
            self.assertEqual(result["malware_type"], "valleyrat")
            self.assertEqual(result["campaign_type"], "unknown")
            self.assertEqual(result["attribution_basis"], "explicit_user_type_unmatched")


class VirusTotalSandboxTests(unittest.TestCase):
    """Exercise VirusTotal sandbox normalization without network access."""

    @classmethod
    def setUpClass(cls):
        """Load the VirusTotal sandbox module once for the test class."""
        cls.vt = load_module("vt_sandbox", ROOT / "common" / "vt_sandbox.py")

    def test_extract_relationship_items_filters_non_dicts(self):
        """Keep only dictionary relationship entries from a VT payload."""
        self.assertEqual(self.vt.extract_relationship_items({"data": [{"id": "a"}, "bad"]}), [{"id": "a"}])

    def test_summarize_behaviour_reports(self):
        """Summarize sandbox processes, verdicts, domains, and IPs."""
        summary = self.vt.summarize_behaviour_reports([
            {"id": "r1", "attributes": {"sandbox_name": "box", "verdict": "malicious", "contacted_domains": ["Example.COM"], "ip_traffic": [{"destination_ip": "1.2.3.4"}], "processes_tree": [{"name": "host.exe"}]}}
        ])
        self.assertEqual(summary["sandbox_count"], 1)
        self.assertEqual(summary["contacted_domains"], ["example.com"])
        self.assertEqual(summary["contacted_ips"], ["1.2.3.4"])
        self.assertIn("host.exe", summary["process_names"])

    def test_fetch_file_behaviours_uses_vt_get(self):
        """Fetch behavior data through a stubbed VT API call."""
        original = self.vt.vt_get
        try:
            self.vt.vt_get = lambda path, api_key, api_root, timeout: {"data": [{"id": "r1", "attributes": {"verdict": "clean"}}]}
            result = self.vt.fetch_file_behaviours("a" * 64, "key")
            self.assertEqual(result["summary"]["verdicts"], ["clean"])
        finally:
            self.vt.vt_get = original


if __name__ == "__main__":
    unittest.main()
