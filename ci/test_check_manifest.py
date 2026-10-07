"""Negative tests for check_manifest.py: each mutation of the real manifest
or profile must fail the check. Run: python3 -m unittest discover -s ci -p 'test_*.py'"""

import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

import check_manifest

APP = Path(__file__).resolve().parent.parent / "haos_exporter"


class CheckManifestTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.config = yaml.safe_load((APP / "config.yaml").read_text())
        self.profile = (APP / "apparmor.txt").read_text()

    def errors(self):
        (self.dir / "config.yaml").write_text(yaml.safe_dump(self.config))
        (self.dir / "apparmor.txt").write_text(self.profile)
        return check_manifest.check(self.dir)

    def assertFails(self, needle):
        errs = self.errors()
        self.assertTrue(any(needle in e for e in errs), f"no error mentions {needle!r}: {errs}")

    def test_real_manifest_passes(self):
        self.assertEqual(self.errors(), [])

    def test_writable_config_map(self):
        self.config["map"][0]["read_only"] = False
        self.assertFails("map must be exactly")

    def test_second_map_entry(self):
        self.config["map"].append({"type": "ssl", "read_only": True})
        self.assertFails("map must be exactly")

    def test_no_backup_exclude(self):
        del self.config["backup_exclude"]
        self.assertFails("backup_exclude")

    def test_client_auth_on_by_default(self):
        self.config["options"]["tls_client_auth"] = True
        self.assertFails("tls_client_auth")

    def test_config_write_rule(self):
        self.profile = self.profile.replace("/config/client-ca.crt r,", "/config/client-ca.crt rw,")
        self.assertFails("/config rules")

    def test_broader_config_rule(self):
        head, tail = self.profile.rsplit("}", 1)
        self.profile = head + "  /config/** r,\n}" + tail
        self.assertFails("/config rules")

    def test_key_rule_without_owner(self):
        self.profile = self.profile.replace("owner /config/server.key r,", "/config/server.key r,")
        self.assertFails("/config rules")

    def test_unknown_key(self):
        self.config["host_netwrk"] = True
        self.assertFails("ALLOWED_KEYS")

    def test_forbidden_key(self):
        self.config["ingress"] = True
        self.assertFails("must not be set")


if __name__ == "__main__":
    unittest.main()
