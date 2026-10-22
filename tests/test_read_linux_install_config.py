import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "read-linux-install-config.py"


def sample_config():
    return {
        "schema_version": 1,
        "package_dir": "/srv/releases/helicoid",
        "verify_key": "a" * 64,
        "deployment_kind": "linux_systemd",
        "network": {
            "scope": "lan",
            "bind_address": "192.168.1.10",
            "client_hostname": "server.school.lan",
            "authority_port": 8920,
        },
        "storage": {
            "data_directory": "/var/lib/helicoid/data/school-a",
            "backup_directory": "/var/backups/helicoid/school-a",
        },
    }


class InstallerConfigTests(unittest.TestCase):
    def run_config(self, content):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "install.json"
            config_path.write_text(content, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(SCRIPT), str(config_path)],
                capture_output=True,
                check=False,
            )

    def test_emits_fixed_nul_delimited_fields(self):
        result = self.run_config(json.dumps(sample_config()))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(
            result.stdout.split(b"\0"),
            [
                b"/srv/releases/helicoid",
                b"a" * 64,
                b"linux_systemd",
                b"lan",
                b"192.168.1.10",
                b"server.school.lan",
                b"8920",
                b"/var/lib/helicoid/data/school-a",
                b"/var/backups/helicoid/school-a",
                b"",
            ],
        )

    def test_rejects_duplicate_keys_and_unknown_fields(self):
        duplicate = json.dumps(sample_config()).replace(
            '"schema_version": 1,', '"schema_version": 1, "schema_version": 1,'
        )
        result = self.run_config(duplicate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"duplicate JSON key", result.stderr)

        config = sample_config()
        config["unexpected"] = "value"
        result = self.run_config(json.dumps(config))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"exactly", result.stderr)

    def test_rejects_reserved_development_port_in_lan_mode(self):
        config = sample_config()
        config["network"]["authority_port"] = 8787
        result = self.run_config(json.dumps(config))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"LAN requires", result.stderr)

    def test_preserves_empty_loopback_address_fields(self):
        config = sample_config()
        config["network"] = {
            "scope": "loopback_development",
            "bind_address": "",
            "client_hostname": "",
            "authority_port": 8787,
        }
        result = self.run_config(json.dumps(config))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        fields = result.stdout.split(b"\0")
        self.assertEqual(fields[3:7], [b"loopback_development", b"", b"", b"8787"])


if __name__ == "__main__":
    unittest.main()
