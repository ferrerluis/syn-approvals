#!/usr/bin/env python3

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


TOOL = Path(__file__).resolve().parents[1] / "e2e-resource-manifest.py"
SPEC = importlib.util.spec_from_file_location("e2e_resource_manifest", TOOL)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


RUN_ID = "syn-e2e-20260912t120000z-abcd"


def valid_manifest(root):
    source = root / f"{RUN_ID}.source"
    source.mkdir(exist_ok=True)
    nonce = "0123456789abcdef"
    marker = source / MODULE.OWNER_MARKER
    marker.write_text(json.dumps({
        "schema_version": 1,
        "run_id": RUN_ID,
        "resource_type": "source_directory",
        "path": str(source),
        "creation_nonce": nonce,
    }))
    marker.chmod(0o600)
    token = MODULE.run_token(RUN_ID)
    return {
        "schema_version": 1,
        "run_id": RUN_ID,
        "host": "pi",
        "resources": [
            {
                "type": "source_directory",
                "path": str(source),
                "content_digest": "a" * 64,
                "creation_nonce": nonce,
            },
            {
                "type": "test_approval_profile",
                "profile_id": RUN_ID,
                "approval_public_key_id": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "denial_public_key_id": "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "scenario_payload_hash": "b" * 64,
                "request_id": "request_0123456789",
                "nonce": "nonce_01234567890",
                "request_context_digest": "c" * 64,
            },
            {"type": "linux_test_account", "name": f"syn-e2e-{token}-pam"},
            {"type": "linux_test_unit", "name": f"syn-e2e-{token}-recovery.timer"},
        ],
    }


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.original_temp_root = MODULE.TEMP_ROOT
        MODULE.TEMP_ROOT = self.root

    def tearDown(self):
        MODULE.TEMP_ROOT = self.original_temp_root
        self.directory.cleanup()

    def test_valid_manifest_has_fixed_safe_cleanup_order(self):
        result = MODULE.validate_manifest(valid_manifest(self.root))
        self.assertTrue(result["dry_run"])
        self.assertEqual(
            [item["resource"] for item in result["cleanup_plan"]],
            ["linux_test_unit", "test_approval_profile", "linux_test_account", "source_directory"],
        )
        self.assertNotIn("command", str(result))

    def test_source_path_must_be_one_exact_known_shape(self):
        for path in ("/", str(self.root), str(self.root / "*"),
                     str(self.root / "../foreign"), str(self.root / "other.x")):
            manifest = valid_manifest(self.root)
            manifest["resources"][0]["path"] = path
            with self.assertRaises(MODULE.ManifestError):
                MODULE.validate_manifest(manifest)

    def test_manifest_cannot_supply_cleanup_or_create_actions(self):
        for field in ("cleanup", "cleanup_action", "create_action", "command"):
            manifest = valid_manifest(self.root)
            manifest["resources"][0][field] = "anything"
            with self.assertRaises(MODULE.ManifestError):
                MODULE.validate_manifest(manifest)

    def test_profile_binds_exact_request_and_distinct_public_keys(self):
        for field in ("scenario_payload_hash", "request_id", "nonce", "request_context_digest"):
            manifest = valid_manifest(self.root)
            del manifest["resources"][1][field]
            with self.assertRaises(MODULE.ManifestError):
                MODULE.validate_manifest(manifest)
        manifest = valid_manifest(self.root)
        manifest["resources"][1]["denial_public_key_id"] = \
            manifest["resources"][1]["approval_public_key_id"]
        with self.assertRaises(MODULE.ManifestError):
            MODULE.validate_manifest(manifest)

    def test_rejects_broad_or_production_resource_names(self):
        manifest = valid_manifest(self.root)
        manifest["resources"][2]["name"] = "root"
        with self.assertRaises(MODULE.ManifestError):
            MODULE.validate_manifest(manifest)
        manifest = valid_manifest(self.root)
        manifest["resources"][3]["name"] = "syn-agent.service"
        with self.assertRaises(MODULE.ManifestError):
            MODULE.validate_manifest(manifest)

    def test_rejects_duplicates_and_unknown_types(self):
        manifest = valid_manifest(self.root)
        manifest["resources"].append(dict(manifest["resources"][0]))
        with self.assertRaises(MODULE.ManifestError):
            MODULE.validate_manifest(manifest)
        manifest = valid_manifest(self.root)
        manifest["resources"][0] = {"type": "package", "name": "anything"}
        with self.assertRaises(MODULE.ManifestError):
            MODULE.validate_manifest(manifest)

    def test_rejects_symlinked_source_and_marker(self):
        manifest = valid_manifest(self.root)
        source = Path(manifest["resources"][0]["path"])
        real_source = self.root / "real-source"
        source.rename(real_source)
        source.symlink_to(real_source, target_is_directory=True)
        with self.assertRaises(MODULE.ManifestError):
            MODULE.validate_manifest(manifest)

        source.unlink()
        real_source.rename(source)
        marker = source / MODULE.OWNER_MARKER
        marker.unlink()
        foreign_marker = self.root / "foreign-marker"
        foreign_marker.write_text("{}")
        marker.symlink_to(foreign_marker)
        with self.assertRaises(MODULE.ManifestError):
            MODULE.validate_manifest(manifest)

    def test_rejects_foreign_run_names_and_ownership_marker(self):
        manifest = valid_manifest(self.root)
        manifest["resources"][1]["profile_id"] = "syn-e2e-20260912t120000z-foreign"
        with self.assertRaises(MODULE.ManifestError):
            MODULE.validate_manifest(manifest)

        manifest = valid_manifest(self.root)
        manifest["resources"][2]["name"] = "syn-e2e-aaaaaaaaaaaa-pam"
        with self.assertRaises(MODULE.ManifestError):
            MODULE.validate_manifest(manifest)

        manifest = valid_manifest(self.root)
        marker = Path(manifest["resources"][0]["path"]) / MODULE.OWNER_MARKER
        value = json.loads(marker.read_text())
        value["run_id"] = "syn-e2e-20260912t120000z-foreign"
        marker.write_text(json.dumps(value))
        marker.chmod(0o600)
        with self.assertRaises(MODULE.ManifestError):
            MODULE.validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
