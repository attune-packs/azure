import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from actions.lib.security import (
    CLOUDS,
    AzurePackError,
    Profile,
    artifact_path,
    collect_secret_values,
    open_artifact_file,
    redact,
    require_confirmation,
    validate_service_url,
)

SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"
TENANT = "11111111-1111-1111-1111-111111111111"
CLIENT = "22222222-2222-2222-2222-222222222222"


class ProfileTests(unittest.TestCase):
    def test_cloud_endpoints_and_audiences_are_fixed(self):
        profile = Profile.parse(
            json.dumps({"cloud": "usgov", "auth_mode": "managed_identity"})
        )
        self.assertEqual(profile.cloud.graph, "https://graph.microsoft.us")
        self.assertEqual(
            profile.cloud.arm_scope, "https://management.usgovcloudapi.net/.default"
        )
        self.assertEqual(
            profile.cloud.vault_scope, "https://vault.usgovcloudapi.net/.default"
        )
        self.assertEqual(CLOUDS["usdod"].graph, "https://dod-graph.microsoft.us")

    def test_unknown_cloud_and_fields_are_rejected(self):
        with self.assertRaises(AzurePackError):
            Profile.parse({"cloud": "custom", "arm_url": "https://attacker.invalid"})
        with self.assertRaises(AzurePackError):
            Profile.parse({"cloud": "public", "endpoint": "https://attacker.invalid"})

    def test_subscription_tenant_and_client_are_not_interchangeable(self):
        profile = Profile.parse(
            {
                "auth_mode": "service_principal",
                "subscription_id": SUBSCRIPTION,
                "tenant_id": TENANT,
                "client_id": CLIENT,
                "client_secret": "private-value",
            }
        )
        self.assertEqual(profile.require_subscription(), SUBSCRIPTION)
        self.assertEqual(profile.tenant_id, TENANT)
        self.assertEqual(profile.client_id, CLIENT)

    def test_secret_is_only_accepted_for_service_principal(self):
        with self.assertRaises(AzurePackError):
            Profile.parse({"auth_mode": "default", "client_secret": "bad"})


class BoundaryTests(unittest.TestCase):
    def test_graph_continuation_ssrf_is_rejected(self):
        with self.assertRaises(AzurePackError):
            validate_service_url(
                "https://attacker.invalid/v1.0/users", CLOUDS["public"].graph
            )
        with self.assertRaises(AzurePackError):
            validate_service_url(
                "https://graph.microsoft.com/beta/users", CLOUDS["public"].graph
            )
        accepted = validate_service_url(
            "https://graph.microsoft.com/v1.0/users?$skiptoken=safe",
            CLOUDS["public"].graph,
        )
        self.assertIn("$skiptoken", accepted)

    def test_redacts_nested_and_embedded_secrets(self):
        value = {
            "password": "visible",
            "message": "failure for private-value, Bearer abc.def.ghi, and https://x/?sig=signed",
            "nested": [{"accessKey": "visible"}],
            "armOutput": {"type": "SecureString", "value": "secure-output"},
        }
        result = redact(value, ("private-value",))
        self.assertEqual(result["password"], "[REDACTED]")
        self.assertNotIn("private-value", result["message"])
        self.assertNotIn("abc.def.ghi", result["message"])
        self.assertNotIn("signed", result["message"])
        self.assertEqual(result["nested"][0]["accessKey"], "[REDACTED]")
        self.assertEqual(result["armOutput"]["value"], "[REDACTED]")

    def test_collects_secrets_from_flat_json_contracts(self):
        values = collect_secret_values(
            {
                "resource_json": '{"properties":{"adminPassword":"p4ss"}}',
                "safe": "visible",
            }
        )
        self.assertEqual(values, ("p4ss",))

    def test_confirmation_is_exact(self):
        require_confirmation("DELETE graph:user:abc", "DELETE", "graph:user:abc")
        with self.assertRaises(AzurePackError):
            require_confirmation("yes", "DELETE", "graph:user:abc")

    def test_artifact_confinement_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.bin"
            source.write_bytes(b"payload")
            link = root / "link.bin"
            link.symlink_to(source)
            with patch.dict(
                os.environ, {"ATTUNE_ARTIFACT_DIR": directory}, clear=False
            ):
                self.assertEqual(artifact_path("source.bin", for_write=False), source)
                self.assertEqual(
                    artifact_path("new.bin", for_write=True), root / "new.bin"
                )
                with open_artifact_file("source.bin", "rb") as stream:
                    self.assertEqual(stream.read(), b"payload")
                with open_artifact_file("created.bin", "xb") as stream:
                    stream.write(b"new")
                with self.assertRaises(AzurePackError):
                    artifact_path("../escape", for_write=True)
                with self.assertRaises(AzurePackError):
                    artifact_path(str(source), for_write=False)
                with self.assertRaises(AzurePackError):
                    artifact_path("link.bin", for_write=False)
                with self.assertRaises(AzurePackError):
                    open_artifact_file("link.bin", "rb")


if __name__ == "__main__":
    unittest.main()
