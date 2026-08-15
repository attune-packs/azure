import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ContractTests(unittest.TestCase):
    def test_all_actions_are_fully_qualified_and_share_hardened_entrypoint(self):
        contracts = sorted((ROOT / "actions").glob("*.yaml"))
        self.assertEqual(len(contracts), 60)
        for contract in contracts:
            text = contract.read_text(encoding="ascii")
            self.assertIn(f"ref: azure.{contract.stem}\n", text)
            self.assertIn("entry_point: azure_action.py\n", text)
            self.assertIn("  profile:\n", text)
            self.assertIn("    secret: true\n", text)

    def test_destructive_contracts_require_confirmation(self):
        destructive = [
            path
            for path in (ROOT / "actions").glob("*.yaml")
            if path.stem.endswith("_delete")
            or path.stem
            in {
                "deployment_create_or_update",
                "graph_memberships_add",
                "graph_memberships_remove",
            }
        ]
        self.assertGreater(len(destructive), 10)
        for contract in destructive:
            text = contract.read_text(encoding="ascii")
            self.assertRegex(
                text, r"(?m)^  confirmation:\n(?:    .+\n)*    required: true$"
            )
        blob_upload = (ROOT / "actions/blob_upload.yaml").read_text(encoding="ascii")
        self.assertIn("  confirmation:\n", blob_upload)
        self.assertIn("  if_match:\n", blob_upload)

    def test_no_retired_packages_or_stale_actions(self):
        requirements = (ROOT / "requirements.txt").read_text(encoding="ascii").lower()
        for retired in (
            "azurerm",
            "libcloud",
            "azure-graphrbac",
            "azure-mgmt==",
            "azure<",
        ):
            self.assertNotIn(retired, requirements)
        names = {path.name for path in (ROOT / "actions").glob("*.yaml")}
        self.assertNotIn("detroy_vm.yaml", names)
        self.assertNotIn("destroy_vm.yaml", names)

    def test_source_metadata_is_exact(self):
        metadata = json.loads(
            (ROOT / "SOURCE_METADATA.json").read_text(encoding="ascii")
        )
        source = metadata["attributed_requirements_source"]
        self.assertEqual(source["revision"], "9746497e88b18f66a5084094f246e20ebcc30723")
        self.assertEqual(source["license"], "Apache-2.0")
        self.assertRegex(source["tree"], re.compile(r"^[0-9a-f]{40}$"))


if __name__ == "__main__":
    unittest.main()
