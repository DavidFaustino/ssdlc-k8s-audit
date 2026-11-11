import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from auditlib.core import EvidenceStore, Runner, load_evidence, sanitize


class CoreTests(unittest.TestCase):
    def test_tool_version_records_only_version_not_arbitrary_output(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "aws-cli/2.39.1 Python/3.13\n", "")):
            self.assertEqual(Runner().version("aws"), "aws-cli/2.39.1")
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            self.assertEqual(Runner().version("aws"), "indisponivel")

    def test_arbitrary_header_storage_and_docker_label_values_are_omitted(self):
        raw = {"spec": {"containers": [{"livenessProbe": {"httpGet": {"httpHeaders": [{"name": "Authorization", "value": "SENSITIVE"}]}}, "lifecycle": {"postStart": {"httpGet": {"httpHeaders": [{"name": "x", "value": "SENSITIVE"}]}}}}],
                        "csi": {"driver": "efs.csi.aws.com", "volumeAttributes": {"token": "SENSITIVE"}}, "flexVolume": {"options": {"key": "SENSITIVE"}}},
               "parameters": {"key": "SENSITIVE"}, "containerDefinitions": [{"dockerLabels": {"key": "SENSITIVE"}}]}
        safe = sanitize(raw)
        self.assertNotIn("SENSITIVE", json.dumps(safe))
        self.assertEqual(safe["spec"]["csi"]["driver"], "efs.csi.aws.com")

    def test_inconsistent_status_metadata_is_rejected(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(Path(tmp) / "run", {})
            item = store.record("aws", "eks.list-clusters", "eu-west-1", "123456789012", "*",
                                {"status": "ok", "complete": True, "data": {"clusters": []}, "error": None})
            p = store.root / item["file"]
            raw = json.loads(p.read_text())
            raw["metadata"]["complete"] = False
            p.write_text(json.dumps(raw))
            m = json.loads((store.root / "manifest.json").read_text())
            m["records"][0]["complete"] = False
            m["records"][0]["sha256"] = hashlib.sha256(p.read_bytes()).hexdigest()
            (store.root / "manifest.json").write_text(json.dumps(m))
            with self.assertRaisesRegex(ValueError, "coerência"):
                load_evidence(store.root)

    def test_sensitive_values_never_exported_but_references_survive(self):
        raw = {"Environment": {"Variables": {"TOKEN": "SENSITIVE"}},
               "UserData": "SENSITIVE", "metadata": {"name": "api", "annotations": {"x": "SENSITIVE"}},
               "containers": [{"name": "app", "command": ["SENSITIVE"],
                               "env": [{"name": "PASSWORD", "value": "SENSITIVE"},
                                       {"name": "DB", "valueFrom": {"secretKeyRef": {"name": "db", "key": "pass"}}}]}]}
        safe = sanitize(raw)
        self.assertNotIn("SENSITIVE", json.dumps(safe))
        self.assertEqual(safe["containers"][0]["env"][1]["valueFrom"]["secretKeyRef"]["name"], "db")

    def test_runner_rejects_mutations_before_process(self):
        with patch("subprocess.run") as proc:
            with self.assertRaises(ValueError):
                Runner().aws("eks", "delete-cluster", ["--name", "x"], "eu-west-1", "corp")
            proc.assert_not_called()

    def test_access_denied_is_error_not_empty_inventory(self):
        p = subprocess.CompletedProcess([], 254, "", "An error occurred (AccessDeniedException): secret details")
        with patch("subprocess.run", return_value=p):
            r = Runner().aws("eks", "list-clusters", [], "eu-west-1", "corp")
        self.assertEqual(r["status"], "error")
        self.assertEqual(r["error"], "AccessDeniedException")
        self.assertNotIn("secret details", json.dumps(r))
        self.assertIsNone(r["data"])

    def test_pagination_token_marks_incomplete(self):
        p = subprocess.CompletedProcess([], 0, '{"clusters":["a"],"NextToken":"opaque"}', "")
        with patch("subprocess.run", return_value=p) as proc:
            r = Runner().aws("eks", "list-clusters", [], "eu-west-1", "corp")
        self.assertEqual(r["status"], "partial")
        self.assertFalse(r["complete"])
        self.assertNotIn("--no-paginate", proc.call_args.args[0])
        self.assertFalse(proc.call_args.kwargs.get("shell", False))

    def test_timeout_and_missing_cli_are_recorded(self):
        for exc, code in [(subprocess.TimeoutExpired("aws", 1), "Timeout"), (FileNotFoundError(), "ExecutableNotFound")]:
            with self.subTest(code=code), patch("subprocess.run", side_effect=exc):
                r = Runner().aws("eks", "list-clusters", [], "eu-west-1", "corp")
                self.assertEqual(r["error"], code)
                self.assertFalse(r["complete"])

    def test_malformed_json_is_not_a_success(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, 'not json', "")):
            self.assertEqual(Runner().aws("eks", "list-clusters", [], "eu-west-1", "corp")["error"], "InvalidJSON")

    def test_aws_cli_execution_disables_interactive_prompt(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, '{}', "")) as proc:
            Runner().aws("eks", "list-clusters", [], "eu-west-1", "corp")
        self.assertEqual(proc.call_args.kwargs["env"]["AWS_CLI_AUTO_PROMPT"], "off")

    def test_evidence_hash_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(Path(tmp) / "run", {"regions": ["eu-west-1"]})
            item = store.record("aws", "eks.list-clusters", "eu-west-1", "123456789012", "*",
                                {"status": "ok", "complete": True, "data": {"clusters": ["a"]}, "error": None})
            records = load_evidence(store.root)
            self.assertEqual(records[0]["data"]["clusters"], ["a"])
            (store.root / item["file"]).write_text('{}')
            with self.assertRaisesRegex(ValueError, "integridade"):
                load_evidence(store.root)

    def test_evidence_directory_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "run"
            EvidenceStore(p, {})
            with self.assertRaises(FileExistsError):
                EvidenceStore(p, {})

    def test_manifest_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = EvidenceStore(Path(tmp) / "run", {})
            s.record("aws", "eks.list-clusters", "x", "123456789012", "*",
                     {"status": "ok", "complete": True, "data": {}, "error": None})
            m = json.loads((s.root / "manifest.json").read_text())
            m["records"][0]["file"] = "../other.json"
            (s.root / "manifest.json").write_text(json.dumps(m))
            with self.assertRaises(ValueError):
                load_evidence(s.root)


if __name__ == "__main__":
    unittest.main()
