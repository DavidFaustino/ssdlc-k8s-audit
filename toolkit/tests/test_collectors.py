import json
import tempfile
import unittest
from pathlib import Path

from auditlib.core import EvidenceStore, load_evidence
from auditlib.aws import AWSCollector
from auditlib.kubernetes import collect_context


class FixtureRunner:
    """Fronteira externa controlada: nenhuma chamada real de AWS/Kubernetes."""
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def aws(self, service, operation, args, region, profile):
        self.calls.append((service, operation, args, region, profile))
        value = self.responses.get(service + "." + operation, {})
        if callable(value):
            value = value(args)
        if isinstance(value, str):
            return {"status": "error", "complete": False, "data": None, "error": value}
        return {"status": "ok", "complete": True, "data": value, "error": None}

    def kubernetes(self, context, resource, namespace=None):
        self.calls.append((context, resource, namespace))
        return {"status": "ok", "complete": True, "data": self.responses.get(resource, {"items": []}), "error": None}


class CollectorTests(unittest.TestCase):
    def test_ecr_uses_describe_registry_for_replication(self):
        f = FixtureRunner({"ecr.describe-registry": {"registryId": "123456789012", "replicationConfiguration": {"rules": []}}})
        with tempfile.TemporaryDirectory() as tmp:
            s = self.setup_store(tmp)
            AWSCollector(f, s, "corp", "123456789012", "eu-west-1", 100).ecr()
            records = load_evidence(s.root)
            self.assertTrue(any(r["operation"] == "ecr.describe-registry" and "replicationConfiguration" in r["data"] for r in records))

    def test_lambda_alias_url_and_policy_are_collected(self):
        f = FixtureRunner({"lambda.list-functions": {"Functions": [{"FunctionName": "api"}]},
                           "lambda.list-aliases": {"Aliases": [{"Name": "prod"}]},
                           "lambda.get-function-url-config": {"AuthType": "NONE"}})
        with tempfile.TemporaryDirectory() as tmp:
            s = self.setup_store(tmp)
            AWSCollector(f, s, "corp", "123456789012", "eu-west-1", 100).lambda_()
            calls = [c for c in f.calls if c[1] in {"get-function-url-config", "get-policy"} and "--qualifier" in c[2]]
            self.assertEqual(len(calls), 2)
            self.assertTrue(any(r["resource"] == "api:prod" for r in load_evidence(s.root)))

    def setup_store(self, tmp):
        return EvidenceStore(Path(tmp) / "run", {"test": True})

    def test_eks_details_include_access_and_each_nodegroup(self):
        f = FixtureRunner({"eks.list-clusters": {"clusters": ["prod"]},
                           "eks.list-nodegroups": {"nodegroups": ["workers"]},
                           "eks.list-access-entries": {"accessEntries": ["arn:aws:iam::123456789012:role/team"]}})
        with tempfile.TemporaryDirectory() as tmp:
            s = self.setup_store(tmp)
            AWSCollector(f, s, "corp", "123456789012", "eu-west-1", 100).eks()
            ops = [c[1] for c in f.calls]
            self.assertIn("describe-nodegroup", ops)
            self.assertIn("list-associated-access-policies", ops)
            self.assertIn("describe-cluster", ops)

    def test_detail_limit_is_explicit_partial_not_silent(self):
        f = FixtureRunner({"eks.list-clusters": {"clusters": ["a", "b"]}})
        with tempfile.TemporaryDirectory() as tmp:
            s = self.setup_store(tmp)
            AWSCollector(f, s, "corp", "123456789012", "eu-west-1", 1).eks()
            limits = [x for x in load_evidence(s.root) if x["error"] == "DetailLimit"]
            self.assertTrue(limits)
            self.assertEqual(limits[0]["data"]["omitted"], 1)

    def test_ecs_resolves_running_task_definition(self):
        f = FixtureRunner({"ecs.list-clusters": {"clusterArns": ["arn:cluster/c"]},
                           "ecs.list-tasks": {"taskArns": ["arn:task/t"]},
                           "ecs.describe-tasks": {"tasks": [{"taskArn": "arn:task/t", "taskDefinitionArn": "arn:td/api:2"}]}})
        with tempfile.TemporaryDirectory() as tmp:
            AWSCollector(f, self.setup_store(tmp), "corp", "123456789012", "eu-west-1", 100).ecs()
        calls = [c for c in f.calls if c[1] == "describe-task-definition"]
        self.assertEqual(calls[0][2], ["--task-definition", "arn:td/api:2"])

    def test_lambda_exports_identity_but_no_environment(self):
        f = FixtureRunner({"lambda.list-functions": {"Functions": [{"FunctionName": "api", "CodeSha256": "abc",
                         "Environment": {"Variables": {"TOKEN": "SENSITIVE"}}}]}})
        with tempfile.TemporaryDirectory() as tmp:
            s = self.setup_store(tmp)
            AWSCollector(f, s, "corp", "123456789012", "eu-west-1", 100).lambda_()
            output = json.dumps(load_evidence(s.root))
            self.assertIn("abc", output)
            self.assertNotIn("SENSITIVE", output)
            self.assertIn("list-aliases", [c[1] for c in f.calls])

    def test_kubernetes_context_is_bound_and_secrets_are_not_requested(self):
        f = FixtureRunner({"pods": {"items": [{"metadata": {"name": "api"}, "spec": {"containers": [{"env": [{"name": "PASS", "value": "SENSITIVE"}]}]}}]}})
        with tempfile.TemporaryDirectory() as tmp:
            s = self.setup_store(tmp)
            collect_context(f, s, "corp-prod", namespace="payments", account="123456789012", region="eu-west-1")
            self.assertNotIn("SENSITIVE", json.dumps(load_evidence(s.root)))
        self.assertTrue(all(c[0] == "corp-prod" for c in f.calls))
        self.assertNotIn("secrets", [c[1] for c in f.calls])
        self.assertNotIn("configmaps", [c[1] for c in f.calls])

    def test_failure_does_not_generate_resource_absence(self):
        f = FixtureRunner({"eks.list-clusters": "AccessDenied"})
        with tempfile.TemporaryDirectory() as tmp:
            s = self.setup_store(tmp)
            AWSCollector(f, s, "corp", "123456789012", "eu-west-1", 100).eks()
            self.assertEqual(len(f.calls), 1)
            self.assertEqual(load_evidence(s.root)[0]["status"], "error")


if __name__ == "__main__":
    unittest.main()
