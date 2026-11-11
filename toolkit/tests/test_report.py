import json
import tempfile
import unittest
from pathlib import Path

from auditlib.core import EvidenceStore
from auditlib.controls import CONTROL_CATALOG, analyze, generate_report


def record(operation, data, status="ok"):
    return {"id": "EV-000001", "operation": operation, "source": "kubernetes" if operation.startswith("kubernetes.") else "aws", "data": data, "status": status,
            "complete": status == "ok", "account": "123456789012", "region": "eu-west-1", "resource": "prod",
            "directory": "/fixture", "file": "evidence/EV-000001.json", "collected_at": "2026-11-10T20:00:00+00:00", "error": None}


class ReportTests(unittest.TestCase):
    def test_ecs_linux_default_readonly_is_false_but_windows_not_evaluated_as_linux(self):
        linux = record("ecs.describe-task-definition", {"taskDefinition": {"containerDefinitions": [{"name": "api"}]}})
        _, obs = analyze([linux])
        self.assertTrue(any(o["check"] == "ECS_READONLY" and o["status"] == "DESVIO_OBSERVADO" for o in obs))
        windows = record("ecs.describe-task-definition", {"taskDefinition": {"runtimePlatform": {"operatingSystemFamily": "WINDOWS_SERVER_2022_CORE"}, "containerDefinitions": [{"name": "api"}]}})
        _, obs = analyze([windows])
        self.assertFalse(any(o["check"] == "ECS_READONLY" for o in obs))

    def test_partial_or_wrong_source_cannot_generate_verified_observation(self):
        r = record("ec2.describe-volumes", {"Volumes": [{"VolumeId": "vol-x", "Encrypted": True}]})
        r.update(source="manual", complete=False, error="PaginationIncomplete")
        _, obs = analyze([r])
        self.assertEqual(obs, [])

    def test_twenty_one_controls_exist_and_empty_input_is_not_compliance(self):
        self.assertEqual(len(CONTROL_CATALOG), 21)
        controls, observations = analyze([])
        self.assertEqual(len(controls), 21)
        self.assertTrue(all(c["status"] == "NAO_VERIFICADO" for c in controls))
        self.assertEqual(observations, [])

    def test_enabled_audit_logging_is_observation_not_entire_control_approval(self):
        c, o = analyze([record("eks.describe-cluster", {"cluster": {"name": "prod", "logging": {"clusterLogging": [{"types": ["audit"], "enabled": True}]}}})])
        self.assertTrue(any(x["check"] == "EKS_AUDIT" and x["status"] == "VERIFICADO" for x in o))
        self.assertEqual(next(x for x in c if x["id"] == "CT-05")["status"], "NAO_VERIFICADO")

    def test_disabled_audit_logging_and_privileged_container_have_actions(self):
        records = [record("eks.describe-cluster", {"cluster": {"name": "prod", "logging": {"clusterLogging": [{"types": ["audit"], "enabled": False}]}}}),
                   record("kubernetes.pods", {"items": [{"metadata": {"name": "api", "namespace": "apps"}, "spec": {"containers": [{"name": "app", "securityContext": {"privileged": True}}]}}]})]
        c, o = analyze(records)
        self.assertTrue(any(x["check"] == "K8S_PRIVILEGED" and x["status"] == "DESVIO_OBSERVADO" and x["action"] for x in o))
        self.assertEqual(next(x for x in c if x["id"] == "CT-05")["status"], "DESVIO_OBSERVADO")

    def test_absent_security_context_is_unknown_not_pass(self):
        c, o = analyze([record("kubernetes.pods", {"items": [{"metadata": {"name": "api"}, "spec": {"containers": [{"name": "app"}]}}]})])
        self.assertTrue(any(x["check"] == "K8S_NONROOT" and x["status"] == "NAO_VERIFICADO" for x in o))

    def test_invalid_hash_stops_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = EvidenceStore(Path(tmp) / "run", {})
            e = s.record("aws", "eks.describe-cluster", "r", "123456789012", "prod",
                         {"status": "ok", "complete": True, "error": None, "data": {"cluster": {"name": "prod"}}})
            (s.root / e["file"]).write_text('{}')
            with self.assertRaises(ValueError):
                generate_report([s.root], Path(tmp) / "report")

    def test_report_contains_plan_and_html_escaped_resource(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = EvidenceStore(Path(tmp) / "run", {"regions": ["eu-west-1"]})
            s.record("aws", "eks.describe-cluster", "eu-west-1", "123456789012", "<img src=x>",
                     {"status": "ok", "complete": True, "error": None, "data": {"cluster": {"name": "<img src=x>", "logging": {"clusterLogging": []}}}})
            s.finish()
            out = Path(tmp) / "report"
            generate_report([s.root], out)
            for name in ("RELATORIO.md", "RELATORIO.html", "CONTROLES.csv", "OBSERVACOES.csv", "PLANO-ACAO.csv", "INVENTARIO.csv", "EVIDENCIAS.csv"):
                self.assertTrue((out / name).is_file(), name)
            self.assertNotIn("<img src=x>", (out / "RELATORIO.html").read_text())
            self.assertIn("&lt;img src=x&gt;", (out / "RELATORIO.html").read_text())

    def test_manual_claim_cannot_auto_approve_and_invalid_control_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = EvidenceStore(Path(tmp) / "run", {})
            s.finish()
            manual = Path(tmp) / "manual.json"
            manual.write_text(json.dumps({"items": [{"control": "CT-12", "resource": "node", "reference": "SEC-123", "description": "FIM dito ativo", "collected_at": "2026-11-10", "owner": "Equipe", "private_unexpected_key": "SENSITIVE_EXTRA"}]}))
            out = Path(tmp) / "report"
            generate_report([s.root], out, manual)
            self.assertIn("FIM dito ativo", (out / "RELATORIO.md").read_text())
            rows = (out / "CONTROLES.csv").read_text()
            self.assertNotIn(",VERIFICADO,", rows)
            self.assertNotIn("SENSITIVE_EXTRA", (out / "RESULTADO.json").read_text())
            manual.write_text('{"items":[{"control":"INVALID"}]}')
            with self.assertRaises(ValueError):
                generate_report([s.root], Path(tmp) / "bad", manual)


if __name__ == "__main__":
    unittest.main()
