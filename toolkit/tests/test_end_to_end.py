"""Percurso real dos CLIs Python, com fronteira AWS/kubectl substituída por executáveis locais."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FAKE = r'''import json, sys
a = sys.argv[1:]
if a == ["--version"]:
    print("aws-cli/2.fixture Python/3.fixture")
    sys.exit(0)
service, op = a[:2]
results = {
"sts.get-caller-identity": {"Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/audit/session","UserId":"fixture"},
"eks.list-clusters": {"clusters":["demo"]},
"eks.describe-cluster": {"cluster":{"name":"demo","arn":"arn:aws:eks:eu-west-1:123456789012:cluster/demo","version":"1.34","logging":{"clusterLogging":[{"types":["audit"],"enabled":False}]},"resourcesVpcConfig":{"endpointPublicAccess":True,"publicAccessCidrs":["0.0.0.0/0"]}}},
"eks.list-nodegroups": {"nodegroups":[]}, "eks.list-fargate-profiles":{"fargateProfileNames":[]},
"eks.list-access-entries":{"accessEntries":[]}, "eks.list-addons":{"addons":[]},
"lambda.list-functions":{"Functions":[{"FunctionName":"demo","FunctionArn":"arn:aws:lambda:eu-west-1:123456789012:function:demo","CodeSha256":"synthetic","Environment":{"Variables":{"TOKEN":"DO_NOT_EXPORT_SECRET_9b2"}}}]},
"lambda.get-function-url-config":{"AuthType":"NONE"},
"ecs.list-clusters":{"clusterArns":["arn:aws:ecs:eu-west-1:123456789012:cluster/demo"]},
"ecs.list-tasks":{"taskArns":["arn:aws:ecs:eu-west-1:123456789012:task/t"]},
"ecs.describe-tasks":{"tasks":[{"taskArn":"arn:aws:ecs:eu-west-1:123456789012:task/t","taskDefinitionArn":"arn:aws:ecs:eu-west-1:123456789012:task-definition/demo:1"}]},
"ecs.describe-task-definition":{"taskDefinition":{"taskDefinitionArn":"arn:aws:ecs:eu-west-1:123456789012:task-definition/demo:1","containerDefinitions":[{"name":"api","privileged":False,"readonlyRootFilesystem":False,"environment":[{"name":"TOKEN","value":"DO_NOT_EXPORT_SECRET_9b2"}]}]}},
"ec2.describe-instances":{"Reservations":[{"Instances":[{"InstanceId":"i-demo","ImageId":"ami-demo","State":{"Name":"running"}}]}]},
"ec2.describe-volumes":{"Volumes":[{"VolumeId":"vol-demo","Encrypted":False}]},
"ecr.describe-repositories":{"repositories":[{"repositoryName":"demo","repositoryArn":"arn:aws:ecr:eu-west-1:123456789012:repository/demo","encryptionConfiguration":{"encryptionType":"AES256"}}]},
"logs.describe-log-groups":{"logGroups":[{"logGroupName":"/aws/lambda/demo","retentionInDays":90}]},
"iam.get-account-password-policy":{"PasswordPolicy":{"MinimumPasswordLength":14}},
}
if service == "--context":
    resource = a[a.index("get")+1]
    if resource == "pods":
        print(json.dumps({"items":[{"metadata":{"name":"api","namespace":"apps","annotations":{"x":"DO_NOT_EXPORT_SECRET_9b2"}},"spec":{"containers":[{"name":"app","image":"example.invalid/api:1","env":[{"name":"PASS","value":"DO_NOT_EXPORT_SECRET_9b2"}],"securityContext":{"privileged":True}}]}}]}))
    else:
        print('{"items":[]}')
else:
    print(json.dumps(results.get(service+"."+op, {})))
'''


@unittest.skipIf(os.name == "nt", "Executáveis fake usam shebang POSIX; CLIs principais são multiplataforma")
class E2ETests(unittest.TestCase):
    def test_clean_copy_all_modules_and_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bindir = root / "bin"
            bindir.mkdir()
            for name in ("aws", "kubectl"):
                path = bindir / name
                path.write_text("#!" + sys.executable + "\n" + FAKE)
                path.chmod(0o700)
            env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ["PATH"])
            awsout, k8sout, report = root / "aws", root / "k8s", root / "report"
            runs = [
                ["collect_aws.py", "--profiles", "fixture", "--regions", "eu-west-1", "--expected-accounts", "123456789012", "--out", str(awsout)],
                ["collect_kubernetes.py", "--context", "fixture", "--account", "123456789012", "--region", "eu-west-1", "--out", str(k8sout)],
                ["build_report.py", "--input", str(awsout), str(k8sout), "--out", str(report)],
            ]
            for args in runs:
                p = subprocess.run([sys.executable, *args], cwd=ROOT, env=env, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            result = json.loads((report / "RESULTADO.json").read_text())
            self.assertEqual(len(result["controls"]), 21)
            self.assertTrue(any(o["check"] == "EKS_AUDIT" and o["status"] == "DESVIO_OBSERVADO" for o in result["observations"]))
            self.assertTrue(any(o["check"] == "LAMBDA_URL_AUTH" and o["status"] == "DESVIO_OBSERVADO" for o in result["observations"]))
            self.assertIn("AC-OBS-", (report / "PLANO-ACAO.csv").read_text(encoding="utf-8-sig"))
            exported = "".join(f.read_text(encoding="utf-8-sig") for d in (awsout, k8sout, report) for f in d.rglob("*") if f.is_file())
            self.assertNotIn("DO_NOT_EXPORT_SECRET_9b2", exported)

    def test_unexpected_account_skips_resource_queries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bindir = root / "bin"
            bindir.mkdir()
            fake = bindir / "aws"
            fake.write_text("#!" + sys.executable + "\n" + FAKE)
            fake.chmod(0o700)
            env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ["PATH"])
            p = subprocess.run([sys.executable, "collect_aws.py", "--profiles", "fixture", "--regions", "eu-west-1", "--expected-accounts", "999999999999", "--out", str(root / "run")], cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(p.returncode, 2)
            m = json.loads((root / "run" / "manifest.json").read_text())
            self.assertEqual([x["operation"] for x in m["records"]], ["sts.get-caller-identity", "coverage.identity"])


if __name__ == "__main__":
    unittest.main()
