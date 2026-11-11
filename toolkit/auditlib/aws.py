"""Consultas de leitura. Limites são evidências explícitas, nunca inventário completo."""
from .core import Runner


MODULES = ("eks", "ec2", "ecs", "ecr", "lambda", "iam", "logs", "cloudtrail", "storage", "backup", "security", "ssm")


class AWSCollector:
    def __init__(self, runner, store, profile, account, region, max_details=100):
        self.runner, self.store = runner, store
        self.profile, self.account, self.region = profile, account, region
        self.max_details = max_details

    def ask(self, service, operation, args=None, resource="*"):
        result = self.runner.aws(service, operation, args or [], self.region, self.profile)
        # Alguns Describe retornam HTTP 200 com failures por recurso.
        if isinstance(result.get("data"), dict) and result["data"].get("failures"):
            result = {**result, "status": "partial", "complete": False, "error": "ResourceFailures"}
        self.store.record("aws", service + "." + operation, self.region, self.account, resource, result, self.profile)
        return result.get("data") or {}

    def details(self, entries, scope):
        if not isinstance(entries, list):
            self.store.record("aws", "coverage." + scope, self.region, self.account, scope,
                              Runner.failure("UnexpectedShape"), self.profile)
            return []
        if self.max_details and len(entries) > self.max_details:
            self.store.record("aws", "coverage." + scope, self.region, self.account, scope,
                              {"status": "partial", "complete": False, "error": "DetailLimit", "data": {
                                  "total_listed": len(entries), "selected": self.max_details, "omitted": len(entries) - self.max_details}}, self.profile)
            return entries[:self.max_details]
        return entries

    def eks(self):
        for name in self.details(self.ask("eks", "list-clusters").get("clusters", []), "eks.clusters"):
            arg = ["--name", name]
            self.ask("eks", "describe-cluster", arg, name)
            for ng in self.details(self.ask("eks", "list-nodegroups", ["--cluster-name", name], name).get("nodegroups", []), "eks.nodegroups." + name):
                self.ask("eks", "describe-nodegroup", ["--cluster-name", name, "--nodegroup-name", ng], name + "/" + ng)
            for fp in self.details(self.ask("eks", "list-fargate-profiles", ["--cluster-name", name], name).get("fargateProfileNames", []), "eks.fargate." + name):
                self.ask("eks", "describe-fargate-profile", ["--cluster-name", name, "--fargate-profile-name", fp], name + "/" + fp)
            for principal in self.details(self.ask("eks", "list-access-entries", ["--cluster-name", name], name).get("accessEntries", []), "eks.access." + name):
                args = ["--cluster-name", name, "--principal-arn", principal]
                self.ask("eks", "describe-access-entry", args, name + "/" + principal)
                self.ask("eks", "list-associated-access-policies", args, name + "/" + principal)
            for addon in self.details(self.ask("eks", "list-addons", ["--cluster-name", name], name).get("addons", []), "eks.addons." + name):
                self.ask("eks", "describe-addon", ["--cluster-name", name, "--addon-name", addon], name + "/" + addon)
            self.ask("eks", "list-pod-identity-associations", ["--cluster-name", name], name)

    def ec2(self):
        data = self.ask("ec2", "describe-instances")
        image_ids = sorted({x["ImageId"] for r in data.get("Reservations", []) for x in r.get("Instances", []) if x.get("ImageId")})
        # Consultar por lotes pequenos preserva limites de API e comandos Windows.
        selected = self.details(image_ids, "ec2.images")
        for start in range(0, len(selected), 50):
            self.ask("ec2", "describe-images", ["--image-ids", *selected[start:start + 50]], "AMI")
        for operation in ("describe-security-groups", "describe-vpcs", "describe-subnets", "describe-network-acls", "describe-flow-logs"):
            self.ask("ec2", operation)

    def ecs(self):
        definitions = set()
        clusters = self.details(self.ask("ecs", "list-clusters").get("clusterArns", []), "ecs.clusters")
        for cluster in clusters:
            self.ask("ecs", "describe-clusters", ["--clusters", cluster, "--include", "SETTINGS", "CONFIGURATIONS"], cluster)
            services = self.details(self.ask("ecs", "list-services", ["--cluster", cluster], cluster).get("serviceArns", []), "ecs.services." + cluster)
            for start in range(0, len(services), 10):
                desc = self.ask("ecs", "describe-services", ["--cluster", cluster, "--services", *services[start:start + 10]], cluster)
                definitions.update(s["taskDefinition"] for s in desc.get("services", []) if s.get("taskDefinition"))
                definitions.update(d["taskDefinition"] for s in desc.get("services", []) for d in s.get("deployments", []) if d.get("taskDefinition"))
            tasks = self.details(self.ask("ecs", "list-tasks", ["--cluster", cluster], cluster).get("taskArns", []), "ecs.tasks." + cluster)
            for start in range(0, len(tasks), 100):
                desc = self.ask("ecs", "describe-tasks", ["--cluster", cluster, "--tasks", *tasks[start:start + 100]], cluster)
                definitions.update(t["taskDefinitionArn"] for t in desc.get("tasks", []) if t.get("taskDefinitionArn"))
            hosts = self.details(self.ask("ecs", "list-container-instances", ["--cluster", cluster], cluster).get("containerInstanceArns", []), "ecs.hosts." + cluster)
            for start in range(0, len(hosts), 100):
                self.ask("ecs", "describe-container-instances", ["--cluster", cluster, "--container-instances", *hosts[start:start + 100]], cluster)
        for definition in self.details(sorted(definitions), "ecs.task-definitions"):
            self.ask("ecs", "describe-task-definition", ["--task-definition", definition], definition)

    def ecr(self):
        self.ask("ecr", "get-registry-scanning-configuration")
        self.ask("ecr", "describe-registry")
        for repo in self.details(self.ask("ecr", "describe-repositories").get("repositories", []), "ecr.repositories"):
            name = repo["repositoryName"]
            args = ["--repository-name", name]
            self.ask("ecr", "get-repository-policy", args, name)
            self.ask("ecr", "get-lifecycle-policy", args, name)
            # Inventário completo de metadados; findings por imagem ficam no scanner/console.
            self.ask("ecr", "describe-images", args, name)

    def lambda_(self):
        functions = self.ask("lambda", "list-functions").get("Functions", [])
        for function in self.details(functions, "lambda.functions"):
            name = function["FunctionName"]
            args = ["--function-name", name]
            for operation in ("list-versions-by-function", "get-policy", "get-function-url-config", "get-function-concurrency", "get-function-code-signing-config"):
                self.ask("lambda", operation, args, name)
            aliases = self.ask("lambda", "list-aliases", args, name).get("Aliases", [])
            for alias in self.details(aliases, "lambda.aliases." + name):
                qualifier = alias["Name"]
                for operation in ("get-policy", "get-function-url-config"):
                    self.ask("lambda", operation, [*args, "--qualifier", qualifier], name + ":" + qualifier)
            self.ask("lambda", "list-event-source-mappings", args, name)

    def iam(self):
        self.ask("iam", "get-account-password-policy")
        self.ask("iam", "get-account-summary")
        self.ask("iam", "list-users")
        for role in self.details(self.ask("iam", "list-roles").get("Roles", []), "iam.roles"):
            name = role["RoleName"]
            attached = self.ask("iam", "list-attached-role-policies", ["--role-name", name], name)
            for policy in self.details(attached.get("AttachedPolicies", []), "iam.attached." + name):
                arn = policy["PolicyArn"]
                doc = self.ask("iam", "get-policy", ["--policy-arn", arn], arn).get("Policy", {})
                if doc.get("DefaultVersionId"):
                    self.ask("iam", "get-policy-version", ["--policy-arn", arn, "--version-id", doc["DefaultVersionId"]], arn)
            names = self.ask("iam", "list-role-policies", ["--role-name", name], name).get("PolicyNames", [])
            for pname in self.details(names, "iam.inline." + name):
                self.ask("iam", "get-role-policy", ["--role-name", name, "--policy-name", pname], name + "/" + pname)

    def logs(self):
        groups = self.ask("logs", "describe-log-groups").get("logGroups", [])
        for group in self.details(groups, "logs.groups"):
            name = group["logGroupName"]
            self.ask("logs", "describe-subscription-filters", ["--log-group-name", name], name)
            self.ask("logs", "describe-log-streams", ["--log-group-name", name, "--order-by", "LastEventTime", "--descending", "--max-items", "1"], name)

    def cloudtrail(self):
        for trail in self.details(self.ask("cloudtrail", "describe-trails").get("trailList", []), "cloudtrail.trails"):
            name = trail.get("TrailARN", trail.get("Name"))
            self.ask("cloudtrail", "get-trail-status", ["--name", name], name)
            self.ask("cloudtrail", "get-event-selectors", ["--trail-name", name], name)

    def storage(self):
        self.ask("ec2", "describe-volumes")
        self.ask("ec2", "describe-snapshots", ["--owner-ids", "self"])
        for fs in self.details(self.ask("efs", "describe-file-systems").get("FileSystems", []), "efs.file-systems"):
            fid = fs["FileSystemId"]
            for operation in ("describe-mount-targets", "describe-access-points", "describe-backup-policy"):
                self.ask("efs", operation, ["--file-system-id", fid], fid)
        self.ask("secretsmanager", "list-secrets")

    def backup(self):
        for plan in self.details(self.ask("backup", "list-backup-plans").get("BackupPlansList", []), "backup.plans"):
            pid = plan["BackupPlanId"]
            self.ask("backup", "get-backup-plan", ["--backup-plan-id", pid], pid)
            for selection in self.details(self.ask("backup", "list-backup-selections", ["--backup-plan-id", pid], pid).get("BackupSelectionsList", []), "backup.selections." + pid):
                self.ask("backup", "get-backup-selection", ["--backup-plan-id", pid, "--selection-id", selection["SelectionId"]], pid)
        for vault in self.details(self.ask("backup", "list-backup-vaults").get("BackupVaultList", []), "backup.vaults"):
            self.ask("backup", "list-recovery-points-by-backup-vault", ["--backup-vault-name", vault["BackupVaultName"]], vault["BackupVaultName"])
        self.ask("backup", "list-backup-jobs")
        self.ask("backup", "list-restore-jobs")

    def security(self):
        self.ask("inspector2", "list-coverage")
        # Findings não são baixados em massa; usar ferramenta/console para detalhes por escopo.
        for detector in self.details(self.ask("guardduty", "list-detectors").get("DetectorIds", []), "guardduty.detectors"):
            self.ask("guardduty", "get-detector", ["--detector-id", detector], detector)
            self.ask("guardduty", "list-coverage", ["--detector-id", detector], detector)
        for service, operation in (("securityhub", "describe-hub"), ("securityhub", "get-enabled-standards"),
                                   ("configservice", "describe-configuration-recorders"), ("configservice", "describe-configuration-recorder-status"),
                                   ("configservice", "describe-delivery-channels")):
            self.ask(service, operation)

    def ssm(self):
        instances = self.ask("ssm", "describe-instance-information").get("InstanceInformationList", [])
        ids = self.details([i["InstanceId"] for i in instances if i.get("InstanceId")], "ssm.instances")
        for start in range(0, len(ids), 50):
            self.ask("ssm", "describe-instance-patch-states", ["--instance-ids", *ids[start:start + 50]], "SSM managed instances")
        self.ask("ssm", "list-associations")

    def collect(self, modules):
        for module in modules:
            print(f"[{self.profile or 'sessão'} / {self.account} / {self.region}] {module}", flush=True)
            getattr(self, "lambda_" if module == "lambda" else module)()
