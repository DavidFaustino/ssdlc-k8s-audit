"""Execução sem shell, sanitização e armazenamento verificável de evidências."""
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


READ_OPERATIONS = {
    "sts": "get-caller-identity",
    "iam": "get-account-password-policy get-account-summary list-users list-roles list-attached-role-policies list-role-policies get-role-policy get-policy get-policy-version",
    "eks": "list-clusters describe-cluster list-nodegroups describe-nodegroup list-fargate-profiles describe-fargate-profile list-access-entries describe-access-entry list-associated-access-policies list-addons describe-addon list-pod-identity-associations",
    "ec2": "describe-instances describe-images describe-security-groups describe-volumes describe-snapshots describe-vpcs describe-subnets describe-network-acls describe-flow-logs",
    "ssm": "describe-instance-information describe-instance-patch-states list-compliance-items describe-association list-associations",
    "ecs": "list-clusters describe-clusters list-services describe-services list-tasks describe-tasks list-container-instances describe-container-instances describe-task-definition",
    "ecr": "describe-repositories get-registry-scanning-configuration describe-images get-repository-policy get-lifecycle-policy describe-image-scan-findings describe-registry",
    "lambda": "list-functions list-versions-by-function list-aliases get-policy get-function-url-config get-function-concurrency get-function-code-signing-config list-event-source-mappings",
    "logs": "describe-log-groups describe-log-streams describe-subscription-filters",
    "cloudtrail": "describe-trails get-trail-status get-event-selectors",
    "backup": "list-backup-plans get-backup-plan list-backup-selections get-backup-selection list-backup-vaults list-recovery-points-by-backup-vault list-backup-jobs list-restore-jobs",
    "efs": "describe-file-systems describe-mount-targets describe-access-points describe-backup-policy",
    "secretsmanager": "list-secrets",
    "kms": "describe-key get-key-rotation-status",
    "inspector2": "list-coverage list-findings",
    "guardduty": "list-detectors get-detector get-coverage-statistics list-coverage",
    "securityhub": "describe-hub get-enabled-standards",
    "configservice": "describe-configuration-recorders describe-configuration-recorder-status describe-delivery-channels",
}
TOKENS = {"NextToken", "nextToken", "NextMarker", "Marker", "nextMarker", "continue"}
DROP = {"Environment", "UserData", "SecretString", "SecretBinary", "Password", "password",
        "Code", "Location", "RepositoryCredentials", "repositoryCredentials", "command", "Command",
        "args", "entryPoint", "annotations", "managedFields", "data", "stringData",
        "Tags", "tags", "TagSet", "tagSet", "Description", "description", "reason", "message",
        "httpHeaders", "volumeAttributes", "parameters", "options", "dockerLabels", "headers"} | TOKENS


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sanitize(value):
    """Remove campos que podem conter valores de segredos ou texto arbitrário."""
    if isinstance(value, list):
        return [sanitize(x) for x in value]
    if not isinstance(value, dict):
        return value
    clean = {}
    for key, val in value.items():
        if key in DROP:
            continue
        if key == "env":
            clean[key] = [{"name": e.get("name"), **({"valueFrom": sanitize(e["valueFrom"])} if "valueFrom" in e else {"literalValueOmitted": True})}
                          for e in val if isinstance(e, dict)] if isinstance(val, list) else []
        elif key == "environment":
            clean[key] = [{"name": e.get("name"), "literalValueOmitted": True}
                          for e in val if isinstance(e, dict)] if isinstance(val, list) else []
        elif key == "environmentFiles":
            clean[key] = [{"type": e.get("type"), "referenceOmitted": True} for e in val if isinstance(e, dict)]
        elif key == "metadata" and isinstance(val, dict):
            clean[key] = {k: sanitize(v) for k, v in val.items()
                          if k in {"name", "namespace", "uid", "creationTimestamp", "resourceVersion", "ownerReferences", "labels"}}
        elif key == "labels":
            clean[key] = {k: v for k, v in val.items() if k.startswith("pod-security.kubernetes.io/") or k in {"kubernetes.io/os", "kubernetes.io/arch", "eks.amazonaws.com/compute-type"}} if isinstance(val, dict) else {}
        elif key == "logConfiguration" and isinstance(val, dict):
            opts = val.get("options", {})
            clean[key] = {"logDriver": val.get("logDriver"), "options": {k: v for k, v in opts.items() if k in {"awslogs-group", "awslogs-region", "awslogs-stream-prefix", "mode", "max-buffer-size"}},
                          "secretOptions": [{"name": e.get("name"), "valueFrom": e.get("valueFrom")} for e in val.get("secretOptions", [])]}
        else:
            clean[key] = sanitize(val)
    return clean


class Runner:
    def __init__(self, timeout=120):
        self.timeout = timeout

    def version(self, tool):
        if tool not in {"aws", "kubectl"}:
            raise ValueError("Ferramenta não permitida")
        command = [tool, "--version"] if tool == "aws" else [tool, "version", "--client", "-o", "json"]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=min(self.timeout, 15), shell=False)
            if tool == "aws":
                match = re.search(r"aws-cli/[0-9][A-Za-z0-9._-]*", result.stdout + result.stderr)
                return match.group(0) if match else "indisponivel"
            version = json.loads(result.stdout).get("clientVersion", {}).get("gitVersion", "")
            return version if re.fullmatch(r"v[0-9][A-Za-z0-9.+_-]*", version) else "indisponivel"
        except (OSError, subprocess.TimeoutExpired, ValueError, AttributeError):
            return "indisponivel"

    def _run(self, command):
        env = dict(os.environ, AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off", AWS_RETRY_MODE="standard", AWS_MAX_ATTEMPTS="3")
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout, env=env, shell=False)
        except FileNotFoundError:
            return self.failure("ExecutableNotFound")
        except subprocess.TimeoutExpired:
            return self.failure("Timeout")
        except OSError:
            return self.failure("ProcessError")
        if proc.returncode:
            match = re.search(r"\(([A-Za-z][A-Za-z0-9._-]+)\)", proc.stderr)
            code = match.group(1) if match else ("Forbidden" if "Forbidden" in proc.stderr else "CLIError")
            return self.failure(code, proc.returncode)
        try:
            data = json.loads(proc.stdout)
        except (json.JSONDecodeError, TypeError):
            return self.failure("InvalidJSON")
        if not isinstance(data, (dict, list)):
            return self.failure("UnexpectedJSONShape")
        partial = isinstance(data, dict) and (any(data.get(k) for k in TOKENS) or bool(data.get("metadata", {}).get("continue")))
        return {"status": "partial" if partial else "ok", "complete": not partial, "error": "PaginationIncomplete" if partial else None,
                "data": sanitize(data), "exit_code": 0}

    @staticmethod
    def failure(code, exit_code=None):
        return {"status": "error", "complete": False, "error": code, "data": None, "exit_code": exit_code}

    def aws(self, service, operation, args, region, profile):
        if operation not in READ_OPERATIONS.get(service, "").split():
            raise ValueError("Operação fora da allowlist de leitura")
        forbidden = {"--endpoint-url", "--no-verify-ssl", "--debug", "--no-sign-request", "--cli-input-json", "--cli-input-yaml"}
        if any(a.split("=")[0] in forbidden for a in args):
            raise ValueError("Opção não permitida")
        cmd = ["aws", service, operation, *args, "--output", "json", "--no-cli-pager", "--region", region]
        if profile:
            cmd.extend(["--profile", profile])
        return self._run(cmd)

    def kubernetes(self, context, resource, namespace=None):
        allowed = {"pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs", "namespaces", "nodes", "services", "ingresses", "networkpolicies", "roles", "rolebindings", "clusterroles", "clusterrolebindings", "serviceaccounts", "validatingwebhookconfigurations", "mutatingwebhookconfigurations", "validatingadmissionpolicies", "validatingadmissionpolicybindings", "persistentvolumes", "persistentvolumeclaims", "storageclasses", "resourcequotas", "limitranges"}
        if resource not in allowed:
            raise ValueError("Recurso K8s não permitido")
        cmd = ["kubectl", "--context", context, "--request-timeout", str(self.timeout) + "s", "get", resource, "-o", "json"]
        if resource not in {"namespaces", "nodes", "clusterroles", "clusterrolebindings", "validatingwebhookconfigurations", "mutatingwebhookconfigurations", "validatingadmissionpolicies", "validatingadmissionpolicybindings", "persistentvolumes", "storageclasses"}:
            cmd.extend(["--namespace", namespace] if namespace else ["--all-namespaces"])
        return self._run(cmd)


def write_json(path, obj):
    path = Path(path)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as out:
        json.dump(obj, out, ensure_ascii=False, indent=2, sort_keys=True)
        out.write("\n")
    os.replace(temp, path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


class EvidenceStore:
    def __init__(self, root, scope):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=False)
        try:
            self.root.chmod(0o700)
        except OSError:
            pass
        (self.root / "evidence").mkdir()
        self.manifest = {"schema_version": 1, "created_at": utc_now(), "scope": scope, "state": "collecting", "tool_versions": {"python": sys.version.split()[0]}, "records": []}
        self.save()

    def save(self):
        write_json(self.root / "manifest.json", self.manifest)

    def record(self, source, operation, region, account, resource, result, profile=None):
        ident = "EV-" + str(len(self.manifest["records"]) + 1).zfill(6)
        filename = "evidence/" + ident + ".json"
        item = {"id": ident, "source": source, "operation": operation, "account": account, "region": region,
                "profile": profile, "resource": resource, "collected_at": utc_now(), "file": filename,
                "status": result["status"], "complete": result["complete"], "error": result.get("error")}
        write_json(self.root / filename, {"metadata": item, "data": sanitize(result.get("data"))})
        item["sha256"] = hashlib.sha256((self.root / filename).read_bytes()).hexdigest()
        self.manifest["records"].append(item)
        self.save()
        return item

    def finish(self):
        self.manifest["state"] = "finished"
        self.manifest["finished_at"] = utc_now()
        self.save()


def load_evidence(directory):
    root = Path(directory).resolve()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("records"), list):
        raise ValueError("Manifesto inválido")
    result = []
    seen = set()
    for item in manifest["records"]:
        validate_record(item)
        path = (root / item["file"]).resolve()
        if path.parent != root / "evidence" or path.suffix != ".json" or item["id"] in seen:
            raise ValueError("Caminho/ID inválido no manifesto")
        seen.add(item["id"])
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("Falha de integridade: " + item["id"])
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("metadata") != {k: v for k, v in item.items() if k != "sha256"}:
            raise ValueError("Falha de integridade dos metadados: " + item["id"])
        result.append({**item, "data": payload.get("data"), "directory": str(root)})
    return result


def validate_record(item):
    if not isinstance(item, dict) or not re.fullmatch(r"EV-\d{6}", item.get("id", "")):
        raise ValueError("ID de evidência inválido")
    source, operation = item.get("source"), item.get("operation", "")
    if not isinstance(operation, str):
        raise ValueError("Fonte/operação de evidência inválida")
    if source == "aws":
        service, _, op = operation.partition(".")
        valid_operation = operation.startswith("coverage.") or op in READ_OPERATIONS.get(service, "").split()
    elif source == "kubernetes":
        from .kubernetes import RESOURCES
        valid_operation = operation.startswith("kubernetes.") and operation.split(".", 1)[1] in RESOURCES
    else:
        valid_operation = False
    if not valid_operation:
        raise ValueError("Fonte/operação de evidência inválida")
    status, complete, error = item.get("status"), item.get("complete"), item.get("error")
    if type(complete) is not bool or status not in {"ok", "error", "partial"}:
        raise ValueError("Falha de coerência do status da evidência")
    if (status == "ok" and (not complete or error is not None)) or (status != "ok" and (complete or not isinstance(error, str) or not error)):
        raise ValueError("Falha de coerência: status, complete e error")
