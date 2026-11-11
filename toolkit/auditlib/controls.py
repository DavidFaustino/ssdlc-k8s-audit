"""Critérios observacionais explícitos; nenhuma certificação automática de controle."""
import csv
import html
import json
from collections import Counter
from pathlib import Path

from .core import load_evidence, utc_now, write_json
from .documents import render_markdown


CONTROL_CATALOG = [
    ("CT-01", "Guias de configuração segura", "Guia aprovado, versão, escopo e exceções", "Guia Confluence, repositório da baseline e aprovação de Segurança", "Aprovar baseline e vincular aos ambientes e versões avaliados."),
    ("CT-02", "Contas de acesso", "Identidades, menor privilégio, acesso federado e revisões", "IAM, EKS Access/RBAC, provedor de identidade e revisões", "Reconciliar identidades e permissões com donos; revisar privilégios e acessos de emergência."),
    ("CT-03", "Hardening", "Baseline de workload e SO, benchmark e exceções", "Kubernetes, task definitions, AMI e relatório CIS/Qualys/Wiz", "Tratar configurações divergentes e anexar medição do benchmark aplicável."),
    ("CT-04", "Interfaces de acesso", "Interfaces autorizadas e exposição restrita", "EKS endpoint, Security Groups, ingress/services, ECS Exec e Lambda URLs", "Validar exposição de cada interface, autorização e necessidade de acesso público."),
    ("CT-05", "Logs de auditoria", "Configuração, entrega, retenção e acesso aos logs", "EKS audit, CloudTrail, CloudWatch e destino central", "Comprovar recebimento recente e retenção conforme política aprovada."),
    ("CT-06", "Patches de segurança", "Versões, vulnerabilidades, SLA e correção", "SSM/Inspector, scanners de imagens e processo de atualização de AMI", "Cruzar achados com SLA; planejar patch/rebuild/substituição e comprovar nova avaliação."),
    ("CT-07", "Políticas de senhas", "Política aplicável a cada sistema de identidade", "IAM local, IdP/SSO, SO e aplicações com senha", "Anexar políticas aplicáveis e aprovação; IAM não representa o SSO nem o Linux."),
    ("CT-08", "Senhas padrão", "Credenciais padrão removidas ou desabilitadas", "Baseline de imagem, instalação do produto e validação do owner", "Obter evidência de desabilitação sem testar credenciais nem registrar senhas."),
    ("CT-09", "Sincronização de hora", "Fonte de tempo e estado de sincronização", "chrony/NTP no host EC2 e responsabilidade de serviços gerenciados", "Coletar estado NTP/chrony; justificar responsabilidade gerenciada quando aplicável."),
    ("CT-10", "Proteção de senhas", "Armazenamento, acesso, criptografia e rotação", "Secret references, Secrets Manager, KMS, IdP e processo de rotação", "Revisar acesso e ciclo de vida sem exportar valores de segredos."),
    ("CT-11", "Antimalware", "Política, cobertura e saúde por ativo", "Console da ferramenta efetiva e relação com inventário AWS/K8s", "Anexar cobertura e saúde por ativo; presença de sensor ou scan de CVE não basta."),
    ("CT-12", "FIM", "Monitoramento de integridade com escopo e eventos", "Política FIM e console da solução efetivamente utilizada", "Anexar política, escopo de arquivos e eventos datados; validar aplicabilidade por runtime."),
    ("CT-13", "Locais de armazenamento", "Persistência, criptografia, acesso e proprietário", "Volumes EBS/EFS, PV/PVC/StorageClass, volumes ECS e Lambda", "Relacionar volumes e donos; validar criptografia, exposição e classificação."),
    ("CT-14", "Logs transacionais", "Rastreabilidade e proteção de eventos de aplicação", "Configuração de aplicação, coletores e SIEM/destino central", "Anexar amostra autorizada com correlação e retenção; remover dados sensíveis."),
    ("CT-15", "Backup", "Proteção, execução e teste de restauração", "AWS Backup, snapshots e solução K8s/externa", "Relacionar ativos e políticas; anexar resultado de execução e teste de restauração."),
    ("RG-01", "Container registry", "Acesso, proteção, scan e ciclo de vida", "ECR e administração JFrog", "Revisar policies, criptografia, tags, scans e ciclo de vida; anexar evidência JFrog separada."),
    ("IM-01", "Container images", "Origem, digest, hardening, scan, SBOM e verificação", "ECR, digests em runtime, GitHub Actions, Wiz/Trivy, SBOM/assinatura", "Relacionar digest implantado ao scan, SBOM, assinatura verificada e decisão de liberação."),
    ("DP-01", "Container deployment process", "Mudança revisada, gates e rastreabilidade do deploy", "GitHub Actions, Helm/Argo CD, Git protegido e admission", "Anexar uma execução real com revisão, gates, publicação e digest implantado."),
    ("LM-01", "Lambda — configuração", "Configuração, exposição, identidade e segredo", "Lambda, IAM, resource policy, URLs, VPC/KMS", "Revisar função/role/exposição e controles aplicáveis; não coletar valores de environment."),
    ("LM-02", "Lambda — deploy", "Versão, origem do código e aprovação da mudança", "Versões/aliases/CodeSha256 e CI/CD", "Vincular versão e hash à execução aprovada; validar assinatura quando exigida e aplicável."),
    ("LM-03", "Lambda — gestão de logs", "Destino, entrega, retenção e acesso", "LoggingConfig, CloudWatch ou destino configurado", "Relacionar função e destino, confirmar recebimento e política de retenção."),
]

PREFIX_CONTROLS = {
    "eks.": ["CT-02", "CT-03", "CT-04", "CT-05", "CT-06", "DP-01"],
    "ec2.": ["CT-03", "CT-04", "CT-06", "CT-09", "CT-13"],
    "ecs.": ["CT-02", "CT-03", "CT-04", "CT-10", "CT-13", "CT-14", "IM-01", "DP-01"],
    "ecr.": ["RG-01", "IM-01"], "lambda.": ["LM-01", "LM-02", "LM-03"],
    "iam.": ["CT-02", "CT-07"], "logs.": ["CT-05", "CT-14", "LM-03"],
    "cloudtrail.": ["CT-05", "DP-01", "LM-02"], "backup.": ["CT-15"],
    "efs.": ["CT-13", "CT-15"], "secretsmanager.": ["CT-10"],
    "ssm.": ["CT-06", "CT-11", "CT-12"], "guardduty.": ["CT-11"],
    "inspector2.": ["CT-06", "IM-01"], "securityhub.": ["CT-03", "CT-06"],
    "configservice.": ["CT-03", "CT-05"],
    "kubernetes.": ["CT-02", "CT-03", "CT-04", "CT-10", "CT-11", "CT-12", "CT-13", "CT-14", "IM-01", "DP-01"],
}


def related(operation):
    return next((v for p, v in PREFIX_CONTROLS.items() if operation.startswith(p)), [])


def analyze(records):
    observations = []

    def emit(r, control, check, resource, value, expected, action, status=None):
        if status is None:
            status = "NAO_VERIFICADO" if value is None else "VERIFICADO" if value == expected else "DESVIO_OBSERVADO"
        observations.append({"id": "OBS-" + str(len(observations) + 1).zfill(6), "control": control, "check": check,
                             "status": status, "account": r.get("account"), "region": r.get("region"), "resource": resource,
                             "observed": json.dumps(value, ensure_ascii=False), "criterion": f"Critério técnico proposto: {check}; esperado {json.dumps(expected, ensure_ascii=False)}. Não é certificação do requisito.",
                             "evidence": r.get("ref", r["id"]), "action": action, "collected_at": r.get("collected_at")})

    for r in records:
        expected_source = "kubernetes" if r["operation"].startswith("kubernetes.") else "aws"
        if r["status"] != "ok" or r.get("complete") is not True or r.get("error") is not None or r.get("source") != expected_source:
            continue
        d = r.get("data") or {}
        if not isinstance(d, dict):
            continue
        op = r["operation"]
        if op == "eks.describe-cluster":
            c = d.get("cluster", {})
            name = c.get("name", r["resource"])
            configs = c.get("logging", {}).get("clusterLogging")
            audit = None if configs is None else any(x.get("enabled") is True and "audit" in x.get("types", []) for x in configs)
            emit(r, "CT-05", "EKS_AUDIT", name, audit, True, "Validar/applicar exportação do log audit e comprovar entrega e retenção.")
            vpc = c.get("resourcesVpcConfig", {})
            if vpc.get("endpointPublicAccess") and any(x in {"0.0.0.0/0", "::/0"} for x in vpc.get("publicAccessCidrs", [])):
                emit(r, "CT-04", "EKS_PUBLIC_CIDR", name, "internet", "restrito", "Restringir CIDRs ou acesso privado conforme arquitetura aprovada; revisar exceção.")
        elif op == "cloudtrail.get-trail-status":
            emit(r, "CT-05", "CLOUDTRAIL_LOGGING", r["resource"], d.get("IsLogging"), True, "Confirmar trilha ativa, seletores, entrega e acesso ao destino.")
        elif op == "ecs.describe-task-definition":
            td = d.get("taskDefinition", {})
            if td.get("runtimePlatform", {}).get("operatingSystemFamily", "LINUX").startswith("WINDOWS"):
                emit(r, "CT-03", "ECS_WINDOWS_BASELINE", r["resource"], "windows", "baseline Windows aplicável", "Revisar controles específicos Windows; readonlyRootFilesystem Linux não é suportado.", "NAO_APLICAVEL_PROPOSTO")
                continue
            for c in td.get("containerDefinitions", []):
                res = str(r["resource"]) + "/" + c.get("name", "?")
                emit(r, "CT-03", "ECS_PRIVILEGED", res, c.get("privileged"), False, "Remover modo privilegiado ou documentar necessidade e exceção.")
                emit(r, "CT-03", "ECS_READONLY", res, c.get("readonlyRootFilesystem", False), True, "Adotar root filesystem somente leitura, com volumes de escrita definidos; default Linux false quando campo ausente.")
                user = c.get("user")
                if user is not None and str(user).split(":")[0] in {"root", "0"}:
                    emit(r, "CT-03", "ECS_USER", res, user, "UID não zero", "Usar usuário não root validado na imagem ou justificar exceção.")
                emit(r, "CT-14", "ECS_LOG_DRIVER", res, (c.get("logConfiguration") or {}).get("logDriver"), "destino validado", "Relacionar driver, destino e prova de recebimento.", "NAO_VERIFICADO")
        elif op == "ecr.describe-repositories":
            for repo in d.get("repositories", []):
                name = repo.get("repositoryName", "?")
                encryption = (repo.get("encryptionConfiguration") or {}).get("encryptionType")
                emit(r, "RG-01", "ECR_AT_REST", name, encryption, "AES256 ou KMS", "Validar tipo de chave e política corporativa.", "VERIFICADO" if encryption in {"AES256", "KMS", "KMS_DSSE"} else "NAO_VERIFICADO")
                emit(r, "RG-01", "ECR_MUTABILITY", name, repo.get("imageTagMutability"), "regra de promoção aprovada", "Revisar mutabilidade e exceções para aliases; não presumir que todos devam ser imutáveis.", "NAO_VERIFICADO")
        elif op == "ec2.describe-security-groups":
            for sg in d.get("SecurityGroups", []):
                for permission in sg.get("IpPermissions", []):
                    world = any(x.get("CidrIp") == "0.0.0.0/0" for x in permission.get("IpRanges", [])) or any(x.get("CidrIpv6") == "::/0" for x in permission.get("Ipv6Ranges", []))
                    low, high = permission.get("FromPort", -1), permission.get("ToPort", -1)
                    if world and (permission.get("IpProtocol") == "-1" or any(low <= port <= high for port in (22, 3389))):
                        emit(r, "CT-04", "PUBLIC_ADMIN_PORT", sg.get("GroupId"), {"from": low, "to": high, "world": True}, "acesso administrativo restrito", "Restringir origem/caminho administrativo; conferir associações e alcance real.")
        elif op == "ec2.describe-volumes":
            for vol in d.get("Volumes", []):
                emit(r, "CT-13", "EBS_ENCRYPTED", vol.get("VolumeId"), vol.get("Encrypted"), True, "Planejar migração criptografada e validar KMS/acesso conforme política.")
        elif op == "efs.describe-file-systems":
            for fs in d.get("FileSystems", []):
                emit(r, "CT-13", "EFS_ENCRYPTED", fs.get("FileSystemId"), fs.get("Encrypted"), True, "Validar criptografia, mount targets, acesso e política de backup.")
        elif op == "ssm.describe-instance-patch-states":
            for inst in d.get("InstancePatchStates", []):
                missing = inst.get("MissingCount")
                emit(r, "CT-06", "SSM_MISSING_PATCHES", inst.get("InstanceId"), missing, 0, "Revisar idade e baseline do scan, SLA e janela; em nós imutáveis atualizar AMI/substituir nó.")
        elif op == "lambda.list-functions":
            for f in d.get("Functions", []):
                emit(r, "LM-02", "LAMBDA_CODE_IDENTITY", f.get("FunctionArn", f.get("FunctionName")), bool(f.get("CodeSha256")) if "CodeSha256" in f else None, True, "Vincular CodeSha256/versão à execução aprovada do CI/CD.")
                emit(r, "LM-03", "LAMBDA_LOG_DESTINATION", f.get("FunctionName"), f.get("LoggingConfig"), "destino, entrega e retenção comprovados", "Consultar destino configurado e anexar evidência de recebimento.", "NAO_VERIFICADO")
        elif op == "lambda.get-function-url-config":
            emit(r, "LM-01", "LAMBDA_URL_AUTH", r["resource"], d.get("AuthType"), "AWS_IAM", "Revisar URL sem IAM e controles compensatórios/autorização de acesso público.")
        elif op == "logs.describe-log-groups":
            for group in d.get("logGroups", []):
                emit(r, "CT-05", "LOG_RETENTION", group.get("logGroupName"), group.get("retentionInDays", "sem expiração configurada"), "prazo aprovado", "Comparar retenção efetiva com política e classificação; sem prazo definido não concluir conformidade.", "NAO_VERIFICADO")
        elif op.startswith("kubernetes."):
            for obj in d.get("items", []):
                meta = obj.get("metadata", {})
                res = meta.get("namespace", "cluster") + "/" + meta.get("name", "?")
                kind = op.split(".", 1)[1]
                spec = obj.get("spec", {})
                if kind == "cronjobs":
                    spec = spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
                elif kind in {"deployments", "daemonsets", "statefulsets", "jobs"}:
                    spec = spec.get("template", {}).get("spec", {})
                if kind in {"pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"}:
                    if spec.get("os", {}).get("name") == "windows":
                        emit(r, "CT-03", "K8S_WINDOWS_BASELINE", res, "windows", "baseline Windows aplicável", "Anexar baseline específica; os checks Linux não são aplicados.", "NAO_VERIFICADO")
                        continue
                    podsc = spec.get("securityContext", {})
                    for c in spec.get("containers", []) + spec.get("initContainers", []) + spec.get("ephemeralContainers", []):
                        sc = c.get("securityContext", {})
                        cr = res + "/" + c.get("name", "?")
                        emit(r, "CT-03", "K8S_PRIVILEGED", cr, sc.get("privileged"), False, "Remover privilégio ou registrar exceção aprovada para componente de infraestrutura.")
                        emit(r, "CT-03", "K8S_NONROOT", cr, sc.get("runAsNonRoot", podsc.get("runAsNonRoot")), True, "Declarar não root e validar UID efetivo; tratar exceções de infraestrutura.")
                        emit(r, "CT-03", "K8S_ESCALATION", cr, sc.get("allowPrivilegeEscalation"), False, "Definir allowPrivilegeEscalation=false quando aplicável.")
                        emit(r, "CT-03", "K8S_READONLY", cr, sc.get("readOnlyRootFilesystem"), True, "Definir filesystem somente leitura e volumes explícitos para escrita.")
                        profile = sc.get("seccompProfile", podsc.get("seccompProfile", {})).get("type")
                        emit(r, "CT-03", "K8S_SECCOMP", cr, profile, "RuntimeDefault ou Localhost validado", "Adotar seccomp aplicável e validar perfil local quando usado.", "VERIFICADO" if profile == "RuntimeDefault" else "DESVIO_OBSERVADO" if profile == "Unconfined" else "NAO_VERIFICADO")
                        drop = (sc.get("capabilities") or {}).get("drop")
                        emit(r, "CT-03", "K8S_CAP_DROP", cr, None if drop is None else "ALL" in drop, True, "Remover capabilities por padrão e justificar adições necessárias.")
                        if ":latest" in c.get("image", "") or (c.get("image") and "@sha256:" not in c["image"]):
                            emit(r, "IM-01", "K8S_IMAGE_REFERENCE", cr, c.get("image"), "identidade/digest rastreável", "Correlacionar imageID em runtime ao artefato aprovado; tag sozinha não comprova linhagem.", "NAO_VERIFICADO")
                    for key in ("hostNetwork", "hostPID", "hostIPC"):
                        if spec.get(key) is True:
                            emit(r, "CT-03", "K8S_" + key.upper(), res, True, False, "Revisar namespace de host e exceção autorizada do workload.")
                elif kind in {"validatingwebhookconfigurations", "mutatingwebhookconfigurations"}:
                    for hook in obj.get("webhooks", []):
                        emit(r, "DP-01", "WEBHOOK_FAILURE_POLICY", res + "/" + hook.get("name", "?"), hook.get("failurePolicy"), "política de falha aprovada", "Identificar webhook de segurança e avaliar Ignore/Fail com disponibilidade, escopo e exceções.", "NAO_VERIFICADO")

    controls = []
    for ident, title, needs, where, action in CONTROL_CATALOG:
        obs = [o for o in observations if o["control"] == ident]
        evidence = [r.get("ref", r["id"]) for r in records if ident in related(r["operation"])]
        deviations = sum(o["status"] == "DESVIO_OBSERVADO" for o in obs)
        controls.append({"id": ident, "title": title, "status": "DESVIO_OBSERVADO" if deviations else "NAO_VERIFICADO",
                         "observations": len(obs), "verified_fields": sum(o["status"] == "VERIFICADO" for o in obs),
                         "deviations": deviations, "needs": needs, "where": where, "action": action,
                         "evidence": "; ".join(dict.fromkeys(evidence)),
                         "reason": "Desvio de critério técnico proposto; validar exceção e baseline interna." if deviations else "Há comprovações externas/critério/cobertura a revisar; observações positivas não aprovam o requisito inteiro."})
    return controls, observations


def write_csv(path, rows, headers):
    with Path(path).open("w", encoding="utf-8-sig", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            # Evita fórmulas em planilhas ao abrir nomes controláveis por terceiros.
            writer.writerow({k: ("'" + str(row.get(k, "")) if str(row.get(k, "")).startswith(("=", "+", "-", "@")) else row.get(k, "")) for k in headers})


def md(value):
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def inventory(records):
    paths = {
        "eks.describe-cluster": [("cluster", "arn", "EKS")],
        "eks.describe-nodegroup": [("nodegroup", "nodegroupArn", "EKS_NODEGROUP")],
        "ec2.describe-instances": [("Reservations[].Instances[]", "InstanceId", "EC2")],
        "ec2.describe-volumes": [("Volumes[]", "VolumeId", "EBS")],
        "ecs.describe-tasks": [("tasks[]", "taskArn", "ECS_TASK")],
        "ecs.describe-services": [("services[]", "serviceArn", "ECS_SERVICE")],
        "ecs.describe-task-definition": [("taskDefinition", "taskDefinitionArn", "ECS_TASK_DEFINITION")],
        "ecr.describe-repositories": [("repositories[]", "repositoryArn", "ECR_REPOSITORY")],
        "ecr.describe-images": [("imageDetails[]", "imageDigest", "ECR_IMAGE")],
        "lambda.list-functions": [("Functions[]", "FunctionArn", "LAMBDA")],
        "efs.describe-file-systems": [("FileSystems[]", "FileSystemId", "EFS")],
        "secretsmanager.list-secrets": [("SecretList[]", "ARN", "SECRET_METADATA")],
    }
    output = []
    for r in records:
        if r["status"] != "ok" or not isinstance(r.get("data"), dict):
            continue
        for path, ident, kind in paths.get(r["operation"], []):
            values = [r["data"]]
            for part in path.split("."):
                key = part.replace("[]", "")
                values = [x for v in values for x in ((v.get(key) or []) if part.endswith("[]") else [v.get(key)]) if isinstance(v, dict) and isinstance(x, dict)]
            for obj in values:
                output.append({"kind": kind, "resource": obj.get(ident, "identidade ausente"), "account": r.get("account"), "region": r.get("region"), "parent": r["resource"], "evidence": r.get("ref", r["id"])})
        if r["operation"].startswith("kubernetes."):
            for obj in r["data"].get("items", []):
                m = obj.get("metadata", {})
                output.append({"kind": r["operation"], "resource": m.get("namespace", "cluster") + "/" + m.get("name", "?"), "account": r.get("account"), "region": r.get("region"), "parent": r["resource"], "evidence": r.get("ref", r["id"])})
    return output


def generate_report(inputs, out, manual=None):
    records, manifests = [], []
    for number, source in enumerate(inputs, 1):
        source = Path(source)
        loaded = load_evidence(source)  # verificar tudo antes de criar a saída
        manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
        manifests.append({"source": "S" + str(number), "path": str(source.resolve()), "state": manifest.get("state"), "scope": manifest.get("scope"), "tool_versions": manifest.get("tool_versions"), "created_at": manifest.get("created_at"), "finished_at": manifest.get("finished_at")})
        records.extend({**r, "ref": "S" + str(number) + "/" + r["id"]} for r in loaded)
    declarations = []
    if manual:
        raw = json.loads(Path(manual).read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or not isinstance(raw.get("items"), list):
            raise ValueError("Evidência manual precisa conter items[]")
        ids = {c[0] for c in CONTROL_CATALOG}
        for item in raw["items"]:
            if not isinstance(item, dict) or item.get("control") not in ids or not all(item.get(k) for k in ("resource", "reference", "description", "collected_at", "owner")):
                raise ValueError("Declaração manual inválida; consulte examples/manual-evidence.json")
            declarations.append({k: item[k] for k in ("control", "resource", "reference", "description", "collected_at", "owner")})
    controls, observations = analyze(records)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    write_csv(out / "CONTROLES.csv", controls, list(controls[0]))
    obs_headers = ["id", "control", "check", "status", "account", "region", "resource", "observed", "criterion", "evidence", "action", "collected_at"]
    write_csv(out / "OBSERVACOES.csv", observations, obs_headers)
    actions = [{"id": "AC-" + c["id"], "control": c["id"], "resource": "escopo do requisito", "origin": c["status"], "action": c["action"], "evidence": c["evidence"], "owner": "A definir", "due_date": "A definir", "priority": "A avaliar", "closure_evidence": c["needs"], "status": "A revisar"} for c in controls]
    actions += [{"id": "AC-" + o["id"], "control": o["control"], "resource": o["resource"], "origin": o["status"], "action": o["action"], "evidence": o["evidence"], "owner": "A definir", "due_date": "A definir", "priority": "A avaliar", "closure_evidence": "Nova evidência do mesmo recurso + avaliação da exceção/baseline", "status": "A revisar"} for o in observations if o["status"] == "DESVIO_OBSERVADO"]
    write_csv(out / "PLANO-ACAO.csv", actions, list(actions[0]))
    inv = inventory(records)
    write_csv(out / "INVENTARIO.csv", inv, ["kind", "resource", "account", "region", "parent", "evidence"])
    write_csv(out / "EVIDENCIAS.csv", records, ["ref", "source", "operation", "account", "region", "profile", "resource", "collected_at", "status", "complete", "error", "directory", "file", "sha256"])
    write_json(out / "RESULTADO.json", {"generated_at": utc_now(), "sources": manifests, "controls": controls, "observations": observations, "manual_declarations": declarations})
    errors = [r for r in records if r["status"] != "ok"]
    lines = ["# Preparação da auditoria — relatório de evidências", "", "Gerado em " + utc_now(), "",
             "**Este relatório não certifica conformidade.** VERIFICADO vale somente para um campo/critério observacional. Os requisitos completos ainda exigem revisão de cobertura, baseline, exceções e evidências externas.", "",
             "## Como conferir", "", "1. Revise escopo e falhas abaixo. Conta/região fora das fontes não foi avaliada.",
             "2. Em CONTROLES.csv, selecione o requisito. Em OBSERVACOES.csv, confira recurso e valor observado.",
             "3. Resolva S1/EV-000001 em EVIDENCIAS.csv e abra o JSON correspondente na coleta original.",
             "4. Preencha evidências externas e revise PLANO-ACAO.csv; não há remediação automática.", "",
             f"Consultas: {len(records)}; não completas: {len(errors)}; recursos inventariados: {len(inv)}; observações: {len(observations)}.", "", "## Escopo e cobertura", ""]
    for source in manifests:
        lines += [f"- {source['source']}: estado={source['state']}; início={source['created_at']}; fim={source['finished_at']}; ferramentas={json.dumps(source['tool_versions'], ensure_ascii=False)}; escopo={json.dumps(source['scope'], ensure_ascii=False)}."]
        if source["state"] != "finished":
            lines += ["  **COLETA INTERROMPIDA/INCOMPLETA: módulos posteriores podem não ter sido consultados.**"]
    lines += ["", "Os IDs de conta/região associados ao Kubernetes são declarados pelo operador; confira o contexto com o cluster EKS antes de correlacionar fontes.", "",
              "## Os 21 itens", "", "| Item | Situação | Campos verificados / desvios | Complemento necessário | Onde buscar |", "|---|---|---|---|---|"]
    lines += [f"| {c['id']} — {md(c['title'])} | {c['status']} | {c['verified_fields']} / {c['deviations']} | {md(c['needs'])} | {md(c['where'])} |" for c in controls]
    lines += ["", "## Observações técnicas por recurso", "", "Critérios são a baseline técnica proposta no guia. Confirmar aprovação interna e exceções antes de tratar um desvio como não conformidade formal.", "", "| ID / item | Recurso | Check / observado | Resultado | Evidência | Ação |", "|---|---|---|---|---|---|"]
    lines += [f"| {o['id']} / {o['control']} | {md(o['resource'])} | {md(o['check'])}: {md(o['observed'])} | {o['status']} | {o['evidence']} | {md(o['action'])} |" for o in observations]
    lines += ["", "## Falhas, limites e amostras", "", "| Evidência | Operação | Recurso | Situação / código |", "|---|---|---|---|"]
    lines += [f"| {r['ref']} | {r['operation']} | {md(r['resource'])} | {r['status']} / {r['error']} |" for r in errors]
    if not errors:
        lines += ["Nenhuma falha registrada nas consultas presentes; isto não comprova cobertura de ambientes não selecionados."]
    lines += ["", "## Evidências externas declaradas", "", "Declarações do operador não foram verificadas automaticamente e não alteram o status dos controles.", ""]
    for item in declarations:
        lines += [f"- {md(item['control'])} / {md(item['resource'])}: {md(item['description'])}; referência={md(item['reference'])}; owner={md(item['owner'])}; data={md(item['collected_at'])}."]
    lines += ["", "## Texto-base para resposta ao auditor", "", 
              "Foi realizado levantamento de leitura no escopo e nas datas registrados. Os resultados estão relacionados por requisito, recurso e evidência. As configurações observadas não substituem comprovação de eficácia dos controles. As pendências de coleta, aprovação de baseline, cobertura e documentação externa estão identificadas no plano de ação, cujo responsável e prazo serão definidos e aprovados internamente.", "",
              "## Integridade e limites", "", "Os SHA-256 foram conferidos antes da análise. Eles detectam divergência entre arquivo e manifesto local; não autenticam a origem AWS, o coletor ou a identidade do operador. Guarde a coleta original e o relatório em repositório corporativo controlado. Não enviar evidências corporativas para repositório público.", "",
              "Datas são de observação, não data de início da eficácia do controle. Não foram lidos valores de Secrets Manager/Kubernetes Secrets nem executados testes de credenciais, exec, deploy ou remediação."]
    text = "\n".join(lines) + "\n"
    (out / "RELATORIO.md").write_text(text, encoding="utf-8")
    doc = render_markdown(text, "Relatório de evidências da auditoria")
    (out / "RELATORIO.html").write_text(doc, encoding="utf-8")
    return {"controls": len(controls), "observations": len(observations), "incomplete_queries": len(errors), "inventory": len(inv)}
