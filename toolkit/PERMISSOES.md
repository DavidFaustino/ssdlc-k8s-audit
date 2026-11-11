# Permissões e fontes necessárias

O operador usa uma sessão já autenticada e autorizada. O kit não cria roles, usuários, políticas ou bindings. A lista abaixo serve para o administrador preparar um acesso de leitura temporário e restrito ao escopo. Permissões AWS e RBAC Kubernetes são autorizações distintas.

## AWS

O exemplo [iam-readonly-policy.json](examples/iam-readonly-policy.json) contém somente as ações de leitura da allowlist implementada, sem `GetSecretValue`, leitura de parâmetros SSM, invocação Lambda, download de código, execução SSM ou alterações de recursos. Há operações de leitura disponíveis na biblioteca que não são usadas em todas as rodadas; o administrador pode remover as que não pertencem aos módulos selecionados.

`Resource: "*"` no exemplo atende consultas de descoberta que não aceitam resource-level scoping; **não representa a concessão final recomendada para toda a conta**. O administrador deve separar ações e restringir recursos, contas, regiões, condições e duração da sessão quando o serviço permitir. Não anexar o exemplo automaticamente. Permissões de uma sessão resultam também de boundaries, SCPs, resource policies e outras concessões; este arquivo não calcula acesso efetivo.

| Grupo | Prefixos de leitura | Objetivo / cuidado |
|---|---|---|
| Identidade | `sts:GetCallerIdentity` | Confirmar conta/role. A AWS normalmente não exige permissão específica para esta chamada. |
| IAM | GetAccountPasswordPolicy/GetAccountSummary/ListUsers/ListRoles e leitura das policies de roles | Não lê senhas; não inclui IdP, todos os acessos locais ou uma simulação completa de permissões. |
| EKS | List/Describe de clusters, nodegroups, Fargate profiles, addons, access entries/policies e pod identities | Não concede acesso à API Kubernetes nem lê o ConfigMap legado aws-auth. |
| EC2/EFS | Describe de instâncias, AMIs, rede, volumes, snapshots próprios e EFS | Não faz login no SO. |
| ECS | List/Describe de clusters, serviços, tasks, container instances e task definitions | Não usa ExecuteCommand nem altera deployments. |
| ECR | Describe/Get de repositórios, imagens, registry scanning, replicação e policies | Não faz pull das camadas nem consulta todos os relatórios de scan. |
| Lambda | List/Get de configuração disponível, versões, aliases, resource policies, URLs e mappings | A API de listagem pode devolver Environment em memória; os valores são eliminados antes de persistir. Não chama GetFunction/download nem Invoke. |
| Logs/CloudTrail | Describe/Get de metadados, status, seletores e filtros | Não lê mensagens de logs ou histórico completo de eventos. |
| Backup | List/Get de planos, seleções, vaults, recovery points e jobs | Não inicia backup ou restauração. |
| SSM | DescribeInstanceInformation/DescribeInstancePatchStates/ListAssociations | Não dispara inventário, scan, comando ou patch. |
| Segurança | Leituras de cobertura/configuração Inspector, GuardDuty, Security Hub e Config | Recurso não habilitado ou região sem suporte pode retornar erro. O kit não ativa nada. |
| Secrets Manager/KMS | ListSecrets/DescribeKey/GetKeyRotationStatus | Somente metadados; não lê valores de segredos nem descriptografa dados. |

Para a lista exata implementada, veja `READ_OPERATIONS` em `auditlib/core.py`. O exemplo de política é derivado dessa lista. O prefixo IAM do AWS Config é `config`, embora o nome do CLI seja `configservice`.

## Kubernetes

O exemplo [kubernetes-reader.yaml](examples/kubernetes-reader.yaml) contém somente regras `get/list` dos objetos coletados. Não concede leitura a Secrets ou ConfigMaps, subrecursos `pods/log`, `pods/exec`, token requests ou recursos arbitrários. Não há binding a usuário/grupo no arquivo. A equipe de plataforma decide como e se essa role deve ser criada e associada a uma identidade existente.

Consultas cluster-wide podem revelar nomes de recursos/identidades internos. Mesmo com `--namespace`, o script também consulta objetos de cluster. Se isso ultrapassar o escopo autorizado, ajuste o acesso e a execução com o administrador; não use um contexto privilegiado apenas para eliminar erros do relatório.

EKS Access Policies e Kubernetes RBAC podem coexistir. A ausência de access entries não significa ausência de usuários: o cluster pode usar autenticação legada. Solicite ao administrador um export sanitizado do `aws-auth` e o inventário do IdP quando necessários.

## Fontes fora de AWS/Kubernetes

| Fonte | O que solicitar | Como relacionar |
|---|---|---|
| Wiz/Falcon/Qualys ou solução efetiva | Coverage, política/módulo, saúde, último contato e relatório do controle específico | Instance ID, cluster/node/pod ou digest, escopo e data. |
| GitHub Actions / Git | Revisão, execução de scans/gates, aprovação de mudança e artefatos | Commit, run ID, receita, digest/hash e decisão. |
| Argo CD / Helm | Release desejada e sincronizada, revisão e workload final | Aplicação, cluster, namespace, versão e digest em runtime. |
| JFrog | Acesso, configuração do proxy/registry, auditoria, scans e armazenamento dos reports | Repositório, artefato/digest, policy e data. |
| IdP/SSO | Política de autenticação e revisão de acessos | Aplicação/role/grupo, dono e data da revisão. |
| Backup/restore externo | Cobertura dos dados e teste de restauração | Volume/aplicação, RPO/RTO aprovados, resultado e owner. |
| Baseline/Confluence | Guia aprovado, versão, benchmark/perfil e exceções | Controle, runtime, ambiente e prova de aplicação. |

Não colocar tokens de APIs dessas ferramentas neste kit nem em `manual-evidence.json`. O JSON manual registra referência e descrição, não autenticação ou export de segredo.
