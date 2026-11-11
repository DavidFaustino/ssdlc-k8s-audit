# Runbook — preparar e conferir as evidências da auditoria AWS

**Público:** engenheiro que precisa executar a coleta, compreender o que foi observado e demonstrar evidências ao auditor. **Data de preparação:** 10/11/2026. **Auditoria informada:** 11/11/2026.

## 1. Resultado que você vai obter

Ao terminar, haverá pastas separadas de coleta AWS, coleta Kubernetes e relatório. Cada consulta terá um JSON sanitizado, data UTC, origem, recurso, conta/região e SHA-256. O relatório relacionará esses arquivos aos requisitos e produzirá um plano de ação editável.

Os scripts não alteram configuração, não disparam deploy, não invocam Lambda, não executam comandos em pods/hosts e não usam SSM Run Command. A autenticação acontece antes, pela sessão corporativa que você já utiliza.

O fluxo é:

```text
Lista do auditor + contas/regiões/contextos autorizados
  → collect_aws.py: identifica conta, consulta serviços, sanitiza, guarda evidências
  → collect_kubernetes.py: consulta contexto explícito, sanitiza, guarda evidências
  → build_report.py: confere hashes/metadados e avalia campos observáveis
  → RELATORIO + CONTROLES + OBSERVACOES + INVENTARIO + PLANO-ACAO
  → operador complementa processo/console/host e revisa a resposta da auditoria
```

As duas coletas são independentes. Você pode gerar o relatório apenas com AWS, apenas com Kubernetes ou com ambas. Requisitos sem evidência permanecem pendentes. Os scripts não reconhecem automaticamente que um contexto K8s corresponde a uma conta AWS; essa ligação é declarada e deve ser conferida pelo operador.

## 2. Antes de executar: escopo e acesso

Registre em uma nota interna: contas, regiões, clusters, namespaces, ambiente, owner, escopo da auditoria, janela temporal da evidência e o benchmark/política aprovados. Não existe no kit uma conta, região, retenção ou SLA corporativo presumido.

Você precisa de Python **3.10 ou superior**, AWS CLI **v2** e, para coletar Kubernetes, `kubectl` compatível com seus clusters. Não há pacote pip a instalar. Use distribuição e procedimento de instalação aprovados pela empresa.

```bash
python3 --version
aws --version
kubectl version --client
```

No PowerShell:

```powershell
py -3 --version
aws --version
kubectl version --client
```

Se faltar Python/AWS CLI, pare e instale pelo canal corporativo. Sem kubectl, você ainda consegue coletar AWS e registrar a lacuna de K8s.

Consulte [PERMISSOES.md](PERMISSOES.md). Ter permissão AWS para descrever EKS não concede acesso à API Kubernetes. O coletor não concede permissões e não contorna acessos negados.

## 3. Autenticar e conferir a conta

Use o perfil de leitura aprovado. Se sua empresa usa IAM Identity Center, autentique com o procedimento já configurado:

```bash
aws sso login --profile corporativo-readonly
aws sts get-caller-identity --profile corporativo-readonly --region sa-east-1
```

Confira `Account` e `Arn`. **Os valores `corporativo-readonly`, `sa-east-1` e `111122223333` usados neste runbook são exemplos.** Substitua pelos autorizados. Se a conta ou role não for a esperada, pare antes de coletar.

Para uma sessão temporária já fornecida pelo ambiente, utilize `--ambient-session` no coletor, em vez de `--profiles`. O kit não lê seus arquivos de credenciais para exportação e não solicita chaves no código.

## 4. Coletar AWS

Abra o terminal na pasta extraída do kit. Execute em uma linha; o mesmo formato funciona no PowerShell trocando `python3` por `py -3`:

```bash
python3 collect_aws.py --profiles corporativo-readonly --regions sa-east-1 --expected-accounts 111122223333 --out saidas/aws-20261110-01
```

Para várias regiões/perfis, informe todos explicitamente:

```bash
python3 collect_aws.py --profiles conta-pci-readonly conta-servicos-readonly --regions sa-east-1 us-east-1 --expected-accounts 111122223333 444455556666 --out saidas/aws-20261110-02
```

O conjunto de contas esperado é uma allowlist, não um vínculo individual perfil→conta. Confira os `sts.get-caller-identity` no manifesto. Uma conta fora da lista gera `UnexpectedAccount` e não recebe consultas de inventário.

### O que acontece dentro deste script

1. Cria a pasta de saída; recusa reaproveitar uma pasta existente para preservar coletas anteriores.
2. Executa STS uma vez por perfil; sem identidade válida, registra falha e não consulta os serviços daquele perfil.
3. Executa os módulos selecionados em cada região. IAM é global e é consultado só na primeira região de cada perfil.
4. AWS CLI usa paginação automática. Falhas, tokens de continuidade e limites de detalhes ficam no manifesto.
5. Sanitiza as respostas antes de gravar: remove environment values, comandos/args, user data, tags, descrições e outros campos arbitrários. Preserva referências necessárias sem ler Secrets Manager GetSecretValue nem Kubernetes Secrets. Algumas APIs de configuração retornam campos sensíveis em memória ao CLI; eles são excluídos das saídas.
6. Grava evidência e atualiza o manifesto a cada consulta. Não depende de terminar tudo para preservar o que já foi coletado.

### Módulos e limites

| Módulo | Entrada real | Processamento | Evidência produzida / limite |
|---|---|---|---|
| `eks` | Clusters da região | Descreve cluster, node groups, Fargate profiles, access entries/policies, addons e pod identities | Configuração AWS do EKS; não inclui RBAC legado `aws-auth`, custom AMIs/Karpenter completos ou políticas efetivas do pod. |
| `ec2` | Instâncias e AMIs em uso | Consulta AMI, SGs, VPCs, subnets, ACLs e flow logs | Identidade de hosts e exposição configurada; não executa benchmark no SO nem teste de conectividade. |
| `ecs` | Clusters, serviços e tasks correntes | Resolve task definitions e container instances | Configuração real das definições referenciadas, incluindo tasks independentes em execução; não é histórico de todas as revisões/stopped tasks. |
| `ecr` | Repositórios privados da região | Consulta registry scanning/replicação, policies, lifecycle e metadados de imagens | Configuração e digests; não baixa imagens nem todos os findings/SBOMs/assinaturas. JFrog é externo a este módulo. |
| `lambda` | Funções da região | Consulta versões, aliases, policy, URL, concorrência, code signing e event source mappings | Identidade/configuração de deploy; não baixa código, executa função ou coleta env values. |
| `iam` | Usuários e roles da conta | Consulta política de senha, summary, roles e policies anexadas/inline | Inventário IAM; não é revisão completa de effective permissions, boundaries, SCPs, IdP ou credenciais de aplicação. |
| `logs` | Log groups da região | Retenção, subscription filters e amostra de metadados do stream mais recente | Não baixa mensagens. A amostra de stream pode retornar `partial/PaginationIncomplete` por limitar a 1; isso é amostra declarada, não lista completa de streams. |
| `cloudtrail` | Trails visíveis | Status e seletores | Não equivale a consultar logs da organização, Event Data Stores ou comprovar conteúdo e prazo de retenção do bucket. |
| `storage` | EBS, snapshots próprios, EFS e metadados Secrets Manager | Inventário de persistência e proteção configurada | Não lê conteúdo de arquivos/segredos; S3, RDS e outros serviços exigem coleta específica se entrarem no escopo. |
| `backup` | Plans, selections, vaults e jobs disponíveis | Relaciona políticas, recovery points e restore jobs | Não executa restore. Não cobre sozinho Velero ou backup externo; API pode limitar o histórico consultável. |
| `security` | Inspector, GuardDuty, Security Hub e Config disponíveis | Consulta cobertura/configuração | Não habilita serviços e não comprova licença, saúde ou política dos agentes Wiz/Falcon/Qualys. |
| `ssm` | Managed instances | Coleta metadados e patch states, lista associations | Só enxerga instâncias gerenciadas e scans existentes; não executa inventory/scan/patch no host. |

Por padrão são consultados todos os módulos. Para uma rodada menor, por exemplo:

```bash
python3 collect_aws.py --profiles corporativo-readonly --regions sa-east-1 --modules eks ec2 ecs ecr lambda logs --out saidas/aws-recorte-01
```

Esse recorte **não avalia os módulos omitidos**. A lista selecionada fica no manifesto.

O padrão `--max-details 100` limita detalhamentos **por lista**, não a listagem inicial da API. Omissões geram `DetailLimit`, com total, selecionados e omitidos. Use `--max-details 0` para detalhamento sem esse limite, considerando tempo e volume. Cada comando tem timeout de 120 segundos e retries padrão limitados a três tentativas no SDK usado pelo CLI. `--timeout 240` aumenta o tempo máximo por processo; ele inclui paginação e retries.

## 5. Coletar Kubernetes

Confira o contexto existente; o kit não altera sua configuração:

```bash
kubectl config get-contexts
kubectl --context contexto-eks-autorizado cluster-info
```

Compare o endpoint mostrado com o EKS autorizado. Se ainda não tiver kubeconfig, use o procedimento da equipe de plataforma para criá-lo. O kit não o faz automaticamente.

```bash
python3 collect_kubernetes.py --context contexto-eks-autorizado --account 111122223333 --region sa-east-1 --out saidas/k8s-20261110-01
```

Para limitar os objetos namespaced a um namespace, acrescente `--namespace pagamentos`. Objetos de cluster — nodes, clusterroles, admission, PV e StorageClasses — continuam sendo consultados com a autorização do contexto. Se seu escopo proibir acesso a esses objetos, não execute este coletor sem ajustar com a equipe responsável; acessos negados serão registrados.

O script consulta workloads/pods, nós, namespaces, RBAC, service accounts, serviços/ingresses, NetworkPolicies, admission, storage e quotas. Não pede Secrets ou ConfigMaps; remove anotações, comandos, argumentos e valores literais de variáveis das respostas. Não usa `exec`, `logs`, `apply`, `patch` nem `use-context`.

Também são omitidos HTTP headers de probes, atributos/parâmetros arbitrários de storage e docker labels, pois podem conter valores sensíveis. Essa exclusão reduz a capacidade de avaliar esses campos automaticamente. Como anotações são removidas, a associação IRSA em service account deve ser obtida em evidência sanitizada separada com a equipe responsável.

**Saída esperada:** `manifest.json` e `evidence/EV-000001.json...`. Campos de identidade da conta/região são declarados pelo operador; não são autenticação AWS deste coletor.

## 6. Interpretar o encerramento

| Código | Significado | O que fazer |
|---|---|---|
| `0` no coletor | Consultas presentes terminaram sem falha registrada | Conferir escopo, evidências e controles externos; não é aprovação da auditoria. |
| `2` no coletor | Há erro/limite/amostra/paginação incompleta | Gerar o relatório mesmo assim; identificar cada código e completar o que for necessário. |
| `130` | Operador interrompeu | Preservar pasta e gerar relatório parcial; executar nova rodada em outra pasta. |
| `1` ou outro erro inesperado | Erro de execução | Guardar mensagem, não tratar coleta como completa; diagnosticar antes de usar conclusões. |

`ResourceNotFoundException`, `NoSuchEntity`, `RepositoryPolicyNotFoundException` e similares podem representar recurso opcional ausente, região/conta errada ou outra condição. O kit preserva o código e não transforma automaticamente em “não aplicável” ou desvio.

## 7. Gerar relatório e plano de ação

```bash
python3 build_report.py --input saidas/aws-20261110-01 saidas/k8s-20261110-01 --out saidas/relatorio-20261110-01
```

Com apenas AWS:

```bash
python3 build_report.py --input saidas/aws-20261110-01 --out saidas/relatorio-aws-01
```

O script confere cada hash, o vínculo dos metadados com o manifesto e os caminhos antes de analisar. Falha de integridade impede a geração: recupere a evidência original ou faça outra coleta; não edite o JSON nem recalcule o hash para esconder divergência.

| Arquivo | Como usar |
|---|---|
| `RELATORIO.html` / `.md` | Resumo de escopo, 21 requisitos, observações, falhas e declarações externas. |
| `CONTROLES.csv` | Uma linha por requisito da fotografia, com necessidade de comprovação e onde buscar. |
| `OBSERVACOES.csv` | Um check por recurso/campo, com critério, valor observado e referência de evidência. |
| `EVIDENCIAS.csv` | Resolve a referência `S1/EV-...` para pasta original, arquivo, hash, comando lógico, data e status. |
| `INVENTARIO.csv` | Recursos coletados e a evidência que os identifica; não é CMDB completa. |
| `PLANO-ACAO.csv` | Pendências por requisito e desvios técnicos por recurso; preencher owner, prioridade e prazo. |
| `RESULTADO.json` | Mesma análise estruturada para consumo técnico futuro, sem integração automática com o Hub. |

Abra os CSVs como UTF-8 com vírgula como separador se o Excel não separar colunas automaticamente. Campos iniciados por caracteres de fórmula recebem apóstrofo de proteção.

## 8. Conferir uma evidência do início ao fim

Exemplo: o relatório mostra `CT-05 / EKS_AUDIT / DESVIO_OBSERVADO / S1/EV-000003`.

1. Abra `OBSERVACOES.csv` e confirme conta, região, cluster, instante, observado `false` e critério `true`.
2. Em `EVIDENCIAS.csv`, procure `S1/EV-000003`. S1 é a primeira pasta informada a `build_report.py`; resolva o campo `directory` + `file`.
3. Abra o JSON, confira `metadata.operation=eks.describe-cluster` e `data.cluster.logging.clusterLogging`. Localize a entrada com `types` contendo `audit`.
4. Confira no console **EKS → cluster → Observability/Logging**. Depois confira o destino no CloudWatch e a retenção aplicável. O nome da seção pode variar conforme a UI.
5. Registre se o cluster está no escopo, se há exceção e quem pode alterar o controle. Somente então finalize a ação; o kit não habilita logs nem aceita risco.

Um `VERIFICADO` para `EKS_AUDIT=true` só confirma essa configuração observada. CT-05 ainda exige entrega, acesso, retenção e cobertura. O mesmo raciocínio vale para criptografia, versão de imagem e outros checks positivos.

## 9. Conferir cada item da fotografia

| Item | Primeiro lugar para abrir | Complemento para responder ao auditor |
|---|---|---|
| CT-01 — Guia seguro | Guia Confluence deste kit + baseline interna | Versão aprovada, aprovador, escopo, exceções e evidência de aplicação. Guia novo sem aprovação não deve ser apresentado como controle vigente. |
| CT-02 — Contas | IAM e access entries EKS; RBAC no K8s | IdP/SSO, revisões de acesso, roles de serviço, emergência e donos. `aws-auth` legado não foi coletado porque ConfigMaps estão excluídos; solicitar export sanitizado ao owner. |
| CT-03 — Hardening | OBSERVACOES: `K8S_*`, `ECS_*`; AMI/nodegroup | Benchmark do SO/imagem e política aplicada. Privilégios necessários de agentes de infraestrutura exigem exceção, não remoção indiscriminada. |
| CT-04 — Interfaces | Endpoint EKS, SGs, serviços/ingresses, ECS Exec, Lambda URL | Justificativa, autenticação e caminho real de rede. Uma regra SG não prova sozinha alcance externo. |
| CT-05 — Audit logs | `EKS_AUDIT`, CloudTrail, log groups/filters/streams | Recebimento recente, integridade, restrição de acesso, retenção e centralização. CloudTrail de API não substitui audit Kubernetes. |
| CT-06 — Patches | AMIs, SSM patch state, cobertura Inspector | Relatório Wiz/Qualys/Trivy, SLA, idade do scan e correção/rebuild. Não instalar patches manualmente em nós imutáveis sem o processo aprovado. |
| CT-07 — Política de senha | IAM get-account-password-policy | Política do IdP, SO e apps, conforme identidade realmente usada. Não aplicar política de IAM local ao SSO. |
| CT-08 — Senha padrão | Receita de imagem/provisionamento e checklist do produto | Evidência de desabilitação/remoção pelo owner. O kit não tenta autenticar com senha padrão. |
| CT-09 — Hora | Host Linux autorizado: `examples/host-checks.sh` | Registrar host e data, `NTPSynchronized`/chrony; para Fargate/Lambda documentar responsabilidade gerenciada e validar aplicabilidade. |
| CT-10 — Proteção de senha | Secret references, Secrets Manager e KMS/processo | Controle de acesso, rotação, tratamento no aplicativo e configuração de criptografia. Não anexar o segredo. |
| CT-11 — Antimalware | Inventário AWS/nós e agentes no K8s | Console da solução: ativo, política, último contato, modo de proteção, cobertura e tratamento de alertas. Não confundir scan de CVE com antimalware. |
| CT-12 — FIM | Console/política de integridade | Arquivos monitorados, ativos cobertos, eventos/testes autorizados e tratamento. Sensor presente não comprova FIM. |
| CT-13 — Armazenamento | EBS/EFS e PV/PVC; task definitions/Lambda | Acesso, classificação, criptografia, dono, retenção; confirmar com auditor qual interpretação de “locais com armazenamento” está no escopo. |
| CT-14 — Log transacional | ECS logging, coletores e configuração do app | Amostra sanitizada de transação com correlação no destino, retenção e acesso. Metadado de stream não comprova conteúdo. |
| CT-15 — Backup | Plans/selections/recovery points/jobs e solução K8s | Cobertura dos dados persistentes, RPO/RTO aprovados e restauração testada. Restore job existente não comprova validação funcional da recuperação. |
| RG-01 — Registry | ECR config/policy/lifecycle/scanning | JFrog: permissões, proxy/cache, auditoria, scanners e lifecycle. Scan policy não comprova scan concluído do digest. |
| IM-01 — Imagens | Digests ECR e `imageID` dos pods/tasks | Scan/SBOM/assinatura/attestation vinculados ao digest e execução real de verificação no gate. Tag não é prova de identidade imutável. |
| DP-01 — Deploy | Task definitions, GitHub Actions e Argo CD/Helm | Execução real com revisão de mudança, gates, aprovações exigidas e digest final em runtime. |
| LM-01 — Configuração | Função, role, policy, URL, VPC/KMS | Privilégios efetivos, segredos e exposição. Lambda fora de VPC não é automaticamente exposta por rede; revisar caminhos de invocação. |
| LM-02 — Deploy Lambda | Versões, aliases, CodeSha256 e code signing config | Vincular pacote/versão ao CI e aprovação. Configuração de assinatura não prova verificação para toda forma de pacote. |
| LM-03 — Logs Lambda | LoggingConfig e destino | Entrega recente, acesso, retenção e eventos esperados. Não invocar funções produtivas apenas para fabricar evidência. |

## 10. Complementar prova externa e texto de resposta

Copie `examples/manual-evidence.json` para um arquivo de trabalho e substitua os exemplos por referências reais. Campos: `control`, `resource`, `reference`, `description`, `collected_at` e `owner`. Prefira URL do relatório interno/ticket/Confluence controlado e data com timezone. Não informe tokens, senhas, segredos nem dados pessoais desnecessários.

```bash
python3 build_report.py --input saidas/aws-20261110-01 saidas/k8s-20261110-01 --manual evidencias-externas.json --out saidas/relatorio-complementado-01
```

O kit registra a declaração; ele não abre a URL nem valida automaticamente a afirmação e não muda o controle para aprovado por causa dela.

Depois da análise humana, registre a conclusão formal em cópia revisada de `CONTROLES.csv` ou no sistema interno: estado final, revisor, data, referência da decisão e exceção aplicável. Preserve o resultado automático original; a revisão humana deve ser identificável separadamente.

Exemplo honesto quando falta evidência:

> Na coleta de [data UTC], o cluster [identificador] apresentou [configuração observada]. A referência [ID] contém a comprovação. A cobertura/eficácia de [controle] ainda depende de [fonte]. A pendência foi registrada para [equipe], com prazo [a aprovar].

Exemplo quando há evidência completa revisada pelo responsável:

> Para os recursos [escopo], o controle [nome] está descrito na baseline [versão aprovada]. A evidência [relatório/execução], de [data], demonstra [resultado específico]. Exceções [IDs/nenhuma verificada] foram revisadas por [responsável].

Não substitua os campos por afirmações genéricas como “toda AWS está coberta”.

## 11. Transformar pendências em plano de ação

Abra `PLANO-ACAO.csv`. Uma ação por requisito representa comprovação pendente; ações `AC-OBS-*` representam desvios de configuração observados. Revise duplicatas e junte ações que dependam da mesma mudança, mantendo os IDs/evidências.

Para cada ação, preencha: owner real, impacto/risco validado, prioridade, data-alvo aprovada, dependência, eventual exceção com validade e evidência de encerramento. O kit deixa esses campos a definir porque não conhece seu SLA nem a autoridade de aceitação.

Exemplo de encerramento: para log audit desabilitado, a prova pode exigir mudança autorizada, nova configuração e recebimento confirmado no destino. Não encerre apenas porque um ticket foi aberto.

## 12. Diagnóstico e critérios de parada

| Sinal | Interpretação | Próxima ação |
|---|---|---|
| `ExecutableNotFound` | AWS CLI/kubectl ausente no PATH | Instalar/configurar pelo canal aprovado e repetir em pasta nova. |
| `AccessDenied*`, `Unauthorized*`, `Forbidden` | A sessão não autoriza a consulta | Solicitar leitura ao owner; registrar limitação. Não significa recurso ausente. |
| `ExpiredToken*`, `InvalidClientTokenId`, `UnrecognizedClientException` | Sessão inválida/expirada | Renovar login corporativo e conferir STS antes de nova rodada. |
| `Timeout` | O processo inteiro não concluiu no prazo | Conferir rede/VPN/endpoint, volume e timeout; não desligar verificação TLS. |
| `PaginationIncomplete` | Há token ou amostra limitada | Identificar comando. Em log streams, é amostra intencional; nos demais, repetir/diagnosticar antes de declarar cobertura. |
| `DetailLimit` | Listagem conhecida maior que detalhamento | Rever omitidos e usar `--max-details 0` se autorizado e necessário. |
| `ResourceFailures` | API retornou falhas por recurso mesmo com HTTP 200 | Abrir evidência, verificar recursos afetados e repetir conforme causa. |
| `InvalidJSON`, `CLIError` | CLI/operação incompatível ou erro não classificado | Validar AWS CLI v2 atual e comando documentado, sem compartilhar logs debug com credenciais. |
| Falha de integridade | Arquivo diverge do manifesto/metadados | Parar o uso daquela fonte; recuperar original ou repetir coleta. |
| Fonte sem estado `finished` | Coleta interrompida ou abortada | Identificar módulos não consultados e fazer nova rodada. |

O resultado pode ficar `NAO_VERIFICADO` mesmo sem falha de API: isso acontece quando falta critério, evidência de eficácia ou fonte externa.

## 13. Confluence e manutenção

Abra `CONFLUENCE-HARDENING.html`, copie o conteúdo renderizado e cole em uma página interna com edição restrita. Confira se tabelas, listas e blocos de código foram preservados pela sua versão do editor. O arquivo HTML é uma fonte de cópia, não um formato universal de importação do Confluence.

Preencha owner, aprovadores, versão e data de revisão. Classifique como proposta até aprovação. A página deve apontar para evidências corporativas controladas, não para segredos ou para arquivos do computador pessoal. Consulte o Markdown para manter o conteúdo em Git.

## 14. Preservação e repetição

Guarde as pastas originais de coleta junto do relatório, com acesso restrito e retenção corporativa. O relatório referencia seus caminhos; copiar apenas o HTML perde a capacidade de conferir os JSONs. Uma nova execução recebe nova pasta. Guarde a versão do kit junto dos resultados.

SHA-256 comprova consistência com o manifesto local, não assinatura/autenticidade da AWS. Para cadeia de custódia formal, use armazenamento e processo de evidências aprovados pela empresa. Não publique o conjunto em repositório público.

Para conferir o kit sem AWS, execute:

```bash
python3 -m unittest discover -s tests -v
```

O teste completo usa CLIs locais simuladas; seus resultados são validação do software, não evidência do ambiente corporativo. Veja [VALIDACAO.md](VALIDACAO.md).
