# Guia interno de configuração segura — Kubernetes, contêineres e imagens

| Controle documental | Valor |
|---|---|
| Identificador sugerido | GUIA-CONTAINERS-001 |
| Versão desta proposta | 0.1 — preparada em 10/11/2026 |
| Estado | **Proposta técnica para revisão e aprovação interna** |
| Owner do documento | Preencher equipe responsável |
| Aprovadores | Preencher Segurança e Plataforma, conforme governança interna |
| Escopo aprovado | Preencher contas, regiões, clusters, workloads e ambientes |
| Benchmark aplicável | Preencher nome, edição/versão e perfil adotados |
| Próxima revisão | Definir conforme política interna e mudanças relevantes |
| Evidências de aprovação e aplicação | Vincular páginas/tickets/execuções internos |

**Como usar esta página:** consultar a regra da camada, identificar quem a aplica e anexar a evidência indicada. A redação “deve” descreve a baseline proposta. Após aprovação interna, registrar a versão vigente; antes disso, não apresentar esta página como prova de um controle já implementado.

## 1. Objetivo e limites

Estabelecer uma referência única para configurar, construir, liberar e operar imagens e contêineres com controles verificáveis. O guia atende ao item “existência de guias de configuração segura” da lista de auditoria e organiza os requisitos relacionados. **A existência do guia não demonstra aplicação nem eficácia.** Essa demonstração exige evidência por ambiente e recurso.

Escopo técnico: imagens base e de aplicação, registry, CI/CD, Kubernetes/EKS, nós EC2, ECS em EC2/Fargate e controles relacionados de Lambda. Não substitui as políticas corporativas de acesso, vulnerabilidades, senhas, retenção, backup, mudanças e aceitação de risco. Em caso de conflito, registrar a divergência e obter decisão da autoridade interna; não presumir prioridade deste rascunho.

## 2. Quem faz o quê

| Papel | Responsabilidade | Evidência esperada |
|---|---|---|
| Segurança / DevSecOps | Definir baseline, critérios dos scanners e validação de risco | Regra versionada, benchmark, relatório e decisão rastreável. |
| Plataforma / Foundation | Aplicar configuração do cluster, nó, rede, admission e esteira sob sua autoridade | IaC/Helm/AMI versionados, revisão e configuração efetiva. |
| Dono da imagem base | Manter origem, dependências, hardening, suporte e rebuild | Receita, digest, SBOM, scans e liberação vinculados. |
| Time da aplicação | Validar compatibilidade, permissões, logs, dados e consumo da base | Build/testes, release, deployment e comportamento em runtime. |
| Operação / equipe da ferramenta de segurança | Garantir cobertura, saúde, políticas, alertas e resposta | Console/relatório por ativo e período, com tratamento registrado. |
| Autoridade de risco | Aprovar exceções conforme governança vigente | Justificativa, controle compensatório, escopo, validade e reavaliação. |

Os nomes das equipes são papéis, não atribuição formal de pessoas. Confirmar a matriz de responsabilidade internamente.

## 3. Processo e pontos de controle

```text
Origem autorizada → Receita de build versionada → Build e testes
  → Scans e validação da baseline → Decisão / gate da camada
  → Publicação do digest + evidências no registry/repositório apropriado
  → Deploy pela esteira existente → Confirmação do digest em runtime
  → Monitoramento / reavaliação → Correção ou exceção com prazo
```

Cada passagem precisa preservar o vínculo entre imagem, versão/digest, commit, execução, evidências e decisão. Reconstruir uma base não atualiza aplicações já construídas: consumidores afetados precisam passar pelo seu próprio rebuild, teste e deploy.

**Aplicação ao processo documentado:** GitHub Actions continua sendo a esteira; Helm/Argo CD continuam no caminho de deploy descrito. Os documentos existentes registram scans e aprovação na primeira camada de base e uma pendência de aprovação equivalente na camada derivada. Antes de afirmar que todas as camadas aplicam o mesmo gate, anexar execuções reais de ambas. O tipo de aprovação, humana ou automática, deve ser confirmado pela configuração vigente.

### 3.1 Registro mínimo por liberação

| Objeto | Identidade e vínculo mínimo |
|---|---|
| Origem | Registry, nome, referência observada, digest e origem autorizada. |
| Imagem construída | Digest, arquitetura/plataforma, receita e commit. |
| Execução | Workflow/job/run ID, data UTC, ferramentas e versões. |
| Evidência | Scan, SBOM, assinatura/attestation quando exigidas, resultado e local controlado. |
| Decisão | Regra aplicada, resultado, responsável/autoridade, exceção e validade quando houver. |
| Consumo | Aplicação, ambiente, cluster/namespace/workload ou task/função e digest/versão efetivos. |

## 4. Controles por camada

### 4.1 Imagens base e imagens de aplicação

| ID | Regra proposta | Como aplicar e conferir | Evidência |
|---|---|---|---|
| IMG-01 | Usar origem autorizada e identidade rastreável | Registrar o digest resolvido por plataforma. Tags podem facilitar a distribuição, mas não substituem a identidade do conteúdo. | Origem, digest pai/filho, manifesto e execução. |
| IMG-02 | Reduzir a superfície da imagem | Instalar somente componentes necessários; manter receita e dependências revisadas; excluir ferramentas de debug desnecessárias da distribuição produtiva. | Dockerfile/receita, revisão e inventário/SBOM. |
| IMG-03 | Executar aplicação sem root, quando compatível | Definir usuário e validar UID/permissões efetivas. Nome de usuário, isoladamente, não comprova UID não zero. | Receita, security context/task definition e teste funcional. |
| IMG-04 | Impedir segredos no artefato | Não incorporar senha, token, chave privada ou credencial em camadas, argumentos ou arquivos de build. Usar o mecanismo aprovado de segredo de build/runtime. | Configuração e resultado do controle de segredos, sem valores sensíveis. |
| IMG-05 | Avaliar vulnerabilidades e configuração antes da liberação | Reusar scanners existentes. Registrar data do feed/scan, digest, política e exceções; não converter ausência de finding em garantia absoluta. | Reports de scan e gate da execução real. |
| IMG-06 | Atualizar componentes dentro da política de suporte e SLA | Relacionar finding aplicável, correção disponível e plano de rebuild. Vulnerabilidade sem fix exige tratamento, não aprovação silenciosa. | Finding, versão corrigida/mitigação, decisão e nova avaliação. |
| IMG-07 | Produzir e verificar evidências exigidas | Vincular SBOM e proveniência ao digest; quando assinatura/attestation forem exigidas, comprovar a verificação no gate. | Artefato, resultado da verificação e identidade autorizada. |

### 4.2 Kubernetes / EKS e workloads Linux

O Pod Security Standards distingue `Privileged`, `Baseline` e `Restricted`. Selecionar perfil por classe de workload, versão de Kubernetes e necessidade operacional. Aplicar gradualmente `audit`/`warn` antes de `enforce` quando necessário para avaliar impacto; **não confundir aviso com bloqueio**. A política aprovada deve registrar versão e exceções. [Referência Kubernetes](https://kubernetes.io/docs/concepts/security/pod-security-standards/).

| ID | Regra proposta | Como aplicar e conferir | Evidência |
|---|---|---|---|
| K8S-01 | Acesso humano e de serviço com menor privilégio | Relacionar federação/IAM, EKS access entries e RBAC. Revisar `cluster-admin`, wildcard e contas de emergência; inventariar o modo legado de autenticação quando usado. | Entradas de acesso, roles/bindings, revisão de acesso e proprietário. |
| K8S-02 | Conter privilégios de workloads de aplicação | Avaliar `privileged=false`, `runAsNonRoot=true` e `allowPrivilegeEscalation=false`; aplicar ao contêiner e considerar herança válida do pod. | Manifesto efetivo e teste de execução/compatibilidade. |
| K8S-03 | Restringir escrita e capacidades | Usar root filesystem somente leitura e volumes explícitos para escrita; remover capabilities desnecessárias. `drop: ALL` é a baseline proposta para aplicações, com adições justificadas. | Security context, volumes e exceção quando necessária. |
| K8S-04 | Restringir chamadas ao kernel | Adotar perfil seccomp compatível, como `RuntimeDefault`; perfil `Localhost` exige arquivo e gestão no nó. Não usar `Unconfined` sem justificativa aprovada. | Perfil declarado, presença/gestão do perfil quando local e teste. |
| K8S-05 | Evitar compartilhamento do host por aplicações | Revisar `hostNetwork`, `hostPID`, `hostIPC`, `hostPath`, mounts sensíveis e acesso ao socket do runtime. Componentes de infraestrutura podem precisar de exceção específica. | Manifesto, justificativa, escopo e revisão da exceção. |
| K8S-06 | Delimitar identidade do workload | Usar service account específica quando necessária; reduzir permissões Kubernetes e AWS. Desabilitar montagem automática de token nos workloads que não usam a API. | Service account, bindings, role/pod identity e configuração do pod. |
| K8S-07 | Controlar consumo e isolamento | Definir requests/limits e quotas conforme dimensionamento; separar workloads/ambientes conforme arquitetura e requisitos de isolamento. | Manifestos, quotas, testes de carga e decisão de capacidade. |
| K8S-08 | Aplicar políticas de rede e exposição | Restringir fluxos necessários e interfaces administrativas. NetworkPolicy só produz bloqueio se houver implementação compatível e enforcement ativo; provar efeito em teste autorizado. | Política, CNI/configuração e teste de tráfego permitido/negado. |
| K8S-09 | Admission coerente com a política | Identificar quais controles bloqueiam publicação/deploy. Definir escopo, failure policy, disponibilidade e exceções; um webhook instalado não comprova uma política efetiva. | Regra, configuração e teste autorizado de admissão. |

Os controles de security context têm escopo e herança específicos; validar os campos no nível correto de pod/contêiner. [Referência de security context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/). O requisito de enforcement da rede está na [documentação de NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

**Exemplo de configuração de aplicação Linux — não é um deployment completo:**

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: aplicacao
      # Definir image, portas, volumes, recursos e probes no manifesto real.
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
```

Não aplicar esse trecho indiscriminadamente em agentes de segurança, CSI/CNI, Windows ou componentes que exigem privilégios. Validar UID, diretórios de escrita, recursos e compatibilidade antes de promover a mudança.

### 4.3 Nós EC2 e execução ECS/Fargate

| ID | Regra proposta | Como aplicar e conferir | Evidência |
|---|---|---|---|
| HOST-01 | Baseline do SO identificada e medida | Relacionar AMI/versão/perfil ao benchmark aprovado. Inventário de AMI não substitui relatório de benchmark do SO. | AMI/receita e relatório datado por ativo ou amostra justificada. |
| HOST-02 | Patch conforme modelo operacional | Em nós imutáveis, preferir o mecanismo de atualização/substituição aprovado; em hosts mutáveis, seguir janela e executor definidos. Não usar dois executores concorrentes sem desenho explícito. | Scan, plano de atualização, mudança e nova avaliação. |
| HOST-03 | Sincronização de hora verificada | Conferir fonte e estado NTP/chrony no host sob gestão do cliente. Horário atual, isoladamente, não comprova sincronização contínua. | `chronyc tracking/sources` ou mecanismo equivalente, host e data. |
| ECS-01 | Task definitions revisadas | Avaliar privilégio, usuário, filesystem, roles, segredos, recursos, rede e logs por revisão efetivamente utilizada. | Task definition, serviço/task e execução que a liberou. |
| ECS-02 | Aplicabilidade por sistema operacional | No ECS Linux, `readonlyRootFilesystem` omitido tem default `false`; a opção não é suportada para contêineres Windows. Usar baseline Windows específica. | OS family e regra aplicável à revisão da task. |
| FGT-01 | Responsabilidade gerenciada explicitada | Fargate não dá acesso ao host subjacente. Manter controles de imagem, identidade, rede, dados e aplicação e obter evidência adequada para controles de infraestrutura AWS. | Matriz de responsabilidade e referência de asseguração aplicável ao serviço. |

Fontes: [parâmetros ECS](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters_ec2.html), [limites Fargate](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-security-considerations.html) e [Amazon Time Sync](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configure-time-sync.html).

### 4.4 Acesso, senhas, segredos e dados

| ID | Regra proposta | Evidência e cuidados |
|---|---|---|
| SEC-01 | Política de autenticação aplicável por identidade | Aplicar a política aprovada do IdP/SSO a humanos e políticas específicas a identidades locais/técnicas. Política de senha IAM local não comprova controles do SSO, Linux ou aplicação. |
| SEC-02 | Credenciais padrão removidas | Manter checklist do provisionamento/produto, configuração e revisão do owner; não registrar senhas nem provar o controle com tentativas não autorizadas de autenticação. |
| SEC-03 | Segredos com acesso restrito e ciclo de vida | Usar mecanismo aprovado, criptografia, menor privilégio e rotação conforme risco/política. Em evidências, usar referências e metadados, nunca o valor. |
| SEC-04 | Criptografia interpretada por camada | Avaliar API data, EBS/EFS, transporte e chaves conforme requisito. No EKS 1.28+, existe envelope encryption padrão para dados da API; ausência de chave do cliente em `encryptionConfig` não prova texto claro. Validar separadamente a exigência de chave gerenciada pelo cliente. |
| SEC-05 | Persistência inventariada | Relacionar volume, aplicação, dono, classificação, acesso e retenção. PV/PVC criado não prova proteção de todo o dado da aplicação. |

Fonte para o comportamento gerenciado: [EKS envelope encryption](https://docs.aws.amazon.com/eks/latest/userguide/envelope-encryption.html).

### 4.5 Registry, logs, runtime e recuperação

| ID | Regra proposta | Evidência necessária |
|---|---|---|
| REG-01 | Registry com acesso e promoção controlados | Policies, identidades de leitura/escrita, criptografia, regra de tags/aliases, lifecycle e auditoria de publicação. ECR e JFrog devem ser avaliados separadamente. |
| REG-02 | Scan associado ao digest | Configuração do scan, cobertura do repositório, resultado concluído para o digest e política aplicada. Basic/enhanced têm escopos próprios; scan configurado não é scan executado. |
| LOG-01 | Auditoria de APIs e cluster preservada | Configuração e evidência de entrega do EKS audit e CloudTrail conforme escopo; acesso e retenção aprovados. As duas fontes registram superfícies diferentes. |
| LOG-02 | Logs transacionais utilizáveis e protegidos | Eventos necessários do aplicativo com correlação e destino, controle de acesso, retenção e mascaramento de dados sensíveis; amostra autorizada e datada. |
| RUN-01 | Proteção de runtime com cobertura comprovada | Inventário esperado versus ativos protegidos, política, modo de operação, saúde/último contato e tratamento de alertas. Não equiparar sensor instalado, scan de vulnerabilidade e antimalware. |
| RUN-02 | FIM quando exigido/aplicável | Escopo de arquivos/configurações, ativos, política e eventos. Imagem imutável ou assinatura não substitui automaticamente o requisito de monitoramento de integridade. |
| BCP-01 | Backup orientado ao dado persistente | Política, seleção/cobertura, execução e recovery point; RPO/RTO aprovados e teste de restauração com validação funcional e responsável. |

Fontes: [ECR scanning](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html) e [auditoria EKS](https://docs.aws.amazon.com/eks/latest/best-practices/auditing-and-logging.html). Prazos e cobertura são decisões internas; este guia não define retenção ou SLA arbitrários.

### 4.6 Controles relacionados de Lambda

Relacionar função, role, versão, alias e hash do pacote à execução aprovada da esteira. Revisar resource policy, event sources, URLs de `$LATEST` **e dos aliases**, permissões e tratamento de segredos. Não presumir que Lambda fora de VPC está exposta à internet: revisar o caminho de invocação e autorização.

Relacionar cada função ao destino de logging e comprovar entrega/retencão. Assinatura, quando exigida, precisa ser avaliada conforme o tipo de pacote e o mecanismo utilizado. Controles do host gerenciado exigem matriz de responsabilidade, não comandos de inspeção do SO.

Fontes: [URLs de funções e aliases](https://docs.aws.amazon.com/lambda/latest/dg/urls-configuration.html) e [logs Lambda](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-logs.html).

## 5. Verificação, exceções e tratamento

### 5.1 Como verificar a aplicação do guia

1. Selecionar escopo, versão da baseline e critério aplicável ao runtime.
2. Coletar configuração efetiva e identidade dos artefatos/ativos, seguindo o runbook.
3. Anexar evidências das ferramentas e do processo: scanner, benchmark, revisão/gate, logs, saúde, FIM e restore, conforme controle.
4. Comparar observado e esperado; separar desvio de configuração, falta de evidência e aplicabilidade ainda não decidida.
5. Registrar ação com owner, prazo aprovado, impacto e evidência de encerramento.
6. Revisar periodicamente e após mudanças relevantes de plataforma, fornecedor, receita ou política.

O kit gera observações técnicas, não uma declaração automática de conformidade. Declaração manual de evidência também exige revisão; anexar uma URL sem conteúdo verificado não encerra o requisito.

### 5.2 Registro de exceção

| Campo | O que registrar |
|---|---|
| Escopo | Contas, ambiente, recursos/digests e controle afetado. |
| Justificativa | Necessidade técnica/negócio e razão da incompatibilidade com a baseline. |
| Avaliação | Risco, impacto, dependências e autoridade responsável pela decisão. |
| Compensação | Medida concreta, sua cobertura e evidência de funcionamento. |
| Validade | Data final e gatilho de reavaliação, conforme política vigente. |
| Plano | Responsável, prazo e comprovação prevista para remoção da exceção. |

Exceção não apaga achado nem altera retroativamente a evidência. Um componente de infraestrutura privilegiado pode ser necessário; a decisão deve estar registrada em vez de marcar o ambiente inteiro como conforme ou remover privilégio sem avaliar impacto.

## 6. Relação com a lista do auditor e publicação

| Lista recebida | Seção desta página | Prova adicional |
|---|---|---|
| Guia seguro / hardening / patches | 1 a 4.3 | Aprovação, configuração real e benchmark/scan. |
| Contas / interfaces / políticas de senha / senha padrão / proteção de senha | 4.2 e 4.4 | Identidades, acesso, revisões e configuração do produto. |
| Sincronização de hora | 4.3 | Estado do host ou responsabilidade gerenciada validada. |
| Audit logs / logs transacionais | 4.5 | Entrega, amostra, acesso e retenção. |
| Antimalware / FIM | 4.5 | Cobertura, política, saúde e eventos da ferramenta efetiva. |
| Armazenamento / backup | 4.4 e 4.5 | Proteção por dado e restauração validada. |
| Registry / imagens / deploy | 3, 4.1, 4.2 e 4.5 | Digest → execução → evidência → decisão → runtime. |
| Lambda configuração / deploy / logs | 4.6 | Função/alias/hash, autorização da mudança e logs. |

**Antes de publicar como vigente:** preencher os campos de governança, validar o benchmark e o escopo com os owners, ajustar as regras às exceções autorizadas e obter aprovação registrada. A página publicada deve manter histórico de versões e apontar para evidências corporativas com acesso controlado. Esta proposta não é uma retrospectiva de controles já comprovados na empresa.
