# Os 21 controles explicados

A fotografia recebida é um roteiro de assuntos a examinar. Para cada item, a conversa precisa chegar a três respostas: **qual controle existe, quais recursos ele cobre e qual evidência demonstra isso**.

## Primeiro, separe as camadas

- **Execução:** o cluster, os nós e os workloads que estão rodando.
- **Registry:** o armazenamento e a distribuição de imagens, por exemplo ECR ou JFrog.
- **Imagem:** o conteúdo empacotado — sistema, bibliotecas e aplicação.
- **Deploy:** o processo que libera uma versão e a coloca em execução.

Essas camadas se relacionam, mas uma prova não responde automaticamente por todas. Uma imagem escaneada não prova segurança do nó; um gate configurado não prova que a versão em produção passou por ele.

## Ambiente de contêineres

| ID | Item | O que significa | Exemplo de evidência |
|---|---|---|---|
| CT-01 | Guias de configuração segura | A referência interna que orienta como configurar o ambiente. | Guia aprovado, versão, escopo e aplicação demonstrada. |
| CT-02 | Contas de acesso | Quem entra ou administra, com quais permissões e autorização. | Identidades, roles, RBAC, revisão de acesso e donos. |
| CT-03 | Hardening | Reduzir exposição pela configuração: privilégios, escrita e recursos desnecessários. | Baseline e comparação com configuração efetiva. |
| CT-04 | Interfaces de acesso | Caminhos de acesso: APIs, console, SSH e interfaces administrativas. | Endpoints, rede, autenticação e justificativa. |
| CT-05 | Logs de auditoria | Quem fez o quê e quando na administração do ambiente. | Eventos de API/cluster, entrega, acesso e retenção. |
| CT-06 | Patches de segurança | Corrigir componentes vulneráveis no host e nas imagens. | Finding, SLA, atualização/rebuild e nova avaliação. |
| CT-07 | Políticas de senhas | Regras do sistema de identidade que realmente usa senha. | Política do IdP, IAM local, SO ou aplicação, conforme escopo. |
| CT-08 | Senhas padrão | Remover ou desabilitar credenciais conhecidas de instalação. | Checklist/configuração do produto e revisão do owner. |
| CT-09 | Sincronização de hora | Manter referência temporal confiável para eventos e investigações. | Estado NTP/chrony no host ou responsabilidade gerenciada documentada. |
| CT-10 | Proteção de senhas | Proteger armazenamento, entrega, acesso e ciclo de vida dos segredos. | Referências, políticas, criptografia e rotação, sem expor valores. |
| CT-11 | Antimalware | Detectar/prevenir software malicioso nos ativos aplicáveis. | Cobertura, política, saúde e tratamento de alertas. |
| CT-12 | FIM | Monitorar alterações relevantes em arquivos e configurações. | Escopo monitorado, política, eventos e tratamento. |
| CT-13 | Locais com armazenamento | Identificar onde há dados persistentes e como são protegidos. | Volumes, dono, acesso, classificação e criptografia. |
| CT-14 | Logs transacionais | Registrar operações da aplicação, seus resultados e correlação. | Amostra autorizada e sanitizada no destino de logs. |
| CT-15 | Backup | Conseguir recuperar dados e serviços após perda ou falha. | Cobertura, execução e restauração validada conforme RPO/RTO aprovados. |

O texto “locais com armazenamento” é genérico na foto: confirmar com o auditor quais tipos de dados e serviços estão incluídos.

## Imagens, registry e publicação

| ID | Item | Pergunta principal | Evidência |
|---|---|---|---|
| RG-01 | Container registry | Quem publica/baixa e como os artefatos são protegidos? | Policies, promoção, scan, criptografia, lifecycle e auditoria. |
| IM-01 | Container images | Qual conteúdo está sendo usado e quais controles o avaliaram? | Origem/digest, composição, scans, SBOM e verificações exigidas. |
| DP-01 | Container deployment process | A versão em execução veio do processo autorizado? | Revisão, testes, gates, aprovação exigida e digest implantado. |

## Lambda

| ID | Item | Pergunta principal | Evidência |
|---|---|---|---|
| LM-01 | Configuração | Quais permissões, formas de invocação e controles estão configurados? | Role, policies, interfaces, segredos e configuração da função. |
| LM-02 | Deploy | Como a versão publicada se relaciona à mudança autorizada? | Versão/alias/hash e execução do CI/CD com decisão. |
| LM-03 | Gestão de logs | Os registros necessários chegam ao destino e são protegidos? | Destino, entrega, acesso e retenção. |

## Distinções que evitam respostas erradas

- Guia escrito não é configuração aplicada.
- Sensor presente não comprova proteção ativa nem FIM.
- Scanner de vulnerabilidades não equivale a antimalware.
- Log habilitado não comprova recebimento e retenção.
- Backup concluído não comprova restauração funcional.
- Tag de imagem não substitui digest para rastrear conteúdo.
- IAM não substitui RBAC Kubernetes, IdP ou permissões da aplicação.

[Próxima leitura: identidades e segredos](02-identidades-segredos-e-rotacao.md).
