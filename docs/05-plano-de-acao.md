# Plano de ação da auditoria

O plano transforma um resultado em trabalho verificável. Não é necessário que toda pendência seja uma vulnerabilidade: pode faltar comprovar cobertura, obter permissão, aprovar baseline ou esclarecer aplicabilidade.

## Classificar antes de agir

| Situação | Tratamento |
|---|---|
| Desvio observado | Revisar critério e exceção; planejar mudança autorizada e validar novamente. |
| Falta de evidência | Identificar fonte/owner e obter comprovação do período e escopo. |
| Coleta incompleta | Resolver acesso, timeout ou limite e repetir em pasta nova. |
| Aplicabilidade incerta | Documentar runtime/responsabilidade e alinhar com auditor/autoridade interna. |

## Uma ação bem definida

| Campo | Como preencher |
|---|---|
| Requisito e recurso | Qual controle, conta/região/cluster/workload/digest está afetado. |
| Situação e prova | Valor observado ou motivo da pendência, com referência de evidência. |
| Ação | Mudança ou coleta específica, evitando “melhorar segurança” sem entrega concreta. |
| Responsável | Quem tem autoridade para executar/coordenar. |
| Prazo | Data acordada; não adotar um SLA inventado. |
| Dependências | Acesso, janela, fornecedor, equipe e testes necessários. |
| Exceção | Aprovação, escopo, compensação e validade, quando aplicável. |
| Encerramento | Evidência nova que permite avaliar se a ação resolveu o problema. |

## Exemplo: atualização de segredo

- **Pendência:** CSI confirmado, mas configuração de atualização automática e recarga da aplicação não demonstradas.
- **Ação:** confirmar configuração e executar demonstração autorizada no ambiente escolhido, relacionando versão na origem, montagem e uso pela aplicação.
- **Responsáveis:** Plataforma e time da aplicação, a confirmar.
- **Prazo:** acordar internamente.
- **Encerramento:** evidências datadas da configuração, entrega e adoção, sem incluir o segredo.

O [gerador de relatório](../toolkit/RUNBOOK.md) produz PLANO-ACAO.csv com ações por requisito e desvios por recurso. Revise duplicatas, prioridade, owner e datas. Preserve o relatório automático original e identifique a revisão humana.
