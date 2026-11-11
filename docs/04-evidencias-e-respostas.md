# Como demonstrar os controles ao auditor

A resposta precisa ligar **critério → recurso → configuração/resultado → evidência → responsável**. Evite responder apenas com o nome da ferramenta.

## Três níveis de afirmação

| Afirmação | O que realmente demonstra |
|---|---|
| “Usamos Secrets Manager.” | Existência/uso informado de um serviço. |
| “A rotação está configurada para este segredo.” | Configuração de um controle no escopo indicado. |
| “Esta rotação foi concluída e o workload adotou a nova versão.” | Evidência de execução e consumo, com data e escopo. |

O terceiro nível não deve ser inferido do primeiro. A mesma distinção vale para antimalware, FIM, logs, hardening e backup.

## Antes da reunião

Alinhe contas, regiões, ambientes, clusters/workloads, responsáveis, período de evidência e política/benchmark aplicáveis. A lista da fotografia não definiu por si só esses limites nem prazos de retenção/SLA.

## Como conferir o resultado do kit

1. No [runbook](../toolkit/RUNBOOK.md), execute as coletas no ambiente autorizado.
2. Abra o relatório e confira primeiro escopo, falhas e limites de cobertura.
3. Escolha o requisito em CONTROLES.csv e a observação em OBSERVACOES.csv.
4. Resolva a referência em EVIDENCIAS.csv e abra o JSON original.
5. Compare recurso, conta/região, instante, operação e valor observado.
6. Acrescente prova do processo/console/host e registre a conclusão humana em cópia revisada ou sistema interno.

O status VERIFICADO do kit vale para o campo/critério observado. Os requisitos inteiros podem permanecer NAO_VERIFICADO por dependerem de eficácia, cobertura, aprovação ou outra fonte. Falta de permissão é limitação de coleta, não prova de recurso ausente.

## Respostas que você pode adaptar

**Quando o controle está documentado, mas a cobertura ainda não foi medida:**

> O processo está descrito e a ferramenta foi informada como utilizada. Estamos reconciliando os recursos abrangidos e as evidências por ativo; a cobertura total ainda não foi comprovada.

**Quando existe observação técnica:**

> Na coleta de [data], o recurso [identificador e escopo] apresentou [configuração]. A referência [evidência] comprova esse campo. A conclusão sobre o requisito depende também de [complemento].

**Quando existe desvio ou falta de comprovação:**

> Identificamos [desvio ou pendência] em [escopo]. Registramos ação para [responsável a confirmar], com [prazo a aprovar] e encerramento condicionado a [evidência].

Não afirmar conformidade, prazo ou aceitação de risco que a autoridade interna ainda não decidiu.

## Evidência adequada por tema

| Tema | Configuração | Eficácia / complemento |
|---|---|---|
| Logs | Fonte/destino/retencão configurados. | Eventos recebidos, consulta autorizada, proteção e cobertura. |
| Antimalware / FIM | Política e ativos vinculados. | Saúde, último contato, eventos/testes autorizados e resposta. |
| Backup | Seleção e política. | Execução e restauração funcional validada. |
| Hardening | Guia, regra e versão. | Configuração efetiva/benchmark e exceções aprovadas. |
| Deploy | Workflow e gate definidos. | Execução da versão realmente implantada e decisão correspondente. |
| Segredos | Identidade, permissões e atualização configuradas. | Versão entregue e adoção da credencial nova pela aplicação. |

[Próxima leitura: plano de ação](05-plano-de-acao.md).
