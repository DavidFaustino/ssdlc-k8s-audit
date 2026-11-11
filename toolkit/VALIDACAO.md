# Validação e limites do kit

**Versão:** 0.1.0-20261110. **Ambiente de desenvolvimento:** macOS, Python 3.14.7. **Validação corporativa:** não realizada nesta entrega.

## O que foi exercitado

- Allowlist de leitura bloqueia comando de mutação antes de iniciar processo.
- Falha de autenticação/permissão, timeout, CLI ausente, JSON inválido e token de paginação não resultam em inventário vazio considerado completo.
- Diretórios novos e evidências escritas a cada consulta preservam coletas anteriores.
- Sanitização remove campos de segredo das fixtures: environment, comandos, anotações, HTTP headers, parâmetros arbitrários de storage e docker labels.
- Hash/metadados e coerência de status/fonte/operação são conferidos antes da análise.
- Limite de detalhamento aparece como parcial, com contagem de omitidos.
- EKS access/nodegroups, ECS task definition e Lambda URLs/policies de aliases foram exercitados com respostas controladas.
- Relatório cobre os 21 requisitos, mantém pendências de eficácia, gera ações por recurso e escapa conteúdo HTML/CSV.
- Fluxo real dos CLIs Python foi executado com executáveis AWS/kubectl locais simulados, sem rede e sem credenciais. Os mesmos arquivos de coleta são consumidos pelo gerador real de relatório.
- Pacote portátil exclui pastas de saída e detecta arquivo alterado após extração.
- Os nomes de 92 operações da allowlist e os nomes/parâmetros obrigatórios de 86 chamadas exercitadas foram conferidos contra os modelos públicos do botocore 1.44.0, sem chamadas à AWS. Isso não substitui execução real nem valida as permissões IAM efetivas.

## Como repetir

Na raiz extraída:

```bash
python3 -m unittest discover -s tests -v
```

Windows: `py -3 -m unittest discover -s tests -v`. Dois testes de integração usam shebang POSIX e são ignorados no Windows; os testes de biblioteca permanecem disponíveis. Não houve execução nativa Windows nesta entrega. A versão mínima de Python especificada é 3.10; os testes locais foram executados na versão indicada acima, não em toda a matriz de versões.

O teste `test_clean_copy_all_modules_and_report` cria CLIs simuladas que devolvem exemplos sintéticos, roda os dois coletores e o relatório, confere os 21 controles e verifica que um segredo sintético não aparece nas saídas. Isso valida a integração local do software, **não a compatibilidade real de todas as APIs/permissões no seu ambiente**.

## Revisão independente

Uma revisão de código independente executou a suíte inicial e encontrou: superfícies adicionais de campos sensíveis, omissão das URLs/policies de aliases Lambda e aceitação de metadados incoerentes. Esses casos receberam regressões, falharam antes das correções e passaram depois. Também foi corrigida a interpretação do default de readonlyRootFilesystem em ECS Linux, preservando tratamento específico Windows.

A revisão documental identificou a consulta de replicação ECR com nome inválido; foi substituída por `ecr describe-registry` e a política de exemplo agora usa `ecr:DescribeRegistry`. O cenário recebeu teste de regressão. Demais documentos foram confrontados com as CLIs, seus limites e as referências locais. A colagem real no editor Confluence não foi testada.

## O que precisa ser conferido no trabalho

1. Sessão, role/conta, regiões e autorização de leitura; restrições de SCP, boundaries e RBAC.
2. Versões reais do AWS CLI/kubectl, serviços habilitados, APIs suportadas e conectividade/VPN.
3. Relação entre contexto K8s e cluster/conta/região; o vínculo informado pelo operador não é validado automaticamente.
4. Escopo e atualidade dos dados: workloads/versões em execução, detalhamento omitido, amostras e fontes externas.
5. Aplicabilidade e aprovação da baseline, benchmark/perfil, retenção, SLA, risco e exceções.
6. Evidências de eficácia: recebimento de logs, cobertura/saúde antimalware/FIM, gates, verificação de assinatura, teste de restauração e revisão de acessos.

Um coletor pode retornar `2` porque um recurso opcional não existe, falta permissão ou uma operação foi amostrada. Não converter automaticamente esse código em desvio do ambiente. O relatório lista os motivos para julgamento do operador.

As referências oficiais consultadas estão no guia de hardening e no escopo. O pacote não foi publicado no GitHub nem no Confluence; o operador decide seu destino corporativo.
