# Kit de preparação da auditoria AWS

Este pacote permite levantar o estado de **EKS/EC2, ECS/Fargate, ECR e Lambda**, relacionar as evidências aos 21 itens da lista da auditoria e preparar um plano de ação. O operador executa no seu computador de trabalho com a sessão corporativa autorizada.

## Por onde começar

1. Abra o [RUNBOOK](RUNBOOK.md): pré-requisitos, funcionamento dos scripts, execução e conferência de cada item.
2. Verifique as [permissões necessárias](PERMISSOES.md) com o administrador; o coletor registra acessos negados e continua onde consegue.
3. Execute as coletas AWS e Kubernetes e gere o relatório offline. Os comandos estão no runbook.
4. Abra `RELATORIO.html` na pasta de saída e confira os CSVs. O relatório aponta para os JSON de evidência preservados nas pastas de coleta.
5. Complete a prova externa — CI/CD, Wiz/Falcon/Qualys, IdP, JFrog, benchmark e restauração — e revise `PLANO-ACAO.csv`.

Após extrair o ZIP, você pode conferir sua consistência local com `python3 package_audit.py --verify .` (Windows: `py -3 package_audit.py --verify .`). O comando deve ser executado dentro da pasta `auditoria-aws`, onde está `package-manifest.json`. Esse hash não substitui validação corporativa da origem do kit.

Para publicar o guia interno, use [CONFLUENCE-HARDENING.html](CONFLUENCE-HARDENING.html): abra no navegador, copie o conteúdo formatado para uma página do Confluence e siga as instruções de governança. O [Markdown equivalente](CONFLUENCE-HARDENING.md) é a fonte versionável. O guia precisa de aprovação interna; a entrega não demonstra que os controles já estão implantados.

## Exemplo de execução

Troque os valores fictícios antes de executar. Cada saída deve ser uma pasta nova. Em Windows, use `py -3` no lugar de `python3`.

```bash
python3 collect_aws.py --profiles corporativo-readonly --regions sa-east-1 --expected-accounts 111122223333 --out saidas/aws-20261110-01
python3 collect_kubernetes.py --context contexto-eks-autorizado --account 111122223333 --region sa-east-1 --out saidas/k8s-20261110-01
python3 build_report.py --input saidas/aws-20261110-01 saidas/k8s-20261110-01 --out saidas/relatorio-20261110-01
```

O código de saída `2` dos coletores significa que alguma consulta ficou incompleta ou retornou erro, **não que o ambiente falhou na auditoria**. Gere o relatório para identificar os motivos. O `build_report.py` usa `0` para sucesso e `1` para erro de entrada/integridade.

## O que está no pacote

| Arquivo | Papel |
|---|---|
| `collect_aws.py` | Consulta APIs AWS com perfil/região explícitos; identifica a conta antes de coletar. |
| `collect_kubernetes.py` | Consulta objetos do contexto informado; não altera o kubeconfig. |
| `build_report.py` | Confere SHA-256 e metadados, analisa observações e gera relatório/CSVs. |
| `auditlib/` | Allowlist de consultas, sanitização, coletores e regras observacionais. |
| `examples/manual-evidence.json` | Modelo para anexar referências de evidências externas; não aprova controles automaticamente. |
| `examples/host-checks.sh` | Consultas locais de leitura a executar manualmente em host Linux autorizado. |
| `examples/iam-readonly-policy.json` | Permissões de leitura propostas para revisão do administrador; não é anexada a nenhuma identidade pelo kit. |
| `RUNBOOK.md` / `.html` | Roteiro de execução e investigação. |
| `CONFLUENCE-HARDENING.md` / `.html` | Guia de configuração segura e seu ciclo de aprovação. |
| `VALIDACAO.md` | O que foi testado e os limites da validação. |
| `tests/` | Testes locais, incluindo percurso completo com CLIs simuladas. |

## Limites que importam na apresentação

- O kit **não certifica conformidade** e não corrige configurações.
- `VERIFICADO` descreve um campo observado, não todo um requisito de auditoria.
- Logs habilitados não provam entrega; backups existentes não provam restauração; sensor presente não prova cobertura/saúde/FIM.
- Fargate e Lambda não expõem o host para inspeção do cliente. A aplicabilidade de controles do SO precisa de justificativa e revisão do auditor.
- A execução aqui foi local e simulada; nenhuma conta corporativa ou pessoal foi acessada para esta entrega.
- ECR não representa JFrog; IAM não representa todas as contas do SSO, SO ou aplicações; AWS CLI não lê RBAC Kubernetes.

O pacote não depende do Base Image Hub, Diun, Vunnel ou de qualquer PoC anterior. Não substitui GitHub Actions, Argo CD, scanners nem ferramentas já existentes.
