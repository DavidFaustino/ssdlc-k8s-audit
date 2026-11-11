# Fontes e situação da preparação

Reunião e documentação preparadas em 11/11/2026. Separar sempre estes estados:

| Material | Origem | O que comprova |
|---|---|---|
| 21 itens | Fotografia fornecida pelo usuário. | Lista de assuntos solicitados, não benchmark ou conformidade. |
| CSI + Secrets Manager + IAM | Relato do usuário em 11/11/2026. | Arquitetura informada; configuração e eficácia ainda não medidas. |
| CertFlow | Documentos recuperados do acervo Engineer. | Desenho/requisitos; não implantação ou teste concluído. |
| Cert Automation | Ficha de planejamento sem escopo técnico. | Existência de tema registrado; identidade com CertFlow não confirmada. |
| Kit de scripts | Pacote desenvolvido e testado localmente em 10/11/2026. | Funcionamento local com fixtures; não estado real da AWS. |
| Guia Confluence | Proposta técnica preparada para revisão interna. | Conteúdo de referência; aprovação e aplicação precisam de evidência. |

## Documentos recuperados preservados

Os arquivos abaixo foram copiados sem alterações de conteúdo. O hash permite conferir a preservação da cópia; não valida a implantação descrita nem autentica sua origem por assinatura.

| Arquivo em referencias/ | SHA-256 |
|---|---|
| certflow-architecture.md | 04a1fb59e3b3ef053baa84f1c7bd68921b5748b1d64bb514a8b401e470609bb9 |
| certflow-functional.md | 24f79365be17f584026480e61c6cb88d9b5f4436d6712de9f6d81c273747fc44 |
| certflow-scope.md | f2a06ba66503ea8b97cc3c3cd0569151f209a3372ff604de827ee27d48412828 |

Os caminhos locais do acervo pessoal e nomes de organizações não são necessários à publicação e não foram incluídos neste índice. Não foram copiados resultados corporativos, credenciais ou o acervo inteiro.

## Limites atuais e continuidade

- O usuário informou que ainda não havia executado o kit no trabalho.
- Nenhuma conta AWS foi acessada nesta preparação.
- Não foram medidos CSI/provider, IRSA/Pod Identity, aplicação consumidora ou CertFlow.
- O kit não inclui avaliação automatizada de todos os recursos específicos do CSI ou teste de rotação.
- Próxima etapa operacional: alinhar escopo/permissões e obter evidências conforme o runbook.
- Mudanças em controles reais seguem autorização e processo da empresa.

As referências públicas de funcionamento ficam junto às explicações e no guia de hardening. O contexto interno foi usado para orientar a discussão, sem promover proposta ou relato a fato medido.
