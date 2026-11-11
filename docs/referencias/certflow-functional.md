# Especificações do Sistema

## Requisitos Funcionais

### 1. Distribuição de Certificados
- **Origem Única**: Operator deve consumir artefatos apenas do S3.
- **Escrita Atômica**: O sistema deve garantir que arquivos nunca sejam lidos parcialmente.
    - *Implementação*: Usar diretório temporário para download seguido de renomeação ou troca de symlink no EFS.
- **Detecção de Versão**: Suporte a polling ou eventos para detectar novos artefatos.

### 2. Gestão de Segredos
- **Separação de Responsabilidade**: Senhas armazenadas exclusivamente no AWS Secrets Manager.
- **Projeção em Arquivo**: Senhas devem ser apresentadas como arquivos ao container (via CSI Driver), não como variáveis de ambiente.

### 3. Hot Reload (Sem Downtime)
- **Monitoramento**: A aplicação deve monitorar o sistema de arquivos (`/opt/certs`) para detectar mudanças.
- **Recarregamento**: Ao detectar alteração, o contexto TLS deve ser recriado em memória.
- **Zero Restart**: O Pod Kubernetes NÃO deve ser reiniciado durante a rotação de certificados ou senhas.

## Requisitos Não-Funcionais

### Segurança
- **Criptografia em Repouso**: S3 com SSE-KMS e Secrets Manager.
- **Princípio do Menor Privilégio**: Roles IAM distintas para Operator e Aplicação.

### Disponibilidade
- **Resiliência a Falhas**: Se o S3 ou SM estiver indisponível, a aplicação deve continuar operando com a última versão válida carregada.

### Auditoria
- Todas as operações de leitura/escrita em S3 e SM devem gerar logs no CloudTrail.
