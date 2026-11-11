# Escopo do Projeto Certflow

## Contexto Inicial

Este projeto visa resolver o problema de distribuição segura e dinâmica de certificados (Keystore e Truststore) para aplicações Java Quarkus.

### Objetivos Chave
- **Centralização**: Truststore no AWS S3, Keystore no AWS Secrets Manager (senhas) e S3 (artefatos).
- **Automação**: O Operator deve consumir esses artefatos e materializá-los no container.
- **Resiliência**: Lib Quarkus com TLS Registry para suportar **Hot Reload** (atualização em runtime sem reiniciar o Pod).
- **Segurança**: Suporte a rotação de segredos e artefatos sem downtime. Integridade garantida via escritas atômicas.

### Componentes Envolvidos
- **Operator Custom**: Gerencia o ciclo de vida dos arquivos no EFS.
- **Lib TLS Registry**: Componente da aplicação para recarregar configurações TLS.
- **Infraestrutura**: AWS S3, AWS Secrets Manager, Kubernetes (EFS, PVC).
