#!/usr/bin/env sh
# Consultas locais de leitura. Execute MANUALMENTE apenas em host Linux autorizado.
# O kit não envia este arquivo por SSM nem acessa hosts.
# Não instala ferramentas, não usa sudo e não coleta configuração completa/segredos.

date -u '+%Y-%m-%dT%H:%M:%SZ'
hostname
uname -srm
if command -v timedatectl >/dev/null 2>&1; then
    timedatectl show -p NTPSynchronized -p NTP -p Timezone
fi
if command -v chronyc >/dev/null 2>&1; then
    chronyc tracking
    chronyc sources -v
fi
if command -v systemctl >/dev/null 2>&1; then
    for service in amazon-ssm-agent falcon-sensor qualys-cloud-agent chronyd chrony; do
        printf '\nService: %s\n' "$service"
        systemctl is-active "$service"
    done
fi
# Serviço ativo é apenas indício de presença. Saúde, política, cobertura e FIM
# exigem evidência no console da ferramenta correspondente.
