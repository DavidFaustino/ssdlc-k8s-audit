#!/usr/bin/env python3
"""Coleta AWS de leitura; use --help. Nunca executa remediação."""
import argparse
import re
import sys
from pathlib import Path

from auditlib.aws import AWSCollector, MODULES
from auditlib.core import EvidenceStore, Runner


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    auth = p.add_mutually_exclusive_group(required=True)
    auth.add_argument("--profiles", nargs="+", help="Perfis AWS CLI já autenticados; exemplo: corp-readonly")
    auth.add_argument("--ambient-session", action="store_true", help="Usar explicitamente credenciais temporárias do ambiente, sem --profile")
    p.add_argument("--regions", required=True, nargs="+", help="Regiões explicitamente autorizadas")
    p.add_argument("--expected-accounts", nargs="+", help="IDs esperados; conta diferente interrompe a coleta daquele perfil")
    p.add_argument("--modules", nargs="+", choices=MODULES, default=list(MODULES))
    p.add_argument("--max-details", type=int, default=100, help="Limite de detalhes por lista; 0 = sem limite. Omissões ficam no manifesto")
    p.add_argument("--timeout", type=int, default=120, help="Timeout por comando em segundos")
    p.add_argument("--out", required=True, type=Path, help="Diretório NOVO para esta coleta")
    a = p.parse_args(argv)
    if a.max_details < 0 or a.timeout <= 0 or any(not re.fullmatch(r"[a-z0-9-]+-\d+", r) for r in a.regions):
        p.error("Limite, timeout ou região inválida")
    scope = {"type": "aws", "profiles": a.profiles, "ambient_session": a.ambient_session, "regions": a.regions,
             "modules": a.modules, "max_details": a.max_details, "timeout": a.timeout, "expected_accounts": a.expected_accounts}
    try:
        store = EvidenceStore(a.out, scope)
    except FileExistsError:
        p.error("Diretório já existe; use um novo --out para preservar a coleta anterior")
    runner = Runner(a.timeout)
    store.manifest["tool_versions"]["aws"] = runner.version("aws")
    store.save()
    try:
        for profile in a.profiles or [None]:
            identity = runner.aws("sts", "get-caller-identity", [], a.regions[0], profile)
            account = (identity.get("data") or {}).get("Account")
            store.record("aws", "sts.get-caller-identity", "global", account, "identity", identity, profile)
            if identity["status"] != "ok" or not re.fullmatch(r"\d{12}", account or ""):
                store.record("aws", "coverage.identity", "global", account, "identity", Runner.failure("IdentityUnavailable"), profile)
                continue
            if a.expected_accounts and account not in a.expected_accounts:
                store.record("aws", "coverage.identity", "global", account, "identity", Runner.failure("UnexpectedAccount"), profile)
                continue
            for region in a.regions:
                # IAM é global: uma vez por perfil, com região operacional da primeira coleta.
                modules = [m for m in a.modules if m != "iam" or region == a.regions[0]]
                AWSCollector(runner, store, profile, account, region, a.max_details).collect(modules)
        store.finish()
    except KeyboardInterrupt:
        print("Interrompido; manifesto parcial preservado. Gere o relatório e revise a cobertura.", file=sys.stderr)
        return 130
    incomplete = sum(r["status"] != "ok" for r in store.manifest["records"])
    print(f"Coleta salva em {store.root}. Consultas não completas: {incomplete}. Gere o relatório mesmo se o código for 2.")
    return 2 if incomplete else 0


if __name__ == "__main__":
    sys.exit(main())
