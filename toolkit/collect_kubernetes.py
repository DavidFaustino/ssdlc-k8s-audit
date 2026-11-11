#!/usr/bin/env python3
"""Coleta K8s de leitura em contexto explícito, sem modificar kubeconfig."""
import argparse
import sys
from pathlib import Path

from auditlib.core import EvidenceStore, Runner
from auditlib.kubernetes import collect_context


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--context", required=True, help="Contexto kubeconfig autorizado; não muda o contexto corrente")
    p.add_argument("--namespace", help="Omitir para todos os namespaces; objetos de cluster continuam no escopo")
    p.add_argument("--account", required=True, help="ID AWS declarado pelo operador; não é validado pelo Kubernetes")
    p.add_argument("--region", required=True, help="Região declarada pelo operador")
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--out", required=True, type=Path, help="Diretório NOVO")
    a = p.parse_args(argv)
    if a.timeout <= 0 or not a.account.isdigit() or len(a.account) != 12:
        p.error("Timeout ou ID de conta inválido")
    try:
        store = EvidenceStore(a.out, {"type": "kubernetes", "context": a.context, "namespace": a.namespace,
                                    "account": a.account, "region": a.region, "identity_binding": "operator_declared"})
    except FileExistsError:
        p.error("Diretório já existe; use um novo --out")
    try:
        runner = Runner(a.timeout)
        store.manifest["tool_versions"]["kubectl"] = runner.version("kubectl")
        store.save()
        collect_context(runner, store, a.context, a.namespace, a.account, a.region)
        store.finish()
    except KeyboardInterrupt:
        print("Interrompido; manifesto parcial preservado.", file=sys.stderr)
        return 130
    failures = sum(r["status"] != "ok" for r in store.manifest["records"])
    print(f"Coleta salva em {store.root}. Consultas não completas: {failures}.")
    return 2 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
