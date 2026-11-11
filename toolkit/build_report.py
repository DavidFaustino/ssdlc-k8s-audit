#!/usr/bin/env python3
"""Verifica integridade das coletas e gera relatório offline + plano de ação."""
import argparse
import sys
from pathlib import Path

from auditlib.controls import generate_report


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True, nargs="+", type=Path, help="Uma ou mais pastas com manifest.json")
    p.add_argument("--manual", type=Path, help="JSON opcional de declarações externas, sem valores de segredos")
    p.add_argument("--out", required=True, type=Path, help="Pasta NOVA para o relatório")
    a = p.parse_args(argv)
    try:
        summary = generate_report(a.input, a.out, a.manual)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("Relatório não gerado: " + str(exc), file=sys.stderr)
        return 1
    print(str(a.out) + ": " + str(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
