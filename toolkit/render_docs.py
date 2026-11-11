#!/usr/bin/env python3
"""Gera os HTMLs locais a partir dos Markdown do kit, sem dependências."""
from pathlib import Path
from auditlib.documents import render_markdown


def main():
    root = Path(__file__).resolve().parent
    for name in ("README", "RUNBOOK", "PERMISSOES", "VALIDACAO", "CONFLUENCE-HARDENING"):
        source = root / (name + ".md")
        if source.exists():
            text = source.read_text(encoding="utf-8")
            (root / (name + ".html")).write_text(render_markdown(text, text.splitlines()[0].lstrip("# ")), encoding="utf-8")
            print(name + ".html")


if __name__ == "__main__":
    main()
