#!/usr/bin/env python3
"""Empacota só o código/docs do kit. Nunca inclui pastas de coleta corporativa."""
import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path

STATIC = {"README.md", "README.html", "RUNBOOK.md", "RUNBOOK.html", "PERMISSOES.md", "PERMISSOES.html",
          "VALIDACAO.md", "VALIDACAO.html", "CONFLUENCE-HARDENING.md", "CONFLUENCE-HARDENING.html",
          "collect_aws.py", "collect_kubernetes.py", "build_report.py", "render_docs.py", "package_audit.py", "VERSION"}


def package(root, destination):
    root, destination = Path(root), Path(destination)
    files = [root / name for name in sorted(STATIC) if (root / name).is_file()]
    for folder in ("auditlib", "tests", "examples"):
        files += [p for p in sorted((root / folder).rglob("*")) if p.is_file() and p.suffix in {".py", ".json", ".yaml", ".sh"} and "__pycache__" not in p.parts]
    manifest = {"schema_version": 1, "files": {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}}
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for p in files:
            archive.write(p, "auditoria-aws/" + p.relative_to(root).as_posix())
        archive.writestr("auditoria-aws/package-manifest.json", json.dumps(manifest, indent=2) + "\n")
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def verify(root):
    root = Path(root).resolve()
    manifest = json.loads((root / "package-manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("files"), dict) or not manifest["files"]:
        raise ValueError("Manifesto do pacote inválido")
    for name, expected in manifest["files"].items():
        path = (root / name).resolve()
        if root not in path.parents or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("Integridade do pacote divergente: " + name)
    return True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", type=Path, help="Destino do ZIP do código/docs")
    group.add_argument("--verify", type=Path, help="Pasta extraída contendo package-manifest.json")
    a = p.parse_args()
    try:
        if a.verify:
            verify(a.verify)
            print("Integridade local do pacote: OK. Não equivale a assinatura de origem.")
        else:
            digest = package(Path(__file__).resolve().parent, a.out)
            print(str(a.out) + " SHA256=" + digest)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
