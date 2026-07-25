from __future__ import annotations

import argparse
from pathlib import Path

import yaml
import yara


def validate_sigma_file(path: Path) -> int:
    """Validate every non-empty Sigma document in *path* and return its count."""
    documents = yaml.safe_load_all(path.read_text(encoding="utf-8"))
    document_number = 0
    sigma_document_count = 0

    while True:
        document_number += 1
        try:
            document = next(documents)
        except StopIteration:
            break
        except yaml.YAMLError as exc:
            raise ValueError(
                f"invalid Sigma YAML: {path} (document {document_number}): {exc}"
            ) from exc

        if document is None:
            continue
        if (
            not isinstance(document, dict)
            or "detection" not in document
            or "logsource" not in document
        ):
            raise ValueError(
                f"not a Sigma-like rule: {path} (document {document_number})"
            )
        sigma_document_count += 1

    if sigma_document_count == 0:
        raise ValueError(
            f"not a Sigma-like rule: {path} "
            "(document 1: no non-empty YAML documents)"
        )
    return sigma_document_count


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse Sigma YAML and compile YARA rules.")
    ap.add_argument("--results-root", required=True, type=Path)
    args = ap.parse_args()
    yaml_count = 0
    yara_count = 0
    for path in args.results_root.rglob("*.yml"):
        validate_sigma_file(path)
        yaml_count += 1
    for path in args.results_root.rglob("*.yar"):
        yara.compile(filepath=str(path))
        yara_count += 1
    print(f"PASS: parsed {yaml_count} Sigma YAML files and compiled {yara_count} YARA files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
