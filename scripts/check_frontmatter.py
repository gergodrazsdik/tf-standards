# /// script
# requires-python = ">=3.12"
# dependencies = ["jsonschema==4.25.1", "pyyaml==6.0.3"]
# ///
"""Validate the frontmatter of every corpus doc against the tf-review contract.

Usage: uv run scripts/check_frontmatter.py
"""

import json
import sys
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "contracts" / "corpus-frontmatter.schema.json"
CORPUS_DIRS = ("adr", "policies", "design")


def frontmatter(path: Path) -> dict:
    """Return the YAML block between the first two --- lines."""
    parts = path.read_text(encoding="utf-8").split("---\n", 2)
    if len(parts) != 3 or parts[0]:
        raise ValueError("no frontmatter block at the top of the file")
    return yaml.safe_load(parts[1])


def check(path: Path, validator: jsonschema.Draft202012Validator) -> tuple[str | None, list[str]]:
    """Return the doc's ID and the problems found in it."""
    try:
        meta = frontmatter(path)
    except (ValueError, yaml.YAMLError) as error:
        return None, [str(error)]
    problems = [error.message for error in validator.iter_errors(meta)]
    if not path.name.startswith(f"{meta.get('id')}-"):
        problems.append(f"file name must start with its id, {meta.get('id')}-")
    rego = meta.get("rego")
    if rego and not (path.parent / rego).is_file():
        problems.append(f"rego file {rego} does not exist")
    return meta.get("id"), problems


def main() -> int:
    validator = jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
    failed = False
    seen: dict[str, Path] = {}
    docs = [doc for name in CORPUS_DIRS for doc in sorted((ROOT / name).glob("*.md"))]
    for doc in docs:
        doc_id, problems = check(doc, validator)
        if doc_id in seen:
            problems.append(f"id {doc_id} is also used by {seen[doc_id].name}")
        if doc_id:
            seen[doc_id] = doc
        for problem in problems:
            failed = True
            print(f"{doc.relative_to(ROOT)}: {problem}")
    print(f"{len(docs)} docs checked")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
