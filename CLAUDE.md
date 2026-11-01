# tf-standards

The standards corpus `tf-review` retrieves and enforces: ADRs in `adr/`, policies in `policies/`, each Markdown doc next to its Rego and Rego tests. The plan is in `../tf-review/docs/plan.md`.

## Commands

- `just policy-test`: `opa fmt`, `opa check`, `conftest verify` and the frontmatter check
- `just lint`: every check the CI `lint` job runs
- `just hooks`: install the git hooks

## Conventions

- Every doc starts with frontmatter matching `contracts/corpus-frontmatter.schema.json`, a copy of the contract `tf-review` owns (`just contracts-sync`). Its file name starts with its ID.
- Only `status: accepted` docs are retrievable. Retire a doc by setting `status: superseded` and `superseded_by`; don't delete it.
- Each Rego package is named after its doc (`adr001`, `pol001`), and `deny` returns `msg` plus `details` with `doc_id`, `address`, `severity` and the top-level `attribute` that failed, which the reviewer's evidence pointers use.
- Run Rego tests with `conftest verify`, the OPA build that enforces them. Standalone `opa` is only for `fmt` and `check`.
