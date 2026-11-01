# List the recipes
default:
    @just --list

# Start Claude Code with the reviewer and demo repos in reach
[group('dev')]
claude *args:
    CLAUDE_CODE_ADDITIONAL_DIRECTORIES_CLAUDE_MD=1 claude \
      --add-dir ../tf-review --add-dir ../tf-review-demo {{ args }}

# Install the git hooks
[group('dev')]
hooks:
    lefthook install

# Run every pre-commit check on all files; the CI lint job runs this too
[group('dev')]
lint: policy-test
    yamllint --strict .
    actionlint
    pinact run --check
    shellcheck scripts/*.sh
    ruff check scripts
    gitleaks git --no-banner

# Format check, unit tests, a real policy run and frontmatter check for the corpus
[group('dev')]
policy-test:
    opa fmt --fail --list adr policies
    opa check --strict adr policies
    conftest verify --policy adr --policy policies
    conftest test --no-color --all-namespaces --parser json --policy adr --policy policies tests/empty-plan.json
    uv run scripts/check_frontmatter.py

# Copy the frontmatter contract from a tf-review checkout next to this repo
[group('dev')]
contracts-sync:
    cp ../tf-review/docs/contracts/corpus-frontmatter.schema.json contracts/
