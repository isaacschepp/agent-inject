# Contributing to agent-inject

Thanks for your interest in contributing. This guide covers the process for
submitting changes to agent-inject.

## What We're Looking For

- Bug fixes and test improvements
- New attack modules, probes, and YAML payloads
- Documentation improvements
- Scorer implementations
- Adapter integrations

For non-trivial changes (new features, architectural changes), please open an
issue first to discuss the approach.

## Security and Responsible Disclosure

**Do not report security vulnerabilities via GitHub Issues.** See
[SECURITY.md](SECURITY.md) for our vulnerability reporting process.

When contributing attack modules or payloads:

- Payloads must target a documented vulnerability class or published research
- Include a reference (CVE, paper, OWASP category, or blog post from the
  original researcher) in the YAML `source` field
- Do not submit zero-day exploits or techniques that haven't been responsibly
  disclosed
- If your contribution demonstrates a novel attack vector, coordinate
  disclosure with the affected vendor before submitting a PR

## Development Setup

```bash
git clone https://github.com/isaacschepp/agent-inject.git
cd agent-inject
uv sync
uv run pre-commit install
```

## Running Tests

```bash
uv run pytest                          # full suite
uv run pytest tests/test_scorers/      # specific directory
uv run pytest -x                       # stop on first failure
uv run pytest --cov                    # with coverage report
```

All new code must include tests. PRs that decrease coverage below 95% will not
be merged. The CI matrix runs tests on Python 3.12, 3.13, and 3.14 across
Ubuntu, macOS, and Windows.

## Code Quality

```bash
uv run ruff check .    # lint
uv run ruff format .   # format
uv run pyright         # type check
```

Pre-commit hooks run these automatically on each commit. If CI passes, your
code meets our standards.

## Commit Messages

We use conventional commits:

```
<type>: <description>

Types: feat, fix, refactor, docs, test, chore, perf, ci
```

## Submitting a Pull Request

1. Fork the repository and create a branch from `main`
2. Implement your changes with tests
3. Ensure all CI checks pass
4. Open a PR against `main`
5. Respond to review feedback

PRs are squash-merged by the maintainer.

## Legal

By submitting a pull request, you agree that your contributions are licensed
under the project's [MIT License](LICENSE).
