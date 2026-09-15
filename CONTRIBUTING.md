# Contributing to LocalSight

Thank you for contributing! This guide covers the development workflow, standards,
and quality gates every PR must pass.

## Getting Started

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_HANDLE/localsight.git
cd localsight

# 2. Set up virtual environment
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 3. Run the full test suite
pytest tests/ -v

# 4. Start the API and worker
uvicorn apps.api.main:app --reload
# in another shell:
python -m apps.worker
```

## Branching Strategy

```
main           — production-ready code, always deployable
develop        — integration branch (optional)
feat/xxx       — feature branches (PR → main)
fix/xxx        — bug fix branches (PR → main)
docs/xxx       — documentation branches (PR → main)
```

## Commit Message Format (Conventional Commits)

LocalSight follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

[optional body]

[optional footer]
```

### Types

| Type | Use for |
|------|---------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `test` | Adding or updating tests |
| `refactor` | Code restructuring (no behavior change) |
| `perf` | Performance improvement |
| `security` | Security fix or hardening |
| `ci` | CI/CD pipeline changes |
| `build` | Build system or dependency changes |
| `chore` | Maintenance, tooling, config |

### Examples

```
feat(alerts): add MQTT channel with topic templating
fix(detector): correct bbox normalization in postprocess_yolo
docs(api): add timeline endpoint examples
test(surveillance): add ONNX lazy session initialization test
security(ssrf): block link-local metadata addresses
ci: add Trivy container vulnerability scanning
```

## Quality Gates

Every PR runs the following checks (all must pass to merge):

| Check | Tool | Fail on |
|-------|------|---------|
| Lint | ruff | Errors (warnings allowed) |
| Type check | mypy | Type errors |
| Unit tests | pytest | Any test failure |
| Dependency audit | pip-audit | Critical/high CVEs |
| SAST | CodeQL + Semgrep | Security findings |
| Container scan | Trivy | Critical CVE in image |

Run locally before pushing:

```bash
# Lint
ruff check . --target-version=py312

# Type check
mypy packages apps --ignore-missing-imports

# Tests
pytest tests/ -v

# Dependency audit
pip-audit
```

## Security Requirements

- **Never commit secrets** — not even to a feature branch. Use `python scripts/gen_env.py` to generate secrets.
- All new dependencies are reviewed for supply-chain risks before merge.
- If you add a new dependency, run `pip-audit` to check for known vulnerabilities.
- Sensitive operations (auth, encryption, key management) must include audit log entries.
- SSRF risks: any new URL-fetching code must go through `validate_egress_url()`.

## Pull Request Checklist

- [ ] `ruff check .` passes with no errors (`ruff.toml` defines the rule set)
- [ ] `mypy packages apps` passes with no type errors
- [ ] `pytest tests/ -v` passes (all 74+ tests green)
- [ ] Regression test included for any bug fix — a fix without a test that
      would have caught the bug will be sent back
- [ ] `pip-audit` shows no critical/high vulnerabilities
- [ ] Commit messages follow Conventional Commits
- [ ] New features include tests
- [ ] New API endpoints include use-case examples in the docs
- [ ] Security-sensitive changes are reviewed by a team member
- [ ] `docs/` updated if user-facing behavior changed
- [ ] Read `AGENTS.md` invariants if touching: storage backends, the detection
      pipeline, retention, subprocess handling, or the auth login path

## Code Review Expectations

Reviewers will check:
- Correctness and test coverage
- Security posture (SSRF, injection, auth bypass, crypto misuse)
- Performance implications of any new I/O or computation
- Whether the change is consistent with the existing API surface
- Whether docs/ runbook / API summary need updating

## Documentation Standards

When adding or changing a feature, update:

1. **README.md** — capabilities table if a feature is promoted to production
2. **docs/api/openapi-summary.md** — new endpoints with use-case examples
3. **docs/architecture/system-architecture.md** — data flow or component changes
4. **docs/operations/runbook.md** — operational procedures
5. **docs/USER_GUIDE.md** — operator-facing usage (with a real screenshot)

## Filing Issues

- **Bug reports**: include Python version, stack trace, steps to reproduce, and environment details.
- **Feature requests**: describe the use case, expected behavior, and how it fits the LocalSight architecture.
- **Security issues**: do NOT open a public issue. Use GitHub Private Vulnerability Reporting or email the maintainers directly.

## License

By contributing, you agree that your contributions will be licensed under the same license as LocalSight (see LICENSE).
