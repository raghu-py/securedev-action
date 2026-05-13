<div align="center">

# SecureDev Action

**A self-contained Docker GitHub Action that scans code and configuration files for security risks.**

Built by **Raghu Soni**

<br>

![GitHub Actions](https://img.shields.io/badge/GitHub-Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Action-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-Security%20Scanner-3776AB?style=for-the-badge&logo=python&logoColor=white)
![SARIF](https://img.shields.io/badge/SARIF-Compatible-6f42c1?style=for-the-badge)

<br>

[Overview](#overview) ·
[Usage](#usage) ·
[Inputs](#inputs) ·
[Outputs](#outputs) ·
[Rules](#security-rules) ·
[Local Development](#local-development) ·
[FAQ](#faq)

</div>

---

## Overview

**SecureDev Action** is a lightweight, self-contained security scanner for GitHub Actions.

It scans source code, scripts, Docker files, infrastructure files, configuration files, and text-based project files for common security problems such as:

- Hardcoded secrets
- Dangerous command execution
- SQL injection patterns
- Unsafe deserialization
- Weak cryptography
- Insecure Docker configuration
- Risky Kubernetes settings
- Insecure GitHub Actions usage
- Debug and unsafe configuration values

> The goal is simple: catch serious security mistakes before they reach production.

---

## Key Features

| Feature | Description |
|---|---|
| Docker Action | Runs inside a Docker container |
| Self-contained | Does not depend on an external scanner service |
| Multi-language scanning | Supports Python, JavaScript, PHP, Ruby, Java, Go, shell, config, Docker, Kubernetes, IaC, and more |
| Critical-only failure by default | Fails CI only when critical findings are detected |
| JSON output | Generates a machine-readable report |
| SARIF output | Generates a SARIF report for security tooling |
| Markdown output | Generates a readable security summary |
| GitHub annotations | Shows findings in GitHub Actions logs |
| No PR comments | Does not post comments on pull requests |
| Configurable scanning | Supports include, exclude, file size, output format, and severity threshold options |

---

## Usage

Create a workflow file:

```yaml
name: SecureDev Scan

on:
  push:
    branches:
      - main
  pull_request:

permissions:
  contents: read

jobs:
  securedev:
    name: SecureDev Security Scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run SecureDev Action
        uses: raghu-py/securedev-action@v1
        with:
          path: "."
          fail-on: "critical"
          output-format: "all"
          output-dir: "securedev-results"
```

For testing before creating a release tag, you can use:

```yaml
uses: raghu-py/securedev-action@main
```

For stable usage, create a release tag such as `v1` and use:

```yaml
uses: raghu-py/securedev-action@v1
```

---

## Inputs

| Input | Required | Default | Description |
|---|---:|---|---|
| `path` | No | `.` | Path to scan. Use `.` for the checked-out repository root. |
| `fail-on` | No | `critical` | Minimum severity that fails the action. Allowed values: `critical`, `high`, `medium`, `low`, `none`. |
| `output-dir` | No | `securedev-results` | Directory where JSON, SARIF, and Markdown reports are written. |
| `output-format` | No | `all` | Report formats to generate. Allowed values: `all`, `json`, `sarif`, `markdown`, `md`, or comma-separated values like `json,sarif`. |
| `include` | No | empty | Comma-separated glob patterns to include. Empty means all files under `path`. |
| `exclude` | No | empty | Comma-separated glob patterns to exclude in addition to built-in defaults. |
| `max-file-size-kb` | No | `1024` | Maximum file size to scan, in KB. |
| `show-snippets` | No | `true` | Include matching source snippets in reports. Allowed values: `true`, `false`. |
| `annotations` | No | `true` | Create GitHub workflow annotations for findings. This does not post PR comments. |

---

## Outputs

| Output | Description |
|---|---|
| `result` | Final result: `pass` or `fail`. |
| `findings_count` | Total number of findings. |
| `critical_count` | Number of critical findings. |
| `high_count` | Number of high findings. |
| `medium_count` | Number of medium findings. |
| `low_count` | Number of low findings. |
| `report_json` | Path to the JSON report, when generated. |
| `report_sarif` | Path to the SARIF report, when generated. |
| `report_markdown` | Path to the Markdown report, when generated. |

Example output usage:

```yaml
- name: Run SecureDev Action
  id: securedev
  uses: raghu-py/securedev-action@v1
  with:
    path: "."
    fail-on: "critical"

- name: Print result
  if: always()
  run: |
    echo "Result: ${{ steps.securedev.outputs.result }}"
    echo "Findings: ${{ steps.securedev.outputs.findings_count }}"
    echo "Critical: ${{ steps.securedev.outputs.critical_count }}"
```

---

## Generated Reports

By default, reports are written to:

```text
securedev-results/
```

Generated report files:

| File | Format | Purpose |
|---|---|---|
| `securedev-report.json` | JSON | Full machine-readable security report |
| `securedev-report.sarif` | SARIF | Static analysis report for security tools |
| `securedev-summary.md` | Markdown | Human-readable scan summary |

Example:

```text
securedev-results/
├── securedev-report.json
├── securedev-report.sarif
└── securedev-summary.md
```

---

## Upload Reports as Artifacts

```yaml
name: SecureDev Scan

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run SecureDev Action
        uses: raghu-py/securedev-action@v1
        with:
          path: "."
          fail-on: "critical"
          output-format: "all"
          output-dir: "securedev-results"

      - name: Upload SecureDev reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: securedev-results
          path: securedev-results/
```

---

## Upload SARIF to GitHub Code Scanning

SecureDev Action generates SARIF. To upload it to GitHub code scanning, add a SARIF upload step.

```yaml
name: SecureDev Code Scanning

on:
  push:
    branches:
      - main
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  securedev:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run SecureDev Action
        uses: raghu-py/securedev-action@v1
        with:
          path: "."
          fail-on: "critical"
          output-format: "sarif"
          output-dir: "securedev-results"

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: securedev-results/securedev-report.sarif
```

---

## Severity Levels

| Severity | Meaning | Fails CI by Default |
|---|---|---:|
| `critical` | Highly dangerous issue that should be fixed immediately | Yes |
| `high` | Serious security issue | No |
| `medium` | Risky pattern that needs review | No |
| `low` | Weakness or hardening suggestion | No |
| `info` | Informational finding | No |

Default behavior:

```text
fail-on = critical
```

This means the action only fails when at least one critical finding is detected.

---

## Failure Modes

| `fail-on` Value | Workflow Fails On |
|---|---|
| `critical` | Critical findings |
| `high` | Critical and high findings |
| `medium` | Critical, high, and medium findings |
| `low` | Critical, high, medium, and low findings |
| `none` | Never fails because of findings |

Example:

```yaml
with:
  fail-on: "none"
```

---

## Security Rules

SecureDev Action includes rules across multiple categories.

| Rule ID | Name | Severity | Category |
|---|---|---|---|
| `SEC001` | AWS access key exposed | `critical` | secrets |
| `SEC002` | GitHub token exposed | `critical` | secrets |
| `SEC003` | Private key material committed | `critical` | secrets |
| `SEC004` | Google API key exposed | `critical` | secrets |
| `SEC005` | Stripe live secret key exposed | `critical` | secrets |
| `SEC006` | Slack token exposed | `critical` | secrets |
| `SEC007` | Generic hardcoded secret | `high` | secrets |
| `PY001` | Python `eval` used | `high` | injection |
| `PY002` | Python `exec` used | `high` | injection |
| `PY003` | Shell command execution | `high` | command injection |
| `PY004` | `subprocess` with `shell=True` | `critical` | command injection |
| `PY005` | Unsafe pickle deserialization | `high` | deserialization |
| `PY006` | Unsafe YAML load | `high` | deserialization |
| `PY007` | TLS certificate verification disabled | `high` | transport security |
| `PY008` | Debug mode enabled | `high` | configuration |
| `PY009` | SQL query built with string formatting | `critical` | SQL injection |
| `PY010` | Weak hash algorithm | `medium` | cryptography |
| `PY011` | Weak or risky cipher mode | `high` | cryptography |
| `PY012` | JWT signature verification disabled | `critical` | authentication |
| `JS001` | JavaScript `eval` used | `high` | injection |
| `JS002` | HTML injection sink | `high` | XSS |
| `JS003` | React `dangerouslySetInnerHTML` used | `high` | XSS |
| `JS004` | Node command execution | `high` | command injection |
| `JS005` | TLS certificate verification disabled in Node | `high` | transport security |
| `WEB001` | Inline script detected | `low` | XSS hardening |
| `PHP001` | PHP `eval` used | `critical` | injection |
| `PHP002` | PHP unsafe deserialization | `high` | deserialization |
| `PHP003` | Possible PHP SQL injection | `critical` | SQL injection |
| `RB001` | Ruby unsafe YAML load | `high` | deserialization |
| `RB002` | Ruby command execution | `high` | command injection |
| `JAVA001` | Java command execution | `high` | command injection |
| `GO001` | Go command execution | `high` | command injection |
| `CFG001` | CORS wildcard origin | `high` | configuration |
| `CFG002` | Insecure debug configuration | `high` | configuration |
| `CFG003` | SSH root login enabled | `high` | configuration |
| `CFG004` | SSH password authentication enabled | `medium` | configuration |
| `DOCKER001` | Docker image uses latest tag | `medium` | supply chain |
| `DOCKER002` | Docker `ADD` from remote URL | `medium` | supply chain |
| `DOCKER003` | Privileged container configured | `critical` | container security |
| `K8S001` | Kubernetes privileged container | `critical` | container security |
| `K8S002` | Kubernetes host network enabled | `high` | container security |
| `K8S003` | Kubernetes privilege escalation enabled | `high` | container security |
| `IAC001` | Public SSH ingress | `critical` | cloud security |
| `IAC002` | Public object storage ACL | `critical` | cloud security |
| `GHA001` | GitHub Action pinned to mutable ref | `medium` | supply chain |
| `GEN001` | Overly permissive file mode | `high` | configuration |
| `JWT001` | JWT none algorithm accepted | `critical` | authentication |
| `SQL001` | Possible SQL injection pattern | `critical` | SQL injection |

---

## Scan Flow

```mermaid
flowchart TD
    A[GitHub workflow starts] --> B[Checkout repository]
    B --> C[Run SecureDev Docker Action]
    C --> D[Resolve scan path]
    D --> E[Walk files]
    E --> F[Skip binary, large, generated, and excluded files]
    F --> G[Apply security rules]
    G --> H[Create findings]
    H --> I[Generate JSON, SARIF, and Markdown reports]
    I --> J[Emit GitHub annotations]
    J --> K{Findings meet fail-on threshold?}
    K -->|Yes| L[Fail workflow]
    K -->|No| M[Pass workflow]
```

---

## Project Structure

```text
securedev-action/
├── action.yml
├── Dockerfile
├── entrypoint.sh
├── .gitignore
├── .dockerignore
├── securedev_action/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── config.py
│   ├── filewalker.py
│   ├── models.py
│   ├── reporters.py
│   ├── rules.py
│   └── scanner.py
└── tests/
    └── test_scanner.py
```

---

## File and Folder Exclusions

The scanner skips common generated, dependency, cache, binary, archive, media, and lock files.

### Built-in excluded folders

```text
.git/
.hg/
.svn/
.idea/
.vscode/
.tox/
.nox/
.venv/
venv/
env/
node_modules/
bower_components/
vendor/
dist/
build/
target/
out/
coverage/
htmlcov/
__pycache__/
.pytest_cache/
.mypy_cache/
.ruff_cache/
.next/
.nuxt/
.turbo/
.cache/
tmp/
temp/
logs/
```

### Built-in excluded file patterns

```text
*.png
*.jpg
*.jpeg
*.gif
*.webp
*.ico
*.pdf
*.zip
*.tar
*.tar.gz
*.tgz
*.rar
*.7z
*.gz
*.bz2
*.xz
*.mp4
*.mov
*.mp3
*.wav
*.woff
*.woff2
*.ttf
*.otf
*.eot
*.lock
package-lock.json
pnpm-lock.yaml
yarn.lock
poetry.lock
Pipfile.lock
Cargo.lock
Gemfile.lock
composer.lock
```

---

## Include and Exclude Examples

Scan only Python files:

```yaml
with:
  path: "."
  include: "**/*.py"
```

Scan Python and JavaScript files:

```yaml
with:
  path: "."
  include: "**/*.py,**/*.js,**/*.ts"
```

Exclude test and documentation folders:

```yaml
with:
  path: "."
  exclude: "tests/**,docs/**"
```

Increase max file size to 2 MB:

```yaml
with:
  max-file-size-kb: "2048"
```

Disable code snippets in reports:

```yaml
with:
  show-snippets: "false"
```

Disable GitHub annotations:

```yaml
with:
  annotations: "false"
```

---

## GitHub Annotations

When `annotations` is enabled, SecureDev Action prints GitHub-compatible workflow annotations.

Example:

```text
::error file=app/main.py,line=20,col=1,title=PY004: subprocess with shell=True::subprocess is called with shell=True, which can allow command injection.
```

These annotations appear in GitHub Actions logs.

Important:

> SecureDev Action does not post pull request comments.

---

## Local Development

Clone the repository:

```bash
git clone https://github.com/raghu-py/securedev-action.git
cd securedev-action
```

Run the scanner locally:

```bash
python -m securedev_action.cli --path . --fail-on critical --output-format all
```

You can also run it through the package entry point:

```bash
python -m securedev_action --path . --fail-on critical --output-format all
```

Run tests:

```bash
python -m pytest tests
```

Build the Docker image:

```bash
docker build -t securedev-action .
```

Run the Docker image locally:

```bash
docker run --rm -v "$PWD:/workspace" securedev-action --path /workspace --fail-on critical
```

Check version:

```bash
python -m securedev_action --version
```

---

## Example Findings

### Hardcoded GitHub token

```python
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

Expected finding:

```text
SEC002: GitHub token exposed
Severity: critical
```

### Dangerous Python subprocess usage

```python
import subprocess

subprocess.run(user_input, shell=True)
```

Expected finding:

```text
PY004: subprocess with shell=True
Severity: critical
```

### SQL injection pattern

```python
query = "SELECT * FROM users WHERE id = " + user_id
```

Expected finding:

```text
SQL001: Possible SQL injection pattern
Severity: critical
```

### Weak hash algorithm

```python
import hashlib

password_hash = hashlib.md5(password.encode()).hexdigest()
```

Expected finding:

```text
PY010: Weak hash algorithm
Severity: medium
```

---

## Suppressing Findings

The scanner recognizes common suppression markers.

Use suppression only when you have manually reviewed the finding and confirmed it is safe.

Supported markers include:

```text
securedev: ignore
securedev-ignore
pragma: allowlist secret
nosec
```

Example:

```python
example_token = "not-a-real-token"  # securedev: ignore
```

---

## Recommended Workflow

```yaml
name: Security

on:
  pull_request:
  push:
    branches:
      - main

permissions:
  contents: read

jobs:
  securedev:
    name: SecureDev
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Scan repository
        uses: raghu-py/securedev-action@v1
        with:
          path: "."
          fail-on: "critical"
          output-format: "all"
          output-dir: "securedev-results"

      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: securedev-results
          path: securedev-results/
```

---

## Advanced Workflow

This workflow scans source files, generates reports, uploads them as artifacts, and uploads SARIF to GitHub code scanning.

```yaml
name: Advanced SecureDev Scan

on:
  push:
    branches:
      - main
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  securedev:
    name: SecureDev Advanced Scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run SecureDev Action
        uses: raghu-py/securedev-action@v1
        with:
          path: "."
          fail-on: "critical"
          output-format: "all"
          output-dir: "securedev-results"
          exclude: "tests/fixtures/**,docs/examples/**"
          max-file-size-kb: "1024"
          show-snippets: "true"
          annotations: "true"

      - name: Upload SecureDev reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: securedev-results
          path: securedev-results/

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: securedev-results/securedev-report.sarif
```

---

## JSON Report Example

```json
{
  "tool": {
    "name": "SecureDev Action",
    "version": "1.0.0",
    "author": "Raghu Soni"
  },
  "summary": {
    "scanned_files": 25,
    "skipped_files": 4,
    "findings_count": 2,
    "counts_by_severity": {
      "critical": 1,
      "high": 1,
      "medium": 0,
      "low": 0,
      "info": 0
    }
  },
  "findings": [
    {
      "rule_id": "PY004",
      "title": "subprocess with shell=True",
      "severity": "critical",
      "file_path": "app/runner.py",
      "line": 14
    }
  ]
}
```

---

## Markdown Report Example

```markdown
# SecureDev Security Scan

**Status:** FAIL

## Summary

| Metric | Value |
|---|---:|
| Scanned files | 25 |
| Skipped files | 4 |
| Total findings | 2 |
| Critical | 1 |
| High | 1 |
| Medium | 0 |
| Low | 0 |
| Info | 0 |
```

---

## When to Use This Action

SecureDev Action is useful for:

- Open-source repositories
- Python projects
- JavaScript and TypeScript projects
- Docker-based applications
- DevSecOps learning
- Security checks in CI
- Pull request safety checks
- Lightweight static analysis

---

## What This Action Is Not

SecureDev Action is not a complete replacement for:

- Manual security reviews
- Professional SAST platforms
- Dependency vulnerability scanners
- Runtime security testing
- Penetration testing
- Secret scanning with full Git history support

It is designed to catch common risky patterns early.

---

## Security Philosophy

1. Keep security checks understandable.
2. Avoid hiding useful information behind complex tooling.
3. Make reports readable for developers.
4. Fail CI only on serious findings by default.
5. Prefer practical detection over noisy output.

---

## Checklist for Maintainers

Before creating a new release:

- [ ] Run tests locally
- [ ] Build Docker image locally
- [ ] Test action on a sample repository
- [ ] Verify JSON report generation
- [ ] Verify SARIF report generation
- [ ] Verify Markdown report generation
- [ ] Confirm `fail-on: critical` behavior
- [ ] Create a version tag such as `v1.0.0`
- [ ] Move or update the major tag such as `v1`

---

## Release Tagging

Recommended tags:

| Tag | Purpose |
|---|---|
| `v1.0.0` | Exact release version |
| `v1` | Stable major version |
| `main` | Development version |

Create a release tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Create or update the major tag:

```bash
git tag -f v1 v1.0.0
git push origin v1 --force
```

Recommended user syntax:

```yaml
uses: raghu-py/securedev-action@v1
```

---

## Details

<details>
<summary><strong>How does SecureDev Action decide whether to fail?</strong></summary>

SecureDev Action compares all findings against the configured `fail-on` severity.

For example:

```yaml
with:
  fail-on: "critical"
```

This fails only when at least one critical finding exists.

If the scan finds high, medium, or low findings but no critical findings, the workflow passes.

</details>

<details>
<summary><strong>Does SecureDev Action post PR comments?</strong></summary>

No.

This action does not post pull request comments.

It reports findings through:

- GitHub Actions logs
- GitHub workflow annotations
- JSON report
- SARIF report
- Markdown summary

</details>

<details>
<summary><strong>Can I disable workflow annotations?</strong></summary>

Yes.

```yaml
with:
  annotations: "false"
```

</details>

<details>
<summary><strong>Can I stop the action from failing CI?</strong></summary>

Yes.

```yaml
with:
  fail-on: "none"
```

This still generates reports, but findings will not fail the workflow.

</details>

<details>
<summary><strong>Does this scan binary files?</strong></summary>

No.

Binary files are skipped automatically. The scanner focuses on text-based files that can contain code, configuration, secrets, or infrastructure definitions.

</details>

---

## Keyboard Shortcuts for Review

When reviewing findings in GitHub:

| Action | Shortcut |
|---|---|
| Search repository | <kbd>t</kbd> |
| Open command palette | <kbd>Ctrl</kbd> + <kbd>K</kbd> |
| Search in browser page | <kbd>Ctrl</kbd> + <kbd>F</kbd> |
| Search in macOS browser page | <kbd>Cmd</kbd> + <kbd>F</kbd> |

---

## Troubleshooting

| Problem | Possible Cause | Fix |
|---|---|---|
| No files scanned | Wrong `path` input | Use `path: "."` |
| Reports missing | Wrong `output-format` value | Use `output-format: "all"` |
| Workflow fails | Critical finding detected | Review the generated reports |
| SARIF upload fails | Missing permission | Add `security-events: write` |
| Too many skipped files | File size or exclude rules | Check `max-file-size-kb` and `exclude` |
| No annotations shown | Annotations disabled | Set `annotations: "true"` |

---

## FAQ

### Is SecureDev Action self-contained?

Yes. It runs as a Docker GitHub Action and does not require an external API.

### Does it send my code anywhere?

No. The scanner runs inside the GitHub Actions environment.

### Does it scan private repositories?

Yes. It can scan any repository where the workflow is installed and allowed to run.

### Does it replace professional security tools?

No. It is a lightweight scanner for common risky patterns. Use it alongside other security tools and manual reviews.

### Does it scan Git history?

No. It scans the checked-out working tree.

### Does it support SARIF?

Yes. It can generate:

```text
securedev-results/securedev-report.sarif
```

### Does it support Markdown reports?

Yes. It can generate:

```text
securedev-results/securedev-summary.md
```

---

## Contributing

Contributions are welcome.

Good contributions include:

- New security rules
- Better false-positive handling
- More test cases
- Improved SARIF output
- Better documentation
- New examples
- Cleaner reports

Before submitting a pull request:

1. Keep the code readable.
2. Add or update tests.
3. Avoid noisy rules.
4. Make findings actionable.
5. Run the test suite.

```bash
python -m pytest tests
```

---

## Author

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/raghu-py">
        <img src="https://github.com/raghu-py.png" width="100px;" alt="Raghu Soni" />
        <br />
        <sub><strong>Raghu Soni</strong></sub>
      </a>
      <br />
      <sub>Python Developer and Cybersecurity Learner</sub>
    </td>
  </tr>
</table>

---

## Disclaimer

SecureDev Action is a lightweight static security scanner.

It may produce:

- False positives
- False negatives
- Context-limited findings
- Missed vulnerabilities

Always review findings manually before making security decisions.

---

## Markdown Features Used

This README uses:

- Headings
- Tables
- Badges
- Links
- Blockquotes
- Ordered lists
- Unordered lists
- Task lists
- Code blocks
- Inline code
- HTML alignment
- Collapsible details sections
- Mermaid diagrams
- Keyboard tags
- Footnotes

---

<div align="center">

**SecureDev Action**

Built with Python, Docker, and GitHub Actions.

</div>

[^sarif]: SARIF means Static Analysis Results Interchange Format.
[^sast]: SAST means Static Application Security Testing.
[^ci]: CI means Continuous Integration.
