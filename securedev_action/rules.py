from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Pattern

from .models import Finding, Rule, Severity


SUPPRESSION_MARKERS = (
    "securedev: ignore",
    "securedev-ignore",
    "pragma: allowlist secret",
    "nosec",
)

PLACEHOLDER_WORDS = {
    "example",
    "sample",
    "dummy",
    "placeholder",
    "changeme",
    "change_me",
    "replace_me",
    "your_token",
    "your_secret",
    "your_api_key",
    "your-key",
    "test",
    "testing",
    "fake",
    "notasecret",
    "none",
    "null",
}


@dataclass(frozen=True)
class RegexRule:
    rule: Rule
    pattern: Pattern[str]
    confidence: str = "medium"
    file_globs: tuple[str, ...] = tuple()
    negative_pattern: Pattern[str] | None = None

    def applies_to(self, relative_path: str) -> bool:
        if not self.file_globs:
            return True
        name = Path(relative_path).name.lower()
        rel = relative_path.lower()
        return any(_glob_like(rel, name, glob.lower()) for glob in self.file_globs)


def _looks_like_kubernetes_manifest(content: str) -> bool:
    lower = content.lower()
    return "apiversion:" in lower and "kind:" in lower


def _glob_like(rel: str, name: str, pattern: str) -> bool:
    if pattern.startswith("*") and name.endswith(pattern[1:]):
        return True
    if pattern.endswith("*") and name.startswith(pattern[:-1]):
        return True
    return rel == pattern or name == pattern or pattern in rel


def _rule(
    rule_id: str,
    name: str,
    severity: Severity,
    category: str,
    message: str,
    recommendation: str,
    cwe: str | None = None,
    tags: tuple[str, ...] = tuple(),
) -> Rule:
    return Rule(
        rule_id=rule_id,
        name=name,
        severity=severity,
        category=category,
        message=message,
        recommendation=recommendation,
        cwe=cwe,
        tags=tags,
    )


REGEX_RULES: tuple[RegexRule, ...] = (
    RegexRule(
        _rule(
            "SEC001",
            "AWS access key exposed",
            Severity.CRITICAL,
            "secrets",
            "A value that looks like an AWS access key was found in source code.",
            "Remove the key, rotate it immediately, and load credentials from a secure secret store.",
            "CWE-798",
            ("secret", "aws", "credential"),
        ),
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "high",
    ),
    RegexRule(
        _rule(
            "SEC002",
            "GitHub token exposed",
            Severity.CRITICAL,
            "secrets",
            "A GitHub token-like value was found in source code.",
            "Revoke the token, rotate credentials, and store it in GitHub Actions secrets or a vault.",
            "CWE-798",
            ("secret", "github", "token"),
        ),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
        "high",
    ),
    RegexRule(
        _rule(
            "SEC003",
            "Private key material committed",
            Severity.CRITICAL,
            "secrets",
            "Private key material appears to be present in the repository.",
            "Remove the key from history if needed, revoke associated credentials, and use secure secret storage.",
            "CWE-798",
            ("secret", "private-key"),
        ),
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        "high",
    ),
    RegexRule(
        _rule(
            "SEC004",
            "Google API key exposed",
            Severity.CRITICAL,
            "secrets",
            "A Google API key-like value was found in source code.",
            "Restrict and rotate the key, then move it to a secret manager.",
            "CWE-798",
            ("secret", "google", "api-key"),
        ),
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "high",
    ),
    RegexRule(
        _rule(
            "SEC005",
            "Stripe live secret key exposed",
            Severity.CRITICAL,
            "secrets",
            "A Stripe live secret key-like value was found.",
            "Revoke the live key immediately and store replacement credentials outside the repository.",
            "CWE-798",
            ("secret", "stripe", "payment"),
        ),
        re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"),
        "high",
    ),
    RegexRule(
        _rule(
            "SEC006",
            "Slack token exposed",
            Severity.CRITICAL,
            "secrets",
            "A Slack token-like value was found.",
            "Revoke the token, rotate affected app credentials, and use secret storage.",
            "CWE-798",
            ("secret", "slack", "token"),
        ),
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"),
        "high",
    ),
    RegexRule(
        _rule(
            "SEC007",
            "Generic hardcoded secret",
            Severity.HIGH,
            "secrets",
            "A hardcoded credential-like assignment was found.",
            "Move secrets to environment variables, GitHub Actions secrets, or a managed vault.",
            "CWE-798",
            ("secret", "credential"),
        ),
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|access[_-]?key)\b\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]"
        ),
        "medium",
    ),
    RegexRule(
        _rule(
            "PY001",
            "Python eval used",
            Severity.HIGH,
            "injection",
            "Python eval() executes dynamic code and can lead to code injection.",
            "Avoid eval(). Use safe parsers such as json.loads, ast.literal_eval, or explicit dispatch tables.",
            "CWE-95",
            ("python", "injection"),
        ),
        re.compile(r"\beval\s*\("),
        "high",
        ("*.py",),
    ),
    RegexRule(
        _rule(
            "PY002",
            "Python exec used",
            Severity.HIGH,
            "injection",
            "Python exec() executes dynamic code and can lead to code injection.",
            "Remove exec() and replace dynamic behavior with safe, explicit logic.",
            "CWE-95",
            ("python", "injection"),
        ),
        re.compile(r"\bexec\s*\("),
        "high",
        ("*.py",),
    ),
    RegexRule(
        _rule(
            "PY003",
            "Shell command execution",
            Severity.HIGH,
            "command-injection",
            "A shell command execution helper was detected.",
            "Prefer subprocess.run with a list of arguments and validate all user-controlled input.",
            "CWE-78",
            ("python", "command-injection"),
        ),
        re.compile(r"\b(?:os\.system|os\.popen|commands\.getoutput)\s*\("),
        "medium",
        ("*.py",),
    ),
    RegexRule(
        _rule(
            "PY004",
            "subprocess with shell=True",
            Severity.CRITICAL,
            "command-injection",
            "subprocess is called with shell=True, which can allow command injection.",
            "Use shell=False with a list of arguments and avoid passing user input to the shell.",
            "CWE-78",
            ("python", "command-injection"),
        ),
        re.compile(r"\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\([^\n]*shell\s*=\s*True"),
        "high",
        ("*.py",),
    ),
    RegexRule(
        _rule(
            "PY005",
            "Unsafe pickle deserialization",
            Severity.HIGH,
            "deserialization",
            "pickle deserialization can execute attacker-controlled code.",
            "Do not unpickle untrusted data. Use JSON or a safe serialization format for untrusted input.",
            "CWE-502",
            ("python", "deserialization"),
        ),
        re.compile(r"\bpickle\.(?:load|loads)\s*\("),
        "high",
        ("*.py",),
    ),
    RegexRule(
        _rule(
            "PY006",
            "Unsafe YAML load",
            Severity.HIGH,
            "deserialization",
            "yaml.load can deserialize arbitrary Python objects when used unsafely.",
            "Use yaml.safe_load or specify SafeLoader explicitly.",
            "CWE-502",
            ("python", "yaml", "deserialization"),
        ),
        re.compile(r"\byaml\.load\s*\((?![^\n]*(?:SafeLoader|safe_load))"),
        "high",
        ("*.py",),
    ),
    RegexRule(
        _rule(
            "PY007",
            "TLS certificate verification disabled",
            Severity.HIGH,
            "transport-security",
            "An HTTP request disables TLS certificate verification.",
            "Remove verify=False and fix certificate trust configuration instead.",
            "CWE-295",
            ("python", "tls"),
        ),
        re.compile(r"\brequests\.(?:get|post|put|patch|delete|request)\s*\([^\n]*verify\s*=\s*False"),
        "high",
        ("*.py",),
    ),
    RegexRule(
        _rule(
            "PY008",
            "Debug mode enabled",
            Severity.HIGH,
            "configuration",
            "Debug mode appears to be enabled in application code.",
            "Disable debug mode in production and control it through environment-specific configuration.",
            "CWE-489",
            ("python", "config"),
        ),
        re.compile(r"\b(?:app\.run\([^\n]*debug\s*=\s*True|DEBUG\s*=\s*True)"),
        "medium",
        ("*.py",),
    ),
    RegexRule(
        _rule(
            "PY009",
            "SQL query built with string formatting",
            Severity.CRITICAL,
            "sql-injection",
            "A SQL execution call appears to use string interpolation or concatenation.",
            "Use parameterized queries or an ORM query builder instead of building SQL strings manually.",
            "CWE-89",
            ("python", "sql-injection"),
        ),
        re.compile(r"\bexecute(?:many)?\s*\(\s*(?:f['\"]|['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE)[^'\"]*['\"]\s*(?:%|\+|\.format\())", re.IGNORECASE),
        "medium",
        ("*.py",),
    ),
    RegexRule(
        _rule(
            "PY010",
            "Weak hash algorithm",
            Severity.MEDIUM,
            "cryptography",
            "A weak hash algorithm was detected.",
            "Use SHA-256 or stronger for general hashing, and use Argon2, bcrypt, scrypt, or PBKDF2 for passwords.",
            "CWE-327",
            ("python", "crypto"),
        ),
        re.compile(r"\b(?:hashlib\.(?:md5|sha1)|Crypto\.Hash\.(?:MD5|SHA1))\s*\("),
        "high",
        ("*.py",),
    ),
    RegexRule(
        _rule(
            "PY011",
            "Weak or risky cipher mode",
            Severity.HIGH,
            "cryptography",
            "A weak cipher or ECB mode appears to be used.",
            "Use modern authenticated encryption such as AES-GCM or ChaCha20-Poly1305.",
            "CWE-327",
            ("python", "crypto"),
        ),
        re.compile(r"\b(?:DES|ARC4|MODE_ECB)\b"),
        "medium",
        ("*.py",),
    ),
    RegexRule(
        _rule(
            "PY012",
            "JWT signature verification disabled",
            Severity.CRITICAL,
            "auth",
            "JWT verification appears to be disabled.",
            "Always verify JWT signatures and restrict accepted algorithms explicitly.",
            "CWE-347",
            ("python", "jwt", "auth"),
        ),
        re.compile(r"verify_signature\s*['\"]?\s*[:=]\s*False|options\s*=\s*\{[^\n]*verify_signature[^\n]*False"),
        "high",
        ("*.py",),
    ),
    RegexRule(
        _rule(
            "JS001",
            "JavaScript eval used",
            Severity.HIGH,
            "injection",
            "JavaScript eval() executes dynamic code and can lead to code injection.",
            "Avoid eval(). Use JSON.parse for data and explicit safe dispatch for behavior.",
            "CWE-95",
            ("javascript", "injection"),
        ),
        re.compile(r"\beval\s*\("),
        "high",
        ("*.js", "*.jsx", "*.ts", "*.tsx",),
    ),
    RegexRule(
        _rule(
            "JS002",
            "HTML injection sink",
            Severity.HIGH,
            "xss",
            "Code assigns to an HTML injection sink.",
            "Prefer textContent or sanitize untrusted HTML with a trusted sanitizer before rendering.",
            "CWE-79",
            ("javascript", "xss"),
        ),
        re.compile(r"\.(?:innerHTML|outerHTML)\s*="),
        "medium",
        ("*.js", "*.jsx", "*.ts", "*.tsx", "*.html",),
    ),
    RegexRule(
        _rule(
            "JS003",
            "React dangerouslySetInnerHTML used",
            Severity.HIGH,
            "xss",
            "React dangerouslySetInnerHTML can create XSS when fed untrusted content.",
            "Avoid dangerouslySetInnerHTML or sanitize content before rendering.",
            "CWE-79",
            ("react", "xss"),
        ),
        re.compile(r"dangerouslySetInnerHTML"),
        "medium",
        ("*.jsx", "*.tsx", "*.js", "*.ts",),
    ),
    RegexRule(
        _rule(
            "JS004",
            "Node command execution",
            Severity.HIGH,
            "command-injection",
            "Node child_process command execution was detected.",
            "Use execFile or spawn with argument arrays and validate all user input.",
            "CWE-78",
            ("node", "command-injection"),
        ),
        re.compile(r"\bchild_process\.(?:exec|execSync)\s*\("),
        "medium",
        ("*.js", "*.ts", "*.mjs", "*.cjs",),
    ),
    RegexRule(
        _rule(
            "JS005",
            "TLS certificate verification disabled in Node",
            Severity.HIGH,
            "transport-security",
            "TLS certificate verification appears to be disabled.",
            "Do not set NODE_TLS_REJECT_UNAUTHORIZED=0 in production.",
            "CWE-295",
            ("node", "tls"),
        ),
        re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
        "high",
        ("*.js", "*.ts", "*.env", "*.yml", "*.yaml",),
    ),
    RegexRule(
        _rule(
            "WEB001",
            "Inline script detected",
            Severity.LOW,
            "xss-hardening",
            "Inline script blocks make Content Security Policy harder to enforce.",
            "Move scripts into separate files and enforce a strict Content Security Policy.",
            "CWE-79",
            ("html", "xss"),
        ),
        re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>", re.IGNORECASE),
        "low",
        ("*.html", "*.htm",),
    ),
    RegexRule(
        _rule(
            "PHP001",
            "PHP eval used",
            Severity.CRITICAL,
            "injection",
            "PHP eval() executes dynamic code and can lead to remote code execution.",
            "Remove eval() and replace it with explicit, safe logic.",
            "CWE-95",
            ("php", "injection"),
        ),
        re.compile(r"\beval\s*\("),
        "high",
        ("*.php",),
    ),
    RegexRule(
        _rule(
            "PHP002",
            "PHP unsafe deserialization",
            Severity.HIGH,
            "deserialization",
            "PHP unserialize() can be dangerous with untrusted input.",
            "Avoid unserialize() for untrusted data. Use JSON or strict allowed_classes settings.",
            "CWE-502",
            ("php", "deserialization"),
        ),
        re.compile(r"\bunserialize\s*\("),
        "medium",
        ("*.php",),
    ),
    RegexRule(
        _rule(
            "PHP003",
            "Possible PHP SQL injection",
            Severity.CRITICAL,
            "sql-injection",
            "A PHP SQL call appears to be built from request data.",
            "Use prepared statements with bound parameters.",
            "CWE-89",
            ("php", "sql-injection"),
        ),
        re.compile(r"\b(?:mysql_query|mysqli_query)\s*\([^\n]*(?:\$_GET|\$_POST|\$_REQUEST)"),
        "medium",
        ("*.php",),
    ),
    RegexRule(
        _rule(
            "RB001",
            "Ruby unsafe YAML load",
            Severity.HIGH,
            "deserialization",
            "Ruby YAML.load can deserialize unsafe objects.",
            "Use YAML.safe_load with explicit permitted classes.",
            "CWE-502",
            ("ruby", "deserialization"),
        ),
        re.compile(r"\bYAML\.load\s*\("),
        "medium",
        ("*.rb",),
    ),
    RegexRule(
        _rule(
            "RB002",
            "Ruby command execution",
            Severity.HIGH,
            "command-injection",
            "Ruby command execution was detected.",
            "Avoid shell interpolation and use safe argument arrays.",
            "CWE-78",
            ("ruby", "command-injection"),
        ),
        re.compile(r"\b(?:system|exec)\s*\("),
        "medium",
        ("*.rb",),
    ),
    RegexRule(
        _rule(
            "JAVA001",
            "Java command execution",
            Severity.HIGH,
            "command-injection",
            "Java runtime command execution was detected.",
            "Avoid Runtime.exec with untrusted input. Prefer ProcessBuilder with strict argument validation.",
            "CWE-78",
            ("java", "command-injection"),
        ),
        re.compile(r"\bRuntime\.getRuntime\(\)\.exec\s*\("),
        "medium",
        ("*.java",),
    ),
    RegexRule(
        _rule(
            "GO001",
            "Go command execution",
            Severity.HIGH,
            "command-injection",
            "Go command execution was detected.",
            "Use exec.Command with fixed command paths and validated arguments.",
            "CWE-78",
            ("go", "command-injection"),
        ),
        re.compile(r"\bexec\.Command\s*\("),
        "low",
        ("*.go",),
    ),
    RegexRule(
        _rule(
            "CFG001",
            "CORS wildcard origin",
            Severity.HIGH,
            "configuration",
            "A wildcard CORS origin appears to be configured.",
            "Restrict CORS origins to trusted domains and avoid credentials with wildcard origins.",
            "CWE-942",
            ("cors", "config"),
        ),
        re.compile(r"(?i)(?:allow_origins|allowed_origins|Access-Control-Allow-Origin|cors).*['\"]\*['\"]"),
        "medium",
    ),
    RegexRule(
        _rule(
            "CFG002",
            "Insecure debug configuration",
            Severity.HIGH,
            "configuration",
            "Debug or development mode appears to be enabled in configuration.",
            "Disable debug mode in production configuration.",
            "CWE-489",
            ("config", "debug"),
        ),
        re.compile(r"(?i)^\s*(?:debug|app_debug|flask_debug|django_debug|rails_env)\s*[:=]\s*(?:true|1|development)\b", re.MULTILINE),
        "medium",
        ("*.env", "*.ini", "*.cfg", "*.conf", "*.yaml", "*.yml", "*.toml", "*.json", "*.properties",),
    ),
    RegexRule(
        _rule(
            "CFG003",
            "SSH root login enabled",
            Severity.HIGH,
            "configuration",
            "SSH root login appears to be enabled.",
            "Disable PermitRootLogin and require individual user accounts with sudo.",
            "CWE-269",
            ("ssh", "config"),
        ),
        re.compile(r"(?i)^\s*PermitRootLogin\s+yes\b", re.MULTILINE),
        "high",
        ("sshd_config", "*.conf",),
    ),
    RegexRule(
        _rule(
            "CFG004",
            "SSH password authentication enabled",
            Severity.MEDIUM,
            "configuration",
            "SSH password authentication appears to be enabled.",
            "Prefer key-based authentication and disable PasswordAuthentication where possible.",
            "CWE-308",
            ("ssh", "config"),
        ),
        re.compile(r"(?i)^\s*PasswordAuthentication\s+yes\b", re.MULTILINE),
        "medium",
        ("sshd_config", "*.conf",),
    ),
    RegexRule(
        _rule(
            "DOCKER001",
            "Docker image uses latest tag",
            Severity.MEDIUM,
            "supply-chain",
            "A Docker image uses the mutable latest tag.",
            "Pin base images to a specific version or digest.",
            "CWE-1104",
            ("docker", "supply-chain"),
        ),
        re.compile(r"(?im)^\s*FROM\s+[^\s:@]+(?::latest)?\s*$"),
        "medium",
        ("Dockerfile", "*.dockerfile",),
    ),
    RegexRule(
        _rule(
            "DOCKER002",
            "Docker ADD from remote URL",
            Severity.MEDIUM,
            "supply-chain",
            "Docker ADD appears to fetch a remote URL during image build.",
            "Download and verify artifacts outside the Dockerfile, or use COPY for local files.",
            "CWE-494",
            ("docker", "supply-chain"),
        ),
        re.compile(r"(?im)^\s*ADD\s+https?://"),
        "medium",
        ("Dockerfile", "*.dockerfile",),
    ),
    RegexRule(
        _rule(
            "DOCKER003",
            "Privileged container configured",
            Severity.CRITICAL,
            "container-security",
            "A container appears to run in privileged mode.",
            "Remove privileged mode and grant only the specific Linux capabilities required.",
            "CWE-250",
            ("docker", "container"),
        ),
        re.compile(r"(?im)^\s*privileged\s*:\s*true\b"),
        "high",
        ("docker-compose.yml", "docker-compose.yaml",),
    ),
    RegexRule(
        _rule(
            "K8S001",
            "Kubernetes privileged container",
            Severity.CRITICAL,
            "container-security",
            "A Kubernetes container appears to run as privileged.",
            "Set privileged: false and use a restricted Pod Security profile.",
            "CWE-250",
            ("kubernetes", "container"),
        ),
        re.compile(r"(?im)^\s*privileged\s*:\s*true\b"),
        "high",
        ("*.yaml", "*.yml",),
    ),
    RegexRule(
        _rule(
            "K8S002",
            "Kubernetes host network enabled",
            Severity.HIGH,
            "container-security",
            "A Kubernetes pod appears to use the host network namespace.",
            "Disable hostNetwork unless there is a strict, reviewed requirement.",
            "CWE-668",
            ("kubernetes", "container"),
        ),
        re.compile(r"(?im)^\s*hostNetwork\s*:\s*true\b"),
        "high",
        ("*.yaml", "*.yml",),
    ),
    RegexRule(
        _rule(
            "K8S003",
            "Kubernetes allowPrivilegeEscalation enabled",
            Severity.HIGH,
            "container-security",
            "A Kubernetes container allows privilege escalation.",
            "Set allowPrivilegeEscalation: false in the container securityContext.",
            "CWE-250",
            ("kubernetes", "container"),
        ),
        re.compile(r"(?im)^\s*allowPrivilegeEscalation\s*:\s*true\b"),
        "high",
        ("*.yaml", "*.yml",),
    ),
    RegexRule(
        _rule(
            "IAC001",
            "Public SSH ingress",
            Severity.CRITICAL,
            "cloud-security",
            "Infrastructure code appears to expose SSH to the public internet.",
            "Restrict SSH ingress to trusted IP ranges or use a managed access mechanism.",
            "CWE-284",
            ("terraform", "cloud"),
        ),
        re.compile(r"(?is)(?:from_port\s*=\s*22|to_port\s*=\s*22).{0,500}cidr_blocks\s*=\s*\[[^\]]*0\.0\.0\.0/0"),
        "medium",
        ("*.tf",),
    ),
    RegexRule(
        _rule(
            "IAC002",
            "Public object storage ACL",
            Severity.CRITICAL,
            "cloud-security",
            "Infrastructure code appears to make object storage publicly readable or writable.",
            "Use private ACLs and explicit bucket policies with least privilege.",
            "CWE-284",
            ("terraform", "cloud"),
        ),
        re.compile(r"(?i)acl\s*=\s*['\"]public-(?:read|write|read-write)['\"]"),
        "high",
        ("*.tf", "*.yaml", "*.yml", "*.json",),
    ),
    RegexRule(
        _rule(
            "GHA001",
            "GitHub Action pinned to mutable ref",
            Severity.MEDIUM,
            "supply-chain",
            "A GitHub Action appears to be pinned to a mutable branch or tag.",
            "Pin third-party actions to a full commit SHA for stronger supply-chain integrity.",
            "CWE-829",
            ("github-actions", "supply-chain"),
        ),
        re.compile(r"(?im)^\s*uses\s*:\s*[^\s]+@(?:main|master|latest|v\d+)\s*$"),
        "medium",
        ("*.yml", "*.yaml",),
    ),
)


RULE_BY_ID = {regex_rule.rule.rule_id: regex_rule.rule for regex_rule in REGEX_RULES}


def scan_text(relative_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    for regex_rule in REGEX_RULES:
        if not regex_rule.applies_to(relative_path):
            continue
        if regex_rule.rule.rule_id.startswith("K8S") and not _looks_like_kubernetes_manifest(content):
            continue
        if regex_rule.negative_pattern and regex_rule.negative_pattern.search(content):
            continue
        for match in regex_rule.pattern.finditer(content):
            line_no, col_no = _line_col(content, match.start())
            line = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else _line_at(content, match.start())
            if _is_suppressed(line):
                continue
            if regex_rule.rule.category == "secrets" and _looks_like_placeholder(match.group(0), line):
                continue
            if regex_rule.rule.rule_id == "SEC007" and not _generic_secret_is_strong_enough(match):
                continue
            findings.append(
                Finding(
                    rule_id=regex_rule.rule.rule_id,
                    title=regex_rule.rule.name,
                    severity=regex_rule.rule.severity,
                    category=regex_rule.rule.category,
                    message=regex_rule.rule.message,
                    recommendation=regex_rule.rule.recommendation,
                    file_path=relative_path,
                    line=line_no,
                    column=col_no,
                    snippet=line.strip(),
                    cwe=regex_rule.rule.cwe,
                    confidence=regex_rule.confidence,
                ).with_fingerprint()
            )

    findings.extend(_scan_multiline_sql(relative_path, content))
    findings.extend(_scan_insecure_permissions(relative_path, content))
    findings.extend(_scan_jwt_none(relative_path, content))
    return _dedupe(findings)


def all_rules() -> list[Rule]:
    rules = list(RULE_BY_ID.values())
    extra = [
        _rule(
            "GEN001",
            "Overly permissive file mode",
            Severity.HIGH,
            "configuration",
            "A command appears to set world-writable or fully permissive file permissions.",
            "Avoid chmod 777. Use the least permissive mode that satisfies the application requirement.",
            "CWE-732",
            ("permissions",),
        ),
        _rule(
            "JWT001",
            "JWT none algorithm accepted",
            Severity.CRITICAL,
            "auth",
            "JWT code or configuration appears to accept the none algorithm.",
            "Do not allow alg=none. Pin accepted algorithms to secure asymmetric or HMAC algorithms.",
            "CWE-347",
            ("jwt", "auth"),
        ),
        _rule(
            "SQL001",
            "Possible SQL injection pattern",
            Severity.CRITICAL,
            "sql-injection",
            "SQL appears to be concatenated with request or user-controlled data.",
            "Use parameterized queries and never concatenate request data into SQL strings.",
            "CWE-89",
            ("sql-injection",),
        ),
    ]
    known = {rule.rule_id for rule in rules}
    rules.extend(rule for rule in extra if rule.rule_id not in known)
    return sorted(rules, key=lambda r: r.rule_id)


def _scan_multiline_sql(relative_path: str, content: str) -> list[Finding]:
    if Path(relative_path).suffix.lower() not in {".py", ".js", ".ts", ".php", ".java", ".rb", ".go"}:
        return []
    patterns = [
        re.compile(r"(?is)(?:SELECT|INSERT|UPDATE|DELETE).{0,160}(?:\+|%|\.format\(|\$\{|\$_GET|\$_POST|request\.|req\.|params\[)"),
        re.compile(r"(?is)(?:execute|query|rawQuery)\s*\(.{0,180}(?:\+|%|\.format\(|\$\{|\$_GET|\$_POST|request\.|req\.|params\[)"),
    ]
    findings: list[Finding] = []
    for pattern in patterns:
        for match in pattern.finditer(content):
            line_no, col_no = _line_col(content, match.start())
            line = _line_at(content, match.start()).strip()
            if _is_suppressed(line):
                continue
            findings.append(
                Finding(
                    rule_id="SQL001",
                    title="Possible SQL injection pattern",
                    severity=Severity.CRITICAL,
                    category="sql-injection",
                    message="SQL appears to be concatenated with request or user-controlled data.",
                    recommendation="Use parameterized queries and never concatenate request data into SQL strings.",
                    file_path=relative_path,
                    line=line_no,
                    column=col_no,
                    snippet=line,
                    cwe="CWE-89",
                    confidence="medium",
                ).with_fingerprint()
            )
    return findings


def _scan_insecure_permissions(relative_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"\bchmod\s+(?:-R\s+)?(?:777|666)\b")
    for match in pattern.finditer(content):
        line_no, col_no = _line_col(content, match.start())
        line = _line_at(content, match.start()).strip()
        if _is_suppressed(line):
            continue
        findings.append(
            Finding(
                rule_id="GEN001",
                title="Overly permissive file mode",
                severity=Severity.HIGH,
                category="configuration",
                message="A command appears to set world-writable or fully permissive file permissions.",
                recommendation="Avoid chmod 777. Use the least permissive mode that satisfies the application requirement.",
                file_path=relative_path,
                line=line_no,
                column=col_no,
                snippet=line,
                cwe="CWE-732",
                confidence="medium",
            ).with_fingerprint()
        )
    return findings


def _scan_jwt_none(relative_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"(?i)(?:algorithms?\s*[:=]\s*\[[^\]]*['\"]none['\"]|alg\s*[:=]\s*['\"]none['\"])" )
    for match in pattern.finditer(content):
        line_no, col_no = _line_col(content, match.start())
        line = _line_at(content, match.start()).strip()
        if _is_suppressed(line):
            continue
        findings.append(
            Finding(
                rule_id="JWT001",
                title="JWT none algorithm accepted",
                severity=Severity.CRITICAL,
                category="auth",
                message="JWT code or configuration appears to accept the none algorithm.",
                recommendation="Do not allow alg=none. Pin accepted algorithms to secure asymmetric or HMAC algorithms.",
                file_path=relative_path,
                line=line_no,
                column=col_no,
                snippet=line,
                cwe="CWE-347",
                confidence="high",
            ).with_fingerprint()
        )
    return findings


def _line_col(content: str, index: int) -> tuple[int, int]:
    line = content.count("\n", 0, index) + 1
    line_start = content.rfind("\n", 0, index)
    col = index + 1 if line_start == -1 else index - line_start
    return line, col


def _line_at(content: str, index: int) -> str:
    start = content.rfind("\n", 0, index) + 1
    end = content.find("\n", index)
    if end == -1:
        end = len(content)
    return content[start:end]


def _is_suppressed(line: str) -> bool:
    lower = line.lower()
    return any(marker in lower for marker in SUPPRESSION_MARKERS)


def _looks_like_placeholder(value: str, full_line: str) -> bool:
    lower = f"{value} {full_line}".lower()
    if any(word in lower for word in PLACEHOLDER_WORDS):
        return True
    if "xxxx" in lower or "****" in lower:
        return True
    return False


def _generic_secret_is_strong_enough(match: re.Match[str]) -> bool:
    candidate = match.group(1) if match.groups() else match.group(0)
    if _looks_like_placeholder(candidate, match.group(0)):
        return False
    if len(candidate) < 12:
        return False
    if _entropy(candidate) < 3.0 and len(candidate) < 24:
        return False
    return True


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in frequencies.values())


def _dedupe(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file_path, finding.line, finding.snippet)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return sorted(unique, key=lambda f: (-int(f.severity), f.file_path, f.line, f.rule_id))
