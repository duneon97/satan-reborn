"""Pattern and entropy checks; no matched credential is retained or displayed."""

import math
import re
from collections import Counter

from ..models import Finding, Severity, Source

TOKEN_PATTERNS = (
    ("secret.aws", "AWS access key embedded in source",
     re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("secret.github", "GitHub token embedded in source",
     re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b")),
    ("secret.private-key", "Private key header embedded in source",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
)
ASSIGNMENT = re.compile(
    r"""(?ix)
    ["']?(?P<name>[a-z_][a-z0-9_.-]*(?:secret|token|password|passwd|api[_-]?key|access[_-]?key)
    [a-z0-9_.-]*|secret|token|password|passwd|api[_-]?key|access[_-]?key)["']?
    \s*[:=]\s*["'](?P<value>[^"'\r\n]{20,})["']
    """
)


def entropy(value: str) -> float:
    counts = Counter(value)
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())


def analyze(source: Source) -> list[Finding]:
    findings = []
    for number, line in enumerate(source.lines, 1):
        specific = False
        for rule, title, pattern in TOKEN_PATTERNS:
            if pattern.search(line):
                specific = True
                findings.append(Finding(
                    rule, Severity.CRYPT, title, source.path, number,
                    "Revoke and rotate the credential if real. Remove it from source and history; "
                    "load it from an environment variable or a secret manager.",
                    "CWE-798", "[REDACTED]",
                ))
        if not specific:
            for match in ASSIGNMENT.finditer(line):
                if entropy(match["value"]) >= 3.5:
                    findings.append(Finding(
                        "secret.entropy", Severity.HAUNT,
                        "High-entropy value assigned to a credential-like name",
                        source.path, number,
                        "Verify the value, rotate it if real, and load secrets from outside source control.",
                        "CWE-798", "[REDACTED]",
                    ))
                    break
    return findings
