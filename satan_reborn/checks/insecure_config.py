"""Local configuration heuristics, including Docker build-stage defaults."""

import ast
import re
from pathlib import PurePosixPath

from ..models import Finding, Severity, Source

CONFIG_SUFFIXES = {".ini", ".cfg", ".conf", ".toml", ".yaml", ".yml", ".json",
                   ".xml", ".properties", ".env"}


def analyze(source: Source) -> list[Finding]:
    path = PurePosixPath(source.path)
    findings = []

    def add(rule: str, title: str, line: int, advice: str, cwe: str,
            severity: Severity = Severity.HAUNT) -> None:
        findings.append(Finding(rule, severity, title, source.path, line, advice, cwe))

    if path.name.lower().startswith("dockerfile") or path.suffix.lower() == ".dockerfile":
        stage_line = None
        user = None

        def finish_stage() -> None:
            if stage_line is not None and (
                user is None or user.lower().split(":")[0] in {"root", "0", "00", "000"}
            ):
                add("config.docker-root", "Docker stage defaults to, or explicitly uses, root",
                    stage_line,
                    "Create an unprivileged account and set USER to its nonzero UID in each stage.",
                    "CWE-250")

        for number, line in enumerate(source.lines, 1):
            instruction = line.strip()
            if not instruction or instruction.startswith("#"):
                continue
            parts = instruction.split(None, 1)
            command = parts[0].upper()
            value = parts[1].strip() if len(parts) == 2 else ""
            if command == "FROM":
                finish_stage()
                stage_line, user = number, None
            elif command == "USER":
                user = value.split()[0] if value else None
        finish_stage()

    if path.suffix.lower() in {".py", ".pyw"}:
        try:
            tree = ast.parse(source.text)
        except (SyntaxError, ValueError, RecursionError):
            tree = None
        if tree:
            debug_lines = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        if any(
                            (isinstance(t, ast.Name) and t.id.upper() == "DEBUG")
                            or (isinstance(t, ast.Attribute) and t.attr.upper() == "DEBUG")
                            or (isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                                and t.slice.value == "DEBUG")
                            for t in targets
                        ):
                            debug_lines.add(node.lineno)
                elif isinstance(node, ast.Call):
                    for kw in node.keywords:
                        if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            debug_lines.add(kw.value.lineno)
            for number in sorted(debug_lines):
                add("config.debug", "Application debug mode is enabled", number,
                    "Disable Flask/Django debug mode outside an isolated development environment.",
                    "CWE-489")

    is_config = (
        path.suffix.lower() in CONFIG_SUFFIXES or path.name.startswith(".env")
        or path.name.lower().startswith("dockerfile")
        or path.name in {"settings.py", "config.py"}
    )
    for number, line in enumerate(source.lines, 1):
        if line.lstrip().startswith(("#", "//", ";")):
            continue
        if re.search(r"\bchmod\s+(?:-[A-Za-z]+\s+)*0?777\b", line):
            add("config.chmod", "World-writable chmod 777 permissions", number,
                "Grant only necessary access, such as 640 for private files and 750 for directories.",
                "CWE-732")
        if re.search(r"\bcurl\b[^|\n]*\|\s*(?:(?:sudo|env)\s+)*(?:/bin/)?(?:ba|da|z)?sh\b", line):
            add("config.curl-shell", "Remote download piped directly into a shell", number,
                "Download separately, verify its signature or checksum, then review before running.",
                "CWE-494")
        if is_config and re.search(r"\bhttp://[^\s\"'<>]+", line, re.IGNORECASE):
            add("config.http", "Plaintext HTTP URL in configuration", number,
                "Use HTTPS with certificate verification for nonlocal services.",
                "CWE-319", Severity.SPOOK)
    return findings
