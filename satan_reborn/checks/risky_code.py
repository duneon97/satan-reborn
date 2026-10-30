"""AST-based Python checks. Scanned code is never imported or executed."""

import ast
import re
from pathlib import PurePosixPath

from ..models import Finding, Severity, Source


def analyze(source: Source) -> list[Finding]:
    if PurePosixPath(source.path).suffix.lower() not in {".py", ".pyw"}:
        return []
    try:
        tree = ast.parse(source.text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    aliases = {}
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".")[0]] = (
                    item.name if item.asname else item.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"

    def qualified(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{qualified(node.value)}.{node.attr}"
        return ""

    def password_context(node: ast.AST) -> bool:
        # Inspect the containing statement and function name, not unrelated lines.
        current = node
        fragments = [ast.dump(node)]
        while current in parents:
            current = parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fragments.append(current.name)
                break
            if isinstance(current, ast.stmt):
                fragments.append(ast.dump(current))
                # Continue only to learn the enclosing function's name.
                ancestor = current
                while ancestor in parents:
                    ancestor = parents[ancestor]
                    if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        fragments.append(ancestor.name)
                        break
                break
        return bool(re.search(r"password|passwd|pwd|credential", " ".join(fragments), re.I))

    findings = []

    def add(rule: str, title: str, node: ast.AST, advice: str, cwe: str,
            severity: Severity = Severity.HAUNT) -> None:
        findings.append(Finding(rule, severity, title, source.path, node.lineno, advice, cwe))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = qualified(node.func)
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            add("code.dynamic-execution", "Dynamic eval/exec can execute untrusted code", node,
                "Replace dynamic execution with a parser, explicit dispatch, or ast.literal_eval for literals.",
                "CWE-95")
        if name.startswith("subprocess.") and any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        ):
            add("code.shell", "Subprocess invokes a shell", node,
                "Pass an argument list with shell=False and validate untrusted arguments.", "CWE-78")
        if name in {"pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load"}:
            add("code.pickle", "Pickle deserialization may execute attacker code", node,
                "Use a data-only format such as JSON. Never unpickle untrusted input.", "CWE-502")
        if name == "yaml.load":
            loader = node.args[1] if len(node.args) > 1 else None
            for kw in node.keywords:
                if kw.arg == "Loader":
                    loader = kw.value
            safe = qualified(loader) if loader is not None else ""
            if safe not in {"yaml.SafeLoader", "yaml.CSafeLoader"}:
                add("code.yaml", "YAML load does not explicitly use SafeLoader", node,
                    "Use yaml.safe_load or pass yaml.SafeLoader / yaml.CSafeLoader explicitly.",
                    "CWE-502")
        weak_hash = name in {"hashlib.md5", "hashlib.sha1"}
        if name == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant):
            weak_hash = str(node.args[0].value).lower().replace("-", "") in {"md5", "sha1"}
        if weak_hash and password_context(node):
            add("code.password-hash", "MD5/SHA1 is unsuitable for password storage", node,
                "Use a salted, slow password KDF, such as hashlib.scrypt or PBKDF2-HMAC-SHA256, "
                "with current work factors.", "CWE-916")
    return findings
