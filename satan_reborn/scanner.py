"""Bounded filesystem traversal and plugin orchestration."""

import ast
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

from .checks import PLUGINS, dependencies
from .models import Report, Severity, Source
from .osv import OSVClient

MAX_FILE_BYTES = 1024 * 1024
EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__", "node_modules",
    ".mypy_cache", ".pytest_cache", ".tox", "dist", "build", "reports",
}
BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar",
    ".woff", ".woff2", ".ttf", ".mp4", ".mp3", ".pyc", ".so", ".dll", ".exe",
}


def scan(path, *, osv: bool = False, exclude_paths=()) -> Report:
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("Scan target must be an existing local directory.")
    excluded = {Path(p).expanduser().resolve() for p in exclude_paths}
    report = Report(target=root.name or str(root),
                    generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    osv_enabled=osv)
    manifests = []

    def walk_error(_error):
        report.warnings.append("A directory could not be read; scan coverage is incomplete.")

    for directory, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS
                         and not (Path(directory) / d).is_symlink())
        for name in sorted(files):
            file = Path(directory) / name
            if file.is_symlink() or file.resolve() in excluded:
                report.files_skipped += 1
                continue
            if (file.suffix.lower() in BINARY_SUFFIXES
                    or name.endswith((".satan.html", ".satan.json"))
                    or name == "last-report.html"):
                report.files_skipped += 1
                continue
            relative = file.relative_to(root).as_posix()
            try:
                # O_NOFOLLOW and fstat avoid following a swapped link or reading a FIFO.
                fd = os.open(file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_NONBLOCK", 0))
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
                        report.files_skipped += 1
                        report.warnings.append(f"Skipped nonregular or oversized file: {relative}")
                        continue
                    content = stream.read(MAX_FILE_BYTES + 1)
                if len(content) > MAX_FILE_BYTES:
                    report.files_skipped += 1
                    continue
                if b"\0" in content:
                    report.files_skipped += 1
                    continue
                text = content.decode("utf-8-sig")
            except UnicodeDecodeError:
                report.files_skipped += 1
                continue
            except OSError:
                report.files_skipped += 1
                report.warnings.append(f"Could not read file: {relative}")
                continue
            source = Source(relative, text)
            report.files_scanned += 1
            if file.suffix.lower() in {".py", ".pyw"}:
                try:
                    ast.parse(text)
                except (SyntaxError, ValueError, RecursionError):
                    report.warnings.append(f"Python syntax not understood; AST checks skipped: {relative}")
            for plugin in PLUGINS:
                report.findings.extend(plugin.analyze(source))
            if osv:
                manifests.extend(dependencies.pinned_dependencies(source))
    if osv:
        client = OSVClient()
        for dependency in manifests:
            report.findings.extend(client.findings(dependency))
        report.warnings.extend(client.warnings)
    order = {severity: i for i, severity in enumerate(Severity)}
    report.findings = sorted(set(report.findings),
                             key=lambda f: (order[f.severity], f.file, f.line, f.rule_id, f.title))
    return report
