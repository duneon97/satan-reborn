"""Read manifest data without installing packages or executing build scripts."""

import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from ..models import Finding, Severity, Source

PIN = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*==\s*"
    r"([A-Za-z0-9][A-Za-z0-9.!+_-]*)(?=\s*(?:;|--hash(?:=|\s)|\\?$))"
)
NPM_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    file: str
    line: int


def is_requirements(source: Source) -> bool:
    name = PurePosixPath(source.path).name.lower()
    return name.startswith("requirements") and name.endswith(".txt")


def requirement_lines(source: Source):
    for number, line in enumerate(source.lines, 1):
        line = line.split("#", 1)[0].strip()
        editable = line.startswith(("-e ", "--editable ", "--editable="))
        if line and (editable or not line.startswith(("-", "\\"))):
            yield number, line


def json_data(source: Source):
    try:
        data = json.loads(source.text)
        return data if isinstance(data, dict) else {}
    except (ValueError, RecursionError):
        return {}


def key_line(source: Source, key: str) -> int:
    pattern = re.compile(r'^\s*' + re.escape(json.dumps(key)) + r"\s*:")
    return next((n for n, line in enumerate(source.lines, 1) if pattern.search(line)), 1)


def pinned_dependencies(source: Source) -> list[Dependency]:
    dependencies = []
    if is_requirements(source):
        for line, requirement in requirement_lines(source):
            match = PIN.match(requirement)
            if match:
                name = re.sub(r"[-_.]+", "-", match[1]).lower()
                dependencies.append(Dependency("PyPI", name, match[2], source.path, line))
    name = PurePosixPath(source.path).name
    if name == "package.json":
        data = json_data(source)
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            items = data.get(section, {})
            if not isinstance(items, dict):
                continue
            for package, version in items.items():
                if isinstance(version, str) and NPM_VERSION.fullmatch(version):
                    dependencies.append(Dependency("npm", package, version, source.path,
                                                   key_line(source, package)))
    elif name == "package-lock.json":
        data = json_data(source)
        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for location, item in packages.items():
                if "node_modules/" not in location or not isinstance(item, dict):
                    continue
                version = item.get("version", "")
                package = location.rsplit("node_modules/", 1)[-1]
                if isinstance(version, str) and NPM_VERSION.fullmatch(version):
                    dependencies.append(Dependency("npm", package, version, source.path,
                                                   key_line(source, location)))
        # npm lockfile v1 has a nested dependencies tree rather than packages.
        pending = [data.get("dependencies", {})]
        while pending:
            items = pending.pop()
            if not isinstance(items, dict):
                continue
            for package, item in items.items():
                if not isinstance(item, dict):
                    continue
                version = item.get("version", "")
                if isinstance(version, str) and NPM_VERSION.fullmatch(version):
                    dependencies.append(Dependency("npm", package, version, source.path,
                                                   key_line(source, package)))
                pending.append(item.get("dependencies", {}))
    return dependencies


def analyze(source: Source) -> list[Finding]:
    findings = []
    if is_requirements(source):
        for number, requirement in requirement_lines(source):
            if not PIN.match(requirement):
                findings.append(Finding(
                    "deps.unpinned", Severity.WHISPER, "Python dependency is not exactly pinned",
                    source.path, number,
                    "Pin a reviewed version with == (no wildcard); use a lockfile and hashes "
                    "for reproducible installs. Review included requirement files separately.",
                    "CWE-1104",
                ))
    return findings
