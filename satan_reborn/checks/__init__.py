"""Explicit plugin registry. Each plugin exposes analyze(Source)."""

from . import dependencies, hardcoded_secrets, insecure_config, risky_code

PLUGINS = (hardcoded_secrets, insecure_config, risky_code, dependencies)
