"""Compile every integration module, including platforms imported lazily by HA."""

from pathlib import Path
import warnings

import pytest

INTEGRATION = Path(__file__).resolve().parents[1] / "custom_components/pfsense"
SOURCES = sorted(INTEGRATION.rglob("*.py"))


@pytest.mark.parametrize(
    "path", SOURCES, ids=[str(path.relative_to(INTEGRATION)) for path in SOURCES]
)
def test_source_compiles_without_syntax_warnings(path):
    with warnings.catch_warnings():
        warnings.simplefilter("error", SyntaxWarning)
        compile(path.read_text(), str(path), "exec")
