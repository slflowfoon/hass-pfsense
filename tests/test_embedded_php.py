"""Python source and embedded PHP must preserve regular-expression escaping."""

from pathlib import Path
from unittest.mock import Mock
import warnings

from custom_components.pfsense import pypfsense


def test_client_source_compiles_without_syntax_warnings():
    path = Path(pypfsense.__file__)
    with warnings.catch_warnings():
        warnings.simplefilter("error", SyntaxWarning)
        compile(path.read_text(), str(path), "exec")


def test_telemetry_preserves_php_non_digit_regex(monkeypatch):
    client = pypfsense.Client("https://firewall.invalid", "user", "password")
    execute = Mock(return_value={"filesystems": [], "gateways": {}})
    monkeypatch.setattr(client, "_exec_php", execute)

    client.get_telemetry()

    script = execute.call_args.args[0]
    assert r'return preg_replace("/\D/", "", $s);' in script
    assert r'return preg_replace("/\\D/", "", $s);' not in script
