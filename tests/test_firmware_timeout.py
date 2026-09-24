"""Firmware timeout regressions; no connection to a real firewall is needed."""

import base64
from concurrent.futures import ThreadPoolExecutor
import json
import logging
import socket
import ssl
from threading import Event, Thread
import time
from unittest.mock import MagicMock, Mock
import xmlrpc.client
from xmlrpc.server import SimpleXMLRPCRequestHandler, SimpleXMLRPCServer

import pytest

from custom_components.pfsense import PfSenseData
from custom_components.pfsense.pypfsense import (
    Client,
    DEFAULT_TIMEOUT,
    FIRMWARE_UPDATE_TIMEOUT,
    TimeoutSafeTransport,
    TimeoutTransport,
)


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_timeouts_are_connection_local(scheme, monkeypatch):
    set_default = Mock()
    monkeypatch.setattr(socket, "setdefaulttimeout", set_default)
    client = Client(f"{scheme}://firewall.invalid", "user", "password")
    normal = client._get_proxy()
    firmware = client._get_proxy(timeout=FIRMWARE_UPDATE_TIMEOUT)
    normal_transport = normal("transport")
    firmware_transport = firmware("transport")
    host = "user:password@firewall.invalid"

    normal_connection = normal_transport.make_connection(host)
    firmware_connection = firmware_transport.make_connection(host)

    assert normal_connection.timeout == DEFAULT_TIMEOUT == 10
    assert firmware_connection.timeout == FIRMWARE_UPDATE_TIMEOUT == 90
    assert normal_connection is not firmware_connection
    expected_auth = base64.b64encode(b"user:password").decode()
    assert (
        "Authorization",
        f"Basic {expected_auth}",
    ) in normal_transport._extra_headers
    set_default.assert_not_called()
    normal("close")()
    firmware("close")()


@pytest.mark.parametrize("verify_ssl", [True, False])
def test_https_preserves_certificate_verification(verify_ssl):
    client = Client(
        "https://firewall.invalid", "user", "password", {"verify_ssl": verify_ssl}
    )
    with client._get_proxy(timeout=90) as proxy:
        transport = proxy("transport")
        assert isinstance(transport, TimeoutSafeTransport)
        connection = transport.make_connection("firewall.invalid")
        assert connection._context.check_hostname is verify_ssl
        assert connection._context.verify_mode == (
            ssl.CERT_REQUIRED if verify_ssl else ssl.CERT_NONE
        )


@pytest.mark.parametrize("transport_class", [TimeoutTransport, TimeoutSafeTransport])
def test_no_timeout_is_explicit(transport_class):
    transport = transport_class(None)
    assert transport.make_connection("firewall.invalid").timeout is None
    transport.close()


def test_firmware_request_uses_extended_timeout(monkeypatch):
    client = Client("https://firewall.invalid", "user", "password")
    execute = Mock(return_value={"data": {"base": {"version": "test"}}})
    monkeypatch.setattr(client, "_exec_php", execute)
    assert client.get_firmware_update_info() == {"base": {"version": "test"}}
    assert execute.call_args.kwargs == {"timeout": 90}
    assert "get_system_pkg_version()" in execute.call_args.args[0]
    assert "unlock($xmlrpclockkey)" in execute.call_args.args[0]
    assert "pfSense-upgrade" not in execute.call_args.args[0]


@pytest.mark.parametrize("timeout", [10, 90, None])
@pytest.mark.parametrize("fails", [True, False])
def test_php_transport_is_closed_on_success_and_failure(monkeypatch, timeout, fails):
    client = Client("https://firewall.invalid", "user", "password")
    proxy_context = MagicMock()
    proxy = proxy_context.__enter__.return_value
    get_proxy = Mock(return_value=proxy_context)
    monkeypatch.setattr(client, "_get_proxy", get_proxy)
    if fails:
        proxy.pfsense.exec_php.side_effect = TimeoutError("read timed out")
        with pytest.raises(TimeoutError):
            client._exec_php("test", timeout=timeout)
    else:
        proxy.pfsense.exec_php.return_value = {"real": '{"data": 42}'}
        assert client._exec_php("test", timeout=timeout) == {"data": 42}
    get_proxy.assert_called_once_with(timeout=timeout)
    proxy_context.__exit__.assert_called_once()


@pytest.mark.parametrize("operation", ["backup", "restore", "version"])
def test_other_rpc_operations_keep_default_timeout(monkeypatch, operation):
    client = Client("https://firewall.invalid", "user", "password")
    proxy_context = MagicMock()
    proxy = proxy_context.__enter__.return_value
    get_proxy = Mock(return_value=proxy_context)
    monkeypatch.setattr(client, "_get_proxy", get_proxy)
    if operation == "backup":
        proxy.pfsense.backup_config_section.return_value = {"system": {}}
        client._get_config_section("system")
    elif operation == "restore":
        client._restore_config_section("system", {})
    else:
        client.get_host_firmware_version()
    get_proxy.assert_called_once_with()
    proxy_context.__exit__.assert_called_once()


@pytest.fixture
def data():
    return PfSenseData(Mock(spec=Client), Mock(), Mock())


def test_timeout_keeps_cached_result_and_retries(data, caplog):
    old = {"base": {"version": "old"}}
    new = {"base": {"version": "new"}}
    data._firmware_update_info = old
    data._client.get_firmware_update_info.side_effect = [
        TimeoutError("read timed out"),
        TimeoutError("read timed out"),
        new,
        TimeoutError("read timed out"),
    ]

    with caplog.at_level(logging.INFO):
        data._refresh_firmware_update_info()
        data._refresh_firmware_update_info()
        assert data._get_firmware_update_info() == old
        assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1
        data._refresh_firmware_update_info()
        assert data._get_firmware_update_info() == new
        assert "have recovered" in caplog.text
        data._refresh_firmware_update_info()
    assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 2
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert not data._firmware_update_lock.locked()


def test_first_timeout_does_not_invent_firmware_data(data):
    data._client.get_firmware_update_info.side_effect = TimeoutError()
    data._refresh_firmware_update_info()
    assert data._get_firmware_update_info() is None


@pytest.mark.parametrize(
    "error",
    [
        xmlrpc.client.Fault(403, "Access denied"),
        ValueError("bad response"),
        RuntimeError("a non-timeout error mentioning timed out"),
    ],
)
def test_other_failures_are_errors_and_release_lock(data, caplog, error):
    data._firmware_update_info = {"base": "cached"}
    data._client.get_firmware_update_info.side_effect = error
    with caplog.at_level(logging.ERROR):
        data._refresh_firmware_update_info()
    assert "Failed to retrieve pfSense firmware update information" in caplog.text
    assert data._firmware_update_info == {"base": "cached"}
    assert not data._firmware_update_lock.locked()
    data._client.get_firmware_update_info.side_effect = None
    data._client.get_firmware_update_info.return_value = {"base": "recovered"}
    data._refresh_firmware_update_info()
    assert data._firmware_update_info == {"base": "recovered"}


def test_overlapping_polls_do_not_start_another_lookup(data):
    started = Event()
    release = Event()

    def slow_lookup():
        started.set()
        assert release.wait(5)
        return {"base": "updated"}

    data._client.get_firmware_update_info.side_effect = slow_lookup
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(data._refresh_firmware_update_info)
        try:
            assert started.wait(5)
            data._refresh_firmware_update_info()
            data._client.get_firmware_update_info.assert_called_once()
        finally:
            release.set()
        pending.result(timeout=5)
    assert data._firmware_update_info == {"base": "updated"}
    assert not data._firmware_update_lock.locked()


def test_delayed_xmlrpc_response_times_out_then_recovers_without_global_changes():
    class Handler(SimpleXMLRPCRequestHandler):
        rpc_paths = ("/xmlrpc.php",)

    def exec_php(script):
        time.sleep(0.08)
        return {"real": json.dumps({"data": {"base": "current"}})}

    default_timeout = socket.getdefaulttimeout()
    with SimpleXMLRPCServer(
        ("127.0.0.1", 0), requestHandler=Handler, logRequests=False
    ) as server:
        server.register_function(exec_php, "pfsense.exec_php")
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        try:
            client = Client(
                f"http://127.0.0.1:{server.server_address[1]}", "user", "password"
            )
            with pytest.raises(TimeoutError):
                client._exec_php("test", timeout=0.01)
            assert client._exec_php("test", timeout=2) == {"data": {"base": "current"}}
            assert socket.getdefaulttimeout() == default_timeout
        finally:
            server.shutdown()
            thread.join(timeout=5)
            assert not thread.is_alive()
