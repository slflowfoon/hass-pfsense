"""Gateway metrics preserve their numeric values and availability."""

from types import SimpleNamespace

from homeassistant.components.sensor import SensorEntityDescription
from homeassistant.const import STATE_UNKNOWN
import pytest

from custom_components.pfsense.sensor import PfSenseGatewaySensor


def gateway_sensor(metric, gateway):
    coordinator = SimpleNamespace(
        last_update_success=True,
        data={
            "system_info": {"netgate_device_id": "test-firewall"},
            "telemetry": {"gateways": {"WAN_DHCP": gateway}},
        },
    )
    return PfSenseGatewaySensor(
        SimpleNamespace(title="Test firewall"),
        coordinator,
        SensorEntityDescription(key=f"telemetry.gateways.WAN_DHCP.{metric}"),
        True,
    )


@pytest.mark.parametrize("metric", ["stddev", "delay", "loss"])
@pytest.mark.parametrize(
    ("value", "expected", "available"),
    [
        ("12.345ms", 12.345, True),
        (" 0.25 ms ", 0.25, True),
        ("0.0%", 0.0, True),
        ("100%", 100.0, True),
        (0, 0, True),
        (1.5, 1.5, True),
        ("", STATE_UNKNOWN, False),
        ("none", STATE_UNKNOWN, False),
    ],
)
def test_numeric_metrics(metric, value, expected, available):
    sensor = gateway_sensor(metric, {metric: value})
    assert sensor.available is available
    assert sensor.native_value == expected


@pytest.mark.parametrize("metric", ["stddev", "delay", "loss"])
def test_missing_metric_is_unavailable(metric):
    sensor = gateway_sensor(metric, {})
    assert sensor.available is False
    assert sensor.native_value == STATE_UNKNOWN


def test_missing_gateway_is_unavailable():
    sensor = gateway_sensor("delay", {})
    sensor.coordinator.data["telemetry"]["gateways"].clear()
    assert sensor.available is False
    assert sensor.native_value == STATE_UNKNOWN


def test_failed_coordinator_update_is_unavailable():
    sensor = gateway_sensor("delay", {"delay": "10.5ms"})
    sensor.coordinator.last_update_success = False
    assert sensor.available is False


def test_status_is_not_numeric_filtered():
    sensor = gateway_sensor("status", {"status": "online"})
    assert sensor.available is True
    assert sensor.native_value == "online"
