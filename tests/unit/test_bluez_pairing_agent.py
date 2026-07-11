"""Unit tests for the BlueZ passkey agent helper."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from meshcore.bluez_pairing_agent import (
    AGENT_CAPABILITY,
    AGENT_MANAGER_INTERFACE,
    BLUEZ_PATH,
    BLUEZ_SERVICE,
    _get_client_bus,
    _parse_passkey,
    passkey_agent,
)

DEVICE_PATH = "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF"


def _mock_client(bus=None, device_path=DEVICE_PATH):
    if bus is None:
        bus = MagicMock()
        bus.connected = True
    client = MagicMock()
    client._backend = MagicMock()
    client._backend._bus = bus
    client._backend._device_path = device_path
    return client


class TestParsePasskey(unittest.TestCase):
    def test_valid_passkey(self):
        self.assertEqual(_parse_passkey("123456"), 123456)
        self.assertEqual(_parse_passkey("0"), 0)
        self.assertEqual(_parse_passkey("000123"), 123)

    def test_rejects_non_numeric(self):
        with self.assertRaises(ValueError):
            _parse_passkey("abcdef")

    def test_rejects_out_of_range(self):
        with self.assertRaises(ValueError):
            _parse_passkey("1000000")


class TestGetClientBus(unittest.TestCase):
    def test_returns_bus_and_device_path(self):
        bus = MagicMock()
        bus.connected = True
        client = _mock_client(bus=bus)

        got_bus, got_path = _get_client_bus(client)

        self.assertIs(got_bus, bus)
        self.assertEqual(got_path, DEVICE_PATH)

    def test_raises_if_bus_missing(self):
        client = MagicMock()
        client._backend = MagicMock()
        client._backend._bus = None
        client._backend._device_path = DEVICE_PATH

        with self.assertRaises(RuntimeError):
            _get_client_bus(client)

    def test_raises_if_bus_disconnected(self):
        bus = MagicMock()
        bus.connected = False
        client = _mock_client(bus=bus)

        with self.assertRaises(RuntimeError):
            _get_client_bus(client)

    def test_raises_if_device_path_missing(self):
        client = _mock_client(device_path=None)

        with self.assertRaises(RuntimeError):
            _get_client_bus(client)


class TestPasskeyAgentLifecycle(unittest.TestCase):
    def test_registers_and_unregisters_on_client_bus(self):
        mock_bus = MagicMock()
        mock_bus.connected = True
        client = _mock_client(bus=mock_bus)
        agent = MagicMock()

        register = AsyncMock()
        unregister = AsyncMock()

        async def run():
            with patch("sys.platform", "linux"), patch(
                "meshcore.bluez_pairing_agent._build_agent", return_value=agent
            ) as build, patch(
                "meshcore.bluez_pairing_agent._register_agent", register
            ), patch(
                "meshcore.bluez_pairing_agent._unregister_agent", unregister
            ):
                async with passkey_agent("123456", client):
                    pass
                return build

        build = asyncio.run(run())

        # Agent is scoped to the client's device path.
        build.assert_called_once_with("123456", DEVICE_PATH)
        register.assert_awaited_once()
        self.assertIs(register.await_args.args[0], mock_bus)
        self.assertIs(register.await_args.args[2], agent)
        unregister.assert_awaited_once()
        self.assertIs(unregister.await_args.args[0], mock_bus)

    def test_skips_unregister_if_bus_disconnected_after_pairing(self):
        """If pairing tore down the client bus, unregister must be skipped."""
        mock_bus = MagicMock()
        mock_bus.connected = True
        client = _mock_client(bus=mock_bus)

        register = AsyncMock()
        unregister = AsyncMock()

        async def run():
            with patch("sys.platform", "linux"), patch(
                "meshcore.bluez_pairing_agent._build_agent",
                return_value=MagicMock(),
            ), patch(
                "meshcore.bluez_pairing_agent._register_agent", register
            ), patch(
                "meshcore.bluez_pairing_agent._unregister_agent", unregister
            ):
                async with passkey_agent("123456", client):
                    mock_bus.connected = False

        asyncio.run(run())

        register.assert_awaited_once()
        unregister.assert_not_awaited()

    def test_rejects_non_linux(self):
        async def run():
            with patch("sys.platform", "darwin"):
                async with passkey_agent("123456", _mock_client()):
                    pass

        with self.assertRaises(RuntimeError):
            asyncio.run(run())

    def test_rejects_non_numeric_pin_before_pairing(self):
        client = _mock_client()
        register = AsyncMock()

        async def run():
            with patch("sys.platform", "linux"), patch(
                "meshcore.bluez_pairing_agent._register_agent", register
            ):
                async with passkey_agent("not-a-pin", client):
                    pass

        with self.assertRaises(ValueError):
            asyncio.run(run())
        register.assert_not_awaited()

    def test_raises_if_bus_unavailable(self):
        client = MagicMock()
        client._backend = MagicMock()
        client._backend._bus = None
        client._backend._device_path = DEVICE_PATH

        async def run():
            with patch("sys.platform", "linux"):
                async with passkey_agent("123456", client):
                    pass

        with self.assertRaises(RuntimeError):
            asyncio.run(run())


class TestRegisterAgentDbus(unittest.TestCase):
    def test_register_agent_message(self):
        try:
            from dbus_fast.message import Message  # noqa: F401
        except ImportError:
            self.skipTest("dbus_fast not installed")

        from meshcore.bluez_pairing_agent import _register_agent

        mock_bus = MagicMock()
        mock_bus.export = MagicMock()
        mock_bus.call = AsyncMock(return_value=MagicMock())
        agent = MagicMock()

        async def run():
            with patch("bleak.backends.bluezdbus.utils.assert_reply"):
                await _register_agent(mock_bus, "/org/meshcore/agent/1", agent)

        asyncio.run(run())

        mock_bus.export.assert_called_once_with("/org/meshcore/agent/1", agent)
        msg = mock_bus.call.await_args.args[0]
        self.assertEqual(msg.destination, BLUEZ_SERVICE)
        self.assertEqual(msg.path, BLUEZ_PATH)
        self.assertEqual(msg.interface, AGENT_MANAGER_INTERFACE)
        self.assertEqual(msg.member, "RegisterAgent")
        self.assertEqual(msg.body[0], "/org/meshcore/agent/1")
        self.assertEqual(msg.body[1], AGENT_CAPABILITY)

    def test_register_agent_unexports_on_register_failure(self):
        """If RegisterAgent fails after export, the path must be unexported."""
        import sys
        from types import ModuleType

        from meshcore.bluez_pairing_agent import _register_agent

        mock_bus = MagicMock()
        mock_bus.export = MagicMock()
        mock_bus.unexport = MagicMock()
        mock_bus.call = AsyncMock(side_effect=RuntimeError("RegisterAgent failed"))
        agent = MagicMock()

        fake_message_mod = ModuleType("dbus_fast.message")
        fake_message_mod.Message = MagicMock(return_value=MagicMock())
        fake_dbus_fast = ModuleType("dbus_fast")
        fake_utils = ModuleType("bleak.backends.bluezdbus.utils")
        fake_utils.assert_reply = MagicMock()

        async def run():
            with patch.dict(
                sys.modules,
                {
                    "dbus_fast": fake_dbus_fast,
                    "dbus_fast.message": fake_message_mod,
                    "bleak.backends.bluezdbus.utils": fake_utils,
                },
            ):
                await _register_agent(mock_bus, "/org/meshcore/agent/1", agent)

        with self.assertRaises(RuntimeError):
            asyncio.run(run())

        mock_bus.export.assert_called_once_with("/org/meshcore/agent/1", agent)
        mock_bus.unexport.assert_called_once_with("/org/meshcore/agent/1", agent)

    def test_failed_register_does_not_call_unregister_in_context(self):
        """passkey_agent must not run finally-unregister if register never completed."""
        client = _mock_client()

        register = AsyncMock(side_effect=RuntimeError("register failed"))
        unregister = AsyncMock()

        async def run():
            with patch("sys.platform", "linux"), patch(
                "meshcore.bluez_pairing_agent._build_agent",
                return_value=MagicMock(),
            ), patch(
                "meshcore.bluez_pairing_agent._register_agent", register
            ), patch(
                "meshcore.bluez_pairing_agent._unregister_agent", unregister
            ):
                async with passkey_agent("123456", client):
                    pass

        with self.assertRaises(RuntimeError):
            asyncio.run(run())

        register.assert_awaited_once()
        unregister.assert_not_awaited()


def _call_agent(agent, name, *args):
    """Invoke an Agent1 method's original function.

    dbus_fast's @method() wrapper discards the return value on direct
    (non-D-Bus) calls, so unwrap it to assert on returned pins/passkeys.
    """
    fn = getattr(agent, name)
    wrapped = getattr(fn, "__wrapped__", None)
    if wrapped is not None:
        return wrapped(agent, *args)
    return fn(*args)


class TestBuildAgentMethods(unittest.TestCase):
    def _require_dbus_fast(self):
        try:
            from dbus_fast.errors import DBusError  # noqa: F401
        except ImportError:
            self.skipTest("dbus_fast not installed")

    def test_request_passkey_and_pincode(self):
        self._require_dbus_fast()
        from dbus_fast.errors import DBusError

        from meshcore.bluez_pairing_agent import _build_agent

        agent = _build_agent("654321", DEVICE_PATH)
        self.assertEqual(_call_agent(agent, "RequestPinCode", DEVICE_PATH), "654321")
        self.assertEqual(_call_agent(agent, "RequestPasskey", DEVICE_PATH), 654321)

        bad = _build_agent("not-a-pin", DEVICE_PATH)
        with self.assertRaises(DBusError):
            _call_agent(bad, "RequestPasskey", DEVICE_PATH)
        self.assertEqual(
            _call_agent(bad, "RequestPinCode", DEVICE_PATH), "not-a-pin"
        )

    def test_rejects_requests_for_other_devices(self):
        self._require_dbus_fast()
        from dbus_fast.errors import DBusError

        from meshcore.bluez_pairing_agent import _build_agent

        agent = _build_agent("654321", DEVICE_PATH)
        other = "/org/bluez/hci0/dev_11_22_33_44_55_66"

        for request in ("RequestPinCode", "RequestPasskey", "RequestAuthorization"):
            with self.assertRaises(DBusError):
                _call_agent(agent, request, other)
        with self.assertRaises(DBusError):
            _call_agent(agent, "RequestConfirmation", other, 654321)
        with self.assertRaises(DBusError):
            _call_agent(
                agent, "AuthorizeService", other,
                "0000110b-0000-1000-8000-00805f9b34fb",
            )

    def test_request_confirmation_checks_passkey(self):
        self._require_dbus_fast()
        from dbus_fast.errors import DBusError

        from meshcore.bluez_pairing_agent import _build_agent

        agent = _build_agent("654321", DEVICE_PATH)
        # Matching passkey is accepted for our device.
        _call_agent(agent, "RequestConfirmation", DEVICE_PATH, 654321)
        # Mismatched passkey must be rejected (MITM protection).
        with self.assertRaises(DBusError):
            _call_agent(agent, "RequestConfirmation", DEVICE_PATH, 111111)

    def test_authorization_accepted_for_own_device(self):
        self._require_dbus_fast()
        from meshcore.bluez_pairing_agent import _build_agent

        agent = _build_agent("654321", DEVICE_PATH)
        _call_agent(agent, "RequestAuthorization", DEVICE_PATH)
        _call_agent(
            agent, "AuthorizeService", DEVICE_PATH,
            "0000110b-0000-1000-8000-00805f9b34fb",
        )


if __name__ == "__main__":
    unittest.main()
