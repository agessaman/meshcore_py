"""Unit tests for the BlueZ passkey agent helper."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from meshcore.bluez_pairing_agent import (
    AGENT_CAPABILITY,
    AGENT_MANAGER_INTERFACE,
    BLUEZ_PATH,
    BLUEZ_SERVICE,
    _parse_passkey,
    passkey_agent,
)


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


class _AsyncNullLock:
    """Minimal async lock stand-in for manager._bus_lock."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class TestPasskeyAgentLifecycle(unittest.TestCase):
    def test_registers_and_unregisters(self):
        mock_bus = MagicMock()
        mock_bus.connected = True

        mock_manager = MagicMock()
        mock_manager._bus = mock_bus
        mock_manager._bus_lock = _AsyncNullLock()
        agent = MagicMock()

        register = AsyncMock()
        unregister = AsyncMock()

        async def run():
            with patch("sys.platform", "linux"), patch(
                "meshcore.bluez_pairing_agent._get_bluez_manager",
                AsyncMock(return_value=mock_manager),
            ), patch(
                "meshcore.bluez_pairing_agent._build_agent", return_value=agent
            ), patch(
                "meshcore.bluez_pairing_agent._register_agent", register
            ), patch(
                "meshcore.bluez_pairing_agent._unregister_agent", unregister
            ):
                async with passkey_agent("123456"):
                    pass

        asyncio.run(run())

        register.assert_awaited_once()
        self.assertIs(register.await_args.args[0], mock_bus)
        self.assertIs(register.await_args.args[2], agent)
        unregister.assert_awaited_once()
        self.assertIs(unregister.await_args.args[0], mock_bus)

    def test_rejects_non_linux(self):
        async def run():
            with patch("sys.platform", "darwin"):
                async with passkey_agent("123456"):
                    pass

        with self.assertRaises(RuntimeError):
            asyncio.run(run())

    def test_raises_if_bus_unavailable(self):
        mock_manager = MagicMock()
        mock_manager._bus = None
        mock_manager._bus_lock = _AsyncNullLock()

        async def run():
            with patch("sys.platform", "linux"), patch(
                "meshcore.bluez_pairing_agent._get_bluez_manager",
                AsyncMock(return_value=mock_manager),
            ), patch(
                "meshcore.bluez_pairing_agent._build_agent",
                return_value=MagicMock(),
            ):
                async with passkey_agent("123456"):
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
        mock_bus = MagicMock()
        mock_bus.connected = True

        mock_manager = MagicMock()
        mock_manager._bus = mock_bus
        mock_manager._bus_lock = _AsyncNullLock()
        agent = MagicMock()

        register = AsyncMock(side_effect=RuntimeError("register failed"))
        unregister = AsyncMock()

        async def run():
            with patch("sys.platform", "linux"), patch(
                "meshcore.bluez_pairing_agent._get_bluez_manager",
                AsyncMock(return_value=mock_manager),
            ), patch(
                "meshcore.bluez_pairing_agent._build_agent", return_value=agent
            ), patch(
                "meshcore.bluez_pairing_agent._register_agent", register
            ), patch(
                "meshcore.bluez_pairing_agent._unregister_agent", unregister
            ):
                async with passkey_agent("123456"):
                    pass

        with self.assertRaises(RuntimeError):
            asyncio.run(run())

        register.assert_awaited_once()
        unregister.assert_not_awaited()


class TestBuildAgentMethods(unittest.TestCase):
    def test_request_passkey_and_pincode(self):
        try:
            from dbus_fast.errors import DBusError
        except ImportError:
            self.skipTest("dbus_fast not installed")

        from meshcore.bluez_pairing_agent import _build_agent

        agent = _build_agent("654321")
        self.assertEqual(agent.RequestPinCode("/org/bluez/hci0/dev_AA"), "654321")
        self.assertEqual(agent.RequestPasskey("/org/bluez/hci0/dev_AA"), 654321)

        bad = _build_agent("not-a-pin")
        with self.assertRaises(DBusError):
            bad.RequestPasskey("/org/bluez/hci0/dev_AA")
        self.assertEqual(bad.RequestPinCode("/org/bluez/hci0/dev_AA"), "not-a-pin")


if __name__ == "__main__":
    unittest.main()
