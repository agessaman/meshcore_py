"""BlueZ pairing agent that supplies a fixed PIN/passkey during Pair().

On Linux, bleak's BlueZ backend only issues Device1.Pair() and never delivers
a passkey. BlueZ requires a registered org.bluez.Agent1 to answer
RequestPasskey / RequestPinCode. This module registers a short-lived agent on
bleak's shared system D-Bus connection so Pair() from that connection is
authenticated with the caller-provided PIN.
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, AsyncIterator, Optional

logger = logging.getLogger("meshcore")

AGENT_INTERFACE = "org.bluez.Agent1"
AGENT_MANAGER_INTERFACE = "org.bluez.AgentManager1"
BLUEZ_SERVICE = "org.bluez"
BLUEZ_PATH = "/org/bluez"
AGENT_CAPABILITY = "KeyboardOnly"
MAX_PASSKEY = 999999

if TYPE_CHECKING:
    from dbus_fast.aio.message_bus import MessageBus


def _parse_passkey(pin: str) -> int:
    """Convert a PIN string to a BlueZ passkey (uint32, 0–999999)."""
    if not pin.isdigit():
        raise ValueError(f"PIN {pin!r} is not a numeric passkey (0–{MAX_PASSKEY})")
    value = int(pin)
    if not 0 <= value <= MAX_PASSKEY:
        raise ValueError(f"PIN {pin!r} is out of passkey range (0–{MAX_PASSKEY})")
    return value


def _build_agent(pin: str):
    """Build an org.bluez.Agent1 ServiceInterface (lazy dbus_fast import)."""
    from typing import no_type_check

    from dbus_fast.errors import DBusError
    from dbus_fast.service import ServiceInterface, method

    class PasskeyAgent(ServiceInterface):
        def __init__(self, pin_code: str) -> None:
            super().__init__(AGENT_INTERFACE)
            self._pin = pin_code
            self._passkey: Optional[int]
            try:
                self._passkey = _parse_passkey(pin_code)
            except ValueError:
                # Non-numeric PINs can still satisfy RequestPinCode.
                self._passkey = None

        @method()
        def Release(self):
            logger.debug("BlueZ agent Release")

        @method()
        def Cancel(self):
            logger.debug("BlueZ agent Cancel")

        @method()
        @no_type_check
        def RequestPinCode(self, device: "o") -> "s":  # noqa: F821
            logger.debug("BlueZ agent RequestPinCode for %s", device)
            return self._pin

        @method()
        @no_type_check
        def DisplayPinCode(self, device: "o", pincode: "s"):  # noqa: F821
            logger.debug("BlueZ agent DisplayPinCode %s %s", device, pincode)

        @method()
        @no_type_check
        def RequestPasskey(self, device: "o") -> "u":  # noqa: F821
            logger.debug("BlueZ agent RequestPasskey for %s", device)
            if self._passkey is None:
                raise DBusError(
                    "org.bluez.Error.Rejected",
                    f"PIN {self._pin!r} is not a valid numeric passkey",
                )
            return self._passkey

        @method()
        @no_type_check
        def DisplayPasskey(
            self, device: "o", passkey: "u", entered: "q"  # noqa: F821
        ):
            logger.debug(
                "BlueZ agent DisplayPasskey %s %06u entered %u",
                device,
                passkey,
                entered,
            )

        @method()
        @no_type_check
        def RequestConfirmation(self, device: "o", passkey: "u"):  # noqa: F821
            logger.debug(
                "BlueZ agent RequestConfirmation %s %06u (auto-accept)",
                device,
                passkey,
            )

        @method()
        @no_type_check
        def RequestAuthorization(self, device: "o"):  # noqa: F821
            logger.debug("BlueZ agent RequestAuthorization %s (auto-accept)", device)

        @method()
        @no_type_check
        def AuthorizeService(self, device: "o", uuid: "s"):  # noqa: F821
            logger.debug(
                "BlueZ agent AuthorizeService %s %s (auto-accept)", device, uuid
            )

    return PasskeyAgent(pin)


def _unexport_agent(bus: "MessageBus", agent_path: str, agent) -> None:
    try:
        bus.unexport(agent_path, agent)
    except Exception as exc:
        logger.debug("unexport agent failed (ignored): %s", exc)


async def _register_agent(bus: "MessageBus", agent_path: str, agent) -> None:
    from dbus_fast.message import Message

    from bleak.backends.bluezdbus.utils import assert_reply

    # Export before RegisterAgent so BlueZ can invoke methods immediately.
    bus.export(agent_path, agent)
    try:
        reply = await bus.call(
            Message(
                destination=BLUEZ_SERVICE,
                path=BLUEZ_PATH,
                interface=AGENT_MANAGER_INTERFACE,
                member="RegisterAgent",
                signature="os",
                body=[agent_path, AGENT_CAPABILITY],
            )
        )
        assert_reply(reply)
    except BaseException:
        # Roll back the export (and any partial BlueZ registration) so a failed
        # register does not leave the path occupied on bleak's shared bus.
        try:
            reply = await bus.call(
                Message(
                    destination=BLUEZ_SERVICE,
                    path=BLUEZ_PATH,
                    interface=AGENT_MANAGER_INTERFACE,
                    member="UnregisterAgent",
                    signature="o",
                    body=[agent_path],
                )
            )
            assert_reply(reply)
        except Exception as exc:
            logger.debug("UnregisterAgent during register rollback (ignored): %s", exc)
        _unexport_agent(bus, agent_path, agent)
        raise
    logger.debug("Registered BlueZ pairing agent at %s", agent_path)


async def _unregister_agent(bus: "MessageBus", agent_path: str, agent) -> None:
    from dbus_fast.message import Message

    from bleak.backends.bluezdbus.utils import assert_reply

    try:
        reply = await bus.call(
            Message(
                destination=BLUEZ_SERVICE,
                path=BLUEZ_PATH,
                interface=AGENT_MANAGER_INTERFACE,
                member="UnregisterAgent",
                signature="o",
                body=[agent_path],
            )
        )
        assert_reply(reply)
    except Exception as exc:
        logger.debug("UnregisterAgent failed (ignored): %s", exc)
    _unexport_agent(bus, agent_path, agent)


async def _get_bluez_manager():
    """Fetch bleak's shared BlueZ manager (Linux-only import)."""
    from bleak.backends.bluezdbus.manager import get_global_bluez_manager

    return await get_global_bluez_manager()


@asynccontextmanager
async def passkey_agent(pin: str) -> AsyncIterator[None]:
    """Register a BlueZ Agent1 that returns ``pin`` for the duration of Pair().

    The agent is exported on bleak's shared system bus so BlueZ routes
    authentication for that connection's Device1.Pair() to this agent.

    Raises:
        RuntimeError: if not on Linux or the BlueZ bus is unavailable.
        ImportError: if dbus_fast / bleak BlueZ backend are not available.
    """
    if not sys.platform.startswith("linux"):
        raise RuntimeError("BlueZ pairing agent is only available on Linux")

    manager = await _get_bluez_manager()
    agent = _build_agent(pin)
    agent_path = f"/org/meshcore/agent/{os.getpid()}/{id(agent)}"
    registered = False

    try:
        async with manager._bus_lock:  # noqa: SLF001 — same bus bleak uses for Pair
            bus = manager._bus  # noqa: SLF001
            if bus is None or not bus.connected:
                raise RuntimeError("BlueZ D-Bus connection is not available")
            await _register_agent(bus, agent_path, agent)
            registered = True
        yield
    finally:
        if registered:
            async with manager._bus_lock:  # noqa: SLF001
                bus = manager._bus  # noqa: SLF001
                if bus is not None and bus.connected:
                    await _unregister_agent(bus, agent_path, agent)
