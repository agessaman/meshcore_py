"""BlueZ pairing agent that supplies a fixed PIN/passkey during Pair().

On Linux, bleak's BlueZ backend only issues Device1.Pair() and never delivers
a passkey. BlueZ requires a registered org.bluez.Agent1 to answer
RequestPasskey / RequestPinCode, and it routes those requests to the agent
registered by the same D-Bus connection that called Pair() (falling back to
the system default agent otherwise). bleak opens a private D-Bus connection
per BLE connection and calls Pair() on it, so this module registers a
short-lived agent on that same connection — the sender match then wins over
any default agent (e.g. a desktop session's) on every BlueZ version.
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
    from bleak import BleakClient
    from dbus_fast.aio.message_bus import MessageBus


def _parse_passkey(pin: str) -> int:
    """Convert a PIN string to a BlueZ passkey (uint32, 0–999999)."""
    if not pin.isdigit():
        raise ValueError(f"PIN {pin!r} is not a numeric passkey (0–{MAX_PASSKEY})")
    value = int(pin)
    if not 0 <= value <= MAX_PASSKEY:
        raise ValueError(f"PIN {pin!r} is out of passkey range (0–{MAX_PASSKEY})")
    return value


def _build_agent(pin: str, device_path: Optional[str] = None):
    """Build an org.bluez.Agent1 ServiceInterface (lazy dbus_fast import).

    When ``device_path`` is given, the agent only answers requests for that
    device and rejects everything else — while registered it may sit in
    BlueZ's default-agent queue, so it must not leak the PIN to (or approve)
    unrelated pairings happening on the system.
    """
    from typing import no_type_check

    from dbus_fast.errors import DBusError
    from dbus_fast.service import ServiceInterface, method

    class PasskeyAgent(ServiceInterface):
        def __init__(self, pin_code: str, device: Optional[str]) -> None:
            super().__init__(AGENT_INTERFACE)
            self._pin = pin_code
            self._device_path = device
            self._passkey: Optional[int]
            try:
                self._passkey = _parse_passkey(pin_code)
            except ValueError:
                # Non-numeric PINs can still satisfy RequestPinCode.
                self._passkey = None

        def _check_device(self, device: str, request: str) -> None:
            if self._device_path is not None and device != self._device_path:
                logger.warning(
                    "BlueZ agent rejecting %s for unrelated device %s "
                    "(pairing %s)",
                    request,
                    device,
                    self._device_path,
                )
                raise DBusError(
                    "org.bluez.Error.Rejected",
                    f"agent only serves {self._device_path}",
                )

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
            self._check_device(device, "RequestPinCode")
            return self._pin

        @method()
        @no_type_check
        def DisplayPinCode(self, device: "o", pincode: "s"):  # noqa: F821
            logger.debug("BlueZ agent DisplayPinCode %s %s", device, pincode)

        @method()
        @no_type_check
        def RequestPasskey(self, device: "o") -> "u":  # noqa: F821
            logger.debug("BlueZ agent RequestPasskey for %s", device)
            self._check_device(device, "RequestPasskey")
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
                "BlueZ agent RequestConfirmation %s %06u", device, passkey
            )
            self._check_device(device, "RequestConfirmation")
            # Numeric comparison: only accept if the displayed passkey matches
            # the configured PIN, otherwise we would waive MITM protection.
            if self._passkey is None or passkey != self._passkey:
                raise DBusError(
                    "org.bluez.Error.Rejected",
                    "passkey does not match the configured PIN",
                )

        @method()
        @no_type_check
        def RequestAuthorization(self, device: "o"):  # noqa: F821
            logger.debug("BlueZ agent RequestAuthorization %s", device)
            self._check_device(device, "RequestAuthorization")

        @method()
        @no_type_check
        def AuthorizeService(self, device: "o", uuid: "s"):  # noqa: F821
            logger.debug("BlueZ agent AuthorizeService %s %s", device, uuid)
            self._check_device(device, "AuthorizeService")

    return PasskeyAgent(pin, device_path)


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
        # register does not leave the path occupied on the client's bus.
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


def _get_client_bus(client: "BleakClient"):
    """Return (bus, device_path) of a connected bleak BlueZ client.

    Reaches into bleak's BleakClientBlueZDBus backend: ``_bus`` is the private
    D-Bus connection the client calls Device1.Pair() on, ``_device_path`` is
    the org.bluez device object path. Both exist once connect() has returned.
    """
    backend = getattr(client, "_backend", None)
    bus = getattr(backend, "_bus", None)
    device_path = getattr(backend, "_device_path", None)
    if bus is None or not bus.connected:
        raise RuntimeError(
            "BlueZ D-Bus connection is not available (client not connected?)"
        )
    if not device_path:
        raise RuntimeError("BlueZ device path is not available on the client")
    return bus, device_path


@asynccontextmanager
async def passkey_agent(pin: str, client: "BleakClient") -> AsyncIterator[None]:
    """Register a BlueZ Agent1 that answers ``pin`` for ``client``'s Pair().

    The agent is exported on the client's own D-Bus connection so BlueZ's
    sender match routes that connection's Device1.Pair() authentication to
    this agent, taking priority over any system default agent. It only
    answers for the client's device path and is unregistered on exit.

    Raises:
        RuntimeError: if not on Linux or the client's BlueZ bus is unavailable.
        ValueError: if ``pin`` is not a numeric 0–999999 passkey.
        ImportError: if dbus_fast / bleak BlueZ backend are not available.
    """
    if not sys.platform.startswith("linux"):
        raise RuntimeError("BlueZ pairing agent is only available on Linux")

    # BLE passkey entry is numeric-only; fail fast with a clear error instead
    # of mid-pairing (RequestPinCode, which accepts strings, is BR/EDR-only).
    _parse_passkey(pin)

    bus, device_path = _get_client_bus(client)
    agent = _build_agent(pin, device_path)
    agent_path = f"/org/meshcore/agent/{os.getpid()}/{id(agent)}"

    await _register_agent(bus, agent_path, agent)
    try:
        yield
    finally:
        # If pairing tore the connection down, bleak already disconnected the
        # bus and BlueZ dropped the agent with it — nothing left to undo.
        if bus.connected:
            await _unregister_agent(bus, agent_path, agent)
