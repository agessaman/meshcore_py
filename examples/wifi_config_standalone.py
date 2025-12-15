#!/usr/bin/env python3
"""
Standalone WiFi Configuration Script for MeshCore - No meshcore dependency

This script is completely self-contained with embedded connection classes and
minimal packet parsing. It does not require or import any meshcore modules.

Dependencies (optional, only for specific connection types):
  - serial_asyncio: For serial connections (pip install pyserial-asyncio)
  - bleak: For BLE connections (pip install bleak)

Important Notes:
  - After disabling WiFi over TCP, the connection will drop (expected behavior)
  - After disabling WiFi, the device may need a reboot for changes to take effect
  - After rebooting, the device may take several seconds to initialize BLE advertising
  - If connecting via BLE after a reboot, wait a few seconds or use --list-devices to scan

Usage:
    # TCP connection
    python wifi_config_standalone.py --connection-type tcp --host 192.168.1.100 --port 5000 --query
    python wifi_config_standalone.py --connection-type tcp --host 192.168.1.100 --port 5000 --set-ssid "MyNetwork" --set-password "MyPassword" --enable

    # Serial connection
    python wifi_config_standalone.py --connection-type serial --port /dev/ttyUSB0 --query
    python wifi_config_standalone.py --connection-type serial --port /dev/ttyUSB0 --set-ssid "MyNetwork" --set-password "MyPassword" --enable

    # BLE connection
    python wifi_config_standalone.py --connection-type ble --address "MeshCore-123456789" --query
    python wifi_config_standalone.py --connection-type ble --address "MeshCore-123456789" --pin 123456 --set-ssid "MyNetwork" --set-password "MyPassword" --enable
"""
import asyncio
import argparse
import sys
import os
import struct
import socket

# Standalone connection classes (no meshcore dependency)
import logging

# Get logger (using different name to avoid meshcore dependency)
logger = logging.getLogger("wifi_config")

# TCP disconnect detection threshold
TCP_DISCONNECT_THRESHOLD = 5

# BLE UART service UUIDs
UART_SERVICE_UUID = "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
UART_RX_CHAR_UUID = "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"
UART_TX_CHAR_UUID = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"


class TCPConnection:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.transport = None
        self.frame_started = False
        self.frame_size = 0
        self.header = b""
        self.inframe = b""
        self._disconnect_callback = None
        self._send_count = 0
        self._receive_count = 0
        self.reader = None

    class MCClientProtocol(asyncio.Protocol):
        def __init__(self, cx):
            self.cx = cx

        def connection_made(self, transport):
            self.cx.transport = transport
            self.cx._send_count = 0
            self.cx._receive_count = 0
            logger.debug("connection established")

        def data_received(self, data):
            logger.debug("data received")
            self.cx._receive_count += 1
            self.cx.handle_rx(data)

        def error_received(self, exc):
            logger.error(f"Error received: {exc}")

        def connection_lost(self, exc):
            logger.debug("TCP server closed the connection")
            if self.cx._disconnect_callback:
                asyncio.create_task(self.cx._disconnect_callback("tcp_disconnect"))

    async def connect(self):
        """Connects to the device"""
        loop = asyncio.get_running_loop()
        await loop.create_connection(
            lambda: self.MCClientProtocol(self), self.host, self.port
        )
        logger.info("TCP Connection started")
        future = asyncio.Future()
        future.set_result(self.host)
        return future

    def set_reader(self, reader):
        self.reader = reader

    def handle_rx(self, data: bytearray):
        headerlen = len(self.header)
        framelen = len(self.inframe)
        if not self.frame_started:
            if len(data) >= 3 - headerlen:
                self.header = self.header + data[: 3 - headerlen]
                self.frame_started = True
                self.frame_size = int.from_bytes(self.header[1:], byteorder="little")
                self.handle_rx(data[3 - headerlen :])
            else:
                self.header = self.header + data
        else:
            if framelen + len(data) < self.frame_size:
                self.inframe = self.inframe + data
            else:
                self.inframe = self.inframe + data[: self.frame_size - framelen]
                if self.reader is not None:
                    asyncio.create_task(self.reader.handle_rx(self.inframe))
                self.frame_started = False
                self.header = b""
                self.inframe = b""
                if framelen + len(data) > self.frame_size:
                    self.handle_rx(data[self.frame_size - framelen :])

    async def send(self, data):
        if not self.transport:
            logger.error("Transport not connected, cannot send data")
            if self._disconnect_callback:
                await self._disconnect_callback("tcp_transport_lost")
            return
        self._send_count += 1
        if self._send_count - self._receive_count >= TCP_DISCONNECT_THRESHOLD:
            logger.warning(f"TCP disconnect threshold reached: sent {self._send_count}, received {self._receive_count}")
            # Don't return early - still try to send the command
            # The disconnect callback will handle cleanup if needed
        
        size = len(data)
        pkt = b"\x3c" + size.to_bytes(2, byteorder="little") + data
        logger.info(f"TCP sending: packet={pkt.hex()}, data={data.hex()}, size={size}")
        try:
            self.transport.write(pkt)
            logger.debug("TCP packet written successfully")
        except Exception as e:
            logger.error(f"TCP send error: {e}")
            raise

    async def disconnect(self):
        """Close the TCP connection."""
        if self.transport:
            self.transport.close()
            self.transport = None
            logger.debug("TCP Connection closed")

    def set_disconnect_callback(self, callback):
        """Set callback to handle disconnections."""
        self._disconnect_callback = callback


class SerialConnection:
    def __init__(self, port, baudrate, cx_dly=0.2):
        self.port = port
        self.baudrate = baudrate
        self.frame_started = False
        self.frame_size = 0
        self.transport = None
        self.header = b""
        self.reader = None
        self.inframe = b""
        self._disconnect_callback = None
        self.cx_dly = cx_dly
        self._connected_event = asyncio.Event()

    class MCSerialClientProtocol(asyncio.Protocol):
        def __init__(self, cx):
            self.cx = cx

        def connection_made(self, transport):
            self.cx.transport = transport
            logger.debug('port opened')
            try:
                import serial_asyncio
                if isinstance(transport, serial_asyncio.SerialTransport) and transport.serial:
                    transport.serial.rts = False
            except ImportError:
                pass
            self.cx._connected_event.set()

        def data_received(self, data):
            self.cx.handle_rx(data)

        def connection_lost(self, exc):
            logger.debug('Serial port closed')
            self.cx._connected_event.clear()
            if self.cx._disconnect_callback:
                asyncio.create_task(self.cx._disconnect_callback("serial_disconnect"))

        def pause_writing(self):
            logger.debug("pause writing")

        def resume_writing(self):
            logger.debug("resume writing")

    async def connect(self):
        """Connects to the device"""
        try:
            import serial_asyncio
        except ImportError:
            raise ImportError("serial_asyncio is required for serial connections. Install with: pip install pyserial-asyncio")
        
        self._connected_event.clear()
        loop = asyncio.get_running_loop()
        await serial_asyncio.create_serial_connection(
            loop,
            lambda: self.MCSerialClientProtocol(self),
            self.port,
            baudrate=self.baudrate,
        )
        await self._connected_event.wait()
        logger.info("Serial Connection started")
        return self.port

    def set_reader(self, reader):
        self.reader = reader

    def handle_rx(self, data: bytearray):
        headerlen = len(self.header)
        framelen = len(self.inframe)
        if not self.frame_started:
            if len(data) >= 3 - headerlen:
                self.header = self.header + data[: 3 - headerlen]
                self.frame_started = True
                self.frame_size = int.from_bytes(self.header[1:], byteorder="little")
                self.handle_rx(data[3 - headerlen :])
            else:
                self.header = self.header + data
        else:
            if framelen + len(data) < self.frame_size:
                self.inframe = self.inframe + data
            else:
                self.inframe = self.inframe + data[: self.frame_size - framelen]
                if self.reader is not None:
                    asyncio.create_task(self.reader.handle_rx(self.inframe))
                self.frame_started = False
                self.header = b""
                self.inframe = b""
                if framelen + len(data) > self.frame_size:
                    self.handle_rx(data[self.frame_size - framelen :])

    async def send(self, data):
        if not self.transport:
            logger.error("Transport not connected, cannot send data")
            return
        size = len(data)
        pkt = b"\x3c" + size.to_bytes(2, byteorder="little") + data
        logger.debug(f"sending pkt : {pkt}")
        self.transport.write(pkt)

    async def disconnect(self):
        """Close the serial connection."""
        if self.transport:
            self.transport.close()
            self.transport = None
            self._connected_event.clear()
            logger.debug("Serial Connection closed")

    def set_disconnect_callback(self, callback):
        """Set callback to handle disconnections."""
        self._disconnect_callback = callback


class BLEConnection:
    def __init__(self, address=None, device=None, client=None, pin=None):
        self.address = address
        self._user_provided_address = address
        self.client = client
        self._user_provided_client = client
        self.device = device
        self._user_provided_device = device
        self.pin = pin
        self.rx_char = None
        self._disconnect_callback = None
        self.reader = None

    async def connect(self):
        """Connects to the device. Returns address on success, None on failure."""
        try:
            from bleak import BleakClient, BleakScanner
            from bleak.backends.device import BLEDevice
            from bleak.backends.scanner import AdvertisementData
            from bleak.exc import BleakDeviceNotFoundError
        except ImportError:
            raise ImportError("bleak is required for BLE connections. Install with: pip install bleak")
        
        logger.debug(f"Connecting with client: {self.client}, address: {self.address}, device: {self.device}")

        if self.client:
            logger.debug("Using pre-configured BleakClient.")
            from bleak import BleakClient
            if self.client.is_connected:
                logger.error("Client is already connected !!! weird")
                self.address = self.client.address
                return self.address
            self.address = self.client.address
            self.client = BleakClient(self.address, disconnected_callback=self.handle_disconnect)
        elif self.device:
            logger.debug("Directly using a passed device.")
            self.client = BleakClient(self.device, disconnected_callback=self.handle_disconnect)
        else:
            def match_meshcore_device(d: BLEDevice, adv: AdvertisementData):
                """Filter to match MeshCore devices."""
                # Log all MeshCore devices found for debugging
                if adv.local_name and adv.local_name.startswith("MeshCore"):
                    logger.debug(f"Found MeshCore device: {adv.local_name} (address: {d.address})")
                    if self.address is None:
                        return True
                    # Try substring match (case-insensitive, handle emojis)
                    try:
                        if self.address.lower() in adv.local_name.lower():
                            return True
                        # Also try matching without emojis/special chars
                        import re
                        address_clean = re.sub(r'[^\w\s-]', '', self.address.lower())
                        name_clean = re.sub(r'[^\w\s-]', '', adv.local_name.lower())
                        if address_clean and address_clean in name_clean:
                            return True
                    except Exception as e:
                        logger.debug(f"Error matching device name: {e}")
                if d and d.address == self.address:
                    return True
                return False

            if self.address is None or ":" not in self.address:
                logger.info("Scanning for devices...")
                # First, let's scan and list all MeshCore devices for debugging
                if self.address:
                    logger.info(f"Searching for device matching: '{self.address}'")
                
                # Scan with a longer timeout
                device = await BleakScanner.find_device_by_filter(
                    match_meshcore_device,
                    timeout=10.0  # Give more time for scan
                )
                if device is None:
                    logger.warning("No MeshCore device found during scan.")
                    # Try to list all available MeshCore devices
                    logger.info("Attempting to list all MeshCore devices...")
                    try:
                        devices = await BleakScanner.discover(timeout=5.0)
                        meshcore_devices = [d for d in devices if d.name and d.name.startswith("MeshCore")]
                        if meshcore_devices:
                            logger.info(f"Found {len(meshcore_devices)} MeshCore device(s):")
                            for d in meshcore_devices:
                                logger.info(f"  - {d.name} ({d.address})")
                        else:
                            logger.info("No MeshCore devices found in scan.")
                    except Exception as e:
                        logger.debug(f"Could not list devices: {e}")
                    return None
                logger.info(f"Found device: {device.name} ({device.address})")
                self.client = BleakClient(device, disconnected_callback=self.handle_disconnect)
                self.address = self.client.address
            else:
                logger.debug("Connecting using provided address")
                self.client = BleakClient(self.address, disconnected_callback=self.handle_disconnect)

        try:
            await self.client.connect()
            if self.pin is not None:
                logger.debug(f"Attempting BLE pairing with PIN")
                try:
                    await self.client.pair()
                    logger.info("BLE pairing successful")
                except Exception as e:
                    logger.warning(f"BLE pairing failed: {e}")
        except BleakDeviceNotFoundError:
            return None
        except TimeoutError:
            return None

        try:
            await self.client.start_notify(UART_TX_CHAR_UUID, self.handle_rx)
        except AttributeError:
            if self.client:
                await self.client.disconnect()
            logger.info("Connection is not established, need to restart it")
            return None

        nus = self.client.services.get_service(UART_SERVICE_UUID)
        if nus is None:
            logger.error("Could not find UART service")
            return None
        self.rx_char = nus.get_characteristic(UART_RX_CHAR_UUID)

        logger.info("BLE Connection started")
        return self.address

    def handle_disconnect(self, client):
        """Callback to handle disconnection"""
        from bleak import BleakClient
        logger.debug(f"BLE device disconnected: {client.address} (is_connected: {client.is_connected})")
        self.address = self._user_provided_address
        self.client = self._user_provided_client
        self.device = self._user_provided_device
        if self._disconnect_callback:
            asyncio.create_task(self._disconnect_callback("ble_disconnect"))

    def set_disconnect_callback(self, callback):
        """Set callback to handle disconnections."""
        self._disconnect_callback = callback

    def set_reader(self, reader):
        self.reader = reader

    def handle_rx(self, characteristic, data: bytearray):
        if self.reader is not None:
            asyncio.create_task(self.reader.handle_rx(data))

    async def send(self, data):
        if not self.client:
            logger.error("Client is not connected")
            return False
        if not self.rx_char:
            logger.error("RX characteristic not found")
            return False
        await self.client.write_gatt_char(self.rx_char, bytes(data), response=True)

    async def disconnect(self):
        """Disconnect from the BLE device."""
        if self.client and self.client.is_connected:
            await self.client.disconnect()
            logger.debug("BLE Connection closed")

# WiFi status values (from wl_status_t enum)
WIFI_STATUS = {
    0: "WL_IDLE_STATUS",
    1: "WL_NO_SSID_AVAIL",
    2: "WL_SCAN_COMPLETED",
    3: "WL_CONNECTED",
    4: "WL_CONNECT_FAILED",
    5: "WL_CONNECTION_LOST",
    6: "WL_DISCONNECTED",
    7: "WL_AP_LISTENING",
    8: "WL_AP_CONNECTED",
    9: "WL_AP_FAILED",
}

# Packet type constants
PACKET_OK = 0
PACKET_ERROR = 1
PACKET_WIFI = 25


class MinimalReader:
    """Minimal reader that captures WiFi responses"""
    
    def __init__(self, response_queue):
        self.response_queue = response_queue
    
    async def handle_rx(self, data: bytearray):
        """Process complete frames from connection"""
        await self._process_frame(data)
    
    async def _process_frame(self, data: bytearray):
        """Process a complete frame and extract response"""
        if len(data) < 1:
            return
        
        packet_type = data[0]
        # Debug: log received packet type (use wifi_config logger)
        import logging
        log = logging.getLogger("wifi_config")
        log.debug(f"MinimalReader received packet type: {packet_type} (0x{packet_type:02x}), length: {len(data)}, data: {data.hex()[:100]}")
        
        if packet_type == PACKET_OK:
            result = {}
            if len(data) == 5:
                result["value"] = int.from_bytes(data[1:5], byteorder="little")
            await self.response_queue.put(("OK", result))
        
        elif packet_type == PACKET_ERROR:
            result = {"error_code": data[1]} if len(data) > 1 else {}
            await self.response_queue.put(("ERROR", result))
        
        elif packet_type == PACKET_WIFI:
            if len(data) < 2:
                await self.response_queue.put(("ERROR", {"reason": "invalid_frame_length"}))
                return
            
            wifi_subcommand = data[1]
            
            if wifi_subcommand == 0:  # SSID
                if len(data) >= 3:
                    ssid_len = data[2]
                    if len(data) >= 3 + ssid_len:
                        ssid = data[3:3+ssid_len].decode('utf-8', errors='ignore')
                        await self.response_queue.put(("WIFI_SSID", {"ssid": ssid}))
                    else:
                        await self.response_queue.put(("ERROR", {"reason": "invalid_frame_length"}))
                else:
                    await self.response_queue.put(("ERROR", {"reason": "invalid_frame_length"}))
            
            elif wifi_subcommand == 1:  # PASSWORD
                if len(data) >= 3:
                    pwd_len = data[2]
                    if len(data) >= 3 + pwd_len:
                        password = data[3:3+pwd_len].decode('utf-8', errors='ignore')
                        await self.response_queue.put(("WIFI_PASSWORD", {"password": password}))
                    else:
                        await self.response_queue.put(("ERROR", {"reason": "invalid_frame_length"}))
                else:
                    await self.response_queue.put(("ERROR", {"reason": "invalid_frame_length"}))
            
            elif wifi_subcommand == 2:  # CONFIG
                if len(data) >= 26:
                    status = data[2]
                    ip = socket.inet_ntoa(data[3:7])
                    subnet = socket.inet_ntoa(data[7:11])
                    gateway = socket.inet_ntoa(data[11:15])
                    dns1 = socket.inet_ntoa(data[15:19])
                    dns2 = socket.inet_ntoa(data[19:23])
                    rssi = struct.unpack('<h', data[23:25])[0]
                    ssid_len = data[25]
                    if len(data) >= 26 + ssid_len:
                        ssid = data[26:26+ssid_len].decode('utf-8', errors='ignore') if ssid_len > 0 else ""
                        config = {
                            'status': status,
                            'ip': ip,
                            'subnet': subnet,
                            'gateway': gateway,
                            'dns1': dns1,
                            'dns2': dns2,
                            'rssi': rssi,
                            'ssid': ssid
                        }
                        await self.response_queue.put(("WIFI_CONFIG", config))
                    else:
                        await self.response_queue.put(("ERROR", {"reason": "invalid_frame_length"}))
                else:
                    await self.response_queue.put(("ERROR", {"reason": "invalid_frame_length"}))
        
        else:
            # Unhandled packet type - this might be OK (e.g., SELF_INFO from APPSTART)
            # Log it for debugging but don't error
            import logging
            log = logging.getLogger("wifi_config")
            log.debug(f"Unhandled packet type: {packet_type} (0x{packet_type:02x}), data length: {len(data)}")


class MinimalWiFiConfig:
    """Minimal WiFi configuration handler without MeshCore dependency"""
    
    def __init__(self, connection):
        self.connection = connection
        self.response_queue = asyncio.Queue()
        # Create minimal reader to capture responses
        self.reader = MinimalReader(self.response_queue)
        connection.set_reader(self.reader)
    
    async def _send_command(self, data: bytes, timeout=15.0):
        """Send a command and wait for response"""
        # Clear any stale responses from the queue first
        # (in case there are leftover responses from previous commands)
        cleared = 0
        while not self.response_queue.empty():
            try:
                self.response_queue.get_nowait()
                cleared += 1
            except asyncio.QueueEmpty:
                break
        if cleared > 0:
            import logging
            log = logging.getLogger("wifi_config")
            log.debug(f"Cleared {cleared} stale response(s) from queue")
        
        # Use connection's send method which handles packet wrapping
        # The connection.send() wraps data in: 0x3c + size (2 bytes little-endian) + data
        import logging
        log = logging.getLogger("wifi_config")
        log.debug(f"Sending command: {data.hex()} (length: {len(data)})")
        await self.connection.send(data)
        
        # Small delay to allow device to process
        await asyncio.sleep(0.1)
        
        # Wait for response with increased timeout
        try:
            response_type, payload = await asyncio.wait_for(self.response_queue.get(), timeout=timeout)
            return response_type, payload
        except asyncio.TimeoutError:
            import logging
            log = logging.getLogger("wifi_config")
            log.debug(f"Command timeout after {timeout}s. Queue size: {self.response_queue.qsize()}")
            return "ERROR", {"reason": "timeout"}
    
    async def send_appstart(self):
        """Send APPSTART command to initialize connection"""
        appstart = b"\x01\x03      mccli"
        return await self._send_command(appstart)
    
    async def get_wifi_ssid(self):
        """Get WiFi SSID"""
        return await self._send_command(b"\x2C\x02")
    
    async def get_wifi_password(self):
        """Get WiFi password"""
        return await self._send_command(b"\x2C\x03")
    
    async def get_wifi_config(self):
        """Get WiFi configuration"""
        return await self._send_command(b"\x2C\x04")
    
    async def set_wifi_ssid(self, ssid: str):
        """Set WiFi SSID"""
        ssid_bytes = ssid.encode('utf-8')
        if len(ssid_bytes) > 31:
            raise ValueError("SSID too long (max 31 bytes)")
        data = struct.pack('<BB B', 0x2C, 0x00, len(ssid_bytes)) + ssid_bytes
        return await self._send_command(data)
    
    async def set_wifi_password(self, password: str):
        """Set WiFi password"""
        pwd_bytes = password.encode('utf-8')
        if len(pwd_bytes) > 63:
            raise ValueError("Password too long (max 63 bytes)")
        data = struct.pack('<BB B', 0x2C, 0x01, len(pwd_bytes)) + pwd_bytes
        return await self._send_command(data)
    
    async def set_wifi_enabled(self, enabled: bool):
        """Enable or disable WiFi
        
        The device should respond with OK before WiFi disconnects (if it's going to disconnect).
        """
        # CMD_WIFI (44/0x2C) + WIFI_SUBCMD_SET_ENABLED (5) + enabled (0 or 1)
        # Format: <BB B> = command (0x2C), subcommand (0x05), enabled (0 or 1)
        data = struct.pack('<BB B', 0x2C, 0x05, 1 if enabled else 0)
        return await self._send_command(data)
    
    async def set_wifi_config(self, ip: str, subnet: str, gateway: str, dns1: str, dns2: str):
        """Set static IP configuration"""
        ip_bytes = socket.inet_aton(ip)
        subnet_bytes = socket.inet_aton(subnet)
        gateway_bytes = socket.inet_aton(gateway)
        dns1_bytes = socket.inet_aton(dns1)
        dns2_bytes = socket.inet_aton(dns2)
        data = struct.pack('<BB', 0x2C, 0x06) + ip_bytes + subnet_bytes + gateway_bytes + dns1_bytes + dns2_bytes
        return await self._send_command(data)


async def list_ble_devices():
    """List all available MeshCore BLE devices"""
    try:
        from bleak import BleakScanner
    except ImportError:
        print("❌ Error: bleak is required for BLE device listing. Install with: pip install bleak")
        sys.exit(1)
    
    print("Scanning for MeshCore BLE devices...")
    print("(This may take a few seconds)\n")
    try:
        devices = await BleakScanner.discover(timeout=10.0)
        meshcore_devices = [d for d in devices if d.name and d.name.startswith("MeshCore")]
        if meshcore_devices:
            print(f"Found {len(meshcore_devices)} MeshCore device(s):\n")
            for i, d in enumerate(meshcore_devices, 1):
                print(f"  {i}. Name: {d.name}")
                print(f"     Address: {d.address}")
                print(f"     RSSI: {d.rssi if hasattr(d, 'rssi') else 'N/A'} dBm")
                print()
            print("To connect, use:")
            print(f"  --address \"{meshcore_devices[0].name}\"")
            if len(meshcore_devices) > 1:
                print("  (or use any of the device names/addresses listed above)")
        else:
            print("❌ No MeshCore devices found.")
            print("\nMake sure:")
            print("  - Device is powered on")
            print("  - Device is in range")
            print("  - Device is not connected to another app/device")
            print("  - Bluetooth is enabled on your computer")
    except Exception as e:
        print(f"❌ Error scanning for devices: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


async def query_wifi_settings(wifi: MinimalWiFiConfig):
    """Query and display all current WiFi settings"""
    print("=" * 60)
    print("Querying WiFi Settings...")
    print("=" * 60)
    
    # Get WiFi SSID
    print("\n📶 WiFi SSID:")
    try:
        response_type, payload = await wifi.get_wifi_ssid()
        if response_type == "ERROR":
            print(f"  ❌ Error: {payload}")
        elif response_type == "WIFI_SSID":
            ssid = payload.get('ssid', '')
            if ssid:
                print(f"  SSID: {ssid}")
            else:
                print("  SSID: (not configured)")
        else:
            print(f"  ⚠️  Unexpected response: {response_type}")
    except Exception as e:
        print(f"  ❌ Exception: {e}")
    
    # Get WiFi Password
    print("\n🔐 WiFi Password:")
    try:
        response_type, payload = await wifi.get_wifi_password()
        if response_type == "ERROR":
            print(f"  ❌ Error: {payload}")
        elif response_type == "WIFI_PASSWORD":
            password = payload.get('password', '')
            if password:
                masked = '*' * len(password)
                print(f"  Password: {masked} ({len(password)} characters)")
            else:
                print("  Password: (not configured)")
        else:
            print(f"  ⚠️  Unexpected response: {response_type}")
    except Exception as e:
        print(f"  ❌ Exception: {e}")
    
    # Get WiFi Configuration
    print("\n🌐 WiFi Network Configuration:")
    try:
        response_type, payload = await wifi.get_wifi_config()
        if response_type == "ERROR":
            print(f"  ❌ Error: {payload}")
        elif response_type == "WIFI_CONFIG":
            config = payload
            status_code = config.get('status', 0)
            status_name = WIFI_STATUS.get(status_code, f"Unknown ({status_code})")
            
            print(f"  Status: {status_name}")
            print(f"  IP Address: {config.get('ip', '0.0.0.0')}")
            print(f"  Subnet Mask: {config.get('subnet', '0.0.0.0')}")
            print(f"  Gateway: {config.get('gateway', '0.0.0.0')}")
            print(f"  DNS 1: {config.get('dns1', '0.0.0.0')}")
            print(f"  DNS 2: {config.get('dns2', '0.0.0.0')}")
            rssi = config.get('rssi', -128)
            if rssi != -128:
                print(f"  Signal Strength (RSSI): {rssi} dBm")
            else:
                print(f"  Signal Strength (RSSI): Not available")
            connected_ssid = config.get('ssid', '')
            if connected_ssid:
                print(f"  Connected SSID: {connected_ssid}")
            else:
                print(f"  Connected SSID: (not connected)")
        else:
            print(f"  ⚠️  Unexpected response: {response_type}")
    except Exception as e:
        print(f"  ❌ Exception: {e}")
    
    print("\n" + "=" * 60)


async def configure_wifi(wifi: MinimalWiFiConfig, args):
    """Configure WiFi settings based on command-line arguments"""
    print("=" * 60)
    print("Configuring WiFi Settings...")
    print("=" * 60)
    
    # Set SSID
    if args.set_ssid:
        print(f"\n📶 Setting WiFi SSID to: {args.set_ssid}")
        try:
            response_type, payload = await wifi.set_wifi_ssid(args.set_ssid)
            if response_type == "ERROR":
                print(f"  ❌ Error: {payload}")
            elif response_type == "OK":
                print("  ✅ SSID set successfully")
            else:
                print(f"  ⚠️  Unexpected response: {response_type}")
        except ValueError as e:
            print(f"  ❌ Validation error: {e}")
        except Exception as e:
            print(f"  ❌ Exception: {e}")
    
    # Set Password
    if args.set_password:
        print(f"\n🔐 Setting WiFi password...")
        try:
            response_type, payload = await wifi.set_wifi_password(args.set_password)
            if response_type == "ERROR":
                print(f"  ❌ Error: {payload}")
            elif response_type == "OK":
                masked = '*' * len(args.set_password)
                print(f"  ✅ Password set successfully ({masked})")
            else:
                print(f"  ⚠️  Unexpected response: {response_type}")
        except ValueError as e:
            print(f"  ❌ Validation error: {e}")
        except Exception as e:
            print(f"  ❌ Exception: {e}")
    
    # Enable/Disable WiFi
    if args.enable is not None:
        action = "enabling" if args.enable else "disabling"
        print(f"\n⚡ {action.capitalize()} WiFi...")
        try:
            # Wait for response - the device should respond with OK before WiFi disconnects
            response_type, payload = await wifi.set_wifi_enabled(args.enable)
            
            if response_type == "ERROR":
                # If disabling over TCP and we get timeout, it's likely because WiFi was disabled
                if not args.enable and args.connection_type == 'tcp' and payload.get('reason') == 'timeout':
                    print(f"  ⚠️  Command sent, but connection lost (expected when disabling WiFi over TCP)")
                    print(f"  ✅ WiFi should be disabled now")
                else:
                    print(f"  ❌ Error: {payload}")
            elif response_type == "OK":
                status = "enabled" if args.enable else "disabled"
                print(f"  ✅ WiFi {status} successfully")
            else:
                print(f"  ⚠️  Unexpected response: {response_type}")
        except Exception as e:
            print(f"  ❌ Exception: {e}")
    
    # Set Static IP Configuration
    if args.set_ip or args.set_subnet or args.set_gateway:
        if not all([args.set_ip, args.set_subnet, args.set_gateway]):
            print("\n❌ Error: Static IP configuration requires --set-ip, --set-subnet, and --set-gateway")
            return
        
        dns1 = args.set_dns1 or "8.8.8.8"
        dns2 = args.set_dns2 or "8.8.4.4"
        
        print(f"\n🌐 Setting static IP configuration...")
        print(f"  IP: {args.set_ip}")
        print(f"  Subnet: {args.set_subnet}")
        print(f"  Gateway: {args.set_gateway}")
        print(f"  DNS 1: {dns1}")
        print(f"  DNS 2: {dns2}")
        
        try:
            response_type, payload = await wifi.set_wifi_config(
                args.set_ip, args.set_subnet, args.set_gateway, dns1, dns2
            )
            if response_type == "ERROR":
                print(f"  ❌ Error: {payload}")
            elif response_type == "OK":
                print("  ✅ Static IP configuration set successfully")
            else:
                print(f"  ⚠️  Unexpected response: {response_type}")
        except Exception as e:
            print(f"  ❌ Exception: {e}")
    
    print("\n" + "=" * 60)


async def main():
    parser = argparse.ArgumentParser(
        description="Minimal WiFi Configuration Script (No MeshCore dependency)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # TCP connection
  %(prog)s --connection-type tcp --host 192.168.1.100 --tcp-port 5000 --query
  %(prog)s --connection-type tcp --host 192.168.1.100 --tcp-port 5000 --set-ssid "MyNetwork" --set-password "MyPassword" --enable

  # Serial connection
  %(prog)s --connection-type serial --port /dev/ttyUSB0 --query
  %(prog)s --connection-type serial --port /dev/ttyUSB0 --set-ssid "MyNetwork" --set-password "MyPassword" --enable

  # BLE connection
  %(prog)s --connection-type ble --address "MeshCore-123456789" --query
  %(prog)s --connection-type ble --address "MeshCore-123456789" --pin 123456 --set-ssid "MyNetwork" --set-password "MyPassword" --enable
        """
    )
    
    parser.add_argument("--connection-type", "-c", required=True,
                       choices=['ble', 'serial', 'tcp'],
                       help="Connection type: ble, serial, or tcp")
    
    # BLE-specific arguments
    parser.add_argument("--address", "-a", help="BLE device address or name (omit to scan and list all MeshCore devices)")
    parser.add_argument("--pin", type=int, help="PIN for BLE pairing")
    parser.add_argument("--list-devices", action="store_true", help="List all available MeshCore BLE devices and exit")
    
    # Serial-specific arguments
    parser.add_argument("--port", "-p", help="Serial port (e.g., /dev/ttyUSB0, COM3) or TCP port (for TCP connections)")
    parser.add_argument("--baud", "-b", type=int, default=115200, help="Baud rate (default: 115200)")
    
    # TCP-specific arguments
    parser.add_argument("--host", help="TCP host address")
    parser.add_argument("--tcp-port", type=int, default=5000, help="TCP port (default: 5000, can also use --port)")
    
    # Query options
    parser.add_argument("--query", "-q", action="store_true", help="Query WiFi settings")
    
    # Configuration options
    parser.add_argument("--set-ssid", help="Set WiFi SSID (max 31 characters)")
    parser.add_argument("--set-password", help="Set WiFi password (max 63 characters)")
    parser.add_argument("--enable", action="store_true", dest="enable", help="Enable WiFi")
    parser.add_argument("--disable", action="store_false", dest="enable", help="Disable WiFi")
    parser.add_argument("--set-ip", help="Set static IP address")
    parser.add_argument("--set-subnet", help="Set subnet mask")
    parser.add_argument("--set-gateway", help="Set gateway address")
    parser.add_argument("--set-dns1", help="Set primary DNS server (default: 8.8.8.8)")
    parser.add_argument("--set-dns2", help="Set secondary DNS server (default: 8.8.4.4)")
    
    args = parser.parse_args()
    
    # Handle --list-devices flag (must be async)
    if args.list_devices:
        await list_ble_devices()
        return
    
    # Validate connection-specific arguments
    if args.connection_type == 'ble':
        if not args.address:
            parser.error("--address is required for BLE connection (or use --list-devices to scan)")
    elif args.connection_type == 'serial':
        if not args.port:
            parser.error("--port is required for serial connection")
    elif args.connection_type == 'tcp':
        if not args.host:
            parser.error("--host is required for TCP connection")
        # Allow --port as alias for --tcp-port
        if args.port:
            args.tcp_port = int(args.port)
    
    # If no action specified, default to query
    if not any([args.query, args.set_ssid, args.set_password, args.enable is not None, args.set_ip]):
        args.query = True
    
    # Create connection
    connection = None
    try:
        print(f"Connecting via {args.connection_type.upper()}...")
        
        if args.connection_type == 'ble':
            print(f"  Address: {args.address}")
            if args.pin:
                print(f"  PIN: {args.pin}")
            connection = BLEConnection(address=args.address, pin=str(args.pin) if args.pin else None)
        
        elif args.connection_type == 'serial':
            print(f"  Port: {args.port}")
            print(f"  Baud: {args.baud}")
            connection = SerialConnection(args.port, args.baud)
        
        elif args.connection_type == 'tcp':
            print(f"  Host: {args.host}")
            print(f"  Port: {args.tcp_port}")
            connection = TCPConnection(args.host, args.tcp_port)
        
        # Set up WiFi handler BEFORE connecting (reader needs to be ready for incoming data)
        wifi = MinimalWiFiConfig(connection)
        
        # Connect and verify connection succeeded
        try:
            result = await connection.connect()
            # BLE returns None on failure, TCP returns a Future, Serial returns port string
            if args.connection_type == 'ble':
                if result is None:
                    print("❌ BLE connection failed! Device not found or connection refused.")
                    print("   Make sure the device is:")
                    print("     - Powered on and in range")
                    print("     - Advertising (not connected to another device)")
                    print("     - The address/name is correct")
                    if args.address and ":" not in args.address:
                        print(f"   Note: Searching for device name containing '{args.address}'")
                    sys.exit(1)
            elif args.connection_type == 'tcp':
                # TCP returns a Future, await it to get the result
                if hasattr(result, '__await__'):
                    result = await result
                if result is None:
                    print("❌ TCP connection failed!")
                    sys.exit(1)
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
        
        print("✅ Connected successfully!\n")
        
        # Give connection a moment to stabilize
        await asyncio.sleep(0.2)
        
        # Send APPSTART to initialize (required for device to be ready)
        print("Initializing connection...")
        try:
            response_type, payload = await wifi.send_appstart()
            if response_type == "ERROR":
                if payload.get('reason') == 'timeout':
                    print(f"⚠️  Warning: APPSTART timed out (device may not be ready)")
                else:
                    print(f"⚠️  Warning: APPSTART returned error: {payload}")
            elif response_type == "OK":
                print("✅ Connection initialized")
            # Give device time to process APPSTART
            await asyncio.sleep(0.5)
        except Exception as e:
            print(f"⚠️  Warning: APPSTART failed: {e} (continuing anyway)")
            await asyncio.sleep(0.3)
        
        # Query settings if requested
        if args.query:
            await query_wifi_settings(wifi)
        
        # Configure settings if any configuration options are provided
        if any([args.set_ssid, args.set_password, args.enable is not None, args.set_ip]):
            await configure_wifi(wifi, args)
            
            # If we configured something, optionally query again to verify
            if args.query:
                print("\n" + "=" * 60)
                print("Verifying updated settings...")
                print("=" * 60)
                await query_wifi_settings(wifi)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if connection:
            try:
                print("\nDisconnecting...")
                await connection.disconnect()
                print("✅ Disconnected.")
            except:
                pass


if __name__ == "__main__":
    asyncio.run(main())

