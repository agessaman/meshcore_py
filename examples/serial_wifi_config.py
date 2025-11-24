#!/usr/bin/env python3
"""
WiFi Configuration Example for MeshCore Companion Radios

This example demonstrates how to query and configure WiFi settings on a companion radio device.
WiFi configuration is only available on ESP32-based devices.

Usage:
    # Query current WiFi settings
    python serial_wifi_config.py --port /dev/ttyUSB0 --query

    # Set WiFi SSID and password
    python serial_wifi_config.py --port /dev/ttyUSB0 --set-ssid "MyNetwork" --set-password "MyPassword"

    # Enable WiFi
    python serial_wifi_config.py --port /dev/ttyUSB0 --enable

    # Set static IP configuration
    python serial_wifi_config.py --port /dev/ttyUSB0 --set-ip 192.168.1.100 --set-subnet 255.255.255.0 --set-gateway 192.168.1.1
"""
import asyncio
import argparse
import json
from meshcore import MeshCore, EventType

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


async def query_wifi_settings(mc: MeshCore):
    """Query and display all current WiFi settings"""
    print("=" * 60)
    print("Querying WiFi Settings...")
    print("=" * 60)
    
    # Get WiFi SSID
    print("\n📶 WiFi SSID:")
    try:
        result = await mc.commands.get_wifi_ssid()
        if result.type == EventType.ERROR:
            print(f"  ❌ Error: {result.payload}")
        elif result.type == EventType.WIFI_SSID:
            ssid = result.payload.get('ssid', '')
            if ssid:
                print(f"  SSID: {ssid}")
            else:
                print("  SSID: (not configured)")
        else:
            print(f"  ⚠️  Unexpected response: {result.type}")
    except Exception as e:
        print(f"  ❌ Exception: {e}")
    
    # Get WiFi Password (masked for security)
    print("\n🔐 WiFi Password:")
    try:
        result = await mc.commands.get_wifi_password()
        if result.type == EventType.ERROR:
            print(f"  ❌ Error: {result.payload}")
        elif result.type == EventType.WIFI_PASSWORD:
            password = result.payload.get('password', '')
            if password:
                masked = '*' * len(password)
                print(f"  Password: {masked} ({len(password)} characters)")
            else:
                print("  Password: (not configured)")
        else:
            print(f"  ⚠️  Unexpected response: {result.type}")
    except Exception as e:
        print(f"  ❌ Exception: {e}")
    
    # Get WiFi Configuration (status, IP, etc.)
    print("\n🌐 WiFi Network Configuration:")
    try:
        result = await mc.commands.get_wifi_config()
        if result.type == EventType.ERROR:
            print(f"  ❌ Error: {result.payload}")
        elif result.type == EventType.WIFI_CONFIG:
            config = result.payload
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
            print(f"  ⚠️  Unexpected response: {result.type}")
    except Exception as e:
        print(f"  ❌ Exception: {e}")
    
    print("\n" + "=" * 60)


async def configure_wifi(mc: MeshCore, args):
    """Configure WiFi settings based on command-line arguments"""
    print("=" * 60)
    print("Configuring WiFi Settings...")
    print("=" * 60)
    
    # Set SSID
    if args.set_ssid:
        print(f"\n📶 Setting WiFi SSID to: {args.set_ssid}")
        try:
            result = await mc.commands.set_wifi_ssid(args.set_ssid)
            if result.type == EventType.ERROR:
                print(f"  ❌ Error: {result.payload}")
            elif result.type == EventType.OK:
                print("  ✅ SSID set successfully")
            else:
                print(f"  ⚠️  Unexpected response: {result.type}")
        except ValueError as e:
            print(f"  ❌ Validation error: {e}")
        except Exception as e:
            print(f"  ❌ Exception: {e}")
    
    # Set Password
    if args.set_password:
        print(f"\n🔐 Setting WiFi password...")
        try:
            result = await mc.commands.set_wifi_password(args.set_password)
            if result.type == EventType.ERROR:
                print(f"  ❌ Error: {result.payload}")
            elif result.type == EventType.OK:
                masked = '*' * len(args.set_password)
                print(f"  ✅ Password set successfully ({masked})")
            else:
                print(f"  ⚠️  Unexpected response: {result.type}")
        except ValueError as e:
            print(f"  ❌ Validation error: {e}")
        except Exception as e:
            print(f"  ❌ Exception: {e}")
    
    # Enable/Disable WiFi
    if args.enable is not None:
        action = "enabling" if args.enable else "disabling"
        print(f"\n⚡ {action.capitalize()} WiFi...")
        try:
            result = await mc.commands.set_wifi_enabled(args.enable)
            if result.type == EventType.ERROR:
                print(f"  ❌ Error: {result.payload}")
            elif result.type == EventType.OK:
                status = "enabled" if args.enable else "disabled"
                print(f"  ✅ WiFi {status} successfully")
            else:
                print(f"  ⚠️  Unexpected response: {result.type}")
        except Exception as e:
            print(f"  ❌ Exception: {e}")
    
    # Set Static IP Configuration
    if args.set_ip or args.set_subnet or args.set_gateway:
        # Require all IP config parameters
        if not all([args.set_ip, args.set_subnet, args.set_gateway]):
            print("\n❌ Error: Static IP configuration requires --set-ip, --set-subnet, and --set-gateway")
            return
        
        dns1 = args.set_dns1 or "8.8.8.8"  # Default to Google DNS
        dns2 = args.set_dns2 or "8.8.4.4"  # Default to Google DNS
        
        print(f"\n🌐 Setting static IP configuration...")
        print(f"  IP: {args.set_ip}")
        print(f"  Subnet: {args.set_subnet}")
        print(f"  Gateway: {args.set_gateway}")
        print(f"  DNS 1: {dns1}")
        print(f"  DNS 2: {dns2}")
        
        try:
            result = await mc.commands.set_wifi_config(
                args.set_ip,
                args.set_subnet,
                args.set_gateway,
                dns1,
                dns2
            )
            if result.type == EventType.ERROR:
                print(f"  ❌ Error: {result.payload}")
            elif result.type == EventType.OK:
                print("  ✅ Static IP configuration set successfully")
            else:
                print(f"  ⚠️  Unexpected response: {result.type}")
        except Exception as e:
            print(f"  ❌ Exception: {e}")
    
    print("\n" + "=" * 60)


async def main():
    parser = argparse.ArgumentParser(
        description="WiFi Configuration Example for MeshCore Companion Radios",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Query current WiFi settings
  %(prog)s --port /dev/ttyUSB0 --query

  # Set WiFi SSID and password
  %(prog)s --port /dev/ttyUSB0 --set-ssid "MyNetwork" --set-password "MyPassword"

  # Enable WiFi
  %(prog)s --port /dev/ttyUSB0 --enable

  # Set static IP configuration
  %(prog)s --port /dev/ttyUSB0 --set-ip 192.168.1.100 --set-subnet 255.255.255.0 --set-gateway 192.168.1.1

  # Full configuration example
  %(prog)s --port /dev/ttyUSB0 --set-ssid "MyNetwork" --set-password "MyPassword" --enable --set-ip 192.168.1.100 --set-subnet 255.255.255.0 --set-gateway 192.168.1.1
        """
    )
    
    parser.add_argument("--port", "-p", required=True, help="Serial port (e.g., /dev/ttyUSB0, COM3)")
    parser.add_argument("--baud", "-b", type=int, default=115200, help="Baud rate (default: 115200)")
    
    # Query options
    parser.add_argument("--query", "-q", action="store_true", 
                       help="Query and display current WiFi settings")
    
    # Configuration options
    parser.add_argument("--set-ssid", help="Set WiFi SSID (max 31 characters)")
    parser.add_argument("--set-password", help="Set WiFi password (max 63 characters)")
    parser.add_argument("--enable", action="store_true", dest="enable", 
                       help="Enable WiFi")
    parser.add_argument("--disable", action="store_false", dest="enable",
                       help="Disable WiFi")
    parser.add_argument("--set-ip", help="Set static IP address (requires --set-subnet and --set-gateway)")
    parser.add_argument("--set-subnet", help="Set subnet mask (required with --set-ip)")
    parser.add_argument("--set-gateway", help="Set gateway address (required with --set-ip)")
    parser.add_argument("--set-dns1", help="Set primary DNS server (default: 8.8.8.8)")
    parser.add_argument("--set-dns2", help="Set secondary DNS server (default: 8.8.4.4)")
    
    args = parser.parse_args()
    
    # If no action specified, default to query
    if not any([args.query, args.set_ssid, args.set_password, args.enable is not None, args.set_ip]):
        args.query = True
    
    print(f"Connecting to device on {args.port} at {args.baud} baud...")
    
    try:
        # Connect to device
        mc = await MeshCore.create_serial(args.port, args.baud)
        print("✅ Connected successfully!\n")
        
        # Query settings if requested
        if args.query:
            await query_wifi_settings(mc)
        
        # Configure settings if any configuration options are provided
        if any([args.set_ssid, args.set_password, args.enable is not None, args.set_ip]):
            await configure_wifi(mc, args)
            
            # If we configured something, optionally query again to verify
            if args.query or input("\nQuery updated settings? (y/n): ").lower() == 'y':
                await query_wifi_settings(mc)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            print("\nDisconnecting...")
            await mc.disconnect()
            print("✅ Disconnected.")
        except:
            pass


if __name__ == "__main__":
    asyncio.run(main())

