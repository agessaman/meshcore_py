#!/usr/bin/env python3
"""
Interactive WiFi Configuration Example for MeshCore Companion Radios via BLE

This example provides an interactive command-line interface to query and configure 
WiFi settings on a companion radio device using Bluetooth Low Energy (BLE) connection.
WiFi configuration is only available on ESP32-based devices.

Usage:
    python ble_wifi_config.py --address "MeshCore-123456789"
    python ble_wifi_config.py --address "MeshCore-123456789" --pin 123456

Interactive Commands:
    query, q              - Query and display current WiFi settings
    ssid <name>          - Set WiFi SSID (max 31 characters)
    password <pwd>, pwd  - Set WiFi password (max 63 characters)
    enable               - Enable WiFi
    disable              - Disable WiFi
    ip <ip> <subnet> <gateway> [dns1] [dns2] - Set static IP configuration
    help, h              - Show this help message
    quit, exit, q        - Exit the program
"""
import asyncio
import argparse
import sys
import os

# Add the src directory to the path to use local source code
# This ensures local edits supersede any installed package
script_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(os.path.dirname(script_dir), 'src')
if os.path.exists(src_dir) and src_dir not in sys.path:
    sys.path.insert(0, src_dir)

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


async def set_wifi_ssid_interactive(mc: MeshCore, ssid: str):
    """Set WiFi SSID"""
    print(f"\n📶 Setting WiFi SSID to: {ssid}")
    try:
        result = await mc.commands.set_wifi_ssid(ssid)
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


async def set_wifi_password_interactive(mc: MeshCore, password: str):
    """Set WiFi password"""
    print(f"\n🔐 Setting WiFi password...")
    try:
        result = await mc.commands.set_wifi_password(password)
        if result.type == EventType.ERROR:
            print(f"  ❌ Error: {result.payload}")
        elif result.type == EventType.OK:
            masked = '*' * len(password)
            print(f"  ✅ Password set successfully ({masked})")
        else:
            print(f"  ⚠️  Unexpected response: {result.type}")
    except ValueError as e:
        print(f"  ❌ Validation error: {e}")
    except Exception as e:
        print(f"  ❌ Exception: {e}")


async def set_wifi_enabled_interactive(mc: MeshCore, enabled: bool):
    """Enable or disable WiFi"""
    action = "enabling" if enabled else "disabling"
    print(f"\n⚡ {action.capitalize()} WiFi...")
    try:
        result = await mc.commands.set_wifi_enabled(enabled)
        if result.type == EventType.ERROR:
            print(f"  ❌ Error: {result.payload}")
        elif result.type == EventType.OK:
            status = "enabled" if enabled else "disabled"
            print(f"  ✅ WiFi {status} successfully")
        else:
            print(f"  ⚠️  Unexpected response: {result.type}")
    except Exception as e:
        print(f"  ❌ Exception: {e}")


async def set_wifi_ip_interactive(mc: MeshCore, ip: str, subnet: str, gateway: str, dns1: str = None, dns2: str = None):
    """Set static IP configuration"""
    dns1 = dns1 or "8.8.8.8"  # Default to Google DNS
    dns2 = dns2 or "8.8.4.4"  # Default to Google DNS
    
    print(f"\n🌐 Setting static IP configuration...")
    print(f"  IP: {ip}")
    print(f"  Subnet: {subnet}")
    print(f"  Gateway: {gateway}")
    print(f"  DNS 1: {dns1}")
    print(f"  DNS 2: {dns2}")
    
    try:
        result = await mc.commands.set_wifi_config(ip, subnet, gateway, dns1, dns2)
        if result.type == EventType.ERROR:
            print(f"  ❌ Error: {result.payload}")
        elif result.type == EventType.OK:
            print("  ✅ Static IP configuration set successfully")
        else:
            print(f"  ⚠️  Unexpected response: {result.type}")
    except Exception as e:
        print(f"  ❌ Exception: {e}")


def print_help():
    """Print help message"""
    print("\n" + "=" * 60)
    print("WiFi Configuration Commands:")
    print("=" * 60)
    print("  query, q              - Query and display current WiFi settings")
    print("  ssid <name>           - Set WiFi SSID (max 31 characters)")
    print("  password <pwd>, pwd  - Set WiFi password (max 63 characters)")
    print("  enable               - Enable WiFi")
    print("  disable              - Disable WiFi")
    print("  ip <ip> <subnet> <gateway> [dns1] [dns2]")
    print("                       - Set static IP configuration")
    print("  help, h              - Show this help message")
    print("  quit, exit, q        - Exit the program")
    print("=" * 60 + "\n")


async def interactive_loop(mc: MeshCore):
    """Interactive command loop"""
    print_help()
    print("Enter commands (type 'help' for available commands, 'quit' to exit):\n")
    
    try:
        while True:
            try:
                # Read input asynchronously
                line = (await asyncio.to_thread(sys.stdin.readline)).rstrip('\n')
                
                if not line:
                    continue
                
                parts = line.split()
                command = parts[0].lower()
                
                if command in ['quit', 'exit', 'q']:
                    print("Exiting...")
                    break
                
                elif command in ['help', 'h']:
                    print_help()
                
                elif command in ['query', 'q']:
                    await query_wifi_settings(mc)
                
                elif command == 'ssid':
                    if len(parts) < 2:
                        print("❌ Error: SSID required. Usage: ssid <name>")
                    else:
                        ssid = ' '.join(parts[1:])
                        await set_wifi_ssid_interactive(mc, ssid)
                
                elif command in ['password', 'pwd']:
                    if len(parts) < 2:
                        print("❌ Error: Password required. Usage: password <pwd>")
                    else:
                        password = ' '.join(parts[1:])
                        await set_wifi_password_interactive(mc, password)
                
                elif command == 'enable':
                    await set_wifi_enabled_interactive(mc, True)
                
                elif command == 'disable':
                    await set_wifi_enabled_interactive(mc, False)
                
                elif command == 'ip':
                    if len(parts) < 4:
                        print("❌ Error: IP configuration requires at least IP, subnet, and gateway.")
                        print("   Usage: ip <ip> <subnet> <gateway> [dns1] [dns2]")
                    else:
                        ip = parts[1]
                        subnet = parts[2]
                        gateway = parts[3]
                        dns1 = parts[4] if len(parts) > 4 else None
                        dns2 = parts[5] if len(parts) > 5 else None
                        await set_wifi_ip_interactive(mc, ip, subnet, gateway, dns1, dns2)
                
                else:
                    print(f"❌ Unknown command: {command}")
                    print("   Type 'help' for available commands")
                
            except Exception as e:
                print(f"❌ Error processing command: {e}")
                import traceback
                traceback.print_exc()
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except asyncio.CancelledError:
        print("\nTask cancelled")


async def main():
    parser = argparse.ArgumentParser(
        description="Interactive WiFi Configuration for MeshCore Companion Radios via BLE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  %(prog)s --address "MeshCore-123456789"
  %(prog)s --address "MeshCore-123456789" --pin 123456

Once connected, you can use interactive commands:
  query              - Query current WiFi settings
  ssid MyNetwork     - Set WiFi SSID
  password MyPass    - Set WiFi password
  enable             - Enable WiFi
  disable            - Disable WiFi
  ip 192.168.1.100 255.255.255.0 192.168.1.1  - Set static IP
  help               - Show help
  quit               - Exit
        """
    )
    
    parser.add_argument("-a", "--address", required=True,
                       help="BLE device address or name (e.g., 'MeshCore-123456789' or 't1000')")
    parser.add_argument("--pin", type=int, default=None,
                       help="PIN for BLE pairing (optional)")
    
    args = parser.parse_args()
    
    print(f"Connecting to BLE device: {args.address}")
    if args.pin:
        print(f"Using PIN pairing: {args.pin}")
    
    mc = None
    try:
        # Connect to device via BLE
        if args.pin:
            mc = await MeshCore.create_ble(args.address, pin=str(args.pin))
        else:
            mc = await MeshCore.create_ble(args.address)
        
        print("✅ Connected successfully!\n")
        
        # Start interactive loop
        await interactive_loop(mc)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if mc:
            try:
                print("\nDisconnecting...")
                await mc.disconnect()
                print("✅ Disconnected.")
            except:
                pass


if __name__ == "__main__":
    asyncio.run(main())

