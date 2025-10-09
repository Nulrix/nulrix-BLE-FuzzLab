#!/usr/bin/env python3
"""
BLE-FuzzLab - Advanced BLE Fuzzing Framework for Red Team Operations
Author: Nulrix
Purpose: Ethical Hacking and Security Assessment only - Unauthorized use is prohibited
License: MIT License
"""

import asyncio
import random
import struct
import time
import json
import argparse
from dataclasses import dataclass
from typing import List, Dict, Any
from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.service import BleakGATTService
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class FuzzPayload:
    """Fuzzing payload templates"""
    name: str
    payload: bytes
    description: str

class BLEFuzzLab:
    def __init__(self):
        self.target_device = None
        self.client = None
        self.services = []
        self.characteristics = []
        self.fuzz_results = []
        self.fuzz_payloads = self._generate_fuzz_payloads()
        
    def _generate_fuzz_payloads(self) -> List[FuzzPayload]:
        """Generate comprehensive fuzzing payloads"""
        payloads = []
        
        # Buffer Overflows
        payloads.extend([
            FuzzPayload("long_string", b"A" * 1000, "Long string overflow"),
            FuzzPayload("max_int", struct.pack("<I", 0xFFFFFFFF), "Maximum integer"),
            FuzzPayload("null_bytes", b"\x00" * 100, "Null byte injection"),
        ])
        
        # Format String
        payloads.extend([
            FuzzPayload("format_string", b"%s" * 50, "Format string attack"),
            FuzzPayload("format_specifiers", b"%n%x%s%p" * 20, "Multiple format specifiers"),
        ])
        
        # Protocol Specific
        payloads.extend([
            FuzzPayload("ble_reserved", b"\xFF" * 20, "Reserved BLE values"),
            FuzzPayload("invalid_handle", b"\x00\x00", "Invalid handle"),
            FuzzPayload("malformed_uuid", b"\xDE\xAD\xBE\xEF", "Malformed UUID"),
        ])
        
        # Random Data
        for i in range(10):
            random_data = bytes(random.randint(0, 255) for _ in range(50))
            payloads.append(FuzzPayload(f"random_{i}", random_data, "Random data fuzzing"))
            
        return payloads

    async def scan_devices(self, timeout: int = 10) -> List[Dict[str, Any]]:
        """Scan for BLE devices"""
        logger.info(f"Scanning for BLE devices for {timeout} seconds...")
        devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
        
        discovered = []
        for device, adv_data in devices.values():
            device_info = {
                "name": device.name or "Unknown",
                "address": device.address,
                "rssi": adv_data.rssi,
                "metadata": adv_data
            }
            discovered.append(device_info)
            logger.info(f"Found: {device_info['name']} - {device_info['address']} (RSSI: {device_info['rssi']})")
            
        return discovered

    async def connect(self, device_address: str):
        """Connect to target BLE device"""
        try:
            self.client = BleakClient(device_address)
            await self.client.connect()
            logger.info(f"Connected to {device_address}")
            
            # Enumerate services and characteristics
            await self._enumerate_services()
            
        except Exception as e:
            logger.error(f"Connection failed: {e}")

    async def _enumerate_services(self):
        """Enumerate all services and characteristics"""
        if not self.client.is_connected:
            return
            
        self.services = await self.client.get_services()
        
        for service in self.services:
            for char in service.characteristics:
                char_info = {
                    "service_uuid": service.uuid,
                    "char_uuid": char.uuid,
                    "properties": char.properties,
                    "handle": char.handle
                }
                self.characteristics.append(char_info)
                
        logger.info(f"Found {len(self.services)} services and {len(self.characteristics)} characteristics")

    async def fuzz_characteristics(self):
        """Fuzz all writable characteristics"""
        if not self.client.is_connected:
            logger.error("Not connected to device")
            return
            
        for char_info in self.characteristics:
            if "write" in char_info["properties"]:
                await self._fuzz_single_characteristic(char_info)

    async def _fuzz_single_characteristic(self, char_info: Dict[str, Any]):
        """Fuzz a single characteristic with all payloads"""
        service_uuid = char_info["service_uuid"]
        char_uuid = char_info["char_uuid"]
        
        logger.info(f"Fuzzing characteristic {char_uuid} in service {service_uuid}")
        
        for payload in self.fuzz_payloads:
            try:
                result = await self._send_fuzz_payload(char_uuid, payload)
                self.fuzz_results.append(result)
                
                # Add delay to avoid flooding
                await asyncio.sleep(0.1)
                
            except Exception as e:
                error_result = {
                    "timestamp": time.time(),
                    "service_uuid": service_uuid,
                    "char_uuid": char_uuid,
                    "payload": payload.name,
                    "error": str(e),
                    "status": "ERROR"
                }
                self.fuzz_results.append(error_result)
                logger.error(f"Fuzzing error on {char_uuid}: {e}")

    async def _send_fuzz_payload(self, char_uuid: str, payload: FuzzPayload) -> Dict[str, Any]:
        """Send individual fuzz payload"""
        try:
            await self.client.write_gatt_char(char_uuid, payload.payload, response=True)
            
            return {
                "timestamp": time.time(),
                "char_uuid": char_uuid,
                "payload": payload.name,
                "data": payload.payload.hex(),
                "description": payload.description,
                "status": "SENT"
            }
            
        except Exception as e:
            return {
                "timestamp": time.time(),
                "char_uuid": char_uuid,
                "payload": payload.name,
                "error": str(e),
                "status": "FAILED"
            }

    async def read_characteristics(self):
        """Read all readable characteristics"""
        if not self.client.is_connected:
            return
            
        for char_info in self.characteristics:
            if "read" in char_info["properties"]:
                try:
                    data = await self.client.read_gatt_char(char_info["char_uuid"])
                    logger.info(f"Read from {char_info['char_uuid']}: {data.hex()}")
                except Exception as e:
                    logger.error(f"Read failed for {char_info['char_uuid']}: {e}")

    async def enable_notifications(self):
        """Enable notifications for all notifiable characteristics"""
        if not self.client.is_connected:
            return
            
        for char_info in self.characteristics:
            if "notify" in char_info["properties"]:
                try:
                    await self.client.start_notify(
                        char_info["char_uuid"], 
                        self._notification_handler
                    )
                    logger.info(f"Notifications enabled for {char_info['char_uuid']}")
                except Exception as e:
                    logger.error(f"Notification setup failed for {char_info['char_uuid']}: {e}")

    def _notification_handler(self, characteristic: BleakGATTCharacteristic, data: bytearray):
        """Handle incoming notifications"""
        logger.info(f"Notification from {characteristic.uuid}: {data.hex()}")

    async def disconnect(self):
        """Disconnect from device"""
        if self.client and self.client.is_connected:
            await self.client.disconnect()
            logger.info("Disconnected from device")

    def save_results(self, filename: str = "fuzz_results.json"):
        """Save fuzzing results to file"""
        with open(filename, 'w') as f:
            json.dump(self.fuzz_results, f, indent=2)
        logger.info(f"Results saved to {filename}")

    def generate_report(self):
        """Generate summary report"""
        total_tests = len(self.fuzz_results)
        successful = len([r for r in self.fuzz_results if r.get('status') == 'SENT'])
        failed = len([r for r in self.fuzz_results if r.get('status') == 'FAILED'])
        errors = len([r for r in self.fuzz_results if r.get('status') == 'ERROR'])
        
        print("\n" + "="*50)
        print("BLE-FuzzLab Summary Report")
        print("="*50)
        print(f"Total Tests: {total_tests}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")
        print(f"Errors: {errors}")
        print("="*50)
        
        # Show interesting findings
        interesting = [r for r in self.fuzz_results if r.get('status') in ['FAILED', 'ERROR']]
        if interesting:
            print("\nInteresting Findings:")
            for finding in interesting[:10]:  # Show first 10
                print(f"  - {finding.get('char_uuid')}: {finding.get('error', 'Unknown error')}")

async def main():
    parser = argparse.ArgumentParser(description="BLE-FuzzLab - BLE Fuzzing Framework")
    parser.add_argument("--scan", action="store_true", help="Scan for BLE devices")
    parser.add_argument("--target", type=str, help="Target device MAC address")
    parser.add_argument("--timeout", type=int, default=10, help="Scan timeout")
    parser.add_argument("--output", type=str, default="fuzz_results.json", help="Output file")
    
    args = parser.parse_args()
    
    fuzzer = BLEFuzzLab()
    
    try:
        if args.scan:
            await fuzzer.scan_devices(args.timeout)
            return
            
        if args.target:
            await fuzzer.connect(args.target)
            
            # Perform comprehensive fuzzing
            await fuzzer.read_characteristics()
            await fuzzer.enable_notifications()
            await fuzzer.fuzz_characteristics()
            
            # Save results and generate report
            fuzzer.save_results(args.output)
            fuzzer.generate_report()
            
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        await fuzzer.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
