#!/usr/bin/env python3
"""
SNMP Pass Handler Script - Python Version
Handles SNMP GET and GET-NEXT requests for test OIDs.
"""

import sys
from typing import Dict, Tuple, Optional, List
import datetime

# Base OID for our custom MIB
BASE_OID = ".1.3.6.1.4.1.8072.9999"

# OID data structure: {oid_suffix: (type, value)}
# This eliminates duplication and makes maintenance easier
OID_DATA: Dict[str, Tuple[str, str]] = {
    "1.0": ("integer", "42"),
    "2.0": ("string", '"hello world"'),
    "3.0": ("objectid", ".1.3.6.1.2.1"),
    "4.0": ("ipaddress", "192.0.2.1"),
    "5.0": ("counter", "123456789"),
    "6.0": ("gauge", "654321"),
    "7.0": ("timeticks", "987654"),
    "8.0": ("opaque", "foobar"),
    "9.0": ("counter64", "1234567890123"),
    "10.0": ("uinteger", "424242"),
}

def debug_log(message: str) -> None:
    """Log debug message to a temp file for troubleshooting."""
    try:
        with open("/tmp/mib_debug.log", "a") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass  # Ignore any file write errors

def oid_sort_key(oid: str) -> List[int]:
    """Convert OID string to list of integers for proper numeric sorting."""
    # Remove the base OID part and convert remaining parts to integers
    if oid.startswith(BASE_OID + "."):
        suffix = oid[len(BASE_OID) + 1:]
        return [int(x) for x in suffix.split('.')]
    return []

def get_sorted_oids() -> List[str]:
    """Get sorted list of full OIDs for GET-NEXT operations."""
    oids = [f"{BASE_OID}.{suffix}" for suffix in OID_DATA.keys()]
    return sorted(oids, key=oid_sort_key)

def handle_get(oid: str) -> None:
    """Handle SNMP GET request."""
    # Remove base OID to get suffix
    if oid.startswith(BASE_OID + "."):
        suffix = oid[len(BASE_OID) + 1:]
        if suffix in OID_DATA:
            data_type, value = OID_DATA[suffix]
            print(oid)
            print(data_type)
            print(value)
            return
    
    # OID not found - no output for GET requests

def handle_get_next(oid: str) -> None:
    """Handle SNMP GET-NEXT request."""
    debug_log(f"GET-NEXT request for OID: {oid}")
    sorted_oids = get_sorted_oids()
    debug_log(f"Available OIDs: {sorted_oids}")
    
    # Handle base OID or initial requests
    if oid == BASE_OID or oid == f"{BASE_OID}.0.0":
        if sorted_oids:
            next_oid = sorted_oids[0]
            suffix = next_oid[len(BASE_OID) + 1:]
            data_type, value = OID_DATA[suffix]
            debug_log(f"Returning first OID: {next_oid}")
            print(next_oid)
            print(data_type)
            print(value)
        return
    
    # Find next OID in sequence
    try:
        current_index = sorted_oids.index(oid)
        debug_log(f"Found current OID at index {current_index}")
        if current_index + 1 < len(sorted_oids):
            next_oid = sorted_oids[current_index + 1]
            suffix = next_oid[len(BASE_OID) + 1:]
            data_type, value = OID_DATA[suffix]
            debug_log(f"Returning next OID: {next_oid}")
            print(next_oid)
            print(data_type)
            print(value)
            return
        else:
            debug_log("No more OIDs in sequence")
    except ValueError:
        debug_log("Current OID not found, searching for next larger OID")
        # Current OID not in our list, find the next larger OID
        for oid_candidate in sorted_oids:
            if oid_candidate > oid:
                suffix = oid_candidate[len(BASE_OID) + 1:]
                data_type, value = OID_DATA[suffix]
                debug_log(f"Returning next larger OID: {oid_candidate}")
                print(oid_candidate)
                print(data_type)
                print(value)
                return
        debug_log("No larger OID found")
    
    # If we reach here, there's no next OID - return nothing to indicate end of tree
    debug_log("End of OID tree reached")

def main():
    """Main entry point."""
    debug_log(f"Script called with args: {sys.argv}")
    
    if len(sys.argv) < 3:
        debug_log("Insufficient arguments")
        sys.exit(1)
    
    action = sys.argv[1]
    oid = sys.argv[2]
    
    debug_log(f"Action: {action}, OID: {oid}")
    
    if action == "-g":
        handle_get(oid)
    elif action == "-n":
        handle_get_next(oid)
    else:
        debug_log(f"Unrecognized action: {action}")
    # No output for unrecognized actions

if __name__ == "__main__":
    main()
