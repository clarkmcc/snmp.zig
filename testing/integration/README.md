# SNMP.zig Integration Tests

This directory contains the integration test suite for the SNMP.zig library. The tests verify that the library can successfully communicate with a real SNMP agent by performing SNMP walk operations and validating responses.

## Overview

The integration test setup consists of:

1. **Dockerized SNMP Daemon** - A containerized Net-SNMP daemon with custom test data
2. **Test Client** - A Zig test that connects to the daemon and validates responses
3. **Custom MIB Handler** - A Python script that provides test data for specific OIDs

## Architecture

```
┌─────────────────┐    SNMP Protocol    ┌──────────────────────┐
│                 │    (UDP Port 161)   │                      │
│   Zig Test      │◄───────────────────►│   Docker Container   │
│   (client.zig)  │                     │   (snmpd + mib.py)   │
│                 │                     │                      │
└─────────────────┘                     └──────────────────────┘
```

## Files Description

### `client.zig`
The main integration test file that:
- Initializes an SNMP client configured for SNMPv1
- Performs an SNMP walk on the test OID tree (`.1.3.6.1.4.1.8072.9999`)
- Validates that all expected OIDs and values are returned correctly
- Tests various SNMP data types (integer, string, OID, IP address, counters, etc.)

### `Dockerfile`
Creates a test environment with:
- Ubuntu 22.04 base image
- Net-SNMP daemon (`snmpd`)
- Python 3 for the custom MIB handler
- Proper SNMP configuration and MIB setup

### `snmpd.conf`
Configuration for the SNMP daemon:
- Listens on UDP port 161
- Uses "public" as the read-only community string
- Delegates OID `.1.3.6.1.4.1.8072.9999` to the Python script via `pass` directive

### `mib.py`
A Python script that acts as a custom SNMP MIB handler:
- Responds to SNMP GET and GET-NEXT requests
- Provides test data for various SNMP data types
- Implements proper OID sorting and traversal for SNMP walks
- Includes debug logging for troubleshooting

## Test Data

The integration test validates the following OIDs and data types:

| OID | Type | Value | Description |
|-----|------|-------|-------------|
| `.1.3.6.1.4.1.8072.9999.1.0` | INTEGER | 42 | Simple integer value |
| `.1.3.6.1.4.1.8072.9999.2.0` | STRING | "hello world" | Text string |
| `.1.3.6.1.4.1.8072.9999.3.0` | OID | `.1.3.6.1.2.1` | Object identifier |
| `.1.3.6.1.4.1.8072.9999.4.0` | IPADDRESS | 192.0.2.1 | IPv4 address |
| `.1.3.6.1.4.1.8072.9999.5.0` | COUNTER | 123456789 | 32-bit counter |
| `.1.3.6.1.4.1.8072.9999.6.0` | GAUGE | 654321 | Gauge value |
| `.1.3.6.1.4.1.8072.9999.7.0` | TIMETICKS | 987654 | Time ticks |
| `.1.3.6.1.4.1.8072.9999.8.0` | OPAQUE | "foobar" | Opaque data (currently skipped) |
| `.1.3.6.1.4.1.8072.9999.9.0` | COUNTER64 | 1234567890123 | 64-bit counter |

## Running the Tests

### Local Development

1. **Start the SNMP daemon:**
   ```bash
   cd testing/integration
   docker build -t snmp-test-daemon .
   docker run -d --name snmp-daemon -p 16161:161/udp snmp-test-daemon
   ```

2. **Run the integration test:**
   ```bash
   # From the project root
   zig build integration
   ```

3. **Clean up:**
   ```bash
   docker stop snmp-daemon
   docker rm snmp-daemon
   ```

### CI/CD

The integration tests are automatically run in GitHub Actions using the same Docker setup. See `.github/workflows/test.yml` for the complete CI configuration.

## Extending the Tests

### Adding New Data Types

1. **Add to `mib.py`**: Update the `OID_DATA` dictionary with new test cases:
   ```python
   OID_DATA: Dict[str, Tuple[str, str]] = {
       # ... existing entries ...
       "11.0": ("newtype", "test_value"),
   }
   ```

2. **Update `client.zig`**: Add corresponding expectations:
   ```zig
   const expectations = [_]struct {
       oid: []const u8,
       value: Expected,
   }{
       // ... existing entries ...
       .{ .oid = "NET-SNMP-MIB::netSnmpExperimental.11.0", .value = .{ .newtype = expected_value } },
   };
   ```

### Testing Different SNMP Versions

To test SNMPv2c or SNMPv3:

1. **Update client configuration** in `client.zig`:
   ```zig
   var client = try snmp.Client.init(.{
       .peername = "127.0.0.1:16161",
       .community = "public",
       .version = .v2c,  // or .v3
       // Add v3_security for SNMPv3
   });
   ```

2. **Update `snmpd.conf`** if needed for additional security configurations.

### Adding New Test Scenarios

Create additional test functions in `client.zig`:
```zig
test "snmp get single oid" {
    // Test single OID GET operations
}

test "snmp error handling" {
    // Test error conditions and timeouts
}
```

## Troubleshooting

### Common Issues

1. **Port conflicts**: Ensure port 16161 is not in use by other services
2. **Docker issues**: Check that Docker is running and the container starts successfully
3. **Timing issues**: The daemon needs a few seconds to start; increase sleep time if needed

### Debug Information

- **Container logs**: `docker logs snmp-daemon`
- **MIB handler logs**: Check `/tmp/mib_debug.log` inside the container
- **Network status**: `netstat -ln | grep 16161` to verify port binding

### Testing the SNMP Daemon Manually

You can test the daemon directly using command-line tools:

```bash
# Test GET operation
snmpget -v1 -c public localhost:16161 .1.3.6.1.4.1.8072.9999.1.0

# Test WALK operation  
snmpwalk -v1 -c public localhost:16161 .1.3.6.1.4.1.8072.9999
```

## Dependencies

- **Docker**: For running the containerized SNMP daemon
- **Net-SNMP development libraries**: Required for building the Zig library
- **Python 3**: For the custom MIB handler script

## Security Notes

This test setup uses minimal security (SNMPv1 with "public" community) and is intended only for testing. Do not use this configuration in production environments.