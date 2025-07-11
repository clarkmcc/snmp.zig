# snmp.zig

A Zig library for SNMP (Simple Network Management Protocol) client operations, providing a clean interface to the Net-SNMP library.

## Features

- Support for SNMP v1, v2c (v3 in progress)
- Thread-safe client operations
- GET, GETNEXT, SET, WALK, and GETBULK operations  
- Comprehensive SNMP data type support
- Built on the robust Net-SNMP library

## Prerequisites

Before using this library, you need to have Net-SNMP development libraries installed:

### macOS
```bash
brew install net-snmp
```

### Ubuntu/Debian
```bash
sudo apt-get install libsnmp-dev
```

### CentOS/RHEL/Fedora
```bash
sudo yum install net-snmp-devel
# or for newer versions:
sudo dnf install net-snmp-devel
```

## Installation

Add this library as a dependency to your `build.zig.zon`:

```zig
.dependencies = .{
    .snmp = .{
        .url = "https://github.com/username/snmp.zig/archive/main.tar.gz",
        .hash = "...", // Use `zig fetch` to get the hash
    },
},
```

Then in your `build.zig`:

```zig
const snmp = b.dependency("snmp", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("snmp", snmp.module("snmp"));
exe.linkSystemLibrary("netsnmp");
```

## Quick Start

```zig
const std = @import("std");
const snmp = @import("snmp");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize SNMP client
    var client = try snmp.Client.init(.{
        .peername = "192.168.1.1",  // Target device IP
        .community = "public",       // Community string
        .version = .v2c,            // SNMP version
    });
    defer client.deinit();

    // Get a single OID value
    const value = try client.get(allocator, "1.3.6.1.2.1.1.1.0");
    defer value.deinit(allocator);
    std.debug.print("System description: {}\n", .{value});

    // Walk an OID tree
    var walk_result = try client.walk(allocator, "1.3.6.1.2.1.1");
    defer walk_result.deinit();
    
    for (walk_result.items) |item| {
        std.debug.print("OID: {s} = {}\n", .{ item.oid, item.value });
        item.value.deinit(allocator);
    }
}
```

## API Reference

### Client Configuration

```zig
const options = snmp.Client.Options{
    .peername = "192.168.1.1:161",  // Target (IP:port)
    .community = "public",           // Community string (v1/v2c)
    .version = .v2c,                // .v1, .v2c, or .v3
    .timeout = 5_000_000,           // Timeout in microseconds
    .retries = 3,                   // Number of retries
};
```

### Basic Operations

#### GET Operation
```zig
const value = try client.get(allocator, "1.3.6.1.2.1.1.1.0");
defer value.deinit(allocator);
```

#### SET Operation
```zig
const bindings = [_]snmp.VarBind{
    .{ .oid = "1.3.6.1.2.1.1.6.0", .value = .{ .string = "New Location" } },
};
try client.set(&bindings);
```

#### WALK Operation
```zig
var result = try client.walk(allocator, "1.3.6.1.2.1.1");
defer result.deinit();

for (result.items) |item| {
    std.debug.print("{s} = {}\n", .{ item.oid, item.value });
    item.value.deinit(allocator);
}
```

### Supported SNMP Data Types

- `integer` - 32-bit signed integer
- `string` - Octet string  
- `oid` - Object identifier
- `ipaddress` - IP address (4 bytes)
- `counter` - 32-bit counter
- `gauge` - 32-bit gauge
- `timeticks` - Time ticks (hundredths of seconds)
- `counter64` - 64-bit counter
- `null` - Null value

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
