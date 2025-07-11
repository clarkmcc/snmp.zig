const std = @import("std");
const snmp = @import("snmp");

const SNMP_V1_AGENT = "127.0.0.1:16161";
const SNMP_V3_AGENT = "127.0.0.1:16162";

test "snmp client integration test - basic operations" {
    const allocator = std.testing.allocator;

    // Configure client for SNMPv1.
    var client = try snmp.Client.init(.{
        .peername = SNMP_V1_AGENT,
        .community = "public",
        .version = .v1,
        .timeout = 5_000_000, // microseconds
        .retries = 3,
    });
    defer client.deinit();

    // Test SNMP GET
    var r1 = try client.get(allocator, ".1.3.6.1.4.1.8072.9999.1.0");
    defer r1.deinit(allocator);
    std.debug.assert(r1.integer == 42);

    // Test SNMP GETNEXT
    var r2 = try client.getNext(allocator, ".1.3.6.1.4.1.8072.9999.4.0");
    defer r2.deinit(allocator);
    std.debug.assert(r2.value.counter == 123_456_789);

    // Test SNMP WALK
    var walk = try client.walk(allocator, ".1.3.6.1.4.1.8072.9999");
    defer walk.deinit();

    const Expected = union(enum) {
        integer: i64,
        string: []const u8,
        oid: []const u8,
        ip: [4]u8,
        counter: u32,
        gauge: u32,
        timeticks: u32,
        counter64: u64,
        skipped,
    };

    const expectations = [_]struct {
        oid: []const u8,
        value: Expected,
    }{
        .{ .oid = "NET-SNMP-MIB::netSnmpExperimental.1.0", .value = .{ .integer = 42 } },
        .{ .oid = "NET-SNMP-MIB::netSnmpExperimental.2.0", .value = .{ .string = "\"hello world\"" } },
        .{ .oid = "NET-SNMP-MIB::netSnmpExperimental.3.0", .value = .{ .oid = "SNMPv2-SMI::mib-2" } },
        .{ .oid = "NET-SNMP-MIB::netSnmpExperimental.4.0", .value = .{ .ip = .{ 192, 0, 2, 1 } } },
        .{ .oid = "NET-SNMP-MIB::netSnmpExperimental.5.0", .value = .{ .counter = 123_456_789 } },
        .{ .oid = "NET-SNMP-MIB::netSnmpExperimental.6.0", .value = .{ .gauge = 654_321 } },
        .{ .oid = "NET-SNMP-MIB::netSnmpExperimental.7.0", .value = .{ .timeticks = 987_654 } },
        .{ .oid = "NET-SNMP-MIB::netSnmpExperimental.9.0", .value = .{ .counter64 = 1_234_567_890_123 } },
        .{ .oid = "NET-SNMP-MIB::netSnmpExperimental.8.0", .value = .skipped }, // todo: fix opaque
    };

    for (walk.items) |item| {
        std.debug.print("OID: {s}, Value: {any}\n", .{ item.oid, item.value });

        var matched = false;
        inline for (expectations) |exp| {
            if (std.mem.eql(u8, item.oid, exp.oid)) {
                matched = true;
                switch (exp.value) {
                    .integer => |v| std.debug.assert(item.value.integer == v),
                    .string => |v| std.debug.assert(std.mem.eql(u8, item.value.string, v)),
                    .oid => |v| std.debug.assert(std.mem.eql(u8, item.value.oid, v)),
                    .ip => |v| std.debug.assert(std.mem.eql(u8, item.value.ipaddress[0..], v[0..])),
                    .counter => |v| std.debug.assert(item.value.counter == v),
                    .gauge => |v| std.debug.assert(item.value.gauge == v),
                    .timeticks => |v| std.debug.assert(item.value.timeticks == v),
                    .counter64 => |v| std.debug.assert(item.value.counter64 == v),
                    .skipped => {},
                }
                break;
            }
        }

        if (!matched) {
            std.debug.panic("Unexpected OID: {s}", .{item.oid});
        }
    }
}

test "snmpv3 integration test - basic operations" {
    const allocator = std.testing.allocator;

    // Test SNMPv3 with authentication and privacy
    var client = try snmp.Client.init(.{
        .peername = SNMP_V3_AGENT,
        .version = .v3,
        .timeout = 5_000_000, // microseconds
        .retries = 3,
        .v3_security = .{
            .security_name = "testuser",
            .security_level = .auth_priv,
            .auth_protocol = .sha1,
            .auth_passphrase = "authpassphrase",
            .priv_protocol = .aes128,
            .priv_passphrase = "privpassphrase",
        },
    });
    defer client.deinit();

    // Test basic SNMP GET - verify it returns the expected integer value
    var r1 = client.get(allocator, ".1.3.6.1.4.1.8072.9999.1.0") catch |err| {
        std.debug.print("SNMPv3 GET failed: {}\n", .{err});
        return err;
    };
    defer r1.deinit(allocator);

    std.debug.print("SNMPv3 GET succeeded - received value: {}\n", .{r1.integer});
    std.debug.assert(r1.integer == 42);
}

test "snmpv3 integration test - authentication only" {
    const allocator = std.testing.allocator;

    // Test SNMPv3 with authentication but no privacy
    var client = try snmp.Client.init(.{
        .peername = SNMP_V3_AGENT,
        .version = .v3,
        .timeout = 5_000_000, // microseconds
        .retries = 3,
        .v3_security = .{
            .security_name = "authuser",
            .security_level = .auth_no_priv,
            .auth_protocol = .sha1,
            .auth_passphrase = "authpassphrase",
        },
    });
    defer client.deinit();

    // Test basic SNMP GET - verify it returns the expected integer value
    var r1 = client.get(allocator, ".1.3.6.1.4.1.8072.9999.1.0") catch |err| {
        std.debug.print("SNMPv3 auth-only GET failed: {}\n", .{err});
        return err;
    };
    defer r1.deinit(allocator);

    std.debug.print("SNMPv3 auth-only GET succeeded - received value: {}\n", .{r1.integer});
    std.debug.assert(r1.integer == 42);
}

test "snmpv3 integration test - no authentication" {
    const allocator = std.testing.allocator;

    // Test SNMPv3 with no authentication or privacy
    var client = try snmp.Client.init(.{
        .peername = SNMP_V3_AGENT,
        .version = .v3,
        .timeout = 5_000_000, // microseconds
        .retries = 3,
        .v3_security = .{
            .security_name = "noauthuser",
            .security_level = .no_auth_no_priv,
        },
    });
    defer client.deinit();

    // Test basic SNMP GET - just verify it doesn't error
    var r1 = client.get(allocator, ".1.3.6.1.4.1.8072.9999.1.0") catch |err| {
        std.debug.print("SNMPv3 no-auth GET failed: {}\n", .{err});
        return err;
    };
    defer r1.deinit(allocator);

    std.debug.print("SNMPv3 no-auth GET succeeded - received value: {}\n", .{r1.integer});
    std.debug.assert(r1.integer == 42);
}
