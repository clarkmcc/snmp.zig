const std = @import("std");
const snmp = @import("snmp");

test "snmp client integration test" {
    const allocator = std.testing.allocator;

    // Configure client for SNMPv1.
    const client_opts = snmp.Client.Options{
        .peername = "127.0.0.1:16161",
        .community = "public",
        .version = .v1,
        .timeout = 5_000_000, // microseconds
        .retries = 3,
    };
    var client = try snmp.Client.init(client_opts);
    defer client.deinit();

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

    // Compile‑time table of every OID/value pair we expect the agent to return.
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
