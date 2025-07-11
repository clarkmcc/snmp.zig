const std = @import("std");
const SnmpError = @import("errors.zig").SnmpError;
const Allocator = std.mem.Allocator;
const Client = @import("Client.zig").Client;
const SnmpResult = @import("value.zig").SnmpResult;

const c = @cImport({
    @cInclude("stddef.h");
    @cInclude("net-snmp/net-snmp-config.h");
    @cInclude("net-snmp/net-snmp-includes.h");
});

pub const MAX_OID_LEN = 128;
pub const MAX_OID_STR_LEN = 1024;

/// Convert OID array to string representation
pub fn oidToString(allocator: Allocator, oid: [*c]c.oid, oid_len: usize) SnmpError![]u8 {
    var oid_str: [MAX_OID_STR_LEN]u8 = undefined;
    const result_len = c.snprint_objid(&oid_str[0], oid_str.len, oid, oid_len);
    if (result_len < 0) return SnmpError.OidParseFailed;

    const actual_len = @min(@as(usize, @intCast(result_len)), oid_str.len - 1);
    return try allocator.dupe(u8, oid_str[0..actual_len]);
}

/// Converts a numeric OID like ".1.3.6.1.2.1.1.1.0" to a symbolic OID like "SNMPv2-MIB::sysDescr.0"
/// or returns null if it cannot be converted.
pub fn numericToSymbolic(allocator: Allocator, oid: []const u8) SnmpError!?[]u8 {
    var oid_arr: [MAX_OID_LEN]c.oid = undefined;
    var oid_arr_len: usize = oid_arr.len;
    _ = c.snmp_parse_oid(@ptrCast(oid.ptr), &oid_arr[0], &oid_arr_len) != 0;
    return oidToString(allocator, &oid_arr[0], oid_arr_len) catch null;
}

/// Utility functions for common OIDs
pub const CommonOids = struct {
    pub const system = ".1.3.6.1.2.1.1";
    pub const sys_descr = ".1.3.6.1.2.1.1.1.0";
    pub const sys_object_id = ".1.3.6.1.2.1.1.2.0";
    pub const sys_uptime = ".1.3.6.1.2.1.1.3.0";
    pub const sys_contact = ".1.3.6.1.2.1.1.4.0";
    pub const sys_name = ".1.3.6.1.2.1.1.5.0";
    pub const sys_location = ".1.3.6.1.2.1.1.6.0";
    pub const sys_services = ".1.3.6.1.2.1.1.7.0";

    pub const interfaces = ".1.3.6.1.2.1.2";
    pub const if_number = ".1.3.6.1.2.1.2.1.0";
    pub const if_table = ".1.3.6.1.2.1.2.2";
    pub const if_index = ".1.3.6.1.2.1.2.2.1.1";
    pub const if_descr = ".1.3.6.1.2.1.2.2.1.2";
    pub const if_type = ".1.3.6.1.2.1.2.2.1.3";
    pub const if_mtu = ".1.3.6.1.2.1.2.2.1.4";
    pub const if_speed = ".1.3.6.1.2.1.2.2.1.5";
    pub const if_phys_address = ".1.3.6.1.2.1.2.2.1.6";
    pub const if_admin_status = ".1.3.6.1.2.1.2.2.1.7";
    pub const if_oper_status = ".1.3.6.1.2.1.2.2.1.8";

    pub const ip = ".1.3.6.1.2.1.4";
    pub const ip_forwarding = ".1.3.6.1.2.1.4.1.0";
    pub const ip_default_ttl = ".1.3.6.1.2.1.4.2.0";

    pub const tcp = ".1.3.6.1.2.1.6";
    pub const udp = ".1.3.6.1.2.1.7";
    pub const snmp = ".1.3.6.1.2.1.11";
};

/// High-level convenience functions
pub const Utils = struct {
    const SystemInfo = struct {
        description: ?[]const u8,
        name: ?[]const u8,
        location: ?[]const u8,
        contact: ?[]const u8,
        uptime: ?u32,

        pub fn deinit(self: @This(), alloc: Allocator) void {
            if (self.description) |d| alloc.free(d);
            if (self.name) |n| alloc.free(n);
            if (self.location) |l| alloc.free(l);
            if (self.contact) |v| alloc.free(v);
        }
    };

    /// Get system information
    pub fn getSystemInfo(client: *Client, allocator: Allocator) !SystemInfo {
        const oids = [_][]const u8{
            CommonOids.sys_descr,
            CommonOids.sys_name,
            CommonOids.sys_location,
            CommonOids.sys_contact,
            CommonOids.sys_uptime,
        };

        var result = try client.getMultiple(allocator, &oids);
        defer result.deinit();

        var sys_info = SystemInfo{
            .description = null,
            .name = null,
            .location = null,
            .contact = null,
            .uptime = null,
        };

        if (result.getValue(CommonOids.sys_descr)) |val| {
            if (val.asString()) |s| sys_info.description = try allocator.dupe(u8, s);
        }
        if (result.getValue(CommonOids.sys_name)) |val| {
            if (val.asString()) |s| sys_info.name = try allocator.dupe(u8, s);
        }
        if (result.getValue(CommonOids.sys_location)) |val| {
            if (val.asString()) |s| sys_info.location = try allocator.dupe(u8, s);
        }
        if (result.getValue(CommonOids.sys_contact)) |val| {
            if (val.asString()) |s| sys_info.contact = try allocator.dupe(u8, s);
        }
        if (result.getValue(CommonOids.sys_uptime)) |val| {
            if (val.asInt()) |i| sys_info.uptime = @intCast(i);
        }

        return sys_info;
    }

    /// Get interface table
    pub fn getInterfaceTable(client: *Client, allocator: Allocator) !SnmpResult {
        return client.walk(allocator, CommonOids.if_table);
    }

    /// Format timeticks as human-readable duration
    pub fn formatTimeticks(timeticks: u32, allocator: Allocator) ![]u8 {
        const centiseconds = timeticks;
        const total_seconds = centiseconds / 100;
        const days = total_seconds / 86400;
        const hours = (total_seconds % 86400) / 3600;
        const minutes = (total_seconds % 3600) / 60;
        const seconds = total_seconds % 60;

        if (days > 0) {
            return std.fmt.allocPrint(allocator, "{d} days, {d:02}:{d:02}:{d:02}", .{ days, hours, minutes, seconds });
        } else {
            return std.fmt.allocPrint(allocator, "{d:02}:{d:02}:{d:02}", .{ hours, minutes, seconds });
        }
    }
};
