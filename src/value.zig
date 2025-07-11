const std = @import("std");
const Allocator = std.mem.Allocator;
const utils = @import("utils.zig");

/// SNMP value types with proper memory management
pub const Value = union(enum) {
    integer: i32,
    string: []const u8,
    oid: []const u8,
    ipaddress: [4]u8,
    counter: u32,
    gauge: u32,
    timeticks: u32,
    counter64: u64,
    float: f32,
    double: f64,
    null: void,
    no_such_object: void,
    no_such_instance: void,
    end_of_mib_view: void,
    opaquev: []const u8,
    bit_string: []const u8,
    unsigned_integer: u32,

    /// Free any allocated memory associated with this value
    /// Must be called when the value is no longer needed
    pub fn deinit(self: Value, allocator: Allocator) void {
        switch (self) {
            .string => |s| allocator.free(s),
            .oid => |o| allocator.free(o),
            .opaquev => |o| allocator.free(o),
            .bit_string => |b| allocator.free(b),
            else => {},
        }
    }

    /// Format the value for display
    pub fn format(self: Value, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        switch (self) {
            .integer => |v| try writer.print("{d}", .{v}),
            .string => |v| try writer.print("\"{s}\"", .{v}),
            .oid => |v| try writer.print("{s}", .{v}),
            .ipaddress => |v| try writer.print("{d}.{d}.{d}.{d}", .{ v[0], v[1], v[2], v[3] }),
            .counter => |v| try writer.print("{d}c", .{v}),
            .gauge => |v| try writer.print("{d}g", .{v}),
            .timeticks => |v| {
                const centiseconds = v;
                const total_seconds = centiseconds / 100;
                const days = total_seconds / 86400;
                const hours = (total_seconds % 86400) / 3600;
                const minutes = (total_seconds % 3600) / 60;
                const seconds = total_seconds % 60;
                try writer.print("{d}d {d}h {d}m {d}s", .{ days, hours, minutes, seconds });
            },
            .counter64 => |v| try writer.print("{d} (counter64)", .{v}),
            .float => |v| try writer.print("{d}", .{v}),
            .double => |v| try writer.print("{d}", .{v}),
            .null => try writer.print("null", .{}),
            .no_such_object => try writer.print("noSuchObject", .{}),
            .no_such_instance => try writer.print("noSuchInstance", .{}),
            .end_of_mib_view => try writer.print("endOfMibView", .{}),
            .opaquev => |v| try writer.print("opaque({d} bytes)", .{v.len}),
            .bit_string => |v| try writer.print("bits({d} bytes)", .{v.len}),
            .unsigned_integer => |v| try writer.print("{d}u", .{v}),
        }
    }

    /// Convert value to a physical address string (e.g., MAC address)
    /// or return null if not applicable.
    pub fn asPhysicalAddress(self: Value, allocator: Allocator) ?[]u8 {
        // 6 bytes → 17 chars: "XX:XX:XX:XX:XX:XX"
        const str = switch (self) {
            .string => |o| o,
            else => return null,
        };
        const outLen = str.len * 3 - 1;
        var s = allocator.alloc(u8, outLen) catch return null;
        var idx: usize = 0;
        for (str, 0..) |b, i| {
            if (i != 0) {
                s[idx] = ':';
                idx += 1;
            }
            const hex = "0123456789ABCDEF";
            s[idx] = hex[b >> 4];
            s[idx + 1] = hex[b & 0xF];
            idx += 2;
        }
        return s;
    }

    /// Get string value if this is a string type
    pub fn asString(self: Value) ?[]const u8 {
        return switch (self) {
            .string => |s| s,
            else => null,
        };
    }

    /// Get OID value if this is an OID type
    pub fn asOid(self: Value) ?[]const u8 {
        return switch (self) {
            .oid => |o| o,
            else => null,
        };
    }

    /// Convert value to string representation
    /// Caller owns the returned memory
    pub fn toString(self: Value, allocator: Allocator) ![]u8 {
        return switch (self) {
            .string => |s| try allocator.dupe(u8, s),
            .integer => |i| try std.fmt.allocPrint(allocator, "{d}", .{i}),
            .counter => |v| try std.fmt.allocPrint(allocator, "{d}", .{v}),
            .gauge => |g| try std.fmt.allocPrint(allocator, "{d}", .{g}),
            .timeticks => |t| try std.fmt.allocPrint(allocator, "{d}", .{t}),
            .counter64 => |c64| try std.fmt.allocPrint(allocator, "{d}", .{c64}),
            .float => |f| try std.fmt.allocPrint(allocator, "{d}", .{f}),
            .double => |d| try std.fmt.allocPrint(allocator, "{d}", .{d}),
            .ipaddress => |ip| try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }),
            .oid => |o| try allocator.dupe(u8, o),
            .unsigned_integer => |u| try std.fmt.allocPrint(allocator, "{d}", .{u}),
            else => try std.fmt.allocPrint(allocator, "{}", .{self}),
        };
    }

    /// Convert to integer if possible
    pub fn asInt(self: Value) ?i64 {
        return switch (self) {
            .integer => |i| i,
            .counter => |v| @intCast(v),
            .gauge => |g| @intCast(g),
            .timeticks => |t| @intCast(t),
            .counter64 => |c64| @intCast(c64),
            .unsigned_integer => |u| @intCast(u),
            else => null,
        };
    }

    /// Convert to float if possible
    pub fn asFloat(self: Value) ?f64 {
        return switch (self) {
            .integer => |i| @floatFromInt(i),
            .counter => |v| @floatFromInt(v),
            .gauge => |g| @floatFromInt(g),
            .timeticks => |t| @floatFromInt(t),
            .counter64 => |c64| @floatFromInt(c64),
            .float => |f| f,
            .double => |d| d,
            .unsigned_integer => |u| @floatFromInt(u),
            else => null,
        };
    }

    /// Check if value represents an error state
    pub fn isError(self: Value) bool {
        return switch (self) {
            .no_such_object, .no_such_instance, .end_of_mib_view => true,
            else => false,
        };
    }

    /// Clone the value, allocating new memory for string/oid types
    pub fn clone(self: Value, allocator: Allocator) !Value {
        return switch (self) {
            .string => |s| Value{ .string = try allocator.dupe(u8, s) },
            .oid => |o| Value{ .oid = try allocator.dupe(u8, o) },
            .opaquev => |o| Value{ .opaquev = try allocator.dupe(u8, o) },
            .bit_string => |b| Value{ .bit_string = try allocator.dupe(u8, b) },
            else => self,
        };
    }

    /// Create a value for setting in SET operations
    pub fn createForSet(allocator: Allocator, comptime T: type, value: T) !Value {
        return switch (T) {
            i32 => Value{ .integer = value },
            u32 => Value{ .gauge = value },
            []const u8 => Value{ .string = try allocator.dupe(u8, value) },
            [4]u8 => Value{ .ipaddress = value },
            else => @compileError("Unsupported type for SNMP SET: " ++ @typeName(T)),
        };
    }
};

/// OID-Value pair for results
pub const OidValue = struct {
    oid: []const u8,
    value: Value,

    /// Free memory associated with this OID-Value pair
    pub fn deinit(self: OidValue, allocator: Allocator) void {
        allocator.free(self.oid);
        self.value.deinit(allocator);
    }

    /// Clone this OID-Value pair
    pub fn clone(self: OidValue, allocator: Allocator) !OidValue {
        return OidValue{
            .oid = try allocator.dupe(u8, self.oid),
            .value = try self.value.clone(allocator),
        };
    }
};

/// Variable binding for SET operations
pub const VarBind = struct {
    oid: []const u8,
    value: Value,

    pub fn init(oid: []const u8, value: Value) VarBind {
        return VarBind{ .oid = oid, .value = value };
    }

    pub fn deinit(self: VarBind, allocator: Allocator) void {
        self.value.deinit(allocator);
    }
};

pub const SnmpResult = struct {
    allocator: Allocator,
    items: []OidValue,

    /// Initialize a result with the given capacity
    pub fn init(allocator: Allocator) SnmpResult {
        return SnmpResult{
            .allocator = allocator,
            .items = &[_]OidValue{},
        };
    }

    /// Free all memory associated with this result
    pub fn deinit(self: *SnmpResult) void {
        for (self.items) |item| {
            item.deinit(self.allocator);
        }
        self.allocator.free(self.items);
    }

    /// Get a value by OID, matching both numeric and symbolic forms
    pub fn getValue(self: SnmpResult, oid: []const u8) ?Value {
        const symbolic = utils.numericToSymbolic(self.allocator, oid) catch null;
        defer if (symbolic) |s| {
            self.allocator.free(s);
        };

        // Look for a matching entry by either form
        for (self.items) |item| {
            if (std.mem.eql(u8, item.oid, oid) or (symbolic != null and std.mem.eql(u8, item.oid, symbolic.?))) {
                return item.value;
            }
        }

        return null;
    }

    /// Get all OIDs in the result
    pub fn getOids(self: SnmpResult, allocator: Allocator) ![][]const u8 {
        var oids = try allocator.alloc([]const u8, self.items.len);
        for (self.items, 0..) |item, i| {
            oids[i] = item.oid;
        }
        return oids;
    }

    /// Filter results by OID prefix
    pub fn filterByPrefix(self: SnmpResult, allocator: Allocator, prefix: []const u8) !SnmpResult {
        var filtered = std.ArrayList(OidValue).init(allocator);
        defer filtered.deinit();

        for (self.items) |item| {
            if (std.mem.startsWith(u8, item.oid, prefix)) {
                try filtered.append(try item.clone(allocator));
            }
        }

        return SnmpResult{
            .allocator = allocator,
            .items = try filtered.toOwnedSlice(),
        };
    }

    /// Sort results by OID
    pub fn sort(self: *SnmpResult) void {
        std.sort.insertion(OidValue, self.items, {}, oidValueLessThan);
    }

    fn oidValueLessThan(context: void, a: OidValue, b: OidValue) bool {
        _ = context;
        return std.mem.lessThan(u8, a.oid, b.oid);
    }
};

test "value operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test integer value
    const int_val = Value{ .integer = 42 };
    try testing.expect(int_val.asInt() == 42);
    try testing.expect(int_val.asFloat() == 42.0);

    // Test string value
    const str_data = try allocator.dupe(u8, "test string");
    const str_val = Value{ .string = str_data };
    defer str_val.deinit(allocator);

    try testing.expect(std.mem.eql(u8, str_val.asString().?, "test string"));

    // Test error states
    const error_val = Value{ .no_such_object = {} };
    try testing.expect(error_val.isError());

    // Test value creation for SET
    const set_val = try Value.createForSet(allocator, i32, 123);
    defer set_val.deinit(allocator);
    try testing.expect(set_val.asInt() == 123);
}

test "oid value operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const oid_val = OidValue{
        .oid = try allocator.dupe(u8, ".1.2.3.4"),
        .value = Value{ .integer = 42 },
    };
    defer oid_val.deinit(allocator);

    const cloned = try oid_val.clone(allocator);
    defer cloned.deinit(allocator);

    try testing.expect(std.mem.eql(u8, oid_val.oid, cloned.oid));
    try testing.expect(oid_val.value.asInt() == cloned.value.asInt());
}
