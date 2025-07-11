const c = @cImport({
    @cInclude("stddef.h");
    @cInclude("net-snmp/net-snmp-config.h");
    @cInclude("net-snmp/net-snmp-includes.h");
});

pub const Version = enum {
    v1,
    v2c,
    v3,

    pub fn toCInt(self: Version) c_int {
        return switch (self) {
            .v1 => c.SNMP_VERSION_1,
            .v2c => c.SNMP_VERSION_2c,
            .v3 => c.SNMP_VERSION_3,
        };
    }

    pub fn fromCInt(version: c_int) ?Version {
        return switch (version) {
            c.SNMP_VERSION_1 => .v1,
            c.SNMP_VERSION_2c => .v2c,
            c.SNMP_VERSION_3 => .v3,
            else => null,
        };
    }
};

test "version conversion" {
    const std = @import("std");

    try std.testing.expect(Version.v2c.toCInt() == c.SNMP_VERSION_2c);
    try std.testing.expect(Version.fromCInt(c.SNMP_VERSION_2c) == .v2c);
}
