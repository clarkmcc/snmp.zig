const std = @import("std");
const Allocator = std.mem.Allocator;
const Version = @import("version.zig").Version;
const V3Security = @import("snmp_v3.zig").V3Security;
const SnmpError = @import("errors.zig").SnmpError;
const Value = @import("value.zig").Value;
const OidValue = @import("value.zig").OidValue;
const VarBind = @import("value.zig").VarBind;
const SnmpResult = @import("value.zig").SnmpResult;
const utils = @import("utils.zig");

const c = @cImport({
    @cInclude("stddef.h");
    @cInclude("net-snmp/net-snmp-config.h");
    @cInclude("net-snmp/net-snmp-includes.h");
});

/// Global initialization for the netsnmp
var init_once = std.once(initSnmpLibrary);
fn initSnmpLibrary() void {
    c.init_snmp("snmp-zig");
}

pub const Client = @This();

/// Configuration options for SNMP client
pub const Options = struct {
    /// Target IP address or hostname of the SNMP agent
    peername: []const u8,
    /// SNMP community string (default: "public") - ignored for SNMPv3
    community: []const u8 = "public",
    /// SNMP version to use (default: v2c)
    version: Version = .v2c,
    /// SNMPv3 security configuration (required for v3)
    v3_security: ?V3Security = null,
    /// Number of retries for SNMP requests (default: 3)
    retries: u8 = 3,
    /// Timeout in microseconds (default: 1000000 = 1 second)
    timeout: u32 = 1000000,
    /// Maximum receive message size (default: 65536)
    max_recv_size: u32 = 65536,
    /// Local port to bind to (0 = auto)
    local_port: u16 = 0,
    /// Remote port to connect to (161 = default SNMP port)
    remote_port: u16 = 161,
};

session: [*c]c.netsnmp_session,
mutex: std.Thread.Mutex,
options: Options,

/// Initialize a new SNMP client with the given options
pub fn init(options: Options) SnmpError!Client {
    init_once.call();

    var session: c.struct_snmp_session = undefined;
    c.snmp_sess_init(&session);

    // Configure basic session parameters
    session.rcvMsgMaxSize = options.max_recv_size;
    session.retries = options.retries;
    session.timeout = options.timeout;
    session.version = options.version.toCInt();
    session.local_port = options.local_port;
    session.remote_port = options.remote_port;

    // Configure authentication based on version
    switch (options.version) {
        .v1, .v2c => {
            // Configure community string
            session.community = c.strdup(@ptrCast(options.community.ptr)) orelse return SnmpError.OutOfMemory;
            session.community_len = options.community.len;
        },
        .v3 => {
            const v3_sec = options.v3_security orelse return SnmpError.InvalidSecurity;

            // Configure SNMPv3 security
            session.securityModel = c.SNMP_SEC_MODEL_USM;
            session.securityLevel = v3_sec.security_level.toCInt();

            // Security name
            session.securityName = c.strdup(@ptrCast(v3_sec.security_name.ptr)) orelse return SnmpError.OutOfMemory;
            session.securityNameLen = v3_sec.security_name.len;

            // Authentication
            if (v3_sec.auth_protocol != .none) {
                if (v3_sec.auth_protocol.toOid()) |auth_oid| {
                    session.securityAuthProto = @constCast(auth_oid.ptr);
                    session.securityAuthProtoLen = auth_oid.len;
                }

                if (v3_sec.auth_passphrase) |passphrase| {
                    // Set initial key length
                    session.securityAuthKeyLen = session.securityAuthKey.len;

                    // Generate Ku from passphrase
                    const passphrase_cstr = try utils.stringToNullTerminated(passphrase);
                    if (c.generate_Ku(session.securityAuthProto,
                                    @intCast(session.securityAuthProtoLen),
                                    @ptrCast(&passphrase_cstr[0]), passphrase.len,
                                    &session.securityAuthKey,
                                    &session.securityAuthKeyLen) != c.SNMPERR_SUCCESS) {
                        return SnmpError.SessionConfigFailed;
                    }
                }
            }

            // Privacy
            if (v3_sec.priv_protocol != .none) {
                // Privacy requires authentication
                if (v3_sec.auth_protocol == .none) {
                    return SnmpError.InvalidSecurity;
                }

                if (v3_sec.priv_protocol.toOid()) |priv_oid| {
                    session.securityPrivProto = @constCast(priv_oid.ptr);
                    session.securityPrivProtoLen = priv_oid.len;
                }

                if (v3_sec.priv_passphrase) |passphrase| {
                    // Set initial key length
                    session.securityPrivKeyLen = session.securityPrivKey.len;

                    // Generate Ku from passphrase using the same auth protocol
                    const passphrase_cstr = try utils.stringToNullTerminated(passphrase);
                    if (c.generate_Ku(session.securityAuthProto,
                                    @intCast(session.securityAuthProtoLen),
                                    @ptrCast(&passphrase_cstr[0]), passphrase.len,
                                    &session.securityPrivKey,
                                    &session.securityPrivKeyLen) != c.SNMPERR_SUCCESS) {
                        return SnmpError.SessionConfigFailed;
                    }
                }
            }

            // Context
            if (v3_sec.context_name) |context| {
                session.contextName = c.strdup(@ptrCast(context.ptr)) orelse return SnmpError.OutOfMemory;
                session.contextNameLen = context.len;
            }
        },
    }

    // Set peer name
    session.peername = c.strdup(@ptrCast(options.peername.ptr)) orelse {
        freeSessionStrings(&session);
        return SnmpError.OutOfMemory;
    };

    // Open the session
    const netsnmp_session = c.snmp_open(&session);
    if (netsnmp_session == null) {
        freeSessionStrings(&session);
        return SnmpError.SessionOpenFailed;
    }

    return Client{
        .session = netsnmp_session,
        .mutex = .{},
        .options = options,
    };
}

/// Free session strings (helper for init error handling)
fn freeSessionStrings(session: *c.struct_snmp_session) void {
    if (session.community != null) c.free(session.community);
    if (session.peername != null) c.free(session.peername);
    if (session.securityName != null) c.free(session.securityName);
    if (session.contextName != null) c.free(session.contextName);
}

/// Close the SNMP session and free resources
pub fn deinit(self: *Client) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    _ = c.snmp_close(self.session);
}

/// Generic request context for building different PDU types
const RequestContext = struct {
    pdu_type: c_int,
    oids: []const []const u8 = &.{},
    bindings: []const VarBind = &.{},
    non_repeaters: u8 = 0,
    max_repetitions: u8 = 0,

    /// Create a PDU from the request context
    fn createPdu(self: RequestContext) SnmpError!*c.struct_snmp_pdu {
        const pdu = c.snmp_pdu_create(self.pdu_type);
        if (pdu == null) return SnmpError.PduCreationFailed;

        // Handle GETBULK specific fields
        if (self.pdu_type == c.SNMP_MSG_GETBULK) {
            pdu.*.errstat = self.non_repeaters;
            pdu.*.errindex = self.max_repetitions;
        }

        // Add OIDs for GET/GETNEXT/GETBULK operations
        for (self.oids) |oid| {
            try addOidToPdu(pdu, oid);
        }

        // Add variable bindings for SET operations
        for (self.bindings) |binding| {
            try addVarBindToPdu(pdu, binding);
        }

        return pdu;
    }

    /// Add a single OID to a PDU
    fn addOidToPdu(pdu: *c.struct_snmp_pdu, oid: []const u8) SnmpError!void {
        var oid_buf: [utils.MAX_OID_LEN]c.oid = undefined;
        var oid_len: usize = oid_buf.len;

        const oid_cstr = try utils.stringToNullTerminated(oid);
        if (c.snmp_parse_oid(@ptrCast(&oid_cstr), &oid_buf[0], &oid_len) == 0) {
            return SnmpError.OidParseFailed;
        }

        _ = c.snmp_add_null_var(pdu, &oid_buf[0], oid_len);
    }
};

/// Generic SNMP request handler that reduces duplication
fn executeRequest(self: *Client, context: RequestContext) SnmpError!*c.struct_snmp_pdu {
    const pdu = try context.createPdu();
    errdefer c.snmp_free_pdu(pdu);

    var resp_pdu: ?*c.struct_snmp_pdu = null;
    const status = c.snmp_synch_response(self.session, pdu, &resp_pdu);

    if (resp_pdu) |response| {
        if (status != c.SNMP_ERR_NOERROR) {
            c.snmp_free_pdu(response);
            try handleSnmpStatus(status);
        }

        if (response.errstat != c.SNMP_ERR_NOERROR) {
            c.snmp_free_pdu(response);
            try handleSnmpStatus(response.errstat);
        }

        return response;
    } else {
        return SnmpError.Timeout;
    }
}

/// Perform an SNMP GET operation
pub fn get(self: *Client, allocator: Allocator, oid: []const u8) SnmpError!Value {
    self.mutex.lock();
    defer self.mutex.unlock();

    const context = RequestContext{
        .pdu_type = c.SNMP_MSG_GET,
        .oids = &.{oid},
    };

    const response = try self.executeRequest(context);
    defer c.snmp_free_pdu(response);

    if (response.variables == null) {
        return SnmpError.NoSuchName;
    }
    // `response.variables` can legally be null, but we have already
    // returned early when that happens, so cast away the `allowzero`
    // qualifier before passing it to `parseValue`.
    return parseValue(allocator, @ptrCast(response.variables));
}

/// Perform an SNMP GETNEXT operation
pub fn getNext(self: *Client, allocator: Allocator, oid: []const u8) SnmpError!OidValue {
    self.mutex.lock();
    defer self.mutex.unlock();

    const context = RequestContext{
        .pdu_type = c.SNMP_MSG_GETNEXT,
        .oids = &.{oid},
    };

    const response = try self.executeRequest(context);
    defer c.snmp_free_pdu(response);

    if (response.variables == null) {
        return SnmpError.NoSuchName;
    }

    const vb = response.variables[0];
    const oid_str = try utils.oidToString(allocator, vb.name, vb.name_length);
    const value = try parseValue(allocator, @constCast(&vb));

    return OidValue{
        .oid = oid_str,
        .value = value,
    };
}

/// Perform an SNMP SET operation
pub fn set(self: *Client, bindings: []const VarBind) SnmpError!void {
    self.mutex.lock();
    defer self.mutex.unlock();

    const context = RequestContext{
        .pdu_type = c.SNMP_MSG_SET,
        .bindings = bindings,
    };

    const response = try self.executeRequest(context);
    defer c.snmp_free_pdu(response);
}

/// Perform an SNMP GETBULK operation (SNMPv2c and v3 only)
pub fn getBulk(self: *Client, allocator: Allocator, oid: []const u8, non_repeaters: u8, max_repetitions: u8) SnmpError!SnmpResult {
    if (self.options.version == .v1) {
        return SnmpError.WrongType; // GETBULK not supported in SNMPv1
    }

    self.mutex.lock();
    defer self.mutex.unlock();

    const context = RequestContext{
        .pdu_type = c.SNMP_MSG_GETBULK,
        .oids = &.{oid},
        .non_repeaters = non_repeaters,
        .max_repetitions = max_repetitions,
    };

    const response = try self.executeRequest(context);
    defer c.snmp_free_pdu(response);

    return parseMultipleVariables(allocator, response.variables);
}

/// Get multiple OIDs in a single request
pub fn getMultiple(self: *Client, allocator: Allocator, oids: []const []const u8) SnmpError!SnmpResult {
    self.mutex.lock();
    defer self.mutex.unlock();

    const context = RequestContext{
        .pdu_type = c.SNMP_MSG_GET,
        .oids = oids,
    };

    const response = try self.executeRequest(context);
    defer c.snmp_free_pdu(response);

    return parseMultipleVariables(allocator, response.variables);
}

/// State container used during a walk/bulk‑walk traversal.
///
/// A `WalkState` instance tracks the *cursor* OID that will be supplied in the
/// next `GETNEXT`/`GETBULK` request and provides helper methods that keep the
/// calling loop concise.
///
/// The struct stores both the original `base_oid` string and a numeric,
/// pre‑parsed copy so prefix checks do not allocate or parse on every
/// iteration.  All scratch space is kept inside the struct so the walk loop
/// itself remains allocation‑free.
const WalkState = struct {
    /// The *subtree root* originally supplied by the caller.
    base_oid: []const u8,
    /// Buffer containing the numeric OID that will be used in the next request.
    current_oid: [utils.MAX_OID_LEN]c.oid,
    /// Number of valid elements in `current_oid`.
    current_oid_len: usize,
    /// Parsed numeric representation of `base_oid` for constant‑time prefix checks.
    base_oid_parsed: [utils.MAX_OID_LEN]c.oid,
    /// Length of the valid prefix stored in `base_oid_parsed`.
    base_oid_len: usize,
    /// Allocator forwarded from the caller for any on‑the‑fly conversions.
    allocator: Allocator,

    /// Constructs a `WalkState` for the supplied `base_oid`.
    ///
    /// The cursor is initialised to the base OID itself.  Parsing is done
    /// once up‑front so subsequent iterations can reuse the numeric form.
    ///
    /// Returns `SnmpError.OidParseFailed` when the provided string cannot
    /// be parsed by Net‑SNMP.
    fn init(allocator: Allocator, base_oid: []const u8) SnmpError!WalkState {
        var current_oid: [utils.MAX_OID_LEN]c.oid = undefined;
        var current_oid_len: usize = current_oid.len;

        const oid_cstr = try utils.stringToNullTerminated(base_oid);
        if (c.snmp_parse_oid(@ptrCast(&oid_cstr), &current_oid[0], &current_oid_len) == 0) {
            return SnmpError.OidParseFailed;
        }

        var base_oid_parsed: [utils.MAX_OID_LEN]c.oid = undefined;
        @memcpy(base_oid_parsed[0..current_oid_len], current_oid[0..current_oid_len]);

        return WalkState{
            .base_oid = base_oid,
            .current_oid = current_oid,
            .current_oid_len = current_oid_len,
            .base_oid_parsed = base_oid_parsed,
            .base_oid_len = current_oid_len,
            .allocator = allocator,
        };
    }

    /// Returns `true` when `vb` still belongs to the subtree rooted at
    /// `base_oid`, permitting the walk to continue.
    fn isWithinBaseOid(self: WalkState, vb: *c.struct_variable_list) bool {
        if (vb.name_length < self.base_oid_len) return false;

        const vb_oid_prefix = vb.name[0..self.base_oid_len];
        const base_oid_slice = self.base_oid_parsed[0..self.base_oid_len];

        return std.mem.eql(c.oid, vb_oid_prefix, base_oid_slice);
    }

    /// Advances the cursor to the OID contained in `vb`.
    ///
    /// Must be called *after* the caller has processed a variable binding
    /// that was deemed valid.
    fn updateCurrent(self: *WalkState, vb: *c.struct_variable_list) void {
        self.current_oid_len = vb.name_length;
        @memcpy(self.current_oid[0..self.current_oid_len], vb.name[0..vb.name_length]);
    }

    /// Detects agent‑signalled termination markers (`NoSuchObject`,
    /// `NoSuchInstance`, `EndOfMibView`).
    fn isEndOfWalk(vb: *c.struct_variable_list) bool {
        return vb.type == c.SNMP_NOSUCHOBJECT or
            vb.type == c.SNMP_NOSUCHINSTANCE or
            vb.type == c.SNMP_ENDOFMIBVIEW;
    }
};

/// Perform an SNMP walk operation
pub fn walk(self: *Client, allocator: Allocator, base_oid: []const u8) SnmpError!SnmpResult {
    return self.walkWithOperation(allocator, base_oid, .getnext);
}

/// Perform a bulk walk operation (more efficient for large datasets)
pub fn bulkWalk(self: *Client, allocator: Allocator, base_oid: []const u8, max_repetitions: u8) SnmpError!SnmpResult {
    if (self.options.version == .v1) {
        return self.walk(allocator, base_oid);
    }
    return self.walkWithOperation(allocator, base_oid, .{
        .getbulk = max_repetitions,
    });
}

/// Walk operation type
const WalkOperation = union(enum) {
    getnext,
    getbulk: u8, // max_repetitions
};

/// Generic walk implementation
fn walkWithOperation(self: *Client, allocator: Allocator, base_oid: []const u8, operation: WalkOperation) SnmpError!SnmpResult {
    self.mutex.lock();
    defer self.mutex.unlock();

    var state = try WalkState.init(allocator, base_oid);
    var result = SnmpResult.init(allocator);
    var items = std.ArrayList(OidValue).init(allocator);
    defer items.deinit();

    var iterations: u32 = 0;

    // Determine maximum iterations based on SNMP version and operation type
    // SNMP v1 does not support GETBULK.
    const max_iterations: usize = switch (self.options.version) {
        .v1 => 1_000_000,
        .v2c, .v3 => switch (operation) {
            .getnext => 1_000_000,
            .getbulk => 10_000,
        },
    };

    while (iterations < max_iterations) {
        iterations += 1;

        // For walk operations, we need to create PDUs directly rather than use the generic context
        const pdu = switch (operation) {
            .getnext => blk: {
                const p = c.snmp_pdu_create(c.SNMP_MSG_GETNEXT);
                if (p == null) return SnmpError.OutOfMemory;
                _ = c.snmp_add_null_var(p, &state.current_oid[0], state.current_oid_len);
                break :blk p;
            },
            .getbulk => |max_reps| blk: {
                const p = c.snmp_pdu_create(c.SNMP_MSG_GETBULK);
                if (p == null) return SnmpError.OutOfMemory;
                p.*.errstat = 0; // non_repeaters
                p.*.errindex = max_reps; // max_repetitions
                _ = c.snmp_add_null_var(p, &state.current_oid[0], state.current_oid_len);
                break :blk p;
            },
        };

        var resp_pdu: ?*c.struct_snmp_pdu = null;
        const status = c.snmp_synch_response(self.session, pdu, &resp_pdu);

        if (resp_pdu) |response| {
            defer c.snmp_free_pdu(response);

            if (status != c.SNMP_ERR_NOERROR) {
                try handleSnmpStatus(status);
            }

            const vb = response.variables orelse break;

            switch (operation) {
                .getnext => {
                    if (WalkState.isEndOfWalk(vb) or !state.isWithinBaseOid(vb)) break;

                    const oid_str = try utils.oidToString(allocator, vb.*.name, vb.*.name_length);
                    const value = try parseValue(allocator, vb);

                    try items.append(OidValue{ .oid = oid_str, .value = value });
                    state.updateCurrent(vb);
                },
                .getbulk => {
                    var found_valid = false;
                    var current_var = vb;

                    while (current_var) |v| {
                        if (WalkState.isEndOfWalk(v) or !state.isWithinBaseOid(v)) break;

                        const oid_str = try utils.oidToString(allocator, v.*.name, v.*.name_length);
                        const value = try parseValue(allocator, v);

                        try items.append(OidValue{ .oid = oid_str, .value = value });
                        state.updateCurrent(v);
                        found_valid = true;

                        current_var = v.*.next_variable;
                    }

                    if (!found_valid) break;
                },
            }
        } else {
            return SnmpError.Timeout;
        }
    }

    result.items = try items.toOwnedSlice();
    return result;
}

/// Parse multiple variables from a response
fn parseMultipleVariables(allocator: Allocator, first_var: ?*c.struct_variable_list) SnmpError!SnmpResult {
    var result = SnmpResult.init(allocator);
    var items = std.ArrayList(OidValue).init(allocator);
    defer items.deinit();

    var current_var = first_var;
    while (current_var) |vb| {
        const oid_str = try utils.oidToString(allocator, vb.name, vb.name_length);
        const value = try parseValue(allocator, vb);

        try items.append(OidValue{
            .oid = oid_str,
            .value = value,
        });

        current_var = vb.next_variable;
    }

    result.items = try items.toOwnedSlice();
    return result;
}

/// Add a variable binding to a PDU for SET operations
fn addVarBindToPdu(pdu: *c.struct_snmp_pdu, binding: VarBind) SnmpError!void {
    var oid_buf: [utils.MAX_OID_LEN]c.oid = undefined;
    var oid_len: usize = oid_buf.len;

    const oid_cstr = try utils.stringToNullTerminated(binding.oid);
    if (c.snmp_parse_oid(@ptrCast(&oid_cstr), &oid_buf[0], &oid_len) == 0) {
        return SnmpError.OidParseFailed;
    }

    switch (binding.value) {
        .integer => |val| {
            _ = c.snmp_pdu_add_variable(pdu, &oid_buf[0], oid_len, c.ASN_INTEGER, @ptrCast(&val), @sizeOf(i32));
        },
        .string => |val| {
            _ = c.snmp_pdu_add_variable(pdu, &oid_buf[0], oid_len, c.ASN_OCTET_STR, @ptrCast(val.ptr), val.len);
        },
        .gauge => |val| {
            _ = c.snmp_pdu_add_variable(pdu, &oid_buf[0], oid_len, c.ASN_GAUGE, @ptrCast(&val), @sizeOf(u32));
        },
        .counter => |val| {
            _ = c.snmp_pdu_add_variable(pdu, &oid_buf[0], oid_len, c.ASN_COUNTER, @ptrCast(&val), @sizeOf(u32));
        },
        .timeticks => |val| {
            _ = c.snmp_pdu_add_variable(pdu, &oid_buf[0], oid_len, c.ASN_TIMETICKS, @ptrCast(&val), @sizeOf(u32));
        },
        .ipaddress => |val| {
            _ = c.snmp_pdu_add_variable(pdu, &oid_buf[0], oid_len, c.ASN_IPADDRESS, @ptrCast(&val), 4);
        },
        .oid => |val| {
            var val_oid: [utils.MAX_OID_LEN]c.oid = undefined;
            var val_oid_len: usize = val_oid.len;

            const val_cstr = try utils.stringToNullTerminated(val);
            if (c.snmp_parse_oid(@ptrCast(&val_cstr), &val_oid[0], &val_oid_len) == 0) {
                return SnmpError.OidParseFailed;
            }

            _ = c.snmp_pdu_add_variable(pdu, &oid_buf[0], oid_len, c.ASN_OBJECT_ID, @ptrCast(&val_oid), val_oid_len * @sizeOf(c.oid));
        },
        else => return SnmpError.WrongType,
    }
}

/// Handle SNMP status codes and convert to appropriate errors
fn handleSnmpStatus(status: c_long) SnmpError!void {
    if (status == c.SNMP_ERR_NOERROR) return;

    return switch (status) {
        c.SNMP_ERR_TOOBIG => SnmpError.ResponseTooLarge,
        c.SNMP_ERR_NOSUCHNAME => SnmpError.NoSuchName,
        c.SNMP_ERR_BADVALUE => SnmpError.BadValue,
        c.SNMP_ERR_READONLY => SnmpError.ReadOnly,
        c.SNMP_ERR_GENERR => SnmpError.GeneralError,
        c.SNMP_ERR_NOACCESS => SnmpError.NoAccess,
        c.SNMP_ERR_WRONGTYPE => SnmpError.WrongType,
        c.SNMP_ERR_WRONGLENGTH => SnmpError.WrongLength,
        c.SNMP_ERR_WRONGENCODING => SnmpError.WrongEncoding,
        c.SNMP_ERR_WRONGVALUE => SnmpError.WrongValue,
        c.SNMP_ERR_NOCREATION => SnmpError.NoCreation,
        c.SNMP_ERR_INCONSISTENTVALUE => SnmpError.InconsistentValue,
        c.SNMP_ERR_RESOURCEUNAVAILABLE => SnmpError.ResourceUnavailable,
        c.SNMP_ERR_COMMITFAILED => SnmpError.CommitFailed,
        c.SNMP_ERR_UNDOFAILED => SnmpError.UndoFailed,
        c.SNMP_ERR_AUTHORIZATIONERROR => SnmpError.AuthorizationError,
        c.SNMP_ERR_NOTWRITABLE => SnmpError.NotWritable,
        c.SNMP_ERR_INCONSISTENTNAME => SnmpError.InconsistentName,
        else => SnmpError.Unknown,
    };
}

/// Convert C variable to Zig Value
fn parseValue(allocator: Allocator, vb: *c.struct_variable_list) SnmpError!Value {
    return switch (vb.type) {
        c.ASN_INTEGER => Value{ .integer = @intCast(vb.val.integer[0]) },
        c.ASN_OCTET_STR => Value{
            .string = try allocator.dupe(u8, vb.val.string[0..vb.val_len]),
        },
        c.ASN_OBJECT_ID => {
            const oid_str = try utils.oidToString(allocator, vb.val.objid, vb.val_len / @sizeOf(c.oid));
            return Value{ .oid = oid_str };
        },
        c.ASN_IPADDRESS => {
            const ip_bytes = @as([*]u8, @ptrCast(vb.val.string))[0..4];
            return Value{ .ipaddress = [4]u8{ ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3] } };
        },
        c.ASN_COUNTER => Value{ .counter = @intCast(vb.val.integer[0]) },
        c.ASN_GAUGE => Value{ .gauge = @intCast(vb.val.integer[0]) },
        c.ASN_TIMETICKS => Value{ .timeticks = @intCast(vb.val.integer[0]) },
        c.ASN_COUNTER64 => {
            const counter64 = @as(*c.struct_counter64, @ptrCast(vb.val.counter64));
            return Value{ .counter64 = (@as(u64, counter64.high) << 32) | counter64.low };
        },
        c.ASN_FLOAT => Value{ .float = vb.val.floatVal[0] },
        c.ASN_DOUBLE => Value{ .double = vb.val.doubleVal[0] },
        c.ASN_NULL => Value{ .null = {} },
        c.ASN_OPAQUE => Value{
            .opaquev = try allocator.dupe(u8, vb.val.string[0..vb.val_len]),
        },
        c.ASN_BIT_STR => Value{
            .bit_string = try allocator.dupe(u8, vb.val.string[0..vb.val_len]),
        },
        c.SNMP_NOSUCHOBJECT => Value{ .no_such_object = {} },
        c.SNMP_NOSUCHINSTANCE => Value{ .no_such_instance = {} },
        c.SNMP_ENDOFMIBVIEW => Value{ .end_of_mib_view = {} },
        else => SnmpError.UnexpectedType,
    };
}
