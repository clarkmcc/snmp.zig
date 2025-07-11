const c = @cImport({
    @cInclude("stddef.h");
    @cInclude("net-snmp/net-snmp-config.h");
    @cInclude("net-snmp/net-snmp-includes.h");
});

/// SNMP Security Level (for SNMPv3)
pub const SecurityLevel = enum {
    no_auth_no_priv,
    auth_no_priv,
    auth_priv,

    pub fn toCInt(self: SecurityLevel) c_int {
        return switch (self) {
            .no_auth_no_priv => c.SNMP_SEC_LEVEL_NOAUTH,
            .auth_no_priv => c.SNMP_SEC_LEVEL_AUTHNOPRIV,
            .auth_priv => c.SNMP_SEC_LEVEL_AUTHPRIV,
        };
    }
};

/// SNMP Authentication Protocol (for SNMPv3)
pub const AuthProtocol = enum {
    none,
    md5,
    sha1,
    sha224,
    sha256,
    sha384,
    sha512,

    pub fn toOid(self: AuthProtocol) ?[]const c.oid {
        return switch (self) {
            .none => null,
            .md5 => c.usmHMACMD5AuthProtocol[0..c.USM_AUTH_PROTO_MD5_LEN],
            .sha1 => c.usmHMACSHA1AuthProtocol[0..c.USM_AUTH_PROTO_SHA_LEN],
            .sha224 => if (@hasDecl(c, "usmHMAC128SHA224AuthProtocol")) c.usmHMAC128SHA224AuthProtocol[0..c.USM_AUTH_PROTO_SHA224_LEN] else null,
            .sha256 => if (@hasDecl(c, "usmHMAC192SHA256AuthProtocol")) c.usmHMAC192SHA256AuthProtocol[0..c.USM_AUTH_PROTO_SHA256_LEN] else null,
            .sha384 => if (@hasDecl(c, "usmHMAC256SHA384AuthProtocol")) c.usmHMAC256SHA384AuthProtocol[0..c.USM_AUTH_PROTO_SHA384_LEN] else null,
            .sha512 => if (@hasDecl(c, "usmHMAC384SHA512AuthProtocol")) c.usmHMAC384SHA512AuthProtocol[0..c.USM_AUTH_PROTO_SHA512_LEN] else null,
        };
    }
};

/// SNMP Privacy Protocol (for SNMPv3)
pub const PrivProtocol = enum {
    none,
    des,
    aes128,
    aes192,
    aes256,

    pub fn toOid(self: PrivProtocol) ?[]const c.oid {
        return switch (self) {
            .none => null,
            .des => c.usmDESPrivProtocol[0..c.USM_PRIV_PROTO_DES_LEN],
            .aes128 => if (@hasDecl(c, "usmAES128PrivProtocol")) c.usmAES128PrivProtocol[0..c.USM_PRIV_PROTO_AES128_LEN] else null,
            .aes192 => if (@hasDecl(c, "usmAES192PrivProtocol")) c.usmAES192PrivProtocol[0..c.USM_PRIV_PROTO_AES192_LEN] else null,
            .aes256 => if (@hasDecl(c, "usmAES256PrivProtocol")) c.usmAES256PrivProtocol[0..c.USM_PRIV_PROTO_AES256_LEN] else null,
        };
    }
};

/// SNMPv3 Security Configuration
pub const V3Security = struct {
    security_name: []const u8,
    security_level: SecurityLevel = .no_auth_no_priv,
    auth_protocol: AuthProtocol = .none,
    auth_passphrase: ?[]const u8 = null,
    priv_protocol: PrivProtocol = .none,
    priv_passphrase: ?[]const u8 = null,
    context_name: ?[]const u8 = null,
    context_engine_id: ?[]const u8 = null,
};
