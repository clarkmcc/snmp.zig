/// SNMP error types
pub const SnmpError = error{
    /// Failed to initialize SNMP session
    SessionOpenFailed,
    /// Failed to parse OID string
    OidParseFailed,
    /// Response was too large
    ResponseTooLarge,
    /// No such name exists
    NoSuchName,
    /// Bad value in request
    BadValue,
    /// Attempted to modify read-only variable
    ReadOnly,
    /// General SNMP error
    GeneralError,
    /// No access to variable
    NoAccess,
    /// Wrong type for operation
    WrongType,
    /// Wrong length for operation
    WrongLength,
    /// Wrong encoding for operation
    WrongEncoding,
    /// Wrong value for operation
    WrongValue,
    /// Cannot create variable
    NoCreation,
    /// Inconsistent value
    InconsistentValue,
    /// Resource unavailable
    ResourceUnavailable,
    /// Commit failed
    CommitFailed,
    /// Undo failed
    UndoFailed,
    /// Authorization error
    AuthorizationError,
    /// Variable not writable
    NotWritable,
    /// Inconsistent name
    InconsistentName,
    /// Unknown error
    Unknown,
    /// Unexpected ASN.1 type
    UnexpectedType,
    /// Memory allocation failed
    OutOfMemory,
    /// Invalid OID range for walk operation
    InvalidOidRange,
    /// Network timeout
    Timeout,
    /// PDU creation failed
    PduCreationFailed,
    /// Variable binding failed
    VariableBindingFailed,
    /// Session configuration failed
    SessionConfigFailed,
    /// Invalid security configuration
    InvalidSecurity,
    /// Engine ID discovery failed
    EngineIdDiscoveryFailed,
    /// Bulk operation failed
    BulkFailed,
};
