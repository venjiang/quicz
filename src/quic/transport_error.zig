const std = @import("std");

/// RFC 9000 transport error codes used in CONNECTION_CLOSE frames.
pub const TransportErrorCode = enum(u64) {
    no_error = 0x00,
    internal_error = 0x01,
    connection_refused = 0x02,
    flow_control_error = 0x03,
    stream_limit_error = 0x04,
    stream_state_error = 0x05,
    final_size_error = 0x06,
    frame_encoding_error = 0x07,
    transport_parameter_error = 0x08,
    connection_id_limit_error = 0x09,
    protocol_violation = 0x0a,
    invalid_token = 0x0b,
    application_error = 0x0c,
    crypto_buffer_exceeded = 0x0d,
    key_update_error = 0x0e,
    aead_limit_reached = 0x0f,
    no_viable_path = 0x10,
    version_negotiation_error = 0x11,

    _,
};

/// First transport error code reserved for cryptographic handshake errors.
pub const crypto_error_min: u64 = 0x0100;
/// Last transport error code reserved for cryptographic handshake errors.
pub const crypto_error_max: u64 = 0x01ff;

/// Return the wire value for a transport error code.
pub fn codeValue(code: TransportErrorCode) u64 {
    return @intFromEnum(code);
}

/// Return true when `raw_code` is one of the fixed RFC 9000 transport errors.
pub fn isKnownFixedCode(raw_code: u64) bool {
    return switch (raw_code) {
        0x00...0x11 => true,
        else => false,
    };
}

/// Return true when `raw_code` is in RFC 9000's CRYPTO_ERROR reserved range.
pub fn isCryptoErrorCode(raw_code: u64) bool {
    return raw_code >= crypto_error_min and raw_code <= crypto_error_max;
}

/// Return true when `raw_code` is defined by RFC 9000.
pub fn isKnownCode(raw_code: u64) bool {
    return isKnownFixedCode(raw_code) or isCryptoErrorCode(raw_code);
}

/// Return true when `code` is a generic protocol or connection shutdown error.
pub fn isConnectionCloseCode(code: TransportErrorCode) bool {
    return isKnownCode(codeValue(code));
}

/// Compose the CRYPTO_ERROR transport code for a TLS alert value.
pub fn cryptoErrorCode(tls_alert: u8) u64 {
    return crypto_error_min + @as(u64, tls_alert);
}

/// Extract a TLS alert from a CRYPTO_ERROR code.
pub fn cryptoErrorAlert(raw_code: u64) ?u8 {
    if (!isCryptoErrorCode(raw_code)) return null;
    return @intCast(raw_code - crypto_error_min);
}

test "transport error enum exposes RFC 9000 fixed code values" {
    try std.testing.expectEqual(@as(u64, 0x00), codeValue(.no_error));
    try std.testing.expectEqual(@as(u64, 0x01), codeValue(.internal_error));
    try std.testing.expectEqual(@as(u64, 0x02), codeValue(.connection_refused));
    try std.testing.expectEqual(@as(u64, 0x03), codeValue(.flow_control_error));
    try std.testing.expectEqual(@as(u64, 0x04), codeValue(.stream_limit_error));
    try std.testing.expectEqual(@as(u64, 0x05), codeValue(.stream_state_error));
    try std.testing.expectEqual(@as(u64, 0x06), codeValue(.final_size_error));
    try std.testing.expectEqual(@as(u64, 0x07), codeValue(.frame_encoding_error));
    try std.testing.expectEqual(@as(u64, 0x08), codeValue(.transport_parameter_error));
    try std.testing.expectEqual(@as(u64, 0x09), codeValue(.connection_id_limit_error));
    try std.testing.expectEqual(@as(u64, 0x0a), codeValue(.protocol_violation));
    try std.testing.expectEqual(@as(u64, 0x0b), codeValue(.invalid_token));
    try std.testing.expectEqual(@as(u64, 0x0c), codeValue(.application_error));
    try std.testing.expectEqual(@as(u64, 0x0d), codeValue(.crypto_buffer_exceeded));
    try std.testing.expectEqual(@as(u64, 0x0e), codeValue(.key_update_error));
    try std.testing.expectEqual(@as(u64, 0x0f), codeValue(.aead_limit_reached));
    try std.testing.expectEqual(@as(u64, 0x10), codeValue(.no_viable_path));
    try std.testing.expectEqual(@as(u64, 0x11), codeValue(.version_negotiation_error));
}

test "transport error helpers recognize fixed and crypto ranges" {
    try std.testing.expect(isKnownFixedCode(0x00));
    try std.testing.expect(isKnownFixedCode(0x11));
    try std.testing.expect(!isKnownFixedCode(0x12));

    try std.testing.expect(isCryptoErrorCode(0x0100));
    try std.testing.expect(isCryptoErrorCode(0x01ff));
    try std.testing.expect(!isCryptoErrorCode(0x00ff));
    try std.testing.expect(!isCryptoErrorCode(0x0200));

    try std.testing.expect(isKnownCode(0x0a));
    try std.testing.expect(isKnownCode(0x0100));
    try std.testing.expect(isKnownCode(0x11));
    try std.testing.expect(!isKnownCode(0x12));
}

test "crypto error helpers map TLS alert values" {
    try std.testing.expectEqual(@as(u64, 0x0100), cryptoErrorCode(0));
    try std.testing.expectEqual(@as(u64, 0x01ff), cryptoErrorCode(255));
    try std.testing.expectEqual(@as(?u8, 42), cryptoErrorAlert(0x012a));
    try std.testing.expectEqual(@as(?u8, null), cryptoErrorAlert(0x00ff));
    try std.testing.expectEqual(@as(?u8, null), cryptoErrorAlert(0x0200));
}
