const std = @import("std");

/// Basic subset of QUIC frames (RFC 9000 Section 19).
pub const FrameType = enum(u8) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02, // simplified, omitting ECN variants for now
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    stream = 0x08, // 0x08-0x0f STREAM* variants
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close = 0x1c,
    application_close = 0x1d,
};

pub const StreamFrame = struct {
    stream_id: u64,
    offset: u64,
    fin: bool,
    data: []const u8,
};

pub const CryptoFrame = struct {
    offset: u64,
    data: []const u8,
};

pub const PaddingFrame = struct { len: usize };

/// A simplified union of a few important frame types.
pub const Frame = union(enum) {
    padding: PaddingFrame,
    ping: void,
    stream: StreamFrame,
    crypto: CryptoFrame,

    // TODO: add ACK and other frames
};
