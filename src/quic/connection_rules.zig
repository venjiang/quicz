const std = @import("std");

const packet = @import("packet.zig");
const protocol_limits = @import("protocol_limits.zig");
const transport_types = @import("transport_types.zig");

pub const Error = transport_types.Error;

/// Result of checking whether one ack-eliciting payload may be sent.
pub const AckElicitingSendAdmission = enum {
    allowed,
    congestion_limited,
    anti_amplification_limited,
};

pub const PeerTransportParameterValidationError = Error || error{
    VersionNegotiationError,
};

pub fn peerTransportParameterValidationErrorAsPublic(err: PeerTransportParameterValidationError) Error {
    return switch (err) {
        error.VersionNegotiationError => error.InvalidPacket,
        error.ConnectionClosed => error.ConnectionClosed,
        error.InvalidPacket => error.InvalidPacket,
        error.CryptoError => error.CryptoError,
        error.Internal => error.Internal,
        error.OutOfMemory => error.OutOfMemory,
        error.BufferTooSmall => error.BufferTooSmall,
        error.FlowControlBlocked => error.FlowControlBlocked,
        error.StreamClosed => error.StreamClosed,
        error.InvalidStream => error.InvalidStream,
    };
}

pub fn statelessResetTokensEqual(
    a: [packet.stateless_reset_token_len]u8,
    b: [packet.stateless_reset_token_len]u8,
) bool {
    return std.crypto.timing_safe.eql([packet.stateless_reset_token_len]u8, a, b);
}

pub fn validateInitialDestinationConnectionIdLength(dcid: []const u8) Error!void {
    if (dcid.len < protocol_limits.min_initial_destination_connection_id_len or
        dcid.len > protocol_limits.max_connection_id_len)
    {
        return error.InvalidPacket;
    }
}
