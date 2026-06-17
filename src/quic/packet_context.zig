const protection = @import("protection.zig");

/// QUIC packet type context used for frame-payload validation.
///
/// 0-RTT and 1-RTT share the application data packet number space, but RFC 9000
/// still restricts which frame types can appear in 0-RTT packets.
pub const FramePacketType = enum {
    /// Initial long-header packet payload.
    initial,
    /// 0-RTT long-header packet payload.
    zero_rtt,
    /// Handshake long-header packet payload.
    handshake,
    /// 1-RTT short-header packet payload.
    one_rtt,
};

/// Caller-supplied keys for protected long-packet receive routing.
///
/// `initial` is required when a coalesced datagram contains Initial packets.
/// `zero_rtt` is required when it contains 0-RTT packets. `handshake` is
/// required when it contains Handshake packets unless the installed-key
/// Handshake helpers are used. Real TLS transcript ownership and automatic key
/// discard remain future endpoint/TLS work.
pub const ProtectedLongDatagramKeys = struct {
    /// Keys used to open protected Initial long packets.
    initial: ?protection.Aes128PacketProtectionKeys = null,
    /// Keys used to open protected 0-RTT long packets.
    zero_rtt: ?protection.Aes128PacketProtectionKeys = null,
    /// Keys used to open protected Handshake long packets.
    handshake: ?protection.Aes128PacketProtectionKeys = null,
};

/// Modeled ECN codepoint used for packets recorded by the frame-payload API.
pub const EcnCodepoint = enum {
    /// Packet was not sent with an ECN-Capable Transport marking.
    not_ect,
    /// Packet was modeled as sent with ECT(0).
    ect0,
    /// Packet was modeled as sent with ECT(1).
    ect1,
};

/// Per-packet-number-space result of RFC 9000 ECN validation.
pub const EcnValidationState = enum {
    /// No ACK_ECN counter has validated this space yet.
    unknown,
    /// ACK_ECN counters have validated at least one increasing largest ACK.
    capable,
    /// ECN validation failed; future packetization should stop setting ECT.
    failed,
};
