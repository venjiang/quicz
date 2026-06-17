const packet = @import("packet.zig");
const transport_types = @import("transport_types.zig");

const LossDetectionTimerDeadline = transport_types.LossDetectionTimerDeadline;

/// Packet-number-space choice for endpoint installed-key datagram polling.
pub const EndpointInstalledKeyDatagramSpace = enum {
    /// Poll a Handshake long-header datagram with connection-installed keys.
    handshake,
    /// Poll a 0-RTT long-header datagram with connection-installed keys.
    zero_rtt,
    /// Poll a 1-RTT short-header datagram with connection-installed keys.
    application,
};

/// Options for polling a datagram after the connection owns packet-protection keys.
pub const EndpointPollInstalledKeyDatagramOptions = struct {
    /// Packet-number-space/header family to poll.
    space: EndpointInstalledKeyDatagramSpace,
    /// Destination connection ID to encode in the emitted packet.
    destination_connection_id: []const u8,
    /// Source connection ID for long-header Handshake/0-RTT packets.
    source_connection_id: []const u8 = &[_]u8{},

    /// Build installed-key poll options from a loss/PTO recovery deadline.
    ///
    /// Initial recovery returns null because Initial packetization does not use
    /// installed TLS traffic secrets. Application recovery maps to 1-RTT; use
    /// explicit `.zero_rtt` options when servicing accepted early data.
    pub fn fromRecoveryDeadline(
        timer: LossDetectionTimerDeadline,
        destination_connection_id: []const u8,
        source_connection_id: []const u8,
    ) ?EndpointPollInstalledKeyDatagramOptions {
        return switch (timer.space) {
            .initial => null,
            .handshake => .{
                .space = .handshake,
                .destination_connection_id = destination_connection_id,
                .source_connection_id = source_connection_id,
            },
            .application => .{
                .space = .application,
                .destination_connection_id = destination_connection_id,
            },
        };
    }
};

/// Options for feeding a datagram after the connection owns packet-protection keys.
pub const EndpointFeedInstalledKeyDatagramOptions = struct {
    /// Packet-number-space/header family expected for routed datagram processing.
    space: EndpointInstalledKeyDatagramSpace,
    /// Scratch output buffer for Version Negotiation or stateless reset actions.
    out: []u8,
    /// Endpoint entropy used when constructing stateless reset datagrams.
    unpredictable_prefix: []const u8,
    /// Versions supported by this endpoint for Initial accept/VN classification.
    supported_versions: []const packet.Version,
};
