const packet = @import("packet.zig");
const transport_parameters = @import("transport_parameters.zig");

/// Public error set returned by the experimental connection API.
pub const Error = error{
    ConnectionClosed,
    InvalidPacket,
    CryptoError,
    Internal,
    OutOfMemory,
    BufferTooSmall,
    FlowControlBlocked,
    StreamClosed,
    InvalidStream,
};

/// Endpoint role. It determines the locally initiated stream IDs.
pub const ConnectionSide = enum { client, server };

/// Directional RFC 9368 first-flight compatibility relation.
///
/// `original_version` is the version used by the client's first flight.
/// `negotiated_version` is the version a server can select after converting
/// that first flight. Compatibility is directional; callers must list every
/// explicitly specified direction they are willing to use.
pub const VersionCompatibility = struct {
    original_version: packet.Version,
    negotiated_version: packet.Version,
};

fn isZeroVersion(version: packet.Version) bool {
    return @intFromEnum(version) == 0;
}

/// Return whether `negotiated_version` can use `original_version`'s first flight.
///
/// The identity transformation is always compatible. All non-identity
/// conversions require a caller-provided, directional `VersionCompatibility`
/// entry so the library never assumes compatibility between QUIC versions.
pub fn canConvertFirstFlightVersion(
    original_version: packet.Version,
    negotiated_version: packet.Version,
    compatibilities: []const VersionCompatibility,
) bool {
    if (@intFromEnum(original_version) == @intFromEnum(negotiated_version)) return true;
    for (compatibilities) |compatibility| {
        if (@intFromEnum(compatibility.original_version) == @intFromEnum(original_version) and
            @intFromEnum(compatibility.negotiated_version) == @intFromEnum(negotiated_version))
        {
            return true;
        }
    }
    return false;
}

/// Select a compatible QUIC version from authenticated client Version Information.
///
/// `preferred_versions` is the server's preference order. The selected version
/// must be advertised by the client, must not be a reserved/zero version, and
/// must either be the client's chosen version or appear in `compatibilities` as
/// a directional first-flight conversion from the client's chosen version.
pub fn selectCompatibleVersion(
    preferred_versions: []const packet.Version,
    client_version_information: transport_parameters.VersionInformation,
    compatibilities: []const VersionCompatibility,
) ?packet.Version {
    if (isZeroVersion(client_version_information.chosen_version)) return null;
    if (packet.isReservedVersion(client_version_information.chosen_version)) return null;

    for (preferred_versions) |preferred| {
        if (isZeroVersion(preferred) or packet.isReservedVersion(preferred)) continue;
        if (!client_version_information.containsAvailableVersion(preferred)) continue;
        if (canConvertFirstFlightVersion(
            client_version_information.chosen_version,
            preferred,
            compatibilities,
        )) return preferred;
    }
    return null;
}

/// Modeled connection lifecycle for the experimental frame-payload API.
pub const ConnectionState = enum {
    /// Normal send and receive APIs are available.
    active,
    /// A local CONNECTION_CLOSE has been queued or sent; only close transmission remains.
    closing,
    /// A peer CONNECTION_CLOSE was received; packets are discarded until the drain timer ends.
    draining,
    /// Close/drain state has expired and the connection state can be discarded.
    closed,
};

/// Transport-layer close information received from the peer.
///
/// The reason phrase slice is owned by the connection and remains valid until
/// `deinit()`. A null `peerClose()` result means no peer close frame has been
/// accepted yet.
pub const PeerClose = union(enum) {
    /// Peer sent a transport CONNECTION_CLOSE frame.
    connection: struct {
        /// QUIC transport error code carried by the peer.
        error_code: u64,
        /// Frame type that triggered the close, or 0 when not frame-specific.
        frame_type: u64,
        /// Peer-provided diagnostic reason phrase.
        reason_phrase: []const u8,
    },
    /// Peer sent an application CONNECTION_CLOSE frame.
    application: struct {
        /// Application error code carried by the peer.
        error_code: u64,
        /// Peer-provided diagnostic reason phrase.
        reason_phrase: []const u8,
    },
};

/// Modeled QUIC handshake progress for the experimental frame-payload API.
pub const HandshakeState = enum {
    /// Only Initial-level state has been observed or queued.
    initial,
    /// Handshake packet number space is active but the handshake is not confirmed.
    handshake,
    /// The handshake has been confirmed by HANDSHAKE_DONE or an external TLS hook.
    confirmed,
};

/// Modeled send-side lifecycle for a QUIC stream.
pub const StreamSendState = enum {
    /// The connection has no local send-side state for this stream.
    none,
    /// The send side is open and can queue STREAM data when flow control permits.
    ready,
    /// The send side has sent FIN and is closed for further writes.
    data_sent,
    /// All STREAM frames through FIN have been acknowledged by the peer.
    data_acked,
    /// The send side has queued RESET_STREAM and is closed for further writes.
    reset_sent,
    /// The RESET_STREAM frame has been acknowledged by the peer.
    reset_acked,
};

/// Modeled receive-side lifecycle for a QUIC stream.
pub const StreamReceiveState = enum {
    /// The connection has no receive-side state for this stream.
    none,
    /// The receive side is open and has not learned a final size.
    receiving,
    /// The receive side knows a final size but still has gaps before that offset.
    size_known,
    /// All bytes through the final size are buffered for the application.
    data_received,
    /// The application has read or observed all bytes through the final size.
    data_read,
    /// The peer reset the receive side and the final size is known.
    reset_received,
    /// The application has observed the peer reset through `recvOnStream()`.
    reset_read,
};

/// Read-only snapshot of the modeled send and receive state for one stream.
///
/// Null fields mean that side of the stream is not currently open or observed
/// in this connection. The snapshot is informational; callers still use
/// `sendOnStream()`, `recvOnStream()`, `resetStream()`, and `stopSending()` for
/// state transitions.
pub const StreamState = struct {
    /// Stream ID covered by this snapshot.
    stream_id: u64,
    /// Current modeled send-side lifecycle.
    send: StreamSendState,
    /// Current modeled receive-side lifecycle.
    receive: StreamReceiveState,
    /// Next send offset, or null when no send side exists.
    send_offset: ?u64,
    /// Current peer-advertised send credit for this stream, or null when absent.
    send_max_data: ?u64,
    /// Bytes currently buffered on the receive side, including pending ranges.
    receive_buffered: ?u64,
    /// Application read offset for the contiguous receive buffer.
    receive_read_offset: ?u64,
    /// Whether this endpoint has queued or sent STOP_SENDING for the receive side.
    receive_stop_sending_sent: ?bool,
    /// Final size learned from STREAM FIN or RESET_STREAM, if any.
    receive_final_size: ?u64,
    /// Application error code from peer RESET_STREAM, if any.
    receive_reset_error_code: ?u64,
};

/// QUIC packet number spaces from RFC 9000 Section 12.3.
pub const PacketNumberSpace = enum {
    /// Initial packets and ACKs for Initial packets.
    initial,
    /// Handshake packets and ACKs for Handshake packets.
    handshake,
    /// 0-RTT and 1-RTT application data packets.
    application,
};

/// Cause that arms the modeled QUIC loss detection timer.
pub const LossDetectionTimerKind = enum {
    /// Time-threshold loss detection is pending.
    loss_time,
    /// Probe Timeout is pending for ack-eliciting data in flight.
    pto,
};

/// Earliest modeled QUIC loss detection timer deadline.
///
/// `deadline_millis` uses the same caller-controlled millisecond clock passed
/// to send, receive, and recovery APIs. When any packet number space has a
/// loss-time deadline, RFC 9002 gives that timer precedence over PTO.
pub const LossDetectionTimerDeadline = struct {
    /// Packet number space whose timer should be serviced.
    space: PacketNumberSpace,
    /// Timer cause to handle at `deadline_millis`.
    kind: LossDetectionTimerKind,
    /// Absolute deadline in the connection's caller-controlled millisecond clock.
    deadline_millis: i64,
};
