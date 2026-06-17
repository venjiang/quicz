const quicz = @import("../lib.zig");

const Error = quicz.Error;
const PacketNumberSpace = quicz.PacketNumberSpace;
const CryptoBackend = quicz.CryptoBackend;
const HandshakeTrafficSecrets = quicz.HandshakeTrafficSecrets;
const ZeroRttTrafficSecrets = quicz.ZeroRttTrafficSecrets;
const OneRttTrafficSecrets = quicz.OneRttTrafficSecrets;

/// Status returned by C-ABI TLS backend callbacks.
///
/// `pending` means that an optional pull-style callback has no new data yet.
/// Other callbacks should normally return `ok` or an error status.
pub const TlsBackendStatus = enum(c_int) {
    ok = 0,
    pending = 1,
    buffer_too_small = 2,
    crypto_error = 3,
    internal = 4,
};

/// Packet number space tag passed across the C TLS backend ABI.
pub const TlsBackendPacketSpace = enum(c_int) {
    initial = 0,
    handshake = 1,
    application = 2,

    fn fromPacketNumberSpace(space: PacketNumberSpace) TlsBackendPacketSpace {
        return switch (space) {
            .initial => .initial,
            .handshake => .handshake,
            .application => .application,
        };
    }
};

pub const TlsBackendReceiveFn = *const fn (
    context: *anyopaque,
    space: TlsBackendPacketSpace,
    data: [*]const u8,
    data_len: usize,
) callconv(.c) TlsBackendStatus;

pub const TlsBackendPullFn = *const fn (
    context: *anyopaque,
    space: TlsBackendPacketSpace,
    out: [*]u8,
    out_len: usize,
    written_len: *usize,
) callconv(.c) TlsBackendStatus;

pub const TlsBackendSetBytesFn = *const fn (
    context: *anyopaque,
    data: [*]const u8,
    data_len: usize,
) callconv(.c) TlsBackendStatus;

pub const TlsBackendPullBytesFn = *const fn (
    context: *anyopaque,
    out: [*]u8,
    out_len: usize,
    written_len: *usize,
) callconv(.c) TlsBackendStatus;

pub const TlsBackendPullHandshakeSecretsFn = *const fn (
    context: *anyopaque,
    out: *HandshakeTrafficSecrets,
) callconv(.c) TlsBackendStatus;

pub const TlsBackendPullZeroRttSecretsFn = *const fn (
    context: *anyopaque,
    out: *ZeroRttTrafficSecrets,
) callconv(.c) TlsBackendStatus;

pub const TlsBackendPullOneRttSecretsFn = *const fn (
    context: *anyopaque,
    out: *OneRttTrafficSecrets,
) callconv(.c) TlsBackendStatus;

pub const TlsBackendHandshakeConfirmedFn = *const fn (context: *anyopaque) callconv(.c) bool;

fn tlsBackendStatusError(status: TlsBackendStatus) Error!void {
    return switch (status) {
        .ok, .pending => {},
        .buffer_too_small => error.BufferTooSmall,
        .crypto_error => error.CryptoError,
        .internal => error.Internal,
    };
}

/// C-ABI TLS backend adapter for real QUIC TLS libraries.
///
/// This keeps C library bindings outside the transport core. Callbacks use a
/// small status-code ABI and output buffers, while `cryptoBackend()` exposes
/// the existing Zig `CryptoBackend` shape consumed by `Connection`.
pub const TlsBackend = struct {
    /// Opaque TLS library state passed to all callbacks.
    context: *anyopaque,
    /// Consume contiguous QUIC CRYPTO bytes received in `space`.
    receive: TlsBackendReceiveFn,
    /// Copy TLS-produced CRYPTO bytes for `space` into the caller buffer.
    pull: TlsBackendPullFn,
    /// Optional hook receiving encoded local QUIC transport parameters.
    set_local_transport_parameters: ?TlsBackendSetBytesFn = null,
    /// Optional hook returning peer QUIC transport-parameter extension bytes.
    pull_peer_transport_parameters: ?TlsBackendPullBytesFn = null,
    /// Optional hook returning TLS-produced Handshake traffic secrets.
    pull_handshake_traffic_secrets: ?TlsBackendPullHandshakeSecretsFn = null,
    /// Optional hook returning TLS-produced 0-RTT traffic secrets.
    pull_zero_rtt_traffic_secrets: ?TlsBackendPullZeroRttSecretsFn = null,
    /// Optional hook returning TLS-produced 1-RTT traffic secrets.
    pull_1rtt_traffic_secrets: ?TlsBackendPullOneRttSecretsFn = null,
    /// Optional handshake-complete probe.
    handshake_confirmed: ?TlsBackendHandshakeConfirmedFn = null,

    /// Expose this C-ABI TLS backend through the existing crypto drive API.
    pub fn cryptoBackend(self: *TlsBackend) CryptoBackend {
        return .{
            .context = self,
            .receive = receiveAdapter,
            .pull = pullAdapter,
            .set_local_transport_parameters = setLocalTransportParametersAdapter,
            .pull_peer_transport_parameters = pullPeerTransportParametersAdapter,
            .pull_handshake_traffic_secrets = pullHandshakeTrafficSecretsAdapter,
            .pull_zero_rtt_traffic_secrets = pullZeroRttTrafficSecretsAdapter,
            .pull_1rtt_traffic_secrets = pullOneRttTrafficSecretsAdapter,
            .handshake_confirmed = handshakeConfirmedAdapter,
        };
    }

    fn receiveAdapter(context: *anyopaque, space: PacketNumberSpace, data: []const u8) Error!void {
        const self: *TlsBackend = @ptrCast(@alignCast(context));
        const status = self.receive(
            self.context,
            TlsBackendPacketSpace.fromPacketNumberSpace(space),
            data.ptr,
            data.len,
        );
        try tlsBackendStatusError(status);
    }

    fn pullAdapter(context: *anyopaque, space: PacketNumberSpace, out_buf: []u8) Error!?[]const u8 {
        const self: *TlsBackend = @ptrCast(@alignCast(context));
        var written_len: usize = 0;
        const status = self.pull(
            self.context,
            TlsBackendPacketSpace.fromPacketNumberSpace(space),
            out_buf.ptr,
            out_buf.len,
            &written_len,
        );
        if (status == .pending) return null;
        try tlsBackendStatusError(status);
        if (written_len > out_buf.len) return error.BufferTooSmall;
        return out_buf[0..written_len];
    }

    fn setLocalTransportParametersAdapter(context: *anyopaque, data: []const u8) Error!void {
        const self: *TlsBackend = @ptrCast(@alignCast(context));
        const set_local = self.set_local_transport_parameters orelse return;
        const status = set_local(self.context, data.ptr, data.len);
        try tlsBackendStatusError(status);
    }

    fn pullPeerTransportParametersAdapter(context: *anyopaque, out_buf: []u8) Error!?[]const u8 {
        const self: *TlsBackend = @ptrCast(@alignCast(context));
        const pull_peer = self.pull_peer_transport_parameters orelse return null;
        var written_len: usize = 0;
        const status = pull_peer(self.context, out_buf.ptr, out_buf.len, &written_len);
        if (status == .pending) return null;
        try tlsBackendStatusError(status);
        if (written_len > out_buf.len) return error.BufferTooSmall;
        return out_buf[0..written_len];
    }

    fn pullHandshakeTrafficSecretsAdapter(context: *anyopaque) Error!?HandshakeTrafficSecrets {
        const self: *TlsBackend = @ptrCast(@alignCast(context));
        const pull_secrets = self.pull_handshake_traffic_secrets orelse return null;
        var secrets: HandshakeTrafficSecrets = undefined;
        const status = pull_secrets(self.context, &secrets);
        if (status == .pending) return null;
        try tlsBackendStatusError(status);
        return secrets;
    }

    fn pullZeroRttTrafficSecretsAdapter(context: *anyopaque) Error!?ZeroRttTrafficSecrets {
        const self: *TlsBackend = @ptrCast(@alignCast(context));
        const pull_secrets = self.pull_zero_rtt_traffic_secrets orelse return null;
        var secrets = ZeroRttTrafficSecrets{};
        const status = pull_secrets(self.context, &secrets);
        if (status == .pending) return null;
        try tlsBackendStatusError(status);
        return secrets;
    }

    fn pullOneRttTrafficSecretsAdapter(context: *anyopaque) Error!?OneRttTrafficSecrets {
        const self: *TlsBackend = @ptrCast(@alignCast(context));
        const pull_secrets = self.pull_1rtt_traffic_secrets orelse return null;
        var secrets: OneRttTrafficSecrets = undefined;
        const status = pull_secrets(self.context, &secrets);
        if (status == .pending) return null;
        try tlsBackendStatusError(status);
        return secrets;
    }

    fn handshakeConfirmedAdapter(context: *anyopaque) bool {
        const self: *TlsBackend = @ptrCast(@alignCast(context));
        const confirmed = self.handshake_confirmed orelse return false;
        return confirmed(self.context);
    }
};
