const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

const FixedWriter = struct {
    buffer: []u8,
    pos: usize = 0,

    pub fn writer(self: *FixedWriter) *FixedWriter {
        return self;
    }

    pub fn writeByte(self: *FixedWriter, byte: u8) !void {
        if (self.pos >= self.buffer.len) return error.NoSpaceLeft;
        self.buffer[self.pos] = byte;
        self.pos += 1;
    }

    pub fn writeAll(self: *FixedWriter, bytes: []const u8) !void {
        if (self.buffer.len - self.pos < bytes.len) return error.NoSpaceLeft;
        @memcpy(self.buffer[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    pub fn getWritten(self: FixedWriter) []const u8 {
        return self.buffer[0..self.pos];
    }
};

const ScriptedCTlsBackend = struct {
    local_transport_parameters: [256]u8 = undefined,
    local_transport_parameters_len: usize = 0,
    inbound: [128]u8 = undefined,
    inbound_len: usize = 0,
    peer_transport_parameters: []const u8,
    peer_transport_parameters_sent: bool = false,
    outbound: []const u8,
    outbound_sent: bool = false,
    handshake_secrets: quicz.HandshakeTrafficSecrets,
    handshake_secrets_sent: bool = false,

    fn receive(
        context: *anyopaque,
        space: quicz.TlsBackendPacketSpace,
        data: [*]const u8,
        data_len: usize,
    ) callconv(.c) quicz.TlsBackendStatus {
        if (space != .handshake) return .crypto_error;
        const self: *ScriptedCTlsBackend = @ptrCast(@alignCast(context));
        if (data_len > self.inbound.len - self.inbound_len) return .buffer_too_small;
        @memcpy(self.inbound[self.inbound_len..][0..data_len], data[0..data_len]);
        self.inbound_len += data_len;
        return .ok;
    }

    fn pull(
        context: *anyopaque,
        space: quicz.TlsBackendPacketSpace,
        out: [*]u8,
        out_len: usize,
        written_len: *usize,
    ) callconv(.c) quicz.TlsBackendStatus {
        if (space != .handshake) return .crypto_error;
        const self: *ScriptedCTlsBackend = @ptrCast(@alignCast(context));
        if (self.outbound_sent) return .pending;
        if (out_len < self.outbound.len) return .buffer_too_small;
        @memcpy(out[0..self.outbound.len], self.outbound);
        written_len.* = self.outbound.len;
        self.outbound_sent = true;
        return .ok;
    }

    fn setLocalTransportParameters(
        context: *anyopaque,
        data: [*]const u8,
        data_len: usize,
    ) callconv(.c) quicz.TlsBackendStatus {
        const self: *ScriptedCTlsBackend = @ptrCast(@alignCast(context));
        if (data_len > self.local_transport_parameters.len) return .buffer_too_small;
        @memcpy(self.local_transport_parameters[0..data_len], data[0..data_len]);
        self.local_transport_parameters_len = data_len;
        return .ok;
    }

    fn pullPeerTransportParameters(
        context: *anyopaque,
        out: [*]u8,
        out_len: usize,
        written_len: *usize,
    ) callconv(.c) quicz.TlsBackendStatus {
        const self: *ScriptedCTlsBackend = @ptrCast(@alignCast(context));
        if (self.peer_transport_parameters_sent) return .pending;
        if (out_len < self.peer_transport_parameters.len) return .buffer_too_small;
        @memcpy(out[0..self.peer_transport_parameters.len], self.peer_transport_parameters);
        written_len.* = self.peer_transport_parameters.len;
        self.peer_transport_parameters_sent = true;
        return .ok;
    }

    fn pullHandshakeTrafficSecrets(
        context: *anyopaque,
        out: *quicz.HandshakeTrafficSecrets,
    ) callconv(.c) quicz.TlsBackendStatus {
        const self: *ScriptedCTlsBackend = @ptrCast(@alignCast(context));
        if (self.handshake_secrets_sent) return .pending;
        out.* = self.handshake_secrets;
        self.handshake_secrets_sent = true;
        return .ok;
    }

    fn handshakeConfirmed(_: *anyopaque) callconv(.c) bool {
        return true;
    }
};

fn require(condition: bool) ExampleError!void {
    if (!condition) return error.UnexpectedState;
}

fn fixedWriter(buffer: []u8) FixedWriter {
    return .{ .buffer = buffer };
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var peer_transport_parameter_buf: [128]u8 = undefined;
    var peer_transport_parameter_out = fixedWriter(&peer_transport_parameter_buf);
    try quicz.transport_parameters.encode(peer_transport_parameter_out.writer(), .{
        .initial_max_data = 4096,
        .initial_max_stream_data_bidi_local = 1024,
        .initial_max_streams_bidi = 4,
    });

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var scripted = ScriptedCTlsBackend{
        .peer_transport_parameters = peer_transport_parameter_out.getWritten(),
        .outbound = "server tls flight",
        .handshake_secrets = .{
            .local = secrets.server.secret,
            .peer = secrets.client.secret,
        },
    };
    var tls_backend = quicz.TlsBackend{
        .context = &scripted,
        .receive = ScriptedCTlsBackend.receive,
        .pull = ScriptedCTlsBackend.pull,
        .set_local_transport_parameters = ScriptedCTlsBackend.setLocalTransportParameters,
        .pull_peer_transport_parameters = ScriptedCTlsBackend.pullPeerTransportParameters,
        .pull_handshake_traffic_secrets = ScriptedCTlsBackend.pullHandshakeTrafficSecrets,
        .handshake_confirmed = ScriptedCTlsBackend.handshakeConfirmed,
    };

    var connection = try quicz.Connection.init(allocator, .server, .{
        .initial_max_data = 777,
        .initial_max_stream_data = 333,
    });
    defer connection.deinit();

    var inbound_payload_buf: [64]u8 = undefined;
    var inbound_payload = fixedWriter(&inbound_payload_buf);
    try quicz.frame.encodeFrame(inbound_payload.writer(), .{ .crypto = .{
        .offset = 0,
        .data = "client tls flight",
    } });
    try connection.processDatagramInSpace(.handshake, 0, inbound_payload.getWritten());

    var scratch: [256]u8 = undefined;
    const progress = try connection.driveCryptoBackendInSpace(
        .handshake,
        tls_backend.cryptoBackend(),
        &scratch,
    );

    try require(std.mem.eql(u8, scripted.inbound[0..scripted.inbound_len], "client tls flight"));
    try require(scripted.local_transport_parameters_len > 0);
    try require(progress.peer_transport_parameters_applied);
    try require(progress.handshake_keys_installed);
    try require(progress.handshake_confirmed);
    try require(progress.outbound_chunks == 1);
    try require(progress.outbound_bytes == scripted.outbound.len);
    try require(connection.hasHandshakeProtectionKeys());

    std.debug.print(
        "[tls-backend-adapter] local_tp_bytes={} peer_tp_bytes={} inbound_bytes={} outbound_bytes={} handshake_keys={} confirmed={}\n",
        .{
            scripted.local_transport_parameters_len,
            progress.peer_transport_parameters_bytes,
            progress.inbound_bytes,
            progress.outbound_bytes,
            progress.handshake_keys_installed,
            progress.handshake_confirmed,
        },
    );
}
