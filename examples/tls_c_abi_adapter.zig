const std = @import("std");
const c = @import("c");
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

fn require(condition: bool) ExampleError!void {
    if (!condition) return error.UnexpectedState;
}

fn requireStatus(status: quicz.TlsBackendStatus) ExampleError!void {
    try require(status == .ok);
}

fn requireCStatus(status: anytype) ExampleError!void {
    try require(@as(c_int, @intCast(status)) == c.QUICZ_TLS_BACKEND_OK);
}

fn tlsStatus(status: anytype) quicz.TlsBackendStatus {
    return @enumFromInt(@as(c_int, @intCast(status)));
}

fn cPacketSpace(space: quicz.TlsBackendPacketSpace) c.enum_quicz_tls_backend_packet_space {
    return @intCast(@intFromEnum(space));
}

fn cDemoReceive(
    context: *anyopaque,
    space: quicz.TlsBackendPacketSpace,
    data: [*]const u8,
    data_len: usize,
) callconv(.c) quicz.TlsBackendStatus {
    return tlsStatus(c.quicz_tls_c_demo_receive(context, cPacketSpace(space), data, data_len));
}

fn cDemoPull(
    context: *anyopaque,
    space: quicz.TlsBackendPacketSpace,
    out: [*]u8,
    out_len: usize,
    written_len: *usize,
) callconv(.c) quicz.TlsBackendStatus {
    return tlsStatus(c.quicz_tls_c_demo_pull(context, cPacketSpace(space), out, out_len, written_len));
}

fn cDemoSetLocalTransportParameters(
    context: *anyopaque,
    data: [*]const u8,
    data_len: usize,
) callconv(.c) quicz.TlsBackendStatus {
    return tlsStatus(c.quicz_tls_c_demo_set_local_transport_parameters(context, data, data_len));
}

fn cDemoPullPeerTransportParameters(
    context: *anyopaque,
    out: [*]u8,
    out_len: usize,
    written_len: *usize,
) callconv(.c) quicz.TlsBackendStatus {
    return tlsStatus(c.quicz_tls_c_demo_pull_peer_transport_parameters(context, out, out_len, written_len));
}

fn cDemoPullHandshakeTrafficSecrets(
    context: *anyopaque,
    out: *quicz.HandshakeTrafficSecrets,
) callconv(.c) quicz.TlsBackendStatus {
    var c_secrets: c.struct_quicz_handshake_traffic_secrets = undefined;
    const status = c.quicz_tls_c_demo_pull_handshake_traffic_secrets(context, &c_secrets);
    if (@as(c_int, @intCast(status)) == c.QUICZ_TLS_BACKEND_OK) {
        out.* = .{
            .local = c_secrets.local,
            .peer = c_secrets.peer,
        };
    }
    return tlsStatus(status);
}

fn cDemoHandshakeConfirmed(context: *anyopaque) callconv(.c) bool {
    return c.quicz_tls_c_demo_handshake_confirmed(context);
}

fn fixedWriter(buffer: []u8) FixedWriter {
    return .{ .buffer = buffer };
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    c.quicz_tls_c_demo_reset();

    var peer_transport_parameter_buf: [128]u8 = undefined;
    var peer_transport_parameter_out = fixedWriter(&peer_transport_parameter_buf);
    try quicz.transport_parameters.encode(peer_transport_parameter_out.writer(), .{
        .initial_max_data = 8192,
        .initial_max_stream_data_bidi_remote = 2048,
        .initial_max_streams_bidi = 2,
    });
    const peer_transport_parameters = peer_transport_parameter_out.getWritten();
    try requireCStatus(c.quicz_tls_c_demo_set_peer_transport_parameters(
        peer_transport_parameters.ptr,
        peer_transport_parameters.len,
    ));

    const outbound_crypto = "c tls server flight";
    try requireCStatus(c.quicz_tls_c_demo_set_outbound_crypto(
        outbound_crypto.ptr,
        outbound_crypto.len,
    ));

    const original_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0x10, 0x20, 0x30, 0x40 };
    const initial_secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);
    c.quicz_tls_c_demo_set_handshake_secrets(
        &initial_secrets.server.secret,
        &initial_secrets.client.secret,
        initial_secrets.server.secret.len,
    );

    var c_context: u8 = 0;
    var tls_backend = quicz.TlsBackend{
        .context = &c_context,
        .receive = cDemoReceive,
        .pull = cDemoPull,
        .set_local_transport_parameters = cDemoSetLocalTransportParameters,
        .pull_peer_transport_parameters = cDemoPullPeerTransportParameters,
        .pull_handshake_traffic_secrets = cDemoPullHandshakeTrafficSecrets,
        .handshake_confirmed = cDemoHandshakeConfirmed,
    };

    var connection = try quicz.Connection.init(allocator, .server, .{
        .initial_max_data = 1234,
        .initial_max_stream_data = 567,
    });
    defer connection.deinit();

    const inbound_crypto = "zig passes crypto to C";
    var inbound_payload_buf: [96]u8 = undefined;
    var inbound_payload = fixedWriter(&inbound_payload_buf);
    try quicz.frame.encodeFrame(inbound_payload.writer(), .{ .crypto = .{
        .offset = 0,
        .data = inbound_crypto,
    } });
    try connection.processDatagramInSpace(.handshake, 0, inbound_payload.getWritten());

    var scratch: [256]u8 = undefined;
    const progress = try connection.driveCryptoBackendInSpace(
        .handshake,
        tls_backend.cryptoBackend(),
        &scratch,
    );

    try require(c.quicz_tls_c_demo_local_transport_parameters_len() > 0);
    try require(c.quicz_tls_c_demo_inbound_crypto_matches(inbound_crypto.ptr, inbound_crypto.len));
    try require(c.quicz_tls_c_demo_inbound_crypto_len() == inbound_crypto.len);
    try require(progress.peer_transport_parameters_applied);
    try require(progress.peer_transport_parameters_bytes == peer_transport_parameters.len);
    try require(progress.inbound_bytes == inbound_crypto.len);
    try require(progress.outbound_chunks == 1);
    try require(progress.outbound_bytes == outbound_crypto.len);
    try require(progress.handshake_keys_installed);
    try require(progress.handshake_confirmed);
    try require(connection.hasHandshakeProtectionKeys());

    std.debug.print(
        "[tls-c-abi-adapter] local_tp_bytes={} peer_tp_bytes={} inbound_bytes={} outbound_bytes={} handshake_keys={} confirmed={}\n",
        .{
            c.quicz_tls_c_demo_local_transport_parameters_len(),
            progress.peer_transport_parameters_bytes,
            progress.inbound_bytes,
            progress.outbound_bytes,
            progress.handshake_keys_installed,
            progress.handshake_confirmed,
        },
    );
}
