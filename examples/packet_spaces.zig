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

fn fixedWriter(buffer: []u8) FixedWriter {
    return .{ .buffer = buffer };
}

fn require(condition: bool) !void {
    if (!condition) return error.UnexpectedState;
}

fn requireError(expected: anyerror, result: anyerror!void) !void {
    result catch |err| {
        if (err == expected) return;
        return err;
    };
    return error.UnexpectedState;
}

pub fn main() !void {
    var conn = try quicz.QuicConnection.init(std.heap.page_allocator, .client, .{});
    defer conn.deinit();

    const initial_pn = try conn.recordPacketSentInSpace(.initial, 10, 100);
    const app_pn = try conn.recordPacketSentInSpace(.application, 20, 200);
    try require(initial_pn == 0);
    try require(app_pn == 0);

    var ack_raw: [32]u8 = undefined;
    var ack_out = fixedWriter(&ack_raw);
    try quicz.frame.encodeFrame(ack_out.writer(), .{ .ack = .{
        .largest_acknowledged = initial_pn,
        .ack_delay = 0,
        .first_ack_range = initial_pn,
    } });

    try conn.processDatagramInSpace(.initial, 60, ack_out.getWritten());
    try require(conn.sentPacketCount(.initial) == 0);
    try require(conn.sentPacketCount(.application) == 1);

    const ping = [_]u8{@intFromEnum(quicz.frame.FrameType.ping)};
    try conn.processDatagramInSpace(.handshake, 70, &ping);
    try conn.processDatagramInSpace(.application, 80, &ping);
    try require(conn.pendingAckLargest(.handshake) != null);

    try conn.discardPacketNumberSpace(.handshake);
    try require(conn.packetNumberSpaceDiscarded(.handshake));
    try require(conn.pendingAckLargest(.handshake) == null);

    var zero_rtt_server = try quicz.QuicConnection.init(std.heap.page_allocator, .server, .{});
    defer zero_rtt_server.deinit();

    var early_raw: [64]u8 = undefined;
    var early_out = fixedWriter(&early_raw);
    try quicz.frame.encodeFrame(early_out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = true,
        .data = "early",
    } });

    try zero_rtt_server.processDatagramForPacketType(.zero_rtt, 90, early_out.getWritten());
    try require(zero_rtt_server.pendingAckLargest(.application) == 0);
    try require(zero_rtt_server.nextPeerPacketNumber(.application) == 1);

    var stop_raw: [32]u8 = undefined;
    var stop_out = fixedWriter(&stop_raw);
    try quicz.frame.encodeFrame(stop_out.writer(), .{ .stop_sending = .{
        .stream_id = 0,
        .application_error_code = 7,
    } });
    try zero_rtt_server.processDatagramForPacketType(.zero_rtt, 100, stop_out.getWritten());
    try require(zero_rtt_server.pendingAckLargest(.application) == 1);
    try require(zero_rtt_server.nextPeerPacketNumber(.application) == 2);

    try requireError(
        error.InvalidPacket,
        zero_rtt_server.processDatagramForPacketType(.zero_rtt, 110, ack_out.getWritten()),
    );
    try require(zero_rtt_server.nextPeerPacketNumber(.application) == 2);
    try zero_rtt_server.processDatagramForPacketType(.one_rtt, 120, &ping);
    try require(zero_rtt_server.pendingAckLargest(.application) == 2);
    try require(zero_rtt_server.nextPeerPacketNumber(.application) == 3);

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const protected_secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };

    var protected_zero_rtt_client = try quicz.QuicConnection.init(std.heap.page_allocator, .client, .{});
    defer protected_zero_rtt_client.deinit();
    var protected_zero_rtt_server = try quicz.QuicConnection.init(std.heap.page_allocator, .server, .{});
    defer protected_zero_rtt_server.deinit();

    const early_stream_id = try protected_zero_rtt_client.openStream();
    try protected_zero_rtt_client.sendOnStream(early_stream_id, "protected early", true);
    const protected_zero_rtt = (try protected_zero_rtt_client.pollProtectedZeroRttDatagram(
        130,
        &server_scid,
        &client_scid,
        protected_secrets.client,
    )) orelse return error.UnexpectedState;
    defer std.heap.page_allocator.free(protected_zero_rtt);

    const protected_count = try protected_zero_rtt_server.processProtectedLongDatagram(131, .{
        .zero_rtt = protected_secrets.client,
    }, protected_zero_rtt);
    try require(protected_count == 1);
    var protected_recv: [32]u8 = undefined;
    const protected_len = (try protected_zero_rtt_server.recvOnStream(early_stream_id, &protected_recv)) orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, protected_recv[0..protected_len], "protected early"));
    try require(protected_zero_rtt_server.pendingAckLargest(.application) == 0);
    try require(protected_zero_rtt_server.nextPeerPacketNumber(.application) == 1);

    std.debug.print("[spaces] initial_pn={} application_pn={}\n", .{ initial_pn, app_pn });
    std.debug.print("[spaces] after initial ACK bytes initial={} application={}\n", .{
        conn.bytesInFlight(.initial),
        conn.bytesInFlight(.application),
    });
    std.debug.print("[spaces] discarded handshake={} pending ACK handshake={?} application={?}\n", .{
        conn.packetNumberSpaceDiscarded(.handshake),
        conn.pendingAckLargest(.handshake),
        conn.pendingAckLargest(.application),
    });
    std.debug.print("[spaces] 0-rtt shared application next_peer_pn={} pending_ack={?}\n", .{
        zero_rtt_server.nextPeerPacketNumber(.application),
        zero_rtt_server.pendingAckLargest(.application),
    });
    std.debug.print("[spaces] protected 0-rtt packets={} bytes={} next_peer_pn={} pending_ack={?}\n", .{
        protected_count,
        protected_zero_rtt.len,
        protected_zero_rtt_server.nextPeerPacketNumber(.application),
        protected_zero_rtt_server.pendingAckLargest(.application),
    });
}
