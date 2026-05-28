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

fn protectedZeroRttHasStream(
    datagram: []const u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
    expected_packet_number: u64,
    expected_stream_id: u64,
    expected_data: []const u8,
    expected_fin: bool,
) !bool {
    var opened = try quicz.protection.unprotectLongPacketAes128(
        std.heap.page_allocator,
        keys,
        datagram,
        expected_packet_number,
    );
    defer quicz.protection.deinitProtectedLongPacket(&opened, std.heap.page_allocator);

    try require(opened.packet.header.packet_type == .zero_rtt);
    try require(opened.packet.header.packet_number == expected_packet_number);

    var payload_offset: usize = 0;
    while (payload_offset < opened.packet.plaintext.len) {
        var decoded = try quicz.frame.decodeFrameSlice(
            opened.packet.plaintext[payload_offset..],
            std.heap.page_allocator,
        );
        defer quicz.frame.deinitFrame(&decoded.frame, std.heap.page_allocator);

        switch (decoded.frame) {
            .stream => |stream| {
                if (stream.stream_id == expected_stream_id and
                    stream.offset == 0 and
                    stream.fin == expected_fin and
                    std.mem.eql(u8, stream.data, expected_data))
                {
                    return true;
                }
            },
            .padding => {},
            else => return error.UnexpectedState,
        }
        payload_offset += decoded.len;
    }
    return false;
}

const ControlExpectation = union(enum) {
    reset_stream: quicz.frame.ResetStreamFrame,
    stop_sending: quicz.frame.StopSendingFrame,
};

fn protectedZeroRttHasControl(
    datagram: []const u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
    expected_packet_number: u64,
    expected: ControlExpectation,
) !bool {
    var opened = try quicz.protection.unprotectLongPacketAes128(
        std.heap.page_allocator,
        keys,
        datagram,
        expected_packet_number,
    );
    defer quicz.protection.deinitProtectedLongPacket(&opened, std.heap.page_allocator);

    try require(opened.packet.header.packet_type == .zero_rtt);
    try require(opened.packet.header.packet_number == expected_packet_number);

    var payload_offset: usize = 0;
    while (payload_offset < opened.packet.plaintext.len) {
        var decoded = try quicz.frame.decodeFrameSlice(
            opened.packet.plaintext[payload_offset..],
            std.heap.page_allocator,
        );
        defer quicz.frame.deinitFrame(&decoded.frame, std.heap.page_allocator);

        const matched = switch (decoded.frame) {
            .reset_stream => |reset| switch (expected) {
                .reset_stream => |want| reset.stream_id == want.stream_id and
                    reset.application_error_code == want.application_error_code and
                    reset.final_size == want.final_size,
                else => false,
            },
            .stop_sending => |stop_sending| switch (expected) {
                .stop_sending => |want| stop_sending.stream_id == want.stream_id and
                    stop_sending.application_error_code == want.application_error_code,
                else => false,
            },
            .padding => false,
            else => return error.UnexpectedState,
        };
        if (matched) return true;
        payload_offset += decoded.len;
    }
    return false;
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

    const handshake_ecn_pn = try conn.recordEcnPacketSentInSpace(.handshake, 65, 100, .ect0);
    try conn.receiveAckEcnInSpace(.handshake, 66, .{
        .ack = .{
            .largest_acknowledged = handshake_ecn_pn,
            .ack_delay = 0,
            .first_ack_range = 0,
        },
        .ecn_counts = .{
            .ect0_count = 1,
            .ect1_count = 0,
            .ecn_ce_count = 0,
        },
    });
    try require(conn.ecnValidationState(.handshake) == .capable);

    const ping = [_]u8{@intFromEnum(quicz.frame.FrameType.ping)};
    try conn.processDatagramInSpace(.handshake, 70, &ping);
    try conn.processDatagramInSpace(.application, 80, &ping);
    try require(conn.pendingAckLargest(.handshake) != null);

    try conn.discardPacketNumberSpace(.handshake);
    try require(conn.packetNumberSpaceDiscarded(.handshake));
    try require(conn.pendingAckLargest(.handshake) == null);
    try require(conn.ecnValidationState(.handshake) == .unknown);
    try require(conn.ecnCounts(.handshake).ect0_count == 0);

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

    var zero_rtt_loss_client = try quicz.QuicConnection.init(std.heap.page_allocator, .client, .{});
    defer zero_rtt_loss_client.deinit();

    const loss_stream_id = try zero_rtt_loss_client.openStream();
    try zero_rtt_loss_client.sendOnStream(loss_stream_id, "lost early", true);
    const lost_zero_rtt = (try zero_rtt_loss_client.pollProtectedZeroRttDatagram(
        140,
        &server_scid,
        &client_scid,
        protected_secrets.client,
    )) orelse return error.UnexpectedState;
    defer std.heap.page_allocator.free(lost_zero_rtt);
    try require(try protectedZeroRttHasStream(
        lost_zero_rtt,
        protected_secrets.client,
        0,
        loss_stream_id,
        "lost early",
        true,
    ));

    _ = try zero_rtt_loss_client.recordPacketSentInSpace(.application, 150, 1);
    _ = try zero_rtt_loss_client.recordPacketSentInSpace(.application, 160, 1);
    _ = try zero_rtt_loss_client.recordPacketSentInSpace(.application, 170, 1);
    try zero_rtt_loss_client.receiveAckInSpace(.application, 180, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    const zero_rtt_retransmit = (try zero_rtt_loss_client.pollProtectedZeroRttDatagram(
        190,
        &server_scid,
        &client_scid,
        protected_secrets.client,
    )) orelse return error.UnexpectedState;
    defer std.heap.page_allocator.free(zero_rtt_retransmit);
    try require(try protectedZeroRttHasStream(
        zero_rtt_retransmit,
        protected_secrets.client,
        4,
        loss_stream_id,
        "lost early",
        true,
    ));

    var zero_rtt_reset_client = try quicz.QuicConnection.init(std.heap.page_allocator, .client, .{});
    defer zero_rtt_reset_client.deinit();

    const reset_stream_id = try zero_rtt_reset_client.openStream();
    try zero_rtt_reset_client.sendOnStream(reset_stream_id, "reset", false);
    try zero_rtt_reset_client.resetStream(reset_stream_id, 17);
    const zero_rtt_reset = (try zero_rtt_reset_client.pollProtectedZeroRttDatagram(
        200,
        &server_scid,
        &client_scid,
        protected_secrets.client,
    )) orelse return error.UnexpectedState;
    defer std.heap.page_allocator.free(zero_rtt_reset);
    try require(try protectedZeroRttHasControl(
        zero_rtt_reset,
        protected_secrets.client,
        0,
        .{ .reset_stream = .{
            .stream_id = reset_stream_id,
            .application_error_code = 17,
            .final_size = 5,
        } },
    ));

    _ = try zero_rtt_reset_client.recordPacketSentInSpace(.application, 210, 1);
    _ = try zero_rtt_reset_client.recordPacketSentInSpace(.application, 220, 1);
    _ = try zero_rtt_reset_client.recordPacketSentInSpace(.application, 230, 1);
    try zero_rtt_reset_client.receiveAckInSpace(.application, 240, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    const zero_rtt_reset_retransmit = (try zero_rtt_reset_client.pollProtectedZeroRttDatagram(
        250,
        &server_scid,
        &client_scid,
        protected_secrets.client,
    )) orelse return error.UnexpectedState;
    defer std.heap.page_allocator.free(zero_rtt_reset_retransmit);
    try require(try protectedZeroRttHasControl(
        zero_rtt_reset_retransmit,
        protected_secrets.client,
        4,
        .{ .reset_stream = .{
            .stream_id = reset_stream_id,
            .application_error_code = 17,
            .final_size = 5,
        } },
    ));

    var zero_rtt_stop_client = try quicz.QuicConnection.init(std.heap.page_allocator, .client, .{});
    defer zero_rtt_stop_client.deinit();

    const stop_stream_id = try zero_rtt_stop_client.openStream();
    try zero_rtt_stop_client.stopSending(stop_stream_id, 19);
    const zero_rtt_stop = (try zero_rtt_stop_client.pollProtectedZeroRttDatagram(
        260,
        &server_scid,
        &client_scid,
        protected_secrets.client,
    )) orelse return error.UnexpectedState;
    defer std.heap.page_allocator.free(zero_rtt_stop);
    try require(try protectedZeroRttHasControl(
        zero_rtt_stop,
        protected_secrets.client,
        0,
        .{ .stop_sending = .{
            .stream_id = stop_stream_id,
            .application_error_code = 19,
        } },
    ));

    _ = try zero_rtt_stop_client.recordPacketSentInSpace(.application, 270, 1);
    _ = try zero_rtt_stop_client.recordPacketSentInSpace(.application, 280, 1);
    _ = try zero_rtt_stop_client.recordPacketSentInSpace(.application, 290, 1);
    try zero_rtt_stop_client.receiveAckInSpace(.application, 300, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    const zero_rtt_stop_retransmit = (try zero_rtt_stop_client.pollProtectedZeroRttDatagram(
        310,
        &server_scid,
        &client_scid,
        protected_secrets.client,
    )) orelse return error.UnexpectedState;
    defer std.heap.page_allocator.free(zero_rtt_stop_retransmit);
    try require(try protectedZeroRttHasControl(
        zero_rtt_stop_retransmit,
        protected_secrets.client,
        4,
        .{ .stop_sending = .{
            .stream_id = stop_stream_id,
            .application_error_code = 19,
        } },
    ));

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
    std.debug.print("[spaces] discarded handshake ECN state={s} ect0_count={}\n", .{
        @tagName(conn.ecnValidationState(.handshake)),
        conn.ecnCounts(.handshake).ect0_count,
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
    std.debug.print("[spaces] protected 0-rtt retransmit bytes={} stream_id={} remaining_inflight={}\n", .{
        zero_rtt_retransmit.len,
        loss_stream_id,
        zero_rtt_loss_client.bytesInFlight(.application),
    });
    std.debug.print("[spaces] protected 0-rtt control retransmit reset_bytes={} stop_bytes={}\n", .{
        zero_rtt_reset_retransmit.len,
        zero_rtt_stop_retransmit.len,
    });
}
