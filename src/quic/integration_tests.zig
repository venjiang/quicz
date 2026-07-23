//! Integration tests — cross-module end-to-end scenarios.

const std = @import("std");
const connection_module = @import("connection.zig");
const recovery = @import("recovery.zig");
const cubic_module = @import("cubic.zig");
const pmtu = @import("pmtu.zig");
const session_cache = @import("session_cache.zig");
const migration = @import("migration.zig");
const tls13 = @import("../tls/tls13.zig");
const h3_frame = @import("../h3/frame.zig");
const qpack = @import("../h3/qpack.zig");
const h3_connection = @import("../h3/connection.zig");
const buffer = @import("buffer.zig");

const Connection = connection_module.Connection;

test "integration: CUBIC congestion control through recovery" {
    var r = recovery.Recovery.init(.{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
        .congestion_algorithm = .cubic,
    });

    var i: usize = 0;
    while (i < 10) : (i += 1) {
        r.onPacketSent(1200);
    }
    try std.testing.expectEqual(@as(usize, 12000), r.bytes_in_flight);

    r.onPacketAcked(1200, 50, 100, 0);
    r.onPacketAcked(1200, 50, 100, 0);
    try std.testing.expectEqual(@as(usize, 9600), r.bytes_in_flight);

    const cwnd_before = r.congestion_window;
    r.onPacketLost(1200, 50, 200);
    try std.testing.expect(r.congestion_window < cwnd_before);
    try std.testing.expect(r.cubic.w_max > 0);
}

test "integration: DATAGRAM frame through connection" {
    var sender = try Connection.init(std.testing.allocator, .client, .{
        .max_datagram_frame_size = 1200,
    });
    defer sender.deinit();
    try sender.confirmHandshake();

    var receiver = try Connection.init(std.testing.allocator, .server, .{
        .max_datagram_frame_size = 1200,
    });
    defer receiver.deinit();
    try receiver.confirmHandshake();
    try receiver.validatePeerAddress();

    try sender.sendDatagram("integration test datagram");
    try std.testing.expectEqual(@as(usize, 1), sender.pendingDatagramCount());

    var out_buf: [1500]u8 = undefined;
    const payload = (try sender.pollTx(0, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), sender.pendingDatagramCount());

    try receiver.processDatagramInSpace(.application, 0, payload);

    var recv_buf: [256]u8 = undefined;
    const n = (try receiver.recvDatagram(&recv_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("integration test datagram", recv_buf[0..n]);
}

test "integration: session cache with PSK derivation" {
    var cache = session_cache.SessionCache.init(std.testing.allocator);
    defer cache.deinit();

    const server_id = try std.testing.allocator.dupe(u8, "quic.example.com:443");
    const nonce = try std.testing.allocator.dupe(u8, "ticket-nonce-1");
    try cache.store(.{
        .server_id = server_id,
        .psk = [_]u8{0xab} ** 32,
        .lifetime_sec = 7200,
        .age_add = 999,
        .nonce = nonce,
        .allows_early_data = true,
        .remembered_max_data = 65536,
        .created_at_sec = 1000,
    });

    const ticket = cache.retrieve("quic.example.com:443", 1000).?;
    try std.testing.expect(ticket.allows_early_data);

    const resumption_secret = [_]u8{0x01} ** 32;
    const psk = tls13.KeySchedule.derivePskFromTicket(resumption_secret, ticket.nonce);
    try std.testing.expect(!std.mem.allEqual(u8, &psk, 0));
}

test "integration: migration with anti-amplification" {
    var mm = migration.MigrationManager{};

    _ = mm.onDatagramReceived("192.168.1.1:443", 1200);
    mm.onDatagramSent(1200);
    try std.testing.expect(mm.canSend());

    const rebound = mm.onDatagramReceived("10.0.0.1:5555", 1200);
    try std.testing.expect(rebound);

    mm.startValidation();
    mm.onDatagramSent(3600);
    try std.testing.expect(!mm.canSend());

    mm.onPathResponse();
    try std.testing.expect(mm.canSend());
}

test "integration: H3 connection with QPACK headers" {
    var conn = h3_connection.H3Connection.init(std.testing.allocator);
    defer conn.deinit();

    conn.markSettingsSent();
    conn.markSettingsReceived();
    try std.testing.expect(conn.isReady());

    const stream_id = try conn.openRequestStream();
    try std.testing.expectEqual(@as(u64, 0), stream_id);

    const fields = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
    };
    var header_buf: [256]u8 = undefined;
    const header_len = try qpack.encodeHeaderBlock(&header_buf, &fields);
    try std.testing.expect(header_len > 0);

    var frame_buf: [512]u8 = undefined;
    var out = buffer.fixedWriter(&frame_buf);
    try h3_frame.encodeFrame(out.writer(), .{
        .frame_type = @intFromEnum(h3_frame.FrameType.headers),
        .payload = header_buf[0..header_len],
    });
    try std.testing.expect(out.getWritten().len > header_len);
}
