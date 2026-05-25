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

fn endpointPath(remote_port: u16) quicz.endpoint.Udp4Tuple {
    return .{
        .local = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, remote_port),
    };
}

fn expectNewConnectionId(payload: []const u8, allocator: std.mem.Allocator, expected_sequence: u64, expected_cid: []const u8) !void {
    var offset: usize = 0;
    while (offset < payload.len) {
        var decoded = try quicz.frame.decodeFrameSlice(payload[offset..], allocator);
        defer quicz.frame.deinitFrame(&decoded.frame, allocator);
        if (decoded.len == 0) return error.UnexpectedState;

        switch (decoded.frame) {
            .new_connection_id => |new_id| {
                try require(new_id.sequence_number == expected_sequence);
                try require(std.mem.eql(u8, new_id.connection_id, expected_cid));
                return;
            },
            else => {},
        }

        offset += decoded.len;
    }

    return error.UnexpectedState;
}

fn retireConnectionId(conn: *quicz.QuicConnection, sequence_number: u64) !void {
    var raw: [16]u8 = undefined;
    var out = fixedWriter(&raw);
    try quicz.frame.encodeFrame(out.writer(), .{ .retire_connection_id = .{ .sequence_number = sequence_number } });
    try conn.processDatagram(10, out.getWritten());
}

fn protectedShortRoundtrip(allocator: std.mem.Allocator) !void {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try quicz.QuicConnection.init(allocator, .server, .{});
    defer server.deinit();
    var client = try quicz.QuicConnection.init(allocator, .client, .{});
    defer client.deinit();
    try server.validatePeerAddress();

    const token0 = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const cid0 = [_]u8{ 0xf0, 0x0d, 0x00, 0x00 };
    const sequence0 = try server.issueConnectionId(&cid0, token0, 0);

    const protected_new0 = (try server.pollProtectedShortDatagram(0, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(protected_new0);
    try client.processProtectedShortDatagram(1, secrets.server, client_dcid.len, protected_new0);

    const protected_ack0 = (try client.pollProtectedShortDatagram(2, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer allocator.free(protected_ack0);
    try server.processProtectedShortDatagram(3, secrets.client, server_dcid.len, protected_ack0);

    const token1 = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    const cid1 = [_]u8{ 0xf0, 0x0d, 0x00, 0x01 };
    const sequence1 = try server.issueConnectionId(&cid1, token1, 1);
    const protected_new1 = (try server.pollProtectedShortDatagram(4, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(protected_new1);
    try client.processProtectedShortDatagram(5, secrets.server, client_dcid.len, protected_new1);
    try require(client.pendingAckLargest(.application) != null);

    const protected_retire = (try client.pollProtectedShortDatagram(6, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer allocator.free(protected_retire);
    try server.processProtectedShortDatagram(7, secrets.client, server_dcid.len, protected_retire);
    try require(server.localConnectionIdCount() == 1);
    try require(server.bytesInFlight(.application) == 0);

    const protected_ack1 = (try server.pollProtectedShortDatagram(8, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(protected_ack1);
    try client.processProtectedShortDatagram(9, secrets.server, client_dcid.len, protected_ack1);
    try require(client.bytesInFlight(.application) == 0);

    std.debug.print("[cid] protected_new={}->{} protected_retire={} active_local={}\n", .{
        sequence0,
        sequence1,
        protected_retire.len,
        server.localConnectionIdCount(),
    });
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var conn = try quicz.QuicConnection.init(allocator, .server, .{});
    defer conn.deinit();
    try conn.validatePeerAddress();
    var router = quicz.endpoint.EndpointRouter.init(allocator);
    defer router.deinit();
    const path = endpointPath(50_000);

    const token0 = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const cid0 = [_]u8{ 0xc0, 0xff, 0xee, 0x00 };
    const sequence0 = try conn.issueConnectionId(&cid0, token0, 0);
    try router.registerConnectionId(77, &cid0, path, .{ .sequence_number = sequence0, .stateless_reset_token = token0 });
    try require(sequence0 == 0);
    try require(conn.pendingNewConnectionIdCount() == 1);

    var tx: [64]u8 = undefined;
    const payload0 = (try conn.pollTx(0, &tx)) orelse return error.UnexpectedState;
    try expectNewConnectionId(payload0, allocator, sequence0, &cid0);
    std.debug.print("[cid] issued sequence={} pending={}\n", .{ sequence0, conn.pendingNewConnectionIdCount() });

    try retireConnectionId(&conn, sequence0);
    try require(conn.localConnectionIdCount() == 0);
    std.debug.print("[cid] retired sequence={} active_local={}\n", .{ sequence0, conn.localConnectionIdCount() });

    const token1 = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    const cid1 = [_]u8{ 0xc0, 0xff, 0xee, 0x01 };
    const sequence1 = try conn.issueConnectionId(&cid1, token1, 1);
    const replacement = try router.registerReplacementConnectionId(77, &cid1, path, sequence1, 1, .{ .stateless_reset_token = token1 });
    const payload1 = (try conn.pollTx(20, &tx)) orelse return error.UnexpectedState;
    try expectNewConnectionId(payload1, allocator, sequence1, &cid1);
    const retired_route_token = (try router.statelessResetTokenForDatagram(path, &[_]u8{ 0x40, 0xc0, 0xff, 0xee, 0x00, 0x01 })) orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, &retired_route_token, &token0));
    try require((try router.routeDatagram(path, &[_]u8{ 0x40, 0xc0, 0xff, 0xee, 0x01, 0x01 })).sequence_number.? == sequence1);
    std.debug.print("[cid] replacement sequence={} retire_prior_to={} endpoint_retired={}\n", .{
        sequence1,
        replacement.retire_prior_to,
        replacement.retired_count,
    });

    try protectedShortRoundtrip(allocator);
}
