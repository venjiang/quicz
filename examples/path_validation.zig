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

fn expectPathChallenge(payload: []const u8, allocator: std.mem.Allocator, expected: [8]u8) !void {
    var decoded = try quicz.frame.decodeFrameSlice(payload, allocator);
    defer quicz.frame.deinitFrame(&decoded.frame, allocator);
    switch (decoded.frame) {
        .path_challenge => |challenge| try require(std.mem.eql(u8, &challenge.data, &expected)),
        else => return error.UnexpectedState,
    }
}

fn encodePathResponse(buffer: []u8, data: [8]u8) ![]const u8 {
    var out = fixedWriter(buffer);
    try quicz.frame.encodeFrame(out.writer(), .{ .path_response = .{ .data = data } });
    return out.getWritten();
}

fn retryThenSucceed(allocator: std.mem.Allocator) !void {
    var conn = try quicz.Connection.init(allocator, .client, .{});
    defer conn.deinit();

    const challenge_data = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
    try conn.sendPathChallenge(challenge_data);

    var tx: [64]u8 = undefined;
    const first = (try conn.pollTx(0, &tx)) orelse return error.UnexpectedState;
    try expectPathChallenge(first, allocator, challenge_data);
    try require(conn.pendingPathChallengeCount() == 0);
    try require(conn.outstandingPathChallengeCount() == 1);

    try conn.checkPathValidationTimeouts(10_000);
    try require(conn.pendingPathChallengeCount() == 1);
    try require(conn.outstandingPathChallengeCount() == 0);
    try require(conn.failedPathValidationCount() == 0);

    const retry = (try conn.pollTx(10_000, &tx)) orelse return error.UnexpectedState;
    try expectPathChallenge(retry, allocator, challenge_data);
    try require(conn.pendingPathChallengeCount() == 0);
    try require(conn.outstandingPathChallengeCount() == 1);

    var response_raw: [16]u8 = undefined;
    const response = try encodePathResponse(&response_raw, challenge_data);
    try conn.processDatagram(10_010, response);
    try require(conn.outstandingPathChallengeCount() == 0);
    try require(conn.failedPathValidationCount() == 0);

    std.debug.print("[path] timeout queued retry and matching PATH_RESPONSE validated\n", .{});
}

fn retryThenFail(allocator: std.mem.Allocator) !void {
    var conn = try quicz.Connection.init(allocator, .client, .{});
    defer conn.deinit();

    const challenge_data = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 };
    try conn.sendPathChallenge(challenge_data);

    var tx: [64]u8 = undefined;
    _ = (try conn.pollTx(0, &tx)) orelse return error.UnexpectedState;

    try conn.checkPathValidationTimeouts(10_000);
    _ = (try conn.pollTx(10_000, &tx)) orelse return error.UnexpectedState;

    try conn.checkPathValidationTimeouts(20_000);
    _ = (try conn.pollTx(20_000, &tx)) orelse return error.UnexpectedState;

    try conn.checkPathValidationTimeouts(30_000);
    try require(conn.pendingPathChallengeCount() == 0);
    try require(conn.outstandingPathChallengeCount() == 0);
    try require(conn.failedPathValidationCount() == 1);

    std.debug.print("[path] retry budget exhausted failed_validations={}\n", .{conn.failedPathValidationCount()});
}

fn protectedShortRoundtrip(allocator: std.mem.Allocator) !void {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);
    const old_path = endpointPath(50_000);
    const new_path = endpointPath(50_001);

    var lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer lifecycle.deinit();
    try lifecycle.registerConnectionId(33, &client_dcid, old_path, .{});
    try require(lifecycle.routeCount() == 1);

    var client = try quicz.Connection.init(allocator, .client, .{});
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    const challenge_data = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    try client.sendPathChallenge(challenge_data);

    const challenge = (try client.pollProtectedShortDatagram(0, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer allocator.free(challenge);
    try require(challenge.len >= 1200);
    try require(client.pendingPathChallengeCount() == 0);
    try require(client.outstandingPathChallengeCount() == 1);

    try server.processProtectedShortDatagram(1, secrets.client, server_dcid.len, challenge);

    const response = (try server.pollProtectedShortDatagram(2, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(response);
    try require(response.len >= 1200);
    const validation_result = try lifecycle.processRoutedProtectedShortDatagramAndUpdatePath(
        33,
        &client,
        new_path,
        3,
        secrets.server,
        response,
    );
    try require(validation_result.route.path_changed);
    try require(client.outstandingPathChallengeCount() == 0);
    try require(client.bytesInFlight(.application) == 0);

    const updated_route = validation_result.updated_route orelse return error.UnexpectedState;
    try require(!updated_route.path_changed);
    const confirmed_route = try lifecycle.routeDatagram(new_path, response);
    try require(!confirmed_route.path_changed);

    const ack = (try client.pollProtectedShortDatagram(4, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer allocator.free(ack);
    try server.processProtectedShortDatagram(5, secrets.client, server_dcid.len, ack);
    try require(server.bytesInFlight(.application) == 0);

    std.debug.print("[path] protected short PATH_CHALLENGE/PATH_RESPONSE bytes={}/{} endpoint_path_changed={} endpoint_path_updated={}\n", .{
        challenge.len,
        response.len,
        validation_result.route.path_changed,
        !confirmed_route.path_changed,
    });
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    try retryThenSucceed(allocator);
    try retryThenFail(allocator);
    try protectedShortRoundtrip(allocator);
}
