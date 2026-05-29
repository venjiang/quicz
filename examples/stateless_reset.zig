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

pub fn main() !void {
    var conn = try quicz.Connection.init(std.heap.page_allocator, .client, .{});
    defer conn.deinit();

    const cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var frame_raw: [64]u8 = undefined;
    var frame_out = fixedWriter(&frame_raw);
    try quicz.frame.encodeFrame(frame_out.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &cid,
        .stateless_reset_token = token,
    } });
    try conn.processDatagram(0, frame_out.getWritten());

    var reset_raw: [quicz.packet.min_stateless_reset_datagram_len]u8 = undefined;
    var reset_out = fixedWriter(&reset_raw);
    try quicz.packet.encodeStatelessReset(reset_out.writer(), &[_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd }, token);
    try require(conn.detectStatelessReset(reset_out.getWritten()) == 0);

    const other = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    reset_out = fixedWriter(&reset_raw);
    try quicz.packet.encodeStatelessReset(reset_out.writer(), &[_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd }, other);
    try require(conn.detectStatelessReset(reset_out.getWritten()) == null);

    var lifecycle = quicz.EndpointConnectionLifecycle.init(std.heap.page_allocator);
    defer lifecycle.deinit();
    const path = quicz.endpoint.Udp4Tuple{
        .local = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_000),
    };
    try lifecycle.registerConnectionId(7, &cid, path, .{ .stateless_reset_token = token });
    try require(lifecycle.routeCount() == 1);
    const retired = lifecycle.retireConnection(7);
    try require(retired.routes_retired == 1);

    const trigger = [_]u8{
        0x40, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    };
    var endpoint_reset_raw: [64]u8 = undefined;
    const endpoint_action = try lifecycle.handleDatagram(
        &endpoint_reset_raw,
        path,
        &trigger,
        &[_]u8{ 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde },
    );
    const endpoint_reset = switch (endpoint_action) {
        .stateless_reset => |reset| reset,
        else => return error.UnexpectedState,
    };
    try require(endpoint_reset.len < trigger.len);
    try require(quicz.packet.matchesStatelessReset(endpoint_reset, token));

    std.debug.print("[reset] matched peer stateless reset token for sequence=0\n", .{});
    std.debug.print("[reset] false token rejected\n", .{});
    std.debug.print("[reset] endpoint inactive CID reset bytes={} matched=true\n", .{endpoint_reset.len});
}
